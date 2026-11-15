#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
godot-ex (Unified Pro): Termux/Android 专用 Godot EXE/PCK 识别、找密钥与流式解包工具
零第三方依赖 (纯 Python 3.8+ 标准库；若已安装 cryptography/pycryptodome 自动启用 C 加速)
支持: Godot 2.x ~ 4.7+ (PCK V0/V1/V2/V3/V4)、PE/ELF pck 节区、EOF 尾标、带签名 EXE
支持: PACK_DIR_ENCRYPTED / FILE_ENCRYPTED / Godot 3&4 GDEC 解密与自动找 Key
"""

import argparse
import fnmatch
import hashlib
import io
import math
import os
import re
import struct
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Dict, List, Optional, Set, Tuple

PACK_MAGIC = b"GDPC"
GDEC_MAGIC = b"GDEC"

PACK_DIR_ENCRYPTED = 1 << 0
PACK_REL_FILEBASE = 1 << 1
PACK_SPARSE_BUNDLE = 1 << 2

FILE_ENCRYPTED = 1 << 0
FILE_REMOVAL = 1 << 1

CHUNK_SIZE = 1024 * 1024           # 1MB 流式读写块 (必须是 16 的倍数以适配 CFB 流式解密)
MAX_FILE_COUNT = 2_000_000
DEFAULT_MAX_MEM = 64 * 1024 * 1024  # 仅转换媒体资源时的内存上限 (64MB)


# ======================== 1. 纯 Python AES-256 + 流式后端 ========================
def _gf_mul(a: int, b: int) -> int:
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return res


def _gf_inv(a: int) -> int:
    if a == 0:
        return 0
    res, base, exp = 1, a, 254
    while exp:
        if exp & 1:
            res = _gf_mul(res, base)
        base = _gf_mul(base, base)
        exp >>= 1
    return res


def _build_aes_tables():
    sbox = [0] * 256
    inv_sbox = [0] * 256
    for x in range(256):
        inv = _gf_inv(x)
        s = (
            inv
            ^ (((inv << 1) | (inv >> 7)) & 0xFF)
            ^ (((inv << 2) | (inv >> 6)) & 0xFF)
            ^ (((inv << 3) | (inv >> 5)) & 0xFF)
            ^ (((inv << 4) | (inv >> 4)) & 0xFF)
            ^ 0x63
        )
        sbox[x] = s
        inv_sbox[s] = x
    xtime = [(((i << 1) ^ 0x1B) & 0xFF) if (i & 0x80) else (i << 1) for i in range(256)]
    return tuple(sbox), tuple(inv_sbox), tuple(xtime)


SBOX, INV_SBOX, XT = _build_aes_tables()
RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40)


def expand_key_256(key: bytes) -> List[bytes]:
    w = [list(key[i * 4:(i + 1) * 4]) for i in range(8)]
    for i in range(8, 60):
        t = w[i - 1][:]
        if i % 8 == 0:
            t = [SBOX[t[1]] ^ RCON[i // 8], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
        elif i % 8 == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i - 8][j] ^ t[j] for j in range(4)])
    return [bytes(w[4 * r] + w[4 * r + 1] + w[4 * r + 2] + w[4 * r + 3]) for r in range(15)]


def _aes256_encrypt_block(rk: List[bytes], block: bytes) -> bytes:
    s = [block[i] ^ rk[0][i] for i in range(16)]
    for r in range(1, 14):
        a0, a1, a2, a3 = SBOX[s[0]], SBOX[s[5]], SBOX[s[10]], SBOX[s[15]]
        a4, a5, a6, a7 = SBOX[s[4]], SBOX[s[9]], SBOX[s[14]], SBOX[s[3]]
        a8, a9, a10, a11 = SBOX[s[8]], SBOX[s[13]], SBOX[s[2]], SBOX[s[7]]
        a12, a13, a14, a15 = SBOX[s[12]], SBOX[s[1]], SBOX[s[6]], SBOX[s[11]]
        k = rk[r]
        for idx, (c0, c1, c2, c3) in enumerate((
            (a0, a1, a2, a3), (a4, a5, a6, a7), (a8, a9, a10, a11), (a12, a13, a14, a15)
        )):
            t = c0 ^ c1 ^ c2 ^ c3
            b = idx * 4
            s[b] = c0 ^ t ^ XT[c0 ^ c1] ^ k[b]
            s[b + 1] = c1 ^ t ^ XT[c1 ^ c2] ^ k[b + 1]
            s[b + 2] = c2 ^ t ^ XT[c2 ^ c3] ^ k[b + 2]
            s[b + 3] = c3 ^ t ^ XT[c3 ^ c0] ^ k[b + 3]
    k14 = rk[14]
    return bytes([
        SBOX[s[0]] ^ k14[0], SBOX[s[5]] ^ k14[1], SBOX[s[10]] ^ k14[2], SBOX[s[15]] ^ k14[3],
        SBOX[s[4]] ^ k14[4], SBOX[s[9]] ^ k14[5], SBOX[s[14]] ^ k14[6], SBOX[s[3]] ^ k14[7],
        SBOX[s[8]] ^ k14[8], SBOX[s[13]] ^ k14[9], SBOX[s[2]] ^ k14[10], SBOX[s[7]] ^ k14[11],
        SBOX[s[12]] ^ k14[12], SBOX[s[1]] ^ k14[13], SBOX[s[6]] ^ k14[14], SBOX[s[11]] ^ k14[15],
    ])


def _aes256_decrypt_block(rk: List[bytes], block: bytes) -> bytes:
    s = [block[i] ^ rk[14][i] for i in range(16)]
    for r in range(13, 0, -1):
        a0, a1, a2, a3 = INV_SBOX[s[0]], INV_SBOX[s[13]], INV_SBOX[s[10]], INV_SBOX[s[7]]
        a4, a5, a6, a7 = INV_SBOX[s[4]], INV_SBOX[s[1]], INV_SBOX[s[14]], INV_SBOX[s[11]]
        a8, a9, a10, a11 = INV_SBOX[s[8]], INV_SBOX[s[5]], INV_SBOX[s[2]], INV_SBOX[s[15]]
        a12, a13, a14, a15 = INV_SBOX[s[12]], INV_SBOX[s[9]], INV_SBOX[s[6]], INV_SBOX[s[3]]
        k = rk[r]
        cols = (
            (a0 ^ k[0], a1 ^ k[1], a2 ^ k[2], a3 ^ k[3]),
            (a4 ^ k[4], a5 ^ k[5], a6 ^ k[6], a7 ^ k[7]),
            (a8 ^ k[8], a9 ^ k[9], a10 ^ k[10], a11 ^ k[11]),
            (a12 ^ k[12], a13 ^ k[13], a14 ^ k[14], a15 ^ k[15]),
        )
        for idx, (c0, c1, c2, c3) in enumerate(cols):
            u = XT[XT[c0 ^ c2]]
            v = XT[XT[c1 ^ c3]]
            d0, d1, d2, d3 = c0 ^ u, c1 ^ v, c2 ^ u, c3 ^ v
            t = d0 ^ d1 ^ d2 ^ d3
            b = idx * 4
            s[b] = d0 ^ t ^ XT[d0 ^ d1]
            s[b + 1] = d1 ^ t ^ XT[d1 ^ d2]
            s[b + 2] = d2 ^ t ^ XT[d2 ^ d3]
            s[b + 3] = d3 ^ t ^ XT[d3 ^ d0]
    k0 = rk[0]
    return bytes([
        INV_SBOX[s[0]] ^ k0[0], INV_SBOX[s[13]] ^ k0[1], INV_SBOX[s[10]] ^ k0[2], INV_SBOX[s[7]] ^ k0[3],
        INV_SBOX[s[4]] ^ k0[4], INV_SBOX[s[1]] ^ k0[5], INV_SBOX[s[14]] ^ k0[6], INV_SBOX[s[11]] ^ k0[7],
        INV_SBOX[s[8]] ^ k0[8], INV_SBOX[s[5]] ^ k0[9], INV_SBOX[s[2]] ^ k0[10], INV_SBOX[s[15]] ^ k0[11],
        INV_SBOX[s[12]] ^ k0[12], INV_SBOX[s[9]] ^ k0[13], INV_SBOX[s[6]] ^ k0[14], INV_SBOX[s[3]] ^ k0[15],
    ])


_CRYPTO_BACKEND = "pure_python"
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
    _CRYPTO_BACKEND = "cryptography"
except ImportError:
    try:
        from Crypto.Cipher import AES as _PYCRYPTO_AES  # type: ignore
        _CRYPTO_BACKEND = "pycryptodome"
    except ImportError:
        pass


class StreamCFBDecryptor:
    """支持流式块解密与纯 Python rk 复用的 AES-256-CFB128 解密器"""
    def __init__(self, key: bytes, iv: bytes, rk: Optional[List[bytes]] = None):
        if _CRYPTO_BACKEND == "cryptography":
            self._dec = Cipher(algorithms.AES(key), modes.CFB(iv)).decryptor()
            self._mode = "cryptography"
        elif _CRYPTO_BACKEND == "pycryptodome":
            self._dec = _PYCRYPTO_AES.new(key, _PYCRYPTO_AES.MODE_CFB, iv=iv, segment_size=128)
            self._mode = "pycryptodome"
        else:
            self._rk = rk if rk is not None else expand_key_256(key)
            self._state = iv
            self._mode = "pure"

    def update(self, data: bytes) -> bytes:
        if self._mode == "cryptography":
            return self._dec.update(data)
        if self._mode == "pycryptodome":
            return self._dec.decrypt(data)
        out = bytearray()
        state = self._state
        rk = self._rk
        for i in range(0, len(data), 16):
            blk = data[i:i + 16]
            ks = _aes256_encrypt_block(rk, state)
            out.extend(blk[j] ^ ks[j] for j in range(len(blk)))
            if len(blk) == 16:
                state = blk
        self._state = state
        return bytes(out)


def aes256_ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    if _CRYPTO_BACKEND == "cryptography":
        dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        return dec.update(ciphertext) + dec.finalize()
    if _CRYPTO_BACKEND == "pycryptodome":
        return _PYCRYPTO_AES.new(key, _PYCRYPTO_AES.MODE_ECB).decrypt(ciphertext)
    rk = expand_key_256(key)
    out = bytearray()
    for i in range(0, len(ciphertext) - (len(ciphertext) % 16), 16):
        out.extend(_aes256_decrypt_block(rk, ciphertext[i:i + 16]))
    return bytes(out)


def decrypt_fae_stream_to_writer(src: BinaryIO, dst: BinaryIO, key: bytes, context: str = "") -> int:
    """1MB 块流式解密 FileAccessEncrypted (use_magic=false)，避免大文件 OOM"""
    hdr = src.read(40)
    if len(hdr) < 40:
        raise ValueError(f"加密头不完整 ({context})")
    md5_exp = hdr[0:16]
    plain_len = struct.unpack("<Q", hdr[16:24])[0]
    iv = hdr[24:40]
    padded_len = ((plain_len + 15) // 16) * 16

    dec = StreamCFBDecryptor(key, iv)
    md5_h = hashlib.md5()
    rem_ct = padded_len
    rem_pt = plain_len

    while rem_ct > 0:
        want = min(CHUNK_SIZE, rem_ct)
        chunk = src.read(want)
        if len(chunk) < want:
            # 容错：某些非标准工具不补 16 字节对齐，若已够 plain_len 则继续
            if (padded_len - rem_ct) + len(chunk) >= plain_len:
                rem_ct = len(chunk)
            else:
                raise ValueError(f"加密密文被截断 ({context})")
        pt_chunk = dec.update(chunk)
        if len(pt_chunk) > rem_pt:
            pt_chunk = pt_chunk[:rem_pt]
        md5_h.update(pt_chunk)
        dst.write(pt_chunk)
        rem_ct -= len(chunk)
        rem_pt -= len(pt_chunk)

    if md5_h.digest() != md5_exp:
        raise ValueError(f"密钥错误或密文损坏 (MD5 校验失败: {context})")
    return plain_len


def decrypt_fae_bytes(src: BinaryIO, size: int, key: bytes, context: str = "") -> bytes:
    """将完整 FileAccessEncrypted / Godot3&4 GDEC 解密到内存 (适用于中小文件或媒体转换)"""
    magic = src.read(4)
    src.seek(-len(magic), 1)
    if magic == GDEC_MAGIC:
        blob = src.read(size)
        if len(blob) < 32:
            raise ValueError(f"GDEC 头部损坏 ({context})")
        # 优先按长度精确区分 Godot 4 GDEC (44B头) 与 Godot 3 GDEC (32B头)
        if len(blob) >= 44:
            md5_4 = blob[4:20]
            plen_4 = struct.unpack("<Q", blob[20:28])[0]
            pad_4 = ((plen_4 + 15) // 16) * 16
            if 44 + plen_4 <= len(blob) <= 44 + pad_4:
                iv_4 = blob[28:44]
                pt = StreamCFBDecryptor(key, iv_4).update(blob[44:])[:plen_4]
                if hashlib.md5(pt).digest() == md5_4:
                    return pt
        mode_3 = struct.unpack("<I", blob[4:8])[0]
        md5_3 = blob[8:24]
        plen_3 = struct.unpack("<Q", blob[24:32])[0]
        pad_3 = ((plen_3 + 15) // 16) * 16
        if mode_3 <= 3 and 32 + pad_3 <= len(blob):
            pt = aes256_ecb_decrypt(key, blob[32:32 + pad_3])[:plen_3]
            if hashlib.md5(pt).digest() == md5_3:
                return pt
        raise ValueError(f"GDEC 解密失败，密钥错误 ({context})")

    buf = io.BytesIO()
    decrypt_fae_stream_to_writer(src, buf, key, context)
    return buf.getvalue()


# ======================== 2. 数据结构与容器解析 ========================
@dataclass
class PCKEntry:
    path: str
    offset: int
    abs_offset: int
    size: int
    md5: bytes
    flags: int = 0

    @property
    def is_encrypted(self) -> bool:
        return bool(self.flags & FILE_ENCRYPTED)

    @property
    def is_removal(self) -> bool:
        return bool(self.flags & FILE_REMOVAL) or (self.size == 0 and self.offset == 0 and self.md5 == b"\x00" * 16)


@dataclass
class PCKInfo:
    file_path: str
    file_size: int
    container_type: str
    detect_method: str
    pck_start: int
    pck_end: int
    pck_version: int
    engine_version: Tuple[int, int, int]
    pack_flags: int
    file_base: int
    dir_offset: int
    file_count: int
    encrypted_dir: bool
    sparse_bundle: bool
    effective_base: int
    entries: List[PCKEntry]


def human_size(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024:
            return f"{num:.2f} {unit}" if unit != "B" else f"{int(num)} B"
        num /= 1024
    return f"{num:.2f} PB"


def sanitize_rel_path(res_path: str) -> Path:
    p = res_path.replace("\\", "/")
    if p.startswith("res://"):
        p = p[6:]
    elif "://" in p:
        p = p.split("://", 1)[1]
    parts = [re.sub(r'[<>:"|?*\x00-\x1f]', "_", x) for x in p.split("/") if x and x not in (".", "..")]
    return Path(*parts) if parts else Path("unnamed_file")


def validate_pck_header(f: BinaryIO, pos: int, file_size: int) -> Optional[Tuple[int, int, int, int]]:
    if pos < 0 or pos + 84 > file_size:
        return None
    f.seek(pos)
    data = f.read(20)
    if len(data) < 20:
        return None
    magic, version, major, minor, patch = struct.unpack("<4s4I", data)
    if magic != PACK_MAGIC or version not in (0, 1, 2, 3, 4) or major > 10 or minor > 99 or patch > 999:
        return None
    return version, major, minor, patch


def parse_pe_sections(f: BinaryIO, file_size: int) -> Tuple[bool, List[Tuple[str, int, int]]]:
    if file_size < 64:
        return False, []
    f.seek(0)
    if f.read(2) != b"MZ":
        return False, []
    f.seek(0x3C)
    e_lfanew = struct.unpack("<I", f.read(4))[0]
    if e_lfanew + 24 > file_size:
        return False, []
    f.seek(e_lfanew)
    if f.read(4) != b"PE\x00\x00":
        return False, []
    coff = f.read(20)
    if len(coff) < 20:
        return False, []
    _, num_sections, _, _, _, opt_size, _ = struct.unpack("<HHIIIHH", coff)
    sec_pos = e_lfanew + 24 + opt_size
    if sec_pos + num_sections * 40 > file_size:
        return True, []
    sections = []
    f.seek(sec_pos)
    for _ in range(num_sections):
        sec = f.read(40)
        if len(sec) < 40:
            break
        name = sec[0:8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        raw_size, raw_ptr = struct.unpack("<II", sec[16:24])
        sections.append((name, raw_ptr, raw_size))
    return True, sections


def parse_elf_sections(f: BinaryIO, file_size: int) -> Tuple[bool, List[Tuple[str, int, int]]]:
    if file_size < 64:
        return False, []
    f.seek(0)
    ident = f.read(16)
    if ident[:4] != b"\x7fELF" or ident[5] != 1:
        return ident[:4] == b"\x7fELF", []
    ei_class = ident[4]
    if ei_class == 2:
        f.seek(0x28)
        e_shoff = struct.unpack("<Q", f.read(8))[0]
        f.seek(0x3A)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack("<HHH", f.read(6))
    elif ei_class == 1:
        f.seek(0x20)
        e_shoff = struct.unpack("<I", f.read(4))[0]
        f.seek(0x2E)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack("<HHH", f.read(6))
    else:
        return True, []

    if e_shoff == 0 or e_shnum == 0 or e_shoff + e_shentsize * e_shnum > file_size:
        return True, []
    raw_secs = []
    for i in range(e_shnum):
        f.seek(e_shoff + i * e_shentsize)
        sh = f.read(e_shentsize)
        if ei_class == 2 and len(sh) >= 40:
            raw_secs.append((struct.unpack("<I", sh[0:4])[0], *struct.unpack("<QQ", sh[24:40])))
        elif ei_class == 1 and len(sh) >= 24:
            raw_secs.append((struct.unpack("<I", sh[0:4])[0], *struct.unpack("<II", sh[16:24])))
    if e_shstrndx >= len(raw_secs):
        return True, []
    _, str_off, str_size = raw_secs[e_shstrndx]
    if str_off + str_size > file_size or str_size > 16 * 1024 * 1024:
        return True, []
    f.seek(str_off)
    strtab = f.read(str_size)
    sections = []
    for sh_name, sh_off, sh_size in raw_secs:
        end = strtab.find(b"\x00", sh_name)
        sections.append((strtab[sh_name:end if end != -1 else None].decode("ascii", errors="replace"), sh_off, sh_size))
    return True, sections


def _sanity_check_candidate(f: BinaryIO, pck_start: int, version: int, file_size: int, strict: bool = True) -> bool:
    try:
        f.seek(pck_start + 20)
        if version <= 1:
            reserved = f.read(64)
            fc = struct.unpack("<I", f.read(4))[0]
            if len(reserved) < 64 or fc > MAX_FILE_COUNT or (strict and fc == 0):
                return False
            if fc == 0:
                return reserved == b"\x00" * 64
            plen = struct.unpack("<I", f.read(4))[0]
            if not (1 <= plen <= 4096):
                return False
            sample = f.read(min(plen, 16))
            is_path_like = sample.startswith(b"res://") or all(0x20 <= b <= 0x7E or b >= 0x80 for b in sample)
            return (reserved == b"\x00" * 64) and is_path_like if strict else is_path_like
        elif version == 2:
            pack_flags, file_base = struct.unpack("<IQ", f.read(12))
            reserved = f.read(64)
            fc = struct.unpack("<I", f.read(4))[0]
            if fc > MAX_FILE_COUNT or file_base > file_size:
                return False
            if pack_flags & PACK_DIR_ENCRYPTED:
                return reserved == b"\x00" * 64
            if fc == 0:
                return not strict
            plen = struct.unpack("<I", f.read(4))[0]
            return 1 <= plen <= 4096
        else:
            pack_flags, file_base, dir_off = struct.unpack("<IQQ", f.read(20))
            reserved = f.read(64)
            if pck_start + dir_off + 4 > file_size:
                return False
            if pack_flags & PACK_DIR_ENCRYPTED:
                return reserved == b"\x00" * 64
            f.seek(pck_start + dir_off)
            fc = struct.unpack("<I", f.read(4))[0]
            return (0 <= fc <= MAX_FILE_COUNT) and ((not strict) or fc > 0)
    except Exception:
        return False


def check_trailer_at(f: BinaryIO, trailer_end: int, file_size: int) -> Optional[Tuple[int, int]]:
    if trailer_end < 12 or trailer_end > file_size:
        return None
    f.seek(trailer_end - 4)
    if f.read(4) != PACK_MAGIC:
        return None
    f.seek(trailer_end - 12)
    ds = struct.unpack("<Q", f.read(8))[0]
    pck_start = trailer_end - 12 - ds
    hdr = validate_pck_header(f, pck_start, file_size)
    if hdr and _sanity_check_candidate(f, pck_start, hdr[0], file_size, strict=False):
        return pck_start, pck_start + ds
    return None


def locate_pck(f: BinaryIO, file_size: int) -> Tuple[str, str, int, int, List[Tuple[str, int, int]]]:
    """返回 (container_type, detect_method, pck_start, pck_end, sections)"""
    hdr0 = validate_pck_header(f, 0, file_size)
    if hdr0 and _sanity_check_candidate(f, 0, hdr0[0], file_size, strict=False):
        return "PCK", "独立 PCK 文件头", 0, file_size, []

    is_pe, pe_secs = parse_pe_sections(f, file_size)
    is_elf, elf_secs = (False, []) if is_pe else parse_elf_sections(f, file_size)
    container = "PE (EXE)" if is_pe else ("ELF" if is_elf else "UNKNOWN")
    secs = pe_secs if is_pe else elf_secs

    for name, ptr, sz in secs:
        if name.lower() in ("pck", ".pck") and ptr > 0 and sz >= 84:
            for align_off in range(0, 16):
                hdr = validate_pck_header(f, ptr + align_off, file_size)
                if hdr and _sanity_check_candidate(f, ptr + align_off, hdr[0], file_size, strict=False):
                    return container, f"{container.split()[0]} 节区 '{name}' 头部", ptr + align_off, min(file_size, ptr + sz), secs
            tr = check_trailer_at(f, min(file_size, ptr + sz), file_size)
            if tr:
                return container, f"{container.split()[0]} 节区 '{name}' 尾标", tr[0], tr[1], secs

    tr = check_trailer_at(f, file_size, file_size)
    if tr:
        return container, "EOF 尾标 (GDPC Trailer)", tr[0], tr[1], secs

    # 优先扫 PE Overlay，失败再扫前段
    if is_pe and pe_secs:
        max_sec_end = max((ptr + sz for _, ptr, sz in pe_secs if ptr > 0), default=0)
        scan_ranges = [(max_sec_end, file_size), (0, max_sec_end)]
    else:
        scan_ranges = [(0, file_size)]

    overlap = 64
    for r_start, r_end in scan_ranges:
        pos = max(0, r_start)
        while pos < r_end:
            f.seek(pos)
            buf = f.read(min(CHUNK_SIZE + overlap, r_end - pos))
            if not buf:
                break
            idx = 0
            while True:
                found = buf.find(PACK_MAGIC, idx)
                if found == -1:
                    break
                cand = pos + found
                hdr = validate_pck_header(f, cand, file_size)
                if hdr and _sanity_check_candidate(f, cand, hdr[0], file_size, strict=True):
                    return container, f"二进制特征扫描 (0x{cand:X})", cand, file_size, secs
                idx = found + 4
            if len(buf) <= overlap:
                break
            pos += CHUNK_SIZE

    raise ValueError("未能识别到有效的 Godot PCK 数据 (非 Godot 封包，或魔改/加壳)")


def _calc_md5(f: BinaryIO, offset: int, size: int) -> bytes:
    f.seek(offset)
    h = hashlib.md5()
    rem = size
    while rem > 0:
        chunk = f.read(min(CHUNK_SIZE, rem))
        if not chunk:
            break
        h.update(chunk)
        rem -= len(chunk)
    return h.digest()


def _read_directory_entries(stream: BinaryIO, version: int, file_count: int) -> List[Tuple[str, int, int, bytes, int]]:
    if file_count > MAX_FILE_COUNT:
        raise ValueError(f"目录项数量异常 ({file_count})，PCK 可能损坏或已加密")
    raw_entries = []
    for _ in range(file_count):
        plen_bytes = stream.read(4)
        if len(plen_bytes) < 4:
            raise ValueError("目录项读取意外结束")
        plen = struct.unpack("<I", plen_bytes)[0]
        if plen > 16384:
            raise ValueError(f"目录路径长度异常 ({plen})，PCK 可能损坏或密钥错误")
        p_str = stream.read(plen).rstrip(b"\x00").decode("utf-8", errors="replace")
        ofs, sz = struct.unpack("<QQ", stream.read(16))
        md5 = stream.read(16)
        eflags = struct.unpack("<I", stream.read(4))[0] if version >= 2 else 0
        raw_entries.append((p_str, ofs, sz, md5, eflags))
    return raw_entries


def parse_pck(file_path: str, key: Optional[bytes] = None) -> PCKInfo:
    file_size = os.path.getsize(file_path)
    with open(file_path, "rb") as f:
        container, method, pck_start, pck_end, _ = locate_pck(f, file_size)
        hdr = validate_pck_header(f, pck_start, file_size)
        if not hdr:
            raise ValueError(f"PCK 头部校验失败: {file_path}")
        version, major, minor, patch = hdr

        f.seek(pck_start + 20)
        pack_flags = 0
        file_base = 0
        if version <= 1:
            f.read(64)
            dir_pos = f.tell()
        elif version == 2:
            pack_flags, file_base = struct.unpack("<IQ", f.read(12))
            f.read(64)
            dir_pos = f.tell()
        else:
            pack_flags, file_base, dir_off = struct.unpack("<IQQ", f.read(20))
            f.read(64)
            dir_pos = pck_start + dir_off

        enc_dir = bool(pack_flags & PACK_DIR_ENCRYPTED)
        rel_filebase = bool(pack_flags & PACK_REL_FILEBASE)
        sparse_bundle = bool(pack_flags & PACK_SPARSE_BUNDLE)

        f.seek(dir_pos)
        file_count = struct.unpack("<I", f.read(4))[0]
        if file_count > MAX_FILE_COUNT:
            raise ValueError(f"目录项数量异常 ({file_count})，文件可能损坏 ({file_path})")

        if enc_dir and key is None:
            return PCKInfo(
                file_path=file_path, file_size=file_size, container_type=container,
                detect_method=method, pck_start=pck_start, pck_end=pck_end,
                pck_version=version, engine_version=(major, minor, patch),
                pack_flags=pack_flags, file_base=file_base, dir_offset=dir_pos,
                file_count=file_count, encrypted_dir=True, sparse_bundle=sparse_bundle,
                effective_base=0, entries=[],
            )

        if enc_dir and key is not None:
            dir_buf = io.BytesIO()
            decrypt_fae_stream_to_writer(f, dir_buf, key, context="PCK 加密目录")
            dir_buf.seek(0)
            raw_entries = _read_directory_entries(dir_buf, version, file_count)
            dir_end_pos = f.tell()
        else:
            raw_entries = _read_directory_entries(f, version, file_count)
            dir_end_pos = f.tell()

        if version >= 3:
            effective_base = pck_start + file_base
        elif version == 2:
            effective_base = (pck_start + file_base) if rel_filebase else file_base
        else:
            effective_base = 0

        # 多探针 MD5 自动校准 (解决 V1/V2 绝对与相对偏移差异)
        probes = [
            e for e in raw_entries
            if e[2] > 0 and not (e[4] & (FILE_ENCRYPTED | FILE_REMOVAL)) and e[3] != b"\x00" * 16
        ][:5]
        for _, p_off, p_size, p_md5, _ in probes:
            cand_bases = [effective_base]
            if version <= 1:
                cand_bases = [0, pck_start] if p_off >= pck_start else [pck_start, 0]
            elif version == 2 and not rel_filebase and pck_start > 0:
                cand_bases = [file_base, pck_start + file_base]
            matched = False
            for base in cand_bases:
                if base + p_off + p_size <= file_size and _calc_md5(f, base + p_off, p_size) == p_md5:
                    effective_base = base
                    matched = True
                    break
            if matched:
                break

        entries = [
            PCKEntry(path=p, offset=off, abs_offset=effective_base + off, size=sz, md5=md5, flags=ef)
            for (p, off, sz, md5, ef) in raw_entries
        ]

        # 精算真实 pck_end，剥离 PE 节区末尾的对齐填充零
        exact_end = dir_end_pos
        for ent in entries:
            if not ent.is_removal and ent.abs_offset + ent.size <= file_size:
                exact_end = max(exact_end, ent.abs_offset + ent.size)
        if not method.endswith("尾标"):
            pck_end = min(pck_end, exact_end) if exact_end > pck_start else pck_end

        return PCKInfo(
            file_path=file_path, file_size=file_size, container_type=container,
            detect_method=method, pck_start=pck_start, pck_end=pck_end,
            pck_version=version, engine_version=(major, minor, patch),
            pack_flags=pack_flags, file_base=file_base, dir_offset=dir_pos,
            file_count=file_count, encrypted_dir=enc_dir, sparse_bundle=sparse_bundle,
            effective_base=effective_base, entries=entries,
        )


# ======================== 3. 媒体转换与路径映射 ========================
def extract_png_from_bytes(data: bytes) -> Optional[bytes]:
    idx = data.find(b"\x89PNG\r\n\x1a\n")
    if idx == -1:
        return None
    pos = idx + 8
    total = len(data)
    while pos + 12 <= total:
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        ct = data[pos + 4:pos + 8]
        pos += 12 + ln
        if pos > total:
            return None
        if ct == b"IEND":
            return data[idx:pos]
    return None


def extract_webp_from_bytes(data: bytes) -> Optional[bytes]:
    idx = 0
    total = len(data)
    while True:
        idx = data.find(b"RIFF", idx)
        if idx == -1 or idx + 12 > total:
            return None
        if data[idx + 8:idx + 12] == b"WEBP":
            rsz = struct.unpack("<I", data[idx + 4:idx + 8])[0]
            if idx + 8 + rsz <= total:
                return data[idx:idx + 8 + rsz]
        idx += 4


def extract_ogg_from_bytes(data: bytes) -> Optional[bytes]:
    idx = data.find(b"OggS")
    if idx != -1 and idx + 6 <= len(data) and data[idx + 4] == 0:
        return data[idx:]
    return None


def convert_asset(ext: str, data: bytes) -> Tuple[str, bytes, bool]:
    ext = ext.lower()
    if ext in (".ctex", ".stex", ".tex"):
        png = extract_png_from_bytes(data)
        if png:
            return ".png", png, True
        webp = extract_webp_from_bytes(data)
        if webp:
            return ".webp", webp, True
    elif ext in (".oggstr", ".oggvorbisstr"):
        ogg = extract_ogg_from_bytes(data)
        if ogg:
            return ".ogg", ogg, True
    return ext, data, False


def parse_import_mappings(entries_data: Dict[str, bytes]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for res_path, raw in entries_data.items():
        if not res_path.endswith(".import"):
            continue
        text = raw.decode("utf-8", errors="ignore")
        orig_res = res_path[:-7]
        for line in text.splitlines():
            if line.startswith(("path", "dest_files")):
                for imp in re.findall(r'"(res://[^"]+)"', line):
                    mapping[imp] = orig_res
    return mapping


# ======================== 4. 密钥扫描 (find-key) ========================
_LOG2_P = [-(c / 32.0) * math.log2(c / 32.0) if c else 0.0 for c in range(33)]


def _is_high_entropy_key(cand: bytes) -> bool:
    if len(set(cand)) < 18:
        return False
    counts = [0] * 256
    for b in cand:
        counts[b] += 1
    if counts[0] > 8:
        return False
    ent = sum(_LOG2_P[c] for c in counts if c)
    return ent >= 4.2


def cmd_find_key(args: argparse.Namespace) -> int:
    bin_path = Path(args.binary)
    pck_path = Path(args.pck) if args.pck else bin_path
    if not bin_path.exists() or not pck_path.exists():
        print("错误: 指定的文件不存在", file=sys.stderr)
        return 1

    pck_size = pck_path.stat().st_size
    is_dir_oracle = False
    oracle_label = ""
    with open(pck_path, "rb") as pf:
        container, _, pck_start, pck_end, _ = locate_pck(pf, pck_size)
        ver, _, _, _ = validate_pck_header(pf, pck_start, pck_size)
        if ver <= 1:
            print("提示: PCK V0/V1 目录不加密，无需扫描目录密钥。")
            return 0
        pf.seek(pck_start + 20)
        if ver == 2:
            pack_flags, file_base = struct.unpack("<IQ", pf.read(12))
            pf.read(64)
            dir_pos = pf.tell()
            eff_base = (pck_start + file_base) if (pack_flags & PACK_REL_FILEBASE) else file_base
        else:
            pack_flags, file_base, dir_off = struct.unpack("<IQQ", pf.read(20))
            pf.read(64)
            dir_pos = pck_start + dir_off
            eff_base = pck_start + file_base

        if pack_flags & PACK_DIR_ENCRYPTED:
            is_dir_oracle = True
            pf.seek(dir_pos)
            fc = struct.unpack("<I", pf.read(4))[0]
            oracle_hdr = pf.read(40)
            oracle_plen = struct.unpack("<Q", oracle_hdr[16:24])[0]
            if oracle_plen > 64 * 1024 * 1024:
                raise ValueError("加密目录声明长度异常，可能采用了魔改加密")
            padded = ((oracle_plen + 15) // 16) * 16
            oracle_ct = pf.read(padded)
            oracle_label = f"加密目录 ({fc} 项, {oracle_plen} B)"
        else:
            pf.seek(dir_pos)
            fc = struct.unpack("<I", pf.read(4))[0]
            raw_entries = _read_directory_entries(pf, ver, fc)
            sample = next((e for e in raw_entries if (e[4] & FILE_ENCRYPTED) and 40 < e[2] <= 1024 * 1024), None)
            if not sample:
                print("未发现任何加密目录或加密文件，该包无需密钥。")
                return 0
            pf.seek(eff_base + sample[1])
            oracle_hdr = pf.read(40)
            oracle_plen = struct.unpack("<Q", oracle_hdr[16:24])[0]
            padded = ((oracle_plen + 15) // 16) * 16
            oracle_ct = pf.read(padded)
            oracle_label = f"加密文件 {sample[0]}"

    oracle_md5 = oracle_hdr[0:16]
    oracle_iv = oracle_hdr[24:40]
    print(f"已获取校验靶标: {oracle_label}")
    print(f"AES 后端: {_CRYPTO_BACKEND} | 正在分块极速扫描零对齐边界密钥...")

    bin_size = bin_path.stat().st_size
    with open(bin_path, "rb") as bf:
        is_pe, pe_secs = parse_pe_sections(bf, bin_size)
        is_elf, elf_secs = (False, []) if is_pe else parse_elf_sections(bf, bin_size)
        secs = pe_secs if is_pe else elf_secs

        ranges: List[Tuple[str, int, int]] = []
        same_file = bin_path.resolve() == pck_path.resolve()
        if secs:
            for name, ptr, sz in secs:
                if name.lower() in ("pck", ".pck") or ptr <= 0 or sz < 36:
                    continue
                r_end = min(bin_size, ptr + sz)
                if same_file and not (r_end <= pck_start or ptr >= pck_end):
                    if ptr < pck_start:
                        ranges.append((name, ptr, pck_start))
                    if r_end > pck_end:
                        ranges.append((name, pck_end, r_end))
                else:
                    ranges.append((name, ptr, r_end))
        elif same_file:
            ranges = [("BEFORE_PCK", 0, pck_start), ("AFTER_PCK", pck_end, bin_size)]
        else:
            ranges = [("BINARY", 0, bin_size)]

        WINDOW = 8 * 1024 * 1024
        OVERLAP = 40
        tested = 0

        for sec_name, r_start, r_end in ranges:
            if r_end - r_start < 36:
                continue
            pos = r_start
            carry = b""
            while pos < r_end:
                bf.seek(pos)
                chunk = bf.read(min(WINDOW, r_end - pos))
                if not chunk:
                    break
                data = carry + chunk
                base_off = pos - len(carry)
                n = len(data)
                tested_offsets: Set[int] = set()

                # C层 find 跳搜 4字节零块，完美覆盖任意 1字节不对齐密钥且跳过大段零区
                s_idx = 0
                while s_idx < n - 4:
                    z = data.find(b"\x00\x00\x00\x00", s_idx)
                    if z == -1:
                        break
                    z_end = z + 4
                    while z_end < n and data[z_end] == 0:
                        z_end += 1

                    for cand_off in (z - 32, z_end):
                        if cand_off < 0 or cand_off + 32 > n or cand_off in tested_offsets:
                            continue
                        tested_offsets.add(cand_off)
                        cand = data[cand_off:cand_off + 32]
                        if not _is_high_entropy_key(cand):
                            continue
                        tested += 1
                        rk = expand_key_256(cand) if _CRYPTO_BACKEND == "pure_python" else None
                        first_blk = StreamCFBDecryptor(cand, oracle_iv, rk=rk).update(oracle_ct[:16])
                        if is_dir_oracle:
                            slen = struct.unpack("<I", first_blk[:4])[0]
                            if not (1 <= slen <= 1024):
                                continue
                        pt = StreamCFBDecryptor(cand, oracle_iv, rk=rk).update(oracle_ct)[:oracle_plen]
                        if hashlib.md5(pt).digest() == oracle_md5:
                            hex_key = cand.hex()
                            print(f"\n[成功!] 在 {sec_name} (偏移 0x{base_off + cand_off:X}) 找到匹配密钥:")
                            print(f"  KEY = {hex_key}")
                            print(f"\n请运行以下命令直接解密解包:")
                            print(f"  godot-ex unpack \"{pck_path}\" --key {hex_key}")
                            return 0
                    s_idx = z_end

                carry = data[-OVERLAP:] if len(data) >= OVERLAP else data
                pos += len(chunk)

    print(f"\n共测试了 {tested} 个零边界高熵候选块，未找到密钥。")
    print("提示: 可能编译器将密钥紧贴其他常量存放(无零填充)或采用了魔改加密。可在 PC 用 gdke/IDA 提取密钥后带 --key 解包。")
    return 2


# ======================== 5. 基础子命令 ========================
def _parse_hex_key(key_str: Optional[str]) -> Optional[bytes]:
    if not key_str:
        return None
    k = key_str.strip()
    if k.lower().startswith("0x"):
        k = k[2:]
    if len(k) != 64:
        raise ValueError("--key 必须是 64 位十六进制字符串 (AES-256)")
    return bytes.fromhex(k)


def cmd_identify(args: argparse.Namespace) -> int:
    targets: List[Path] = []
    exts = (".exe", ".pck", ".bin", ".x86_64", ".arm64", ".so")
    for p in args.inputs:
        path = Path(p)
        if path.is_dir():
            for child in sorted(path.iterdir()):
                if child.is_file() and (child.suffix.lower() in exts or ".so." in child.name):
                    targets.append(child)
        else:
            targets.append(path)

    if not targets:
        print("未找到可检测的文件。", file=sys.stderr)
        return 1

    key = _parse_hex_key(args.key)
    for target in targets:
        print("=" * 60)
        print(f"文件: {target}")
        if not target.exists():
            print("  状态: 文件不存在")
            continue
        try:
            info = parse_pck(str(target), key=key)
        except Exception as e:
            print(f"  状态: 非标准 Godot 封包或不支持 ({e})")
            continue

        ver_str = ".".join(map(str, info.engine_version))
        print(f"  文件大小    : {human_size(info.file_size)}")
        print(f"  载体类型    : {info.container_type}")
        print(f"  识别方式    : {info.detect_method}")
        print(f"  PCK 偏移范围: 0x{info.pck_start:X} ~ 0x{info.pck_end:X} ({human_size(info.pck_end - info.pck_start)})")
        print(f"  PCK 格式版本: V{info.pck_version}")
        print(f"  Godot 版本  : {ver_str}")
        print(f"  标志位      : 0x{info.pack_flags:X} (目录加密={info.encrypted_dir}, 稀疏包={info.sparse_bundle})")
        if not info.encrypted_dir or key is not None:
            total_assets = sum(e.size for e in info.entries if not e.is_removal)
            enc_files = sum(1 for e in info.entries if e.is_encrypted)
            print(f"  基准偏移    : 0x{info.effective_base:X}")
            print(f"  包含文件数  : {info.file_count} (其中单文件加密: {enc_files})")
            print(f"  资源总大小  : {human_size(total_assets)}")
            ext_counts: Dict[str, int] = {}
            for e in info.entries:
                if not e.is_removal:
                    ext = Path(e.path).suffix.lower() or "<无后缀>"
                    ext_counts[ext] = ext_counts.get(ext, 0) + 1
            top = sorted(ext_counts.items(), key=lambda x: x[1], reverse=True)[:8]
            print("  主要资源类型: " + ", ".join(f"{k}({v})" for k, v in top))
        else:
            print(f"  包含文件数  : {info.file_count} (目录已加密，可尝试 find-key 或传入 --key 查看详情)")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    key = _parse_hex_key(args.key)
    info = parse_pck(args.file, key=key)
    if info.encrypted_dir and key is None:
        print("错误: 目录表已启用 AES-256 加密，请传入 --key 或先用 find-key 扫描密钥。", file=sys.stderr)
        return 2

    matched = 0
    for ent in info.entries:
        if ent.is_removal:
            continue
        if args.filter and not any(fnmatch.fnmatch(ent.path, pat.strip()) for pat in args.filter.split(",")):
            continue
        tag = " [ENC]" if ent.is_encrypted else ""
        print(f"{human_size(ent.size):>10}  0x{ent.abs_offset:08X}  {ent.path}{tag}")
        matched += 1
    print(f"\n共匹配 {matched} / {info.file_count} 个文件")
    return 0


def cmd_extract_pck(args: argparse.Namespace) -> int:
    key = _parse_hex_key(args.key)
    info = parse_pck(args.file, key=key)
    src_path = Path(args.file)
    out_pck = Path(args.output) if args.output else src_path.with_suffix(".pck")
    if out_pck.resolve() == src_path.resolve():
        out_pck = src_path.with_name(src_path.stem + "_extracted.pck")

    pck_len = info.pck_end - info.pck_start
    print(f"识别成功 [{info.detect_method}] -> 正在剥离 PCK ({human_size(pck_len)}) 至: {out_pck}")
    with open(args.file, "rb") as src, open(out_pck, "wb") as dst:
        src.seek(info.pck_start)
        rem = pck_len
        while rem > 0:
            buf = src.read(min(CHUNK_SIZE, rem))
            if not buf:
                break
            dst.write(buf)
            rem -= len(buf)
    print("PCK 剥离完成。")
    return 0


def _unique_session_path(target: Path, written: Set[Path]) -> Path:
    resolved = target.resolve()
    if resolved not in written:
        written.add(resolved)
        return target
    stem, suffix = target.stem, target.suffix
    n = 1
    while True:
        cand = target.with_name(f"{stem}_{n}{suffix}")
        if cand.resolve() not in written:
            written.add(cand.resolve())
            return cand
        n += 1


def cmd_unpack(args: argparse.Namespace) -> int:
    key = _parse_hex_key(args.key)
    info = parse_pck(args.file, key=key)
    print(f"已识别 {info.container_type} | Godot {'.'.join(map(str, info.engine_version))} | PCK V{info.pck_version} | 方式: {info.detect_method}")

    if info.encrypted_dir and key is None:
        print("错误: 该封包目录已启用 AES-256 加密，请传入 --key 或先用 find-key 扫描密钥。", file=sys.stderr)
        return 2

    src_path = Path(args.file)
    out_dir = Path(args.output) if args.output else src_path.with_name(src_path.stem + "_unpacked")
    out_dir.mkdir(parents=True, exist_ok=True)
    filters = [p.strip() for p in args.filter.split(",")] if args.filter else None
    max_mem = args.max_mem * 1024 * 1024

    import_map: Dict[str, str] = {}
    written_paths: Set[Path] = set()

    with open(args.file, "rb") as f:
        if args.restore:
            imp_bytes: Dict[str, bytes] = {}
            for ent in info.entries:
                if ent.path.endswith(".import") and not ent.is_removal and ent.size <= 512 * 1024:
                    f.seek(ent.abs_offset)
                    if ent.is_encrypted:
                        if key is None:
                            continue
                        imp_bytes[ent.path] = decrypt_fae_bytes(f, ent.size, key, ent.path)
                    else:
                        imp_bytes[ent.path] = f.read(ent.size)
            import_map = parse_import_mappings(imp_bytes)
            if import_map:
                print(f"已加载 {len(import_map)} 条 .import 原始路径映射。")

        extracted = 0
        decrypted = 0
        converted = 0
        skipped_enc = 0
        md5_fail = 0

        for ent in info.entries:
            if ent.is_removal:
                continue
            if filters and not any(fnmatch.fnmatch(ent.path, pat) for pat in filters):
                continue
            if ent.abs_offset + ent.size > info.file_size:
                print(f"\n[警告] 跳过越界文件: {ent.path}")
                continue

            f.seek(ent.abs_offset)
            magic4 = f.read(4) if ent.size >= 4 else b""
            f.seek(ent.abs_offset)
            is_enc = ent.is_encrypted or (magic4 == GDEC_MAGIC)
            if is_enc and key is None:
                skipped_enc += 1
                continue

            mapped_res = import_map.get(ent.path, ent.path) if args.restore else ent.path
            if is_enc and mapped_res.endswith(".gde"):
                mapped_res = mapped_res[:-4] + ".gdc"

            rel_out = sanitize_rel_path(mapped_res)
            target_file = out_dir / rel_out
            want_convert = (not args.raw) and rel_out.suffix.lower() in (".ctex", ".stex", ".tex", ".oggstr", ".oggvorbisstr")

            if is_enc:
                decrypted += 1
                if (want_convert or magic4 == GDEC_MAGIC) and ent.size <= max_mem:
                    raw_data = decrypt_fae_bytes(f, ent.size, key, ent.path)
                    if want_convert:
                        new_ext, out_data, conv = convert_asset(rel_out.suffix, raw_data)
                        if conv:
                            converted += 1
                            target_file = target_file.with_suffix(new_ext)
                            raw_data = out_data
                    target_file = _unique_session_path(target_file, written_paths)
                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    with open(target_file, "wb") as out_f:
                        out_f.write(raw_data)
                else:
                    # 大加密文件真流式解密
                    target_file = _unique_session_path(target_file, written_paths)
                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    with open(target_file, "wb") as out_f:
                        decrypt_fae_stream_to_writer(f, out_f, key, ent.path)
            else:
                if want_convert and ent.size <= max_mem:
                    raw_data = f.read(ent.size)
                    if args.verify_md5 and ent.md5 != b"\x00" * 16 and hashlib.md5(raw_data).digest() != ent.md5:
                        md5_fail += 1
                    new_ext, out_data, conv = convert_asset(rel_out.suffix, raw_data)
                    if conv:
                        converted += 1
                        target_file = target_file.with_suffix(new_ext)
                        raw_data = out_data
                    target_file = _unique_session_path(target_file, written_paths)
                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    with open(target_file, "wb") as out_f:
                        out_f.write(raw_data)
                else:
                    target_file = _unique_session_path(target_file, written_paths)
                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    rem = ent.size
                    h = hashlib.md5() if (args.verify_md5 and ent.md5 != b"\x00" * 16) else None
                    with open(target_file, "wb") as out_f:
                        while rem > 0:
                            chunk = f.read(min(CHUNK_SIZE, rem))
                            if not chunk:
                                break
                            if h:
                                h.update(chunk)
                            out_f.write(chunk)
                            rem -= len(chunk)
                    if h and h.digest() != ent.md5:
                        md5_fail += 1

            extracted += 1
            if extracted % 100 == 0:
                print(f"\r进度: 已提取 {extracted} 个 (解密 {decrypted} / 转换 {converted})...", end="", flush=True)

    print(f"\r完成! 输出目录: {out_dir}")
    msg = f"统计: 提取 {extracted} 个 | 解密 {decrypted} 个 | 格式转换 {converted} 个 | 跳过无密钥加密 {skipped_enc} 个"
    if args.verify_md5:
        msg += f" | MD5异常 {md5_fail} 个"
    print(msg)
    return 0


# ======================== 6. CLI 入口 ========================
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="godot-ex",
        description="Termux/Android Godot EXE/PCK 识别、找密钥与流式解包工具 (支持 V1~V4)",
    )
    parser.add_argument("--debug", action="store_true", help="出错时打印完整 Python 调用栈")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_id = sub.add_parser("identify", aliases=["info"], help="识别 EXE/PCK/SO 是否为 Godot 封包及详情")
    p_id.add_argument("inputs", nargs="+", help="目标 .exe/.pck/.so 文件或目录")
    p_id.add_argument("-k", "--key", help="若目录加密，可传入 64位 Hex 密钥以读取详情")
    p_id.set_defaults(func=cmd_identify)

    p_ls = sub.add_parser("list", aliases=["ls"], help="列出包内所有文件 (过滤依据原始 res:// 路径)")
    p_ls.add_argument("file", help="目标文件")
    p_ls.add_argument("-k", "--key", help="64位 Hex AES-256 密钥")
    p_ls.add_argument("-f", "--filter", help="通配符过滤，如 '*.gd,*.png'")
    p_ls.set_defaults(func=cmd_list)

    p_ep = sub.add_parser("extract-pck", help="从 EXE 中剥离纯净的独立 .pck 文件")
    p_ep.add_argument("file", help="目标 .exe 文件")
    p_ep.add_argument("-k", "--key", help="若为目录加密包，传入密钥可精算裁剪尾部对齐填充")
    p_ep.add_argument("-o", "--output", help="输出 .pck 路径")
    p_ep.set_defaults(func=cmd_extract_pck)

    p_fk = sub.add_parser("find-key", help="在 EXE / libgodot_android.so 中极速扫描并验证 AES-256 密钥")
    p_fk.add_argument("binary", help="包含密钥的 .exe 或 .so 文件")
    p_fk.add_argument("--pck", help="若密钥在 .so 而加密数据在独立 .pck 中，指定 .pck 路径")
    p_fk.set_defaults(func=cmd_find_key)

    p_un = sub.add_parser("unpack", help="流式解包 EXE/PCK (支持自动解密与贴图/音频转换)")
    p_un.add_argument("file", help="目标 .exe 或 .pck 文件")
    p_un.add_argument("-k", "--key", help="64位 Hex AES-256 密钥 (用于加密包/加密脚本)")
    p_un.add_argument("-o", "--output", help="输出目录")
    p_un.add_argument("--raw", action="store_true", help="保留原始 .ctex/.stex 容器格式")
    p_un.add_argument("--restore", action="store_true", help="根据 .import 还原原始项目路径")
    p_un.add_argument("-f", "--filter", help="仅解压匹配通配符的文件，如 '*.gd,*.tscn'")
    p_un.add_argument("--max-mem", type=int, default=64, help="媒体转换/GDEC 单文件内存上限 MB (默认 64)")
    p_un.add_argument("--verify-md5", action="store_true", help="校验明文文件 MD5")
    p_un.set_defaults(func=cmd_unpack)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n已取消操作。", file=sys.stderr)
        return 130
    except Exception as e:
        if args.debug:
            traceback.print_exc()
        else:
            print(f"错误: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

