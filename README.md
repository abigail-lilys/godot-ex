# godot-ex

> Termux / Android 专用 Godot 封包识别、找密钥与流式解包工具

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Deps](https://img.shields.io/badge/dependencies-none-brightgreen)

零第三方依赖的纯 Python 工具，用于识别、扫描密钥并解包 Godot 导出的 **EXE / PCK / SO** 文件。

## 特性

- 🎯 Godot **2.x ~ 4.7+**，支持 PCK **V0/V1/V2/V3/V4**
- 🔍 自动识别 PE / ELF 节区、EOF 尾标、带签名 EXE
- 🔑 自动扫描 AES-256 密钥（目录加密 / 单文件加密）
- 📦 全程流式读写，大文件不爆内存
- 🖼️ 自动转换 `.ctex`/`.stex` → PNG/WebP，`.oggstr` → OGG
- 📱 纯标准库，Termux 开箱即用（检测到 `cryptography`/`pycryptodome` 时自动加速）

## 安装

```bash
git clone https://github.com/<you>/godot-ex.git
cd godot-ex
python godot-ex.py --help
```

需要 **Python 3.8+**，无需 pip 安装任何依赖。

## 使用

### 识别封包
```bash
python godot-ex.py identify game.exe
python godot-ex.py identify game.pck -k <64位Hex密钥>
```

### 列出内容
```bash
python godot-ex.py list game.pck
python godot-ex.py list game.pck -f "*.gd,*.tscn"
```

### 扫描密钥
```bash
python godot-ex.py find-key game.exe
python godot-ex.py find-key libgodot_android.so --pck game.pck
```

### 解包
```bash
python godot-ex.py unpack game.exe
python godot-ex.py unpack game.pck -k <key> -o output/
python godot-ex.py unpack game.pck --restore --verify-md5
```

### 剥离纯净 PCK
```bash
python godot-ex.py extract-pck game.exe -o game.pck
```

## 常用参数

| 参数 | 说明 |
| --- | --- |
| `-k, --key` | 64 位 Hex AES-256 密钥 |
| `-o, --output` | 输出目录 / 文件 |
| `-f, --filter` | 通配符过滤，如 `*.gd,*.png` |
| `--raw` | 保留原始 `.ctex`/`.stex` 容器 |
| `--restore` | 按 `.import` 还原原始项目路径 |
| `--verify-md5` | 校验明文文件 MD5 |
| `--debug` | 出错时打印完整调用栈 |

## 支持范围

| 项目 | 范围 |
| --- | --- |
| Godot 版本 | 2.x ~ 4.7+ |
| PCK 格式 | V0 / V1 / V2 / V3 / V4 |
| 载体 | 独立 PCK、PE (EXE)、ELF (SO) |
| 加密 | 目录加密、单文件加密、Godot 3/4 GDEC |

## 免责声明

仅供学习研究与合法备份**自己拥有版权**的游戏资源。请勿用于商业用途或侵犯他人权益。

## License

[MIT](LICENSE)
