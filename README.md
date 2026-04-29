# WMPF Address Rust

<p align="center">
  <strong>WMPF 地址自动分析工具</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Windows-blueviolet" alt="Platform">
  <img src="https://img.shields.io/badge/arch-ARM64%20%7C%20x86__64-blue" alt="Architecture">
  <img src="https://img.shields.io/badge/rust-2024-edition?logo=rust&color=orange" alt="Rust Edition">
  <img src="https://img.shields.io/badge/version-0.2.0-green" alt="Version">
</p>

---

## 简介

WMPF Address Rust 是一个用于自动分析 WMPF（微信小程序框架）二进制文件的工具，能够自动检测并提取以下关键偏移地址：

- **CDPFilterHookOffset** - CDP 过滤器钩子偏移
- **ResourceCachePolicyHookOffset** - 资源缓存策略钩子偏移
- **LoadStartHookOffset** - 加载启动钩子偏移
- **LoadStartHookOffset2** - 场景加载钩子偏移
- **SceneOffsets** - 场景结构体偏移数组

## 特性

- **跨平台支持**：支持 macOS (ARM64) 和 Windows (x86_64) 平台
- **多格式支持**：支持 Mach-O 和 PE (DLL) 文件格式
- **三种使用方式**：
  - GUI 图形界面
  - CLI 命令行
  - MCP 服务器（用于 AI 集成）
- **智能分析**：自动识别二进制格式和架构
- **策略选择**：支持 auto/launch-x2/preload-x3 多种分析策略

## 安装

### 从源码编译

```bash
# 克隆仓库
git clone https://github.com/lemon7Cy/wmpf-address-rust.git
cd wmpf-address-rust

# 编译 Release 版本
cargo build --release

# 可执行文件位于 target/release/wmpf-address-rust
```

### 环境要求

- Rust 2024 Edition (需要较新版本的 Rust 编译器)
- Windows 或 macOS 操作系统

## 使用方法

### 1. GUI 图形界面

```bash
cargo run -- gui
```

GUI 界面支持：
- 拖拽文件或点击浏览选择二进制文件
- 选择目标架构（arm64/x86_64）
- 选择分析策略（auto/launch-x2/preload-x3）
- 实时查看分析日志
- 一键复制 JSON 配置
- 内置 MCP 服务器

### 2. CLI 命令行

```bash
# 基本用法
cargo run -- <binary_path>

# 指定架构
cargo run -- <binary_path> --arch x86_64

# 指定版本号
cargo run -- <binary_path> --version 19481

# 指定策略
cargo run -- <binary_path> --strategy launch-x2

# 输出到指定目录
cargo run -- <binary_path> --out-dir ./output

# 仅打印 JSON
cargo run -- <binary_path> --print

# 详细输出
cargo run -- <binary_path> --verbose
```

### 3. MCP 服务器

```bash
# 启动 MCP 服务器（stdio 模式）
cargo run -- serve

# 指定预加载的二进制文件
cargo run -- serve --binary <path> --arch x86_64
```

MCP 服务器可用于与 AI 客户端（如 Claude Desktop）集成，提供智能分析能力。

## 输出格式

### macOS (ARM64) 配置格式

```json
{
  "Version": 19481,
  "Arch": {
    "arm64": {
      "LoadStartHookOffset": "0x25BBA85",
      "LoadStartHookOffset2": "0x25C3E10",
      "CDPFilterHookOffset": "0x3023420",
      "ResourceCachePolicyHookOffset": "0x264BAE4",
      "StructOffset": 1368,
      "LoadStartHookMode": "disabled",
      "LoadStartHookArgIndex": 2,
      "LoadStartHook2Mode": "runtime-scene",
      "SceneOffset": 456
    }
  }
}
```

### Windows (x86_64) 配置格式

```json
{
  "Version": 19481,
  "LoadStartHookOffset": "0x25BBA85",
  "CDPFilterHookOffset": "0x3023420",
  "SceneOffsets": [1376, 1312, 456]
}
```

## 技术架构

```
src/
├── main.rs        # CLI 入口
├── lib.rs         # 模块导出
├── gui.rs         # GUI 界面 (egui/eframe)
├── analysis.rs    # 核心分析管道
├── mcp.rs         # MCP 服务器
├── config.rs      # 配置结构体
├── macho.rs       # Mach-O 解析器
├── pe.rs          # PE/DLL 解析器
├── arm64.rs       # ARM64 指令解码
└── x64.rs         # x86_64 指令解码
```

## 与 WMPFDebugger 集成

本工具生成的配置文件可直接用于 [WMPFDebugger](https://github.com/evi0s/WMPFDebugger) 项目：

1. 使用本工具分析二进制文件
2. 将生成的 JSON 配置复制到 `WMPFDebugger/frida/config/` 目录
3. 运行 WMPFDebugger 进行调试

## 鸣谢

本项目的开发离不开以下优秀项目的启发和贡献：

- **[WMPFDebugger](https://github.com/evi0s/WMPFDebugger)** - 由 [evi0s](https://github.com/evi0s) 开发的 WMPF 调试工具，提供了 Frida hook 脚本和调试框架
- **[WMPFDebugger-mac](https://github.com/linguo2625469/WMPFDebugger-mac)** - 由 [linguo2625469](https://github.com/linguo2625469) 维护的 macOS 版本，为跨平台支持提供了重要参考

感谢这些项目为微信小程序调试社区做出的贡献！

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！
