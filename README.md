# wmpf-offset-finder

用于 `WMPFDebugger-GUI` 的 `WeChatAppEx Framework` 快速偏移量查找工具。

本工具并非要替代 IDA，而是一个专用的扫描器，用于查找本项目所需的偏移量：

- `LoadStartHookOffset`
- `LoadStartHookOffset2` / `SceneOffsets`
- `CDPFilterHookOffset`
- `ResourceCachePolicyHookOffset`

## 支持平台

- **macOS**: Mach-O 格式，arm64/x86_64 架构
- **Windows**: PE/DLL 格式，x86_64 架构

## 使用方法

### macOS (Mach-O)

打印检测到的配置：

```bash
cargo run --release -- \
  "/Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/Frameworks/WeChatAppEx Framework.framework/Versions/C/WeChatAppEx Framework" \
  --arch arm64 \
  --version 19778 \
  --print
```

### Windows (DLL)

```bash
cargo run --release -- \
  "C:\Users\Administrator\AppData\Roaming\Tencent\xwechat\XPlugin\plugins\RadiumWMPF\19339\extracted\runtime\flue.dll" \
  --arch x86_64 \
  --version 19339 \
  --print
```

将配置和报告写入 `WMPFDebugger-GUI` 项目目录：

```bash
cargo run --release -- \
  "path\to\flue.dll" \
  --arch x86_64 \
  --version 19339 \
  --out-dir ..\WMPFDebugger-GUI
```

输出路径：

- `frida/config/addresses.<version>.json`
- `docs/offsets-<version>-auto.md`

## 扫描策略

扫描器支持三种模式：

- `--strategy auto`
  优先使用经过验证的 `LaunchApplet X2` 路径，当不可用时回退到 `Preload X3`。
- `--strategy launch-x2`
  强制使用较新的 `19766+` 路径。
- `--strategy preload-x3`
  强制使用旧式的 preload 风格路径（如果存在）。

## 主要的启发式规则

### macOS (arm64)

- `SendToClientFilter` 交叉引用 -> 包含 devtools 函数 -> 第一个 `BL` 目标即为 `CDPFilterHookOffset`
- `WAPCAdapterAppIndex.js` 交叉引用 -> 包含资源白名单函数即为 `ResourceCachePolicyHookOffset`
- `AppletBringToTop` 交叉引用 -> 禁用的兼容性钩子即为 `LoadStartHookOffset`
- 场景配置初始化模式 `scene = 1000` 位于 `+0x1C8` 偏移处

### Windows (x86_64)

- `SendToClientFilter` 字符串 -> 包含 devtools 函数 -> 第一个 `CALL` 目标即为 `CDPFilterHookOffset`
- `WAPCAdapterAppIndex.js` 字符串 -> 包含资源白名单函数即为 `ResourceCachePolicyHookOffset`
- `OnLoadStart` 字符串 -> 包含 `applet_index_container.cc` 引用的函数即为 `LoadStartHookOffset`
- 场景配置初始化模式 `scene = 1000` 位于 `+0x1C8` 偏移处

## 输出格式

### macOS (arm64)

```json
{
  "Version": 19778,
  "Arch": {
    "arm64": {
      "LoadStartHookOffset": "0x4F58B4C",
      "LoadStartHookOffset2": "0x4F65910",
      "CDPFilterHookOffset": "0x842C030",
      "ResourceCachePolicyHookOffset": "0x4FEBA90",
      "StructOffset": 168,
      "SceneOffset": 456
    }
  }
}
```

### Windows (x86_64)

```json
{
  "Version": 19339,
  "LoadStartHookOffset": "0x25B5DD0",
  "CDPFilterHookOffset": "0x301BA00",
  "SceneOffsets": [1376, 1312, 456]
}
```

## 输出说明

- 生成的报告包含所有检测到的场景钩子候选，不仅限于选定的那个。
- 在运行时测试确认 `hook scene@456 ... -> 1101` 和 `miniapp client connected` 之前，请将输出视为候选配置。
- Windows 版本的 `LoadStartHookOffset` 可能与手动分析有微小差异（通常在 5 字节以内）。
