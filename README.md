# wmpf-offset-finder

用于 `WMPFDebugger-GUI` 的 `WeChatAppEx Framework` arm64 构建版本的快速偏移量查找工具。

本工具并非要替代 IDA，而是一个专用的扫描器，用于查找本项目所需的偏移量：

- `LoadStartHookOffset`
- `LoadStartHookOffset2`
- `CDPFilterHookOffset`
- `ResourceCachePolicyHookOffset`

工具直接读取 Mach-O 或通用二进制文件，选择 arm64 切片，扫描 `__TEXT` 段中的字符串，追踪常见的 ARM64 `ADRP/ADD/LDR/BL` 指令模式，然后输出可直接使用的 `addresses.<version>.json` 配置文件。

## 使用方法

打印检测到的配置：

```bash
cargo run --release -- \
  "/Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/Frameworks/WeChatAppEx Framework.framework/Versions/C/WeChatAppEx Framework" \
  --arch arm64 \
  --version 19778 \
  --strategy auto \
  --print
```

将配置和报告写入 `WMPFDebugger-GUI` 项目目录：

```bash
cargo run --release -- \
  "/Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/Frameworks/WeChatAppEx Framework.framework/Versions/C/WeChatAppEx Framework" \
  --arch arm64 \
  --version 19778 \
  --strategy auto \
  --out-dir ../WMPFDebugger-GUI
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

主要的启发式规则：

- `SendToClientFilter` 交叉引用 -> 包含 devtools 函数 -> 第一个 `BL` 目标即为 `CDPFilterHookOffset`
- `WAPCAdapterAppIndex.js` 交叉引用 -> 包含资源白名单函数即为 `ResourceCachePolicyHookOffset`
- `AppletBringToTop` 交叉引用 -> 禁用的兼容性钩子即为 `LoadStartHookOffset`
- 场景配置初始化模式 `scene = 1000` 位于 `+0x1C8` 偏移处
- 调用序列 `MOV X2, SP` 后接 `BL` 为新路径
- 调用序列 `MOV X3, SP` 后接 `BL` 为旧式回退候选

输出模式示例：

```json
{
  "LoadStartHookMode": "disabled",
  "LoadStartHookArgIndex": 2,
  "LoadStartHook2Mode": "runtime-scene",
  "SceneOffset": 456,
  "StructOffset": 168
}
```

## 输出说明

- 仅支持 `arm64` 架构。
- 生成的报告包含所有检测到的场景钩子候选，不仅限于选定的那个。
- 在运行时测试确认 `hook scene@456 ... -> 1101` 和 `miniapp client connected` 之前，请将输出视为候选配置。
