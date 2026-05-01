# WMPF Address Rust

<p align="center">
  <strong>WMPF（微信小程序框架）偏移自动分析工具</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Windows-blueviolet" alt="Platform">
  <img src="https://img.shields.io/badge/arch-ARM64%20%7C%20x86__64-blue" alt="Architecture">
  <img src="https://img.shields.io/badge/rust-2024-edition?logo=rust&color=orange" alt="Rust Edition">
  <img src="https://img.shields.io/badge/version-0.2.0-green" alt="Version">
</p>

---

## 项目简介

`wmpf-address-rust` 用于**自动分析 WMPF / WeChatAppEx 二进制文件**，提取调试或 Hook 所需的关键偏移信息，并输出可直接集成到相关调试项目中的 JSON 配置。

当前工具覆盖两类常见目标：

- **macOS / Mach-O / arm64**
- **Windows / PE(DLL) / x86_64**

相较于手工逆向查找字符串、xref、函数边界和场景初始化路径，本工具将这套流程固化为可复现的分析管线，适合：

- WMPFDebugger / Frida 配置生成
- 版本升级后的偏移回归
- 二进制差异比对前的基线提取
- 批量化分析与 AI / MCP 集成

---

## 能力概览

工具会尝试提取以下关键信息：

- **CDPFilterHookOffset**：CDP 过滤相关 Hook 点
- **ResourceCachePolicyHookOffset**：资源缓存策略相关 Hook 点
- **LoadStartHookOffset**：兼容性用加载入口 Hook 点
- **LoadStartHookOffset2**：场景初始化 / 运行时场景 Hook 点
- **SceneOffset / SceneOffsets**：场景对象指针链相关结构偏移
- **Version**：从二进制中自动提取版本号（提取失败时可手动指定）

核心特性：

- 支持 **GUI / CLI / MCP Server** 三种使用方式
- 自动识别 **Mach-O / PE** 文件格式
- 内置基于字符串、xref、函数边界和调用点的分析流程
- 支持 **auto / launch-x2 / preload-x3** 三种策略选择
- 提供 evidence / candidate 信息，便于人工复核

---

## 支持范围

### 平台与格式

| 平台 | 架构 | 文件格式 | 状态 |
|---|---|---|---|
| macOS | arm64 | Mach-O | 支持 |
| Windows | x86_64 | PE / DLL | 支持 |

### 输入目标示例

- macOS: `WeChatAppEx Framework`
- Windows: `WeChatAppEx.dll` 或同类 WMPF 模块

---

## 安装与构建

### 环境要求

- Rust 2024 Edition
- 较新的 `rustc` / `cargo`
- macOS 或 Windows

### 从源码构建

```bash
git clone https://github.com/lemon7Cy/wmpf-address-rust.git
cd wmpf-address-rust
cargo build --release
```

构建产物默认位于：

```bash
target/release/wmpf-address-rust
```

---

## 快速开始

### GUI

```bash
cargo run -- gui
```

GUI 适合手工分析与快速验证，支持：

- 拖拽或浏览选择目标文件
- 切换架构与策略
- 实时查看分析日志
- 复制生成的 JSON
- 本地启动 MCP 服务入口

### CLI

```bash
# 最简单用法
cargo run -- <binary_path>

# 指定架构
cargo run -- <binary_path> --arch arm64
cargo run -- <binary_path> --arch x86_64

# 指定版本号（当自动提取失败时）
cargo run -- <binary_path> --version 19778

# 指定策略
cargo run -- <binary_path> --strategy auto
cargo run -- <binary_path> --strategy launch-x2
cargo run -- <binary_path> --strategy preload-x3

# 仅输出 JSON
cargo run -- <binary_path> --print

# 输出到目录
cargo run -- <binary_path> --out-dir ./output

# 输出更多调试信息
cargo run -- <binary_path> --verbose
```

### MCP Server

```bash
# stdio 模式启动
cargo run -- serve

# 启动时预加载二进制
cargo run -- serve --binary <path> --arch x86_64
```

适合接入支持 MCP 的客户端，用作自动分析后端。

---

## CLI 参数说明

| 参数 | 说明 |
|---|---|
| `<binary_path>` | 目标二进制路径 |
| `--arch arm64|x86_64` | 指定分析架构 |
| `--version N` | 手动覆盖版本号 |
| `--strategy ...` | 指定场景 Hook 候选选择策略 |
| `--out-dir DIR` | 输出 JSON 与 Markdown 报告到指定目录 |
| `--print` | 只打印 JSON，不写额外文件 |
| `--verbose` | 输出更详细的候选与调试信息 |

> 说明：策略参数**只影响 `LoadStartHookOffset2` 的候选选择**，不会影响 `CDPFilterHookOffset`、`ResourceCachePolicyHookOffset`、`LoadStartHookOffset` 的提取逻辑。

---

## 分析流程说明

本工具的核心不是“暴力搜索”，而是几条相对稳定的**特征定位管线**。

### 1. CDPFilterHookOffset

定位方式：

1. 搜索字符串 `SendToClientFilter`
2. 找到该字符串在代码段中的引用（xref）
3. 回溯到引用所在函数起始位置
4. 取该函数内首个 `BL/CALL` 目标作为 `CDPFilterHookOffset`

这一项通常置信度较高。

### 2. ResourceCachePolicyHookOffset

定位方式：

1. 搜索字符串 `WAPCAdapterAppIndex.js`
2. 定位代码引用
3. 回溯到引用所在函数起点
4. 该函数起点作为 `ResourceCachePolicyHookOffset`

这一项也通常具有较高稳定性。

### 3. LoadStartHookOffset

定位方式：

- macOS / Mach-O：通过 `AppletBringToTop` 字符串引用所在函数定位
- Windows / PE：优先尝试 `OnLoadStart` 相关引用，失败时回退到 `AppletBringToTop`

它更多承担**兼容性入口 Hook** 的角色。

### 4. LoadStartHookOffset2

这是策略相关的核心步骤。

工具会先定位“场景初始化配置函数”，其基础特征是对结构体字段写入：

- `+0x1C0 = 1`
- `+0x1C8 = 1000`

在定位到该初始化函数后，工具会继续寻找其调用者，并从调用现场附近提取“场景相关参数传递方式”，从而形成多个候选 `SceneHookCandidate`。

最终由策略决定选用哪个候选作为：

- `LoadStartHookOffset2`
- `LoadStartHookArgIndex`

---

## 策略（Strategy）详解

当前支持三种策略：

| 策略 | 实际行为 | 适用场景 |
|---|---|---|
| `auto` | 优先选择 `arg == 2` 的候选；如果没有，再退回第一个候选 | 默认推荐 |
| `launch-x2` | 强制选择 `arg == 2` 的候选；若不存在则报错 | 明确知道目标版本应走 LaunchApplet/X2 路径 |
| `preload-x3` | 强制选择 `arg == 3` 的候选；若不存在则报错 | 明确知道目标版本更适合 preload/X3 路径 |

### 它们本质上的区别

这里的差异，不是“扫描算法完全不同”，而是：

- **先统一找出一批候选**
- **再根据参数寄存器 / 参数位次选择最终使用的那个 Hook 点**

在源码层面，候选会被标记为：

- `launch-applet-x2-config`
- `preload-runtime-x3-config`

### 为什么 `auto` 默认优先 `x2`

因为当前实现中：

- `auto` 会先找 `arg == 2`
- 找不到时才退回到第一个候选

也就是说，`auto` 本质上是：

> “优先使用 LaunchApplet / X2 风格路径，若没有合适候选，再使用其他可行候选。”

### 什么时候应该手动指定策略

建议：

- **大多数情况**：先用 `auto`
- 如果你已经知道目标版本在调试时需要走明确的 `x2` 路径：用 `launch-x2`
- 如果某个版本 `auto` 选中的候选在实际 Hook 时效果不理想，而你确认应走 preload 路径：尝试 `preload-x3`

### 策略失败意味着什么

例如：

- `requested launch-x2 strategy but no X2 candidate was found`
- `requested preload-x3 strategy but no X3 candidate was found`

这说明：

- 场景初始化函数可能找到了
- 但该版本附近没有形成你要求的那类参数传递候选
- 并不一定表示整个文件无法分析，只表示**指定策略没有匹配到对应候选**

---

## 输出格式

### macOS / arm64 输出

```json
{
  "Version": 19778,
  "Arch": {
    "arm64": {
      "LoadStartHookOffset": "0x25BBA85",
      "LoadStartHookOffset2": "0x25C3E10",
      "CDPFilterHookOffset": "0x3023420",
      "ResourceCachePolicyHookOffset": "0x264BAE4",
      "StructOffset": 168,
      "LoadStartHookMode": "disabled",
      "LoadStartHookArgIndex": 2,
      "LoadStartHook2Mode": "runtime-scene",
      "SceneOffset": 456
    }
  }
}
```

字段说明：

| 字段 | 含义 |
|---|---|
| `Version` | 目标版本号 |
| `LoadStartHookOffset` | 兼容性加载 Hook |
| `LoadStartHookOffset2` | 场景运行时 Hook |
| `CDPFilterHookOffset` | CDP 过滤 Hook |
| `ResourceCachePolicyHookOffset` | 资源缓存策略 Hook |
| `StructOffset` | 结构体偏移常量，当前实现为 `168` |
| `LoadStartHookArgIndex` | 场景 Hook 传参索引，常见为 `2` 或 `3` |
| `SceneOffset` | 场景字段偏移，当前实现为 `456` |

### Windows / x86_64 输出

```json
{
  "Version": 19778,
  "LoadStartHookOffset": "0x25BBA85",
  "CDPFilterHookOffset": "0x3023420",
  "SceneOffsets": [1376, 1312, 456]
}
```

字段说明：

| 字段 | 含义 |
|---|---|
| `Version` | 目标版本号 |
| `LoadStartHookOffset` | 加载入口 Hook |
| `CDPFilterHookOffset` | CDP 过滤 Hook |
| `SceneOffsets` | Windows 路径下用于指针链访问场景对象的固定结构偏移数组 |

> 注意：Windows 当前输出格式是**简化格式**，与 macOS 下的完整结构不同。

---

## 生成的附加信息

除了 JSON，本工具内部还会维护：

- `evidence`：每个关键偏移的定位依据
- `scene_candidates`：所有场景 Hook 候选

如果使用 `--out-dir`，会同时生成：

- `frida/config/addresses.<version>.json`
- `docs/offsets-<version>-auto.md`

这对后续人工复核、版本回归和协作排障都很有帮助。

---

## GUI 使用建议

GUI 模式适合以下场景：

- 快速切换策略看候选差异
- 对单个版本进行人工验证
- 观察日志中的候选与置信度
- 直接复制 JSON 到调试项目

典型操作顺序：

1. 选择 `WeChatAppEx Framework` / `WeChatAppEx.dll`
2. 确认架构
3. 先尝试 `auto`
4. 若目标版本行为异常，再分别测试 `launch-x2` / `preload-x3`
5. 根据日志中的候选和最终 JSON 做集成验证

---

## 与 WMPFDebugger 集成

本工具生成的配置可以直接服务于 [WMPFDebugger](https://github.com/evi0s/WMPFDebugger) 等调试项目。

推荐流程：

1. 用本工具分析目标二进制
2. 获取 JSON 配置
3. 将配置放入对应调试项目的配置目录
4. 启动 Frida / 调试链路验证实际 Hook 行为
5. 若实际运行路径与预期不符，回到本工具切换策略重新验证

---

## 常见问题

### 1. 自动版本识别失败怎么办？

可以手动指定：

```bash
cargo run -- <binary_path> --version 19778
```

### 2. `auto` 成功，但实际 Hook 效果不理想？

这通常意味着：

- 当前版本同时存在多个场景候选
- `auto` 优先挑选了 `x2`
- 但你的调试链路更适合 `x3`

建议直接测试：

```bash
cargo run -- <binary_path> --strategy preload-x3
```

### 3. 为什么指定策略后会报错？

因为指定策略要求必须存在对应候选：

- `launch-x2` 要求候选参数索引为 `2`
- `preload-x3` 要求候选参数索引为 `3`

如果当前版本没有对应候选，就会直接报错。

### 4. 为什么 Windows 输出字段比 macOS 少？

这是当前实现设计使然：

- macOS 输出的是完整结构
- Windows 输出的是适配现有 Hook 链路的简化结构

---

## 源码结构

```text
src/
├── main.rs        # CLI 入口 / 参数解析 / GUI 启动
├── lib.rs         # 模块导出
├── gui.rs         # 图形界面
├── analysis.rs    # 统一分析管线与策略分发
├── mcp.rs         # MCP 服务实现
├── config.rs      # 配置结构与 JSON 输出
├── macho.rs       # Mach-O 解析
├── pe.rs          # PE / DLL 解析
├── arm64.rs       # ARM64 指令级辅助与候选提取
└── x64.rs         # x86_64 指令级辅助与候选提取
```

---

## 开发与验证

常用命令：

```bash
cargo test
cargo run -- gui
cargo run -- <binary_path> --verbose
```

如果你在更新规则、补充新版本适配或调整策略逻辑，建议至少验证：

- 单元测试是否通过
- GUI 是否正常启动
- 目标二进制在 `auto` 与手动策略下的输出是否符合预期

---

## 鸣谢

本项目的开发离不开以下项目的启发与参考：

- **[WMPFDebugger](https://github.com/evi0s/WMPFDebugger)** - 提供了重要的调试链路与 Hook 使用场景
- **[WMPFDebugger-mac](https://github.com/linguo2625469/WMPFDebugger-mac)** - 为 macOS 方向的适配和验证提供了参考

感谢相关项目与社区贡献者的工作。

---

## 许可证

MIT License

---

## 贡献

欢迎通过 Issue / Pull Request 提交：

- 新版本适配样本
- 更稳定的字符串 / xref 定位规则
- 新平台 / 新架构支持
- GUI / CLI / MCP 可用性改进
