# wmpf-offset-finder

Fast offset finder for `WeChatAppEx Framework` arm64 builds used by `WMPFDebugger-GUI`.

This tool does not try to replace IDA. It is a narrow scanner for the offsets this project needs:

- `LoadStartHookOffset`
- `LoadStartHookOffset2`
- `CDPFilterHookOffset`
- `ResourceCachePolicyHookOffset`

It reads the Mach-O or universal binary directly, selects the arm64 slice, scans `__TEXT` strings, follows common ARM64 `ADRP/ADD/LDR/BL` patterns, and emits a ready-to-use `addresses.<version>.json`.

## Usage

Print detected config:

```bash
cargo run --release -- \
  "/Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/Frameworks/WeChatAppEx Framework.framework/Versions/C/WeChatAppEx Framework" \
  --arch arm64 \
  --version 19778 \
  --strategy auto \
  --print
```

Write config and report into a `WMPFDebugger-GUI` checkout:

```bash
cargo run --release -- \
  "/Applications/WeChat.app/Contents/MacOS/WeChatAppEx.app/Contents/Frameworks/WeChatAppEx Framework.framework/Versions/C/WeChatAppEx Framework" \
  --arch arm64 \
  --version 19778 \
  --strategy auto \
  --out-dir ../WMPFDebugger-GUI
```

Output paths:

- `frida/config/addresses.<version>.json`
- `docs/offsets-<version>-auto.md`

## Strategy
The scanner now supports three modes:

- `--strategy auto`
  Prefers the validated `LaunchApplet X2` path and falls back to `Preload X3` when needed.
- `--strategy launch-x2`
  Forces the newer `19766+` path.
- `--strategy preload-x3`
  Forces the older preload-style path when present.

The main heuristics are:

- `SendToClientFilter` xref -> containing devtools function -> first `BL` target for `CDPFilterHookOffset`
- `WAPCAdapterAppIndex.js` xref -> containing resource whitelist function for `ResourceCachePolicyHookOffset`
- `AppletBringToTop` xref -> disabled compatibility hook for `LoadStartHookOffset`
- scene config init pattern `scene = 1000` at `+0x1C8`
- caller sequence `MOV X2, SP` then `BL` for the new path
- caller sequence `MOV X3, SP` then `BL` as old-style fallback candidate

The emitted mode is:

```json
{
  "LoadStartHookMode": "disabled",
  "LoadStartHookArgIndex": 2,
  "LoadStartHook2Mode": "runtime-scene",
  "SceneOffset": 456,
  "StructOffset": 168
}
```

## Output Notes

- Only `arm64` is supported.
- The generated report includes all detected scene-hook candidates, not only the selected one.
- Treat output as a candidate config until a runtime test confirms `hook scene@456 ... -> 1101` and `miniapp client connected`.
