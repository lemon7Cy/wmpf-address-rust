use std::path::PathBuf;
use std::sync::Arc;

use rmcp::{
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content},
    schemars, tool, tool_router, ServiceExt, transport::stdio, ServerHandler, ErrorData as McpError,
};
use tokio::sync::Mutex;

use crate::analysis;
use crate::config;
use crate::macho::{self, Arch, Slice};

/// Holds a loaded binary and its parsed Mach-O data.
/// The slice's data pointer is derived from `data` via unsafe,
/// which is sound because `data` is never moved or dropped before `slice`.
struct LoadedBinary {
    data: Vec<u8>,
    slice: Slice<'static>,
    arch: Arch,
    path: String,
}

impl LoadedBinary {
    fn load(path: &str, arch: Arch) -> Result<Self, String> {
        let data = std::fs::read(path)
            .map_err(|e| format!("failed to read {path}: {e}"))?;
        let slice = macho::parse_slice(&data, arch)?;
        // SAFETY: `slice` borrows from `data`. We extend the lifetime to 'static
        // because `data` lives in the same struct and is never moved out before `slice`.
        let slice: Slice<'static> = unsafe { std::mem::transmute(slice) };
        Ok(Self {
            data,
            slice,
            arch,
            path: path.to_string(),
        })
    }
}

// --- MCP parameter structs ---

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct LoadBinaryParams {
    #[schemars(description = "Path to the Mach-O binary file")]
    path: String,
    #[schemars(description = "Architecture to analyze: 'arm64' or 'x86_64'")]
    arch: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct FindStringParams {
    #[schemars(description = "String to search for in the binary")]
    needle: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct FindXrefParams {
    #[schemars(description = "Target VM address to find references to (decimal or 0x hex)")]
    target: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct FunctionBoundsParams {
    #[schemars(description = "VM address near which to find function boundaries (decimal or 0x hex)")]
    near: String,
}

// --- MCP Server ---

#[derive(Clone)]
pub struct WmpfServer {
    binary: Arc<Mutex<Option<LoadedBinary>>>,
    tool_router: rmcp::handler::server::router::tool::ToolRouter<WmpfServer>,
}

impl std::fmt::Debug for WmpfServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WmpfServer").finish()
    }
}

fn parse_addr(s: &str) -> Result<u64, String> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| format!("invalid hex address: {e}"))
    } else {
        s.parse::<u64>().map_err(|e| format!("invalid address: {e}"))
    }
}

fn parse_arch(s: &str) -> Result<Arch, String> {
    match s {
        "arm64" | "aarch64" => Ok(Arch::Arm64),
        "x86_64" | "x64" => Ok(Arch::X86_64),
        _ => Err(format!("unsupported arch: '{s}', use 'arm64' or 'x86_64'")),
    }
}

#[tool_router(router = tool_router)]
impl WmpfServer {
    pub fn new() -> Self {
        Self {
            binary: Arc::new(Mutex::new(None)),
            tool_router: Self::tool_router(),
        }
    }

    #[tool(name = "load-binary", description = "Load a Mach-O binary file for analysis. Must be called before other tools.")]
    async fn load_binary(
        &self,
        Parameters(LoadBinaryParams { path, arch }): Parameters<LoadBinaryParams>,
    ) -> Result<CallToolResult, McpError> {
        let arch = parse_arch(&arch).map_err(|e| McpError::invalid_params(e, None))?;
        let loaded = LoadedBinary::load(&path, arch)
            .map_err(|e| McpError::invalid_params(e, None))?;

        let info = format!(
            "Loaded: {} (arch={:?}, data=0x{:x} bytes, sections={})",
            path,
            loaded.arch,
            loaded.data.len(),
            loaded.slice.sections.len()
        );

        let mut guard = self.binary.lock().await;
        *guard = Some(loaded);

        Ok(CallToolResult::success(vec![Content::text(info)]))
    }

    #[tool(description = "Run the full 4-pipeline offset analysis (CDP, ResourceCache, LoadStart, LoadStart2). Requires a binary to be loaded first.")]
    async fn analyze(&self) -> Result<CallToolResult, McpError> {
        let guard = self.binary.lock().await;
        let binary = guard.as_ref()
            .ok_or_else(|| McpError::invalid_params("no binary loaded; call load-binary first", None))?;

        let cfg = analysis::analyze(
            &binary.slice,
            binary.arch,
            None,
            config::StrategyChoice::Auto,
            false,
        ).map_err(|e| McpError::internal_error(e, None))?;

        let json = config::json_config(&cfg, binary.arch);
        Ok(CallToolResult::success(vec![Content::text(json)]))
    }

    #[tool(description = "Search for a string in the binary's __TEXT sections. Returns VM addresses where the string is found.")]
    async fn find_string(
        &self,
        Parameters(FindStringParams { needle }): Parameters<FindStringParams>,
    ) -> Result<CallToolResult, McpError> {
        let guard = self.binary.lock().await;
        let binary = guard.as_ref()
            .ok_or_else(|| McpError::invalid_params("no binary loaded; call load-binary first", None))?;

        let addrs = macho::find_string(&binary.slice, &needle);
        if addrs.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text(
                format!("string \"{needle}\" not found in binary"),
            )]));
        }

        let result: Vec<String> = addrs.iter().map(|a| format!("0x{a:X}")).collect();
        Ok(CallToolResult::success(vec![Content::text(
            format!("found {} occurrence(s) of \"{needle}\":\n{}", addrs.len(), result.join("\n")),
        )]))
    }

    #[tool(description = "Find all cross-references (xrefs) to a target VM address in the text section. Works for both arm64 and x86_64.")]
    async fn find_xref(
        &self,
        Parameters(FindXrefParams { target }): Parameters<FindXrefParams>,
    ) -> Result<CallToolResult, McpError> {
        let target = parse_addr(&target).map_err(|e| McpError::invalid_params(e, None))?;
        let guard = self.binary.lock().await;
        let binary = guard.as_ref()
            .ok_or_else(|| McpError::invalid_params("no binary loaded; call load-binary first", None))?;

        let xrefs = match binary.arch {
            Arch::Arm64 => crate::arm64::find_text_xrefs(&binary.slice, target),
            Arch::X86_64 => crate::x64::find_text_xrefs(&binary.slice, target),
        }.map_err(|e| McpError::internal_error(e, None))?;

        if xrefs.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text(
                format!("no xrefs found for 0x{target:X}"),
            )]));
        }

        let result: Vec<String> = xrefs.iter().map(|x| format!("0x{:X}", x.at)).collect();
        Ok(CallToolResult::success(vec![Content::text(
            format!("found {} xref(s) to 0x{target:X}:\n{}", xrefs.len(), result.join("\n")),
        )]))
    }

    #[tool(description = "Find function boundaries (start and end) near a given VM address by scanning for function prologues.")]
    async fn function_bounds(
        &self,
        Parameters(FunctionBoundsParams { near }): Parameters<FunctionBoundsParams>,
    ) -> Result<CallToolResult, McpError> {
        let near = parse_addr(&near).map_err(|e| McpError::invalid_params(e, None))?;
        let guard = self.binary.lock().await;
        let binary = guard.as_ref()
            .ok_or_else(|| McpError::invalid_params("no binary loaded; call load-binary first", None))?;

        let (start, end) = match binary.arch {
            Arch::Arm64 => crate::arm64::function_bounds(&binary.slice, near),
            Arch::X86_64 => crate::x64::function_bounds(&binary.slice, near),
        }.map_err(|e| McpError::internal_error(e, None))?;

        let size = end - start;
        Ok(CallToolResult::success(vec![Content::text(
            format!("function containing 0x{near:X}:\n  start: 0x{start:X}\n  end:   0x{end:X}\n  size:  0x{size:X} ({size} bytes)"),
        )]))
    }

    #[tool(description = "List all Mach-O sections (segment, name, address, size) in the loaded binary.")]
    async fn get_sections(&self) -> Result<CallToolResult, McpError> {
        let guard = self.binary.lock().await;
        let binary = guard.as_ref()
            .ok_or_else(|| McpError::invalid_params("no binary loaded; call load-binary first", None))?;

        let mut lines = Vec::new();
        for sec in &binary.slice.sections {
            lines.push(format!(
                "  {:16} {:16} addr=0x{:08X} size=0x{:X}",
                sec.seg, sec.name, sec.addr, sec.size
            ));
        }

        Ok(CallToolResult::success(vec![Content::text(
            format!("arch: {:?}, path: {}\nsections ({}):\n{}",
                binary.arch, binary.path, lines.len(), lines.join("\n")),
        )]))
    }
}

#[rmcp::tool_handler(router = self.tool_router)]
impl ServerHandler for WmpfServer {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        let mut info = rmcp::model::ServerInfo::default();
        info.server_info = rmcp::model::Implementation {
            name: "wmpf-offset-finder".to_string(),
            title: Some("WMPF Offset Finder".to_string()),
            version: env!("CARGO_PKG_VERSION").to_string(),
            description: Some("Mach-O binary analysis for WeChatAppEx Framework hook offsets".to_string()),
            icons: None,
            website_url: None,
        };
        info.instructions = Some(
            "MCP server for analyzing WeChatAppEx Framework Mach-O binaries.\n\n\
             Workflow:\n\
             1. load-binary(path=..., arch=arm64|x86_64) — load the binary\n\
             2. analyze() — run the full 4-pipeline offset detection\n\
             3. If analysis fails for some offsets, use primitives:\n\
             4. find-string(needle=...) — find string addresses\n\
             5. find-xref(target=0x...) — find code references to an address\n\
             6. function-bounds(near=0x...) — determine function start/end\n\
             7. get_sections() — list all Mach-O sections".to_string()
        );
        info
    }
}

/// Entry point for the MCP server. Called from main.rs.
pub async fn run_server(binary: Option<PathBuf>, arch: Arch) -> Result<(), String> {
    let server = WmpfServer::new();

    // Pre-load binary if provided via --binary
    if let Some(path) = binary {
        let path_str = path.to_string_lossy().to_string();
        let loaded = LoadedBinary::load(&path_str, arch)
            .map_err(|e| format!("failed to load binary: {e}"))?;
        let mut guard = server.binary.lock().await;
        *guard = Some(loaded);
        eprintln!("pre-loaded: {path_str} (arch={arch:?})");
    }

    let service = server.serve(stdio()).await
        .map_err(|e| format!("MCP server error: {e}"))?;

    eprintln!("wmpf-offset-finder MCP server started");
    service.waiting().await
        .map_err(|e| format!("MCP server error: {e}"))?;

    Ok(())
}
