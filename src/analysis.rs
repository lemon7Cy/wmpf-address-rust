use crate::arm64;
use crate::config::{Config, Evidence, StrategyChoice, SCENE_OFFSET, STRUCT_OFFSET};
use crate::macho::Slice;

pub(crate) fn analyze(
    slice: &Slice<'_>,
    version_arg: Option<String>,
    strategy_choice: StrategyChoice,
    verbose: bool,
) -> Result<Config, String> {
    let version = version_arg
        .or_else(|| arm64::extract_version(slice))
        .unwrap_or_else(|| "unknown".to_string());
    let mut evidence = Vec::new();

    // Pipeline 1: CDPFilterHookOffset via SendToClientFilter
    let (send_func, send_end, send_xref) = arm64::function_start_from_xref(slice, "SendToClientFilter")
        .map_err(|e| format!("CDPFilterHook detection failed: {e}"))?;
    let (_bl_at, cdp) =
        arm64::first_bl_in(slice, send_func, (send_func + 0x80).min(send_end))
            .ok_or_else(|| {
                format!(
                    "CDPFilterHook detection failed: no BL instruction found in function at 0x{send_func:x} (searched 0x{send_func:x}..0x{:x})",
                    (send_func + 0x80).min(send_end)
                )
            })?;
    evidence.push(Evidence {
        key: "CDPFilterHookOffset".to_string(),
        value: cdp,
        confidence: "high",
        notes: vec![format!(
            "SendToClientFilter xref at 0x{send_xref:x}; first BL in function 0x{send_func:x} targets 0x{cdp:x}"
        )],
    });

    // Pipeline 2: ResourceCachePolicyHookOffset via WAPCAdapterAppIndex.js
    let (resource, _res_end, res_xref) =
        arm64::function_start_from_xref(slice, "WAPCAdapterAppIndex.js")
            .map_err(|e| format!("ResourceCachePolicy detection failed: {e}"))?;
    evidence.push(Evidence {
        key: "ResourceCachePolicyHookOffset".to_string(),
        value: resource,
        confidence: "high",
        notes: vec![format!(
            "WAPCAdapterAppIndex.js xref at 0x{res_xref:x}; containing function starts at 0x{resource:x}"
        )],
    });

    // Pipeline 3: LoadStartHookOffset via AppletBringToTop
    let (load_start, _load_end, load_xref) =
        arm64::function_start_from_xref(slice, "AppletBringToTop")
            .map_err(|e| format!("LoadStartHook detection failed: {e}"))?;
    evidence.push(Evidence {
        key: "LoadStartHookOffset".to_string(),
        value: load_start,
        confidence: "medium",
        notes: vec![format!(
            "AppletBringToTop xref at 0x{load_xref:x}; used as disabled compatibility hook"
        )],
    });

    // Pipeline 4: LoadStartHookOffset2 via scene init pattern
    let (init_fn, init_site) = arm64::find_init_config_function(slice)
        .map_err(|e| format!("LoadStartHook2 detection failed: {e}"))?;
    let scene_candidates = arm64::find_launch_scene_hook_candidates(slice, init_fn, verbose)
        .map_err(|e| format!("LoadStartHook2 candidate search failed: {e}"))?;
    let selected = match strategy_choice {
        StrategyChoice::Auto => scene_candidates
            .iter()
            .find(|c| c.arg == 2)
            .or_else(|| scene_candidates.first())
            .ok_or("no scene hook candidates found")?,
        StrategyChoice::LaunchX2 => scene_candidates
            .iter()
            .find(|c| c.arg == 2)
            .ok_or("requested launch-x2 strategy but no X2 candidate was found")?,
        StrategyChoice::PreloadX3 => scene_candidates
            .iter()
            .find(|c| c.arg == 3)
            .ok_or("requested preload-x3 strategy but no X3 candidate was found")?,
    };
    evidence.push(Evidence {
        key: "LoadStartHookOffset2".to_string(),
        value: selected.hook,
        confidence: "medium-high",
        notes: vec![
            format!(
                "scene init function 0x{init_fn:x}; scene=1000 at 0x{init_site:x}; field offset +0x1c8"
            ),
            selected.notes.join(" | "),
        ],
    });

    Ok(Config {
        version,
        load_start,
        load_start2: selected.hook,
        cdp,
        resource,
        load_arg: selected.arg,
        scene_offset: SCENE_OFFSET,
        struct_offset: STRUCT_OFFSET,
        strategy: selected.strategy,
        scene_candidates,
        evidence,
    })
}
