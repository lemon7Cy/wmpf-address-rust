use crate::arm64;
use crate::config::{Config, Evidence, ScenePath, StrategyChoice, SCENE_OFFSET, STRUCT_OFFSET};
use crate::macho::{Arch, Slice};
use crate::pe::PeFile;
use crate::scene_chain;
use crate::x64;

pub fn analyze(
    slice: &Slice<'_>,
    arch: Arch,
    version_arg: Option<String>,
    strategy_choice: StrategyChoice,
    verbose: bool,
) -> Result<Config, String> {
    let version = version_arg
        .or_else(|| match arch {
            Arch::Arm64 => arm64::extract_version(slice),
            Arch::X86_64 => x64::extract_version(slice),
        })
        .unwrap_or_else(|| "unknown".to_string());
    let mut evidence = Vec::new();

    // Pipeline 1: CDPFilterHookOffset via SendToClientFilter
    let (send_func, send_end, send_xref) = match arch {
        Arch::Arm64 => arm64::function_start_from_xref(slice, "SendToClientFilter"),
        Arch::X86_64 => x64::function_start_from_xref(slice, "SendToClientFilter"),
    }
    .map_err(|e| format!("CDPFilterHook detection failed: {e}"))?;

    let cdp = match arch {
        Arch::Arm64 => {
            let (_bl_at, target) =
                arm64::first_bl_in(slice, send_func, (send_func + 0x80).min(send_end))
                    .ok_or_else(|| {
                        format!(
                            "CDPFilterHook detection failed: no BL found in function 0x{send_func:x}"
                        )
                    })?;
            target
        }
        Arch::X86_64 => {
            let (_call_at, target) =
                x64::first_call_in(slice, send_func, (send_func + 0x100).min(send_end))
                    .ok_or_else(|| {
                        format!(
                            "CDPFilterHook detection failed: no CALL found in function 0x{send_func:x}"
                        )
                    })?;
            target
        }
    };

    evidence.push(Evidence {
        key: "CDPFilterHookOffset".to_string(),
        value: cdp,
        confidence: "high",
        notes: vec![format!(
            "SendToClientFilter xref at 0x{send_xref:x}; first call in function 0x{send_func:x} targets 0x{cdp:x}"
        )],
    });

    // Pipeline 2: ResourceCachePolicyHookOffset via WAPCAdapterAppIndex.js
    let (resource, _res_end, res_xref) = match arch {
        Arch::Arm64 => arm64::function_start_from_xref(slice, "WAPCAdapterAppIndex.js"),
        Arch::X86_64 => x64::function_start_from_xref(slice, "WAPCAdapterAppIndex.js"),
    }
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
    let (load_start, _load_end, load_xref) = match arch {
        Arch::Arm64 => arm64::function_start_from_xref(slice, "AppletBringToTop"),
        Arch::X86_64 => x64::function_start_from_xref(slice, "AppletBringToTop"),
    }
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
    let (init_fn, init_site) = match arch {
        Arch::Arm64 => arm64::find_init_config_function(slice),
        Arch::X86_64 => x64::find_init_config_function(slice),
    }
    .map_err(|e| format!("LoadStartHook2 detection failed: {e}"))?;

    let scene_candidates = match arch {
        Arch::Arm64 => arm64::find_launch_scene_hook_candidates(slice, init_fn, verbose),
        Arch::X86_64 => x64::find_launch_scene_hook_candidates(slice, init_fn, verbose),
    }
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
        scene_offsets_x64: None,
        scene_path: None,
    })
}

/// Analyze a PE (Windows DLL) file for WMPF offsets.
pub fn analyze_pe(
    pe: &PeFile<'_>,
    _arch: Arch,
    version_arg: Option<String>,
    strategy_choice: StrategyChoice,
    verbose: bool,
) -> Result<Config, String> {
    let slice = pe_to_slice(pe)?;
    let version = version_arg
        .or_else(|| pe_extract_version(pe))
        .unwrap_or_else(|| "unknown".to_string());

    let mut evidence = Vec::new();

    // Pipeline 1: CDPFilterHookOffset via SendToClientFilter
    let (send_func, send_end, send_xref) =
        pe_function_start_from_xref(pe, &slice, "SendToClientFilter")
            .map_err(|e| format!("CDPFilterHook detection failed: {e}"))?;

    let (_call_at, cdp) = x64::first_call_in(&slice, send_func, (send_func + 0x100).min(send_end))
        .ok_or_else(|| {
            format!(
                "CDPFilterHook detection failed: no CALL found in function 0x{send_func:x}"
            )
        })?;

    evidence.push(Evidence {
        key: "CDPFilterHookOffset".to_string(),
        value: cdp,
        confidence: "high",
        notes: vec![format!(
            "SendToClientFilter xref at 0x{send_xref:x}; first call in function 0x{send_func:x} targets 0x{cdp:x}"
        )],
    });

    // Pipeline 2: ResourceCachePolicyHookOffset via WAPCAdapterAppIndex.js
    let (resource, _res_end, res_xref) =
        pe_function_start_from_xref(pe, &slice, "WAPCAdapterAppIndex.js")
            .map_err(|e| format!("ResourceCachePolicy detection failed: {e}"))?;

    evidence.push(Evidence {
        key: "ResourceCachePolicyHookOffset".to_string(),
        value: resource,
        confidence: "high",
        notes: vec![format!(
            "WAPCAdapterAppIndex.js xref at 0x{res_xref:x}; containing function starts at 0x{resource:x}"
        )],
    });

    // Pipeline 3: LoadStartHookOffset — we anchor off the pretty-function
    // literal `virtual void applet::AppletIndexContainer::OnLoadStart`,
    // falling back to `OnLoadStart` + container ref heuristic, and finally to
    // `AppletBringToTop` for very old builds.
    let (load_start, load_end, load_xref) = pe_find_onloadstart_pretty(pe, &slice)
        .or_else(|_| pe_find_onloadstart_xref(pe, &slice))
        .or_else(|_| pe_function_start_from_xref(pe, &slice, "AppletBringToTop"))
        .map_err(|e| format!("LoadStartHook detection failed: {e}"))?;

    evidence.push(Evidence {
        key: "LoadStartHookOffset".to_string(),
        value: load_start,
        confidence: "high",
        notes: vec![format!(
            "OnLoadStart anchor xref at 0x{load_xref:x}; function at 0x{load_start:x}"
        )],
    });

    // Pipeline 4a: static scene pointer chain (ScenePath).
    // This is the fix that used to be missing: hook.js got a hardcoded
    // [1376, 1312, 456] triple, so any new layout (like 19769) silently broke.
    let scene_path_result = scene_chain::derive_scene_chain(&slice, load_start, load_end);

    let (scene_path, scene_offsets_x64) = match &scene_path_result {
        Ok((path, trace)) => {
            evidence.push(Evidence {
                key: "ScenePath".to_string(),
                value: path.scene_offset as u64,
                confidence: "high",
                notes: vec![
                    format!("pointerOffsets={:?}", path.pointer_offsets),
                    trace.clone(),
                ],
            });
            let triple = scene_chain::scene_path_to_triple(path);
            (Some(path.clone()), triple)
        }
        Err(err) => {
            if verbose {
                eprintln!("warning: scene chain derivation failed: {err}");
            }
            evidence.push(Evidence {
                key: "ScenePath".to_string(),
                value: 0,
                confidence: "low",
                notes: vec![format!("derivation failed: {err}; falling back to SCENE_OFFSETS_X64 constant")],
            });
            (None, None)
        }
    };

    // Pipeline 4b: LoadStartHookOffset2 via scene init pattern — kept for
    // parity with macOS output though Windows hook.js doesn't consume it.
    let (init_fn, init_site) = x64::find_init_config_function(&slice)
        .map_err(|e| format!("LoadStartHook2 detection failed: {e}"))?;

    if verbose {
        eprintln!("debug: init_fn=0x{init_fn:x}, init_site=0x{init_site:x}");
    }

    let scene_candidates = match x64::find_launch_scene_hook_candidates(&slice, init_fn, verbose) {
        Ok(candidates) => candidates,
        Err(e) => {
            if verbose {
                eprintln!("warning: failed to find scene hook candidates: {e}");
            }
            vec![crate::config::SceneHookCandidate {
                hook: load_start,
                arg: 2,
                strategy: "launch-applet-x2-config",
                notes: vec![format!(
                    "fallback: using OnLoadStart 0x{load_start:x} as hook"
                )],
            }]
        }
    };

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

    // PE addresses are absolute (include image_base); subtract to get RVAs.
    let base = pe.image_base;
    let load_start = load_start.wrapping_sub(base);
    let load_start2 = selected.hook.wrapping_sub(base);
    let cdp = cdp.wrapping_sub(base);
    let resource = resource.wrapping_sub(base);

    Ok(Config {
        version,
        load_start,
        load_start2,
        cdp,
        resource,
        load_arg: selected.arg,
        scene_offset: SCENE_OFFSET,
        struct_offset: STRUCT_OFFSET,
        strategy: selected.strategy,
        scene_candidates,
        evidence,
        scene_offsets_x64,
        scene_path,
    })
}

/// PE-specific version extraction.
fn pe_extract_version(pe: &PeFile<'_>) -> Option<String> {
    for sec in &pe.sections {
        if sec.name == ".rdata" || sec.name == ".rodata" || sec.name == "_RDATA" {
            if let Some(buf) = crate::pe::section_bytes(pe, sec) {
                let hay = String::from_utf8_lossy(buf);
                for part in hay.split('\0') {
                    if let Some(ver) = find_version_pattern_pe(part) {
                        return Some(ver);
                    }
                }
            }
        }
    }
    None
}

fn find_version_pattern_pe(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    for end in (4..=len).rev() {
        let digit_end = end;
        let mut digit_start = end;
        while digit_start > 0 && bytes[digit_start - 1].is_ascii_digit() {
            digit_start -= 1;
        }
        let digit_len = digit_end - digit_start;
        if !(4..=6).contains(&digit_len) {
            continue;
        }
        if digit_end < len {
            continue;
        }
        if digit_start == 0 || bytes[digit_start - 1] != b'.' {
            continue;
        }
        let prefix = &bytes[..digit_start - 1];
        let prefix_str = match std::str::from_utf8(prefix) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let groups: Vec<&str> = prefix_str.split('.').collect();
        if groups.len() < 2 {
            continue;
        }
        let last_group = groups.last().unwrap();
        if last_group.is_empty() || !last_group.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        return Some(s[digit_start..digit_end].to_string());
    }
    None
}

/// PE-specific string -> xref -> function bounds pipeline.
fn pe_function_start_from_xref(
    pe: &PeFile<'_>,
    slice: &Slice<'_>,
    string: &str,
) -> Result<(u64, u64, u64), String> {
    let addrs = crate::pe::find_string(pe, string);
    if addrs.is_empty() {
        return Err(format!("string not found in binary: \"{string}\""));
    }

    let mut failures = Vec::new();
    for str_addr in addrs {
        let xrefs = pe_find_text_xrefs(slice, str_addr)?;
        if let Some(xref) = xrefs.first() {
            let (start, end) = x64::function_bounds(slice, xref.at)?;
            return Ok((start, end, xref.at));
        }
        failures.push(format!("0x{str_addr:x} (no xrefs)"));
    }
    Err(format!(
        "xref not found for string: \"{string}\"; string at: {}",
        failures.join(", ")
    ))
}

/// Primary OnLoadStart locator: anchor on the `__PRETTY_FUNCTION__` literal.
/// This string is unique and has exactly one LEA xref — the one inside the
/// real OnLoadStart function.
fn pe_find_onloadstart_pretty(
    pe: &PeFile<'_>,
    slice: &Slice<'_>,
) -> Result<(u64, u64, u64), String> {
    let anchor = "virtual void applet::AppletIndexContainer::OnLoadStart";
    let addrs = crate::pe::find_string(pe, anchor);
    if addrs.is_empty() {
        return Err(format!("string not found: \"{anchor}\""));
    }
    for str_addr in addrs {
        let xrefs = pe_find_text_xrefs(slice, str_addr)?;
        if let Some(xref) = xrefs.first() {
            let (start, end) = x64::function_bounds(slice, xref.at)?;
            return Ok((start, end, xref.at));
        }
    }
    Err(format!("no xref into \"{anchor}\""))
}

/// Secondary OnLoadStart locator: search for the bare `OnLoadStart` string
/// and pick the candidate function that also references
/// `applet_index_container`. Keeps working on older builds where the pretty
/// function string isn't present.
fn pe_find_onloadstart_xref(
    pe: &PeFile<'_>,
    slice: &Slice<'_>,
) -> Result<(u64, u64, u64), String> {
    let onload_addrs = crate::pe::find_string(pe, "OnLoadStart");
    if onload_addrs.is_empty() {
        return Err("OnLoadStart string not found".to_string());
    }

    let container_addrs = crate::pe::find_string(pe, "applet_index_container");

    let mut candidates = Vec::new();

    for str_addr in &onload_addrs {
        let xrefs = match pe_find_text_xrefs(slice, *str_addr) {
            Ok(refs) => refs,
            Err(_) => continue,
        };

        for xref in &xrefs {
            let (fn_start, fn_end) = match x64::function_bounds(slice, xref.at) {
                Ok(bounds) => bounds,
                Err(_) => continue,
            };

            let offset_in_fn = xref.at - fn_start;

            let has_container_ref = if !container_addrs.is_empty() {
                container_addrs.iter().any(|caddr| {
                    let container_xrefs = pe_find_text_xrefs(slice, *caddr);
                    match container_xrefs {
                        Ok(refs) => refs.iter().any(|r| r.at >= fn_start && r.at < fn_end),
                        Err(_) => false,
                    }
                })
            } else {
                false
            };

            candidates.push((fn_start, fn_end, xref.at, offset_in_fn, has_container_ref));
        }
    }

    candidates.sort_by(|a, b| {
        if a.4 != b.4 {
            return b.4.cmp(&a.4);
        }
        let a_in_range = a.3 >= 0x50 && a.3 <= 0x200;
        let b_in_range = b.3 >= 0x50 && b.3 <= 0x200;
        if a_in_range != b_in_range {
            return b_in_range.cmp(&a_in_range);
        }
        (b.1 - b.0).cmp(&(a.1 - a.0))
    });

    if let Some((fn_start, fn_end, xref_at, _, _)) = candidates.first() {
        return Ok((*fn_start, *fn_end, *xref_at));
    }

    Err("LoadStartHookOffset not found: no valid OnLoadStart xref found".to_string())
}

/// Find xrefs to a target address in the .text section of a PE file.
fn pe_find_text_xrefs(slice: &Slice<'_>, target: u64) -> Result<Vec<crate::macho::Xref>, String> {
    // After pe_to_slice, .text is mapped to __TEXT,__text
    let text = crate::macho::section(slice, "__TEXT", "__text")
        .or_else(|| slice.sections.iter().find(|s| s.name == "__text"))
        .or_else(|| slice.sections.iter().find(|s| s.name == ".text"))
        .ok_or(".text section not found")?;
    let buf = crate::macho::section_bytes(slice, text)
        .ok_or(".text section data outside file bounds")?;
    let base = text.addr;

    let mut refs = Vec::new();
    let mut i = 0;
    while i + 7 <= buf.len() {
        let b0 = buf[i];
        if b0 == 0x48 || b0 == 0x4C {
            if i + 7 <= buf.len() && buf[i + 1] == 0x8D {
                let modrm = buf[i + 2];
                if (modrm & 0xC7) == 0x05 {
                    let disp = i32::from_le_bytes(
                        buf[i + 3..i + 7].try_into().unwrap(),
                    );
                    let rip_after = base + (i as u64) + 7;
                    let actual = rip_after.wrapping_add(disp as u64);
                    if actual == target {
                        refs.push(crate::macho::Xref { at: base + i as u64 });
                    }
                }
            }
        }
        i += 1;
    }
    Ok(refs)
}

/// Convert a PE file to a Slice-like structure for analysis.
fn pe_to_slice<'a>(pe: &'a PeFile<'a>) -> Result<Slice<'a>, String> {
    use crate::macho::Section;

    let mut sections = Vec::new();

    for sec in &pe.sections {
        if sec.raw_data_size > 0 {
            let (seg, name) = match sec.name.as_str() {
                ".text" => ("__TEXT".to_string(), "__text".to_string()),
                ".rdata" => ("__TEXT".to_string(), "__cstring".to_string()),
                ".data" => ("__DATA".to_string(), "__data".to_string()),
                ".rodata" => ("__TEXT".to_string(), "__const".to_string()),
                "_RDATA" => ("__TEXT".to_string(), "__const".to_string()),
                _ => (sec.name.clone(), sec.name.clone()),
            };

            sections.push(Section {
                seg,
                name,
                addr: pe.image_base + sec.virtual_address as u64,
                size: sec.virtual_size.max(sec.raw_data_size) as u64,
                offset: sec.raw_data_offset as u64,
            });
        }
    }

    Ok(Slice {
        data: pe.data,
        sections,
    })
}
