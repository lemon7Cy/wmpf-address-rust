use crate::macho::{self, Slice, Xref};

/// Find LEA reg, [rip+disp32] instructions that reference a target VM address.
/// Returns the VM address of each matching LEA instruction.
pub(crate) fn find_lea_rip_refs(slice: &Slice<'_>, target: u64) -> Vec<u64> {
    let text = match macho::section(slice, "__TEXT", "__text") {
        Some(s) => s,
        None => return Vec::new(),
    };
    let buf = match macho::section_bytes(slice, text) {
        Some(b) => b,
        None => return Vec::new(),
    };
    let base = text.addr;
    let mut refs = Vec::new();

    let mut i = 0;
    while i + 7 <= buf.len() {
        let b0 = buf[i];
        // Check for REX.W prefix (0x48) or REX.WB (0x4C)
        if b0 == 0x48 || b0 == 0x4C {
            if i + 7 <= buf.len() && buf[i + 1] == 0x8D {
                let modrm = buf[i + 2];
                // mod=00, r/m=101 => RIP-relative
                if (modrm & 0xC7) == 0x05 {
                    let disp = i32::from_le_bytes(
                        buf[i + 3..i + 7].try_into().unwrap(),
                    );
                    let rip_after = base + (i as u64) + 7;
                    let actual = rip_after.wrapping_add(disp as u64);
                    if actual == target {
                        refs.push(base + i as u64);
                    }
                }
            }
        }
        i += 1;
    }
    refs
}

/// Find all xrefs to a target address in the text section.
/// Searches for both LEA rip-relative and MOV rip-relative patterns.
pub(crate) fn find_text_xrefs(slice: &Slice<'_>, target: u64) -> Result<Vec<Xref>, String> {
    let mut refs = find_lea_rip_refs(slice, target);
    refs.sort_unstable();
    refs.dedup();
    Ok(refs.into_iter().map(|at| Xref { at }).collect())
}

/// Detect x86_64 function prologues.
/// Common patterns:
///   push rbp; mov rbp, rsp   = 55 48 89 E5
///   push rbp; sub rsp, N     = 55 48 83 EC xx  or  55 48 81 EC xx xx xx xx
///   endbr64; push rbp        = F3 0F 1E FA 55
///   sub rsp, N (leaf func)   = 48 83 EC xx  or  48 81 EC xx xx xx xx
pub(crate) fn is_probable_prologue(buf: &[u8], pos: usize) -> bool {
    if pos + 4 > buf.len() {
        return false;
    }
    let b = buf[pos];

    // push rbp; mov rbp, rsp
    if b == 0x55 && pos + 4 <= buf.len() {
        if buf[pos + 1] == 0x48 && buf[pos + 2] == 0x89 && buf[pos + 3] == 0xE5 {
            return true;
        }
    }

    // endbr64; push rbp
    if b == 0xF3 && pos + 5 <= buf.len() {
        if buf[pos + 1] == 0x0F
            && buf[pos + 2] == 0x1E
            && buf[pos + 3] == 0xFA
            && buf[pos + 4] == 0x55
        {
            return true;
        }
    }

    // push rbp; sub rsp, imm8
    if b == 0x55 && pos + 4 <= buf.len() {
        if buf[pos + 1] == 0x48
            && buf[pos + 2] == 0x83
            && buf[pos + 3] == 0xEC
        {
            return true;
        }
    }

    // push rbp; sub rsp, imm32
    if b == 0x55 && pos + 7 <= buf.len() {
        if buf[pos + 1] == 0x48
            && buf[pos + 2] == 0x81
            && buf[pos + 3] == 0xEC
        {
            return true;
        }
    }

    // sub rsp, imm8 (leaf function, no frame pointer)
    if b == 0x48 && pos + 4 <= buf.len() {
        if buf[pos + 1] == 0x83 && buf[pos + 2] == 0xEC && buf[pos + 3] != 0 {
            return true;
        }
    }

    // sub rsp, imm32 (leaf function)
    if b == 0x48 && pos + 7 <= buf.len() {
        if buf[pos + 1] == 0x81 && buf[pos + 2] == 0xEC {
            let imm = u32::from_le_bytes(buf[pos + 3..pos + 7].try_into().unwrap_or([0; 4]));
            if imm > 0 && imm < 0x10000 {
                return true;
            }
        }
    }

    false
}

/// Estimate x86_64 instruction length at `pos`.
/// This is a simplified decoder - handles the common patterns we need.
pub(crate) fn x64_insn_len(buf: &[u8], pos: usize) -> usize {
    if pos >= buf.len() {
        return 1;
    }
    let mut p = pos;
    let b = buf[p];
    p += 1;

    // REX prefix
    let has_rex = (0x40..=0x4F).contains(&b);
    let opcode = if has_rex {
        if p >= buf.len() {
            return 2;
        }
        let op = buf[p];
        p += 1;
        op
    } else {
        b
    };

    // prefix_len: REX(1) + opcode(1) = 2 if REX, else opcode(1) = 1
    let prefix_len = p; // p has been incremented past REX (if any) and opcode

    match opcode {
        // CALL rel32
        0xE8 => 5,
        // JMP rel32
        0xE9 => 5,
        // Jcc rel32 (0F 8x)
        0x0F => {
            if p < buf.len() {
                let sub = buf[p];
                if (0x80..=0x8F).contains(&sub) {
                    return 6;
                }
            }
            2 // fallback
        }
        // Jcc rel8
        0x70..=0x7F => 2,
        // RET
        0xC3 => 1,
        // RET imm16
        0xC2 => 3,
        // PUSH reg
        0x50..=0x57 => 1,
        // POP reg
        0x58..=0x5F => 1,
        // NOP
        0x90 => 1,
        // INT3
        0xCC => 1,
        // LEA, MOV, etc with ModR/M
        0x8D | 0x89 | 0x8B | 0x88 | 0x8A | 0x3B | 0x39 | 0x29 | 0x01 | 0x2B | 0x03 => {
            prefix_len + modrm_len(buf, p)
        }
        // MOV r/m, imm32
        0xC7 => prefix_len + modrm_len_with_imm32(buf, p),
        // MOV r, imm64 (with REX.W)
        0xB8..=0xBF => {
            if has_rex {
                10 // REX + opcode + imm64
            } else {
                5 // opcode + imm32
            }
        }
        // ADD/SUB/CMP with AL, imm8
        0x04 | 0x2C | 0x3C => 2,
        // ADD/SUB/CMP with EAX, imm32
        0x05 | 0x2D | 0x3D => 5,
        // TEST
        0x85 | 0xF7 => prefix_len + modrm_len(buf, p),
        // INC/DEC (with REX or 0xFF)
        0xFF => prefix_len + modrm_len(buf, p),
        // XOR
        0x31 | 0x33 => prefix_len + modrm_len(buf, p),
        // SYSCALL (0F 05) - handled by 0x0F case above
        _ => 1, // fallback: assume 1 byte
    }
}

/// Calculate instruction length from ModR/M byte at `buf[pos]`.
/// Returns the number of bytes from the ModR/M byte onward (ModR/M + SIB + disp).
fn modrm_len(buf: &[u8], pos: usize) -> usize {
    if pos >= buf.len() {
        return 1;
    }
    let modrm = buf[pos];
    let mod_bits = (modrm >> 6) & 3;
    let rm = modrm & 7;
    let mut len = 1; // ModR/M byte

    if mod_bits == 0 && rm == 5 {
        // RIP-relative: + disp32
        len += 4;
    } else if mod_bits == 1 {
        // disp8
        len += 1;
    } else if mod_bits == 2 {
        // disp32
        len += 4;
    }

    if mod_bits != 3 && rm == 4 {
        // SIB byte present
        len += 1;
    }

    len
}

/// Calculate instruction length from ModR/M byte at `buf[pos]`, plus imm32.
fn modrm_len_with_imm32(buf: &[u8], pos: usize) -> usize {
    modrm_len(buf, pos) + 4 // imm32
}

/// Find the function start by scanning backwards for a prologue.
pub(crate) fn function_start(slice: &Slice<'_>, near: u64) -> Result<u64, String> {
    let text = macho::section(slice, "__TEXT", "__text")
        .ok_or("__TEXT,__text not found")?;
    let buf = macho::section_bytes(slice, text)
        .ok_or("__TEXT,__text section data outside file bounds")?;
    let base = text.addr;
    let end = base + text.size;

    if near < base || near >= end {
        return Err(format!("address 0x{near:x} outside __text section"));
    }

    let near_off = (near - base) as usize;
    let scan_start = near_off.saturating_sub(0x5000);
    let scan_end = near_off.min(buf.len());

    // Scan backwards for a prologue
    let mut pos = scan_end;
    while pos > scan_start {
        pos -= 1;
        if is_probable_prologue(buf, pos) {
            return Ok(base + pos as u64);
        }
    }

    Err(format!("function prologue not found near 0x{near:x}"))
}

/// Find the function end by scanning forwards for the next prologue or RET sled.
pub(crate) fn function_end(slice: &Slice<'_>, start: u64) -> Result<u64, String> {
    let text = macho::section(slice, "__TEXT", "__text")
        .ok_or("__TEXT,__text not found")?;
    let buf = macho::section_bytes(slice, text)
        .ok_or("__TEXT,__text section data outside file bounds")?;
    let base = text.addr;
    let end = base + text.size;

    let start_off = (start - base) as usize;
    let scan_end = (start_off + 0x8000).min(buf.len());

    // Scan forwards for next prologue after start
    let mut pos = start_off + 1;
    while pos < scan_end {
        if is_probable_prologue(buf, pos) {
            return Ok(base + pos as u64);
        }
        pos += 1;
    }

    Ok(end)
}

/// Find function bounds (start, end) near a given address.
pub(crate) fn function_bounds(slice: &Slice<'_>, near: u64) -> Result<(u64, u64), String> {
    let start = function_start(slice, near)?;
    let end = function_end(slice, start)?;
    Ok((start, end))
}

/// Find the first CALL rel32 instruction in a range.
/// Returns (call_addr, call_target).
pub(crate) fn first_call_in(slice: &Slice<'_>, start: u64, end: u64) -> Option<(u64, u64)> {
    let text = macho::section(slice, "__TEXT", "__text")?;
    let buf = macho::section_bytes(slice, text)?;
    let base = text.addr;

    let start_off = (start.saturating_sub(base)) as usize;
    let end_off = ((end - base) as usize).min(buf.len());

    let mut pos = start_off;
    while pos + 5 <= end_off {
        if buf[pos] == 0xE8 {
            let disp = i32::from_le_bytes(
                buf[pos + 1..pos + 5].try_into().ok()?,
            );
            let rip_after = base + pos as u64 + 5;
            let target = rip_after.wrapping_add(disp as u64);
            return Some((base + pos as u64, target));
        }
        pos += 1;
    }
    None
}

/// String → xref → function bounds pipeline (x86_64 version).
pub(crate) fn function_start_from_xref(
    slice: &Slice<'_>,
    string: &str,
) -> Result<(u64, u64, u64), String> {
    let addrs = macho::find_string(slice, string);
    if addrs.is_empty() {
        return Err(format!("string not found in binary: \"{string}\""));
    }
    let mut failures = Vec::new();
    for str_addr in addrs {
        let xrefs = find_text_xrefs(slice, str_addr)?;
        if let Some(xref) = xrefs.first() {
            let (start, end) = function_bounds(slice, xref.at)?;
            return Ok((start, end, xref.at));
        }
        failures.push(format!("0x{str_addr:x} (no xrefs)"));
    }
    Err(format!(
        "xref not found for string: \"{string}\"; string at: {}",
        failures.join(", ")
    ))
}

/// Find the scene init config function in x86_64.
/// Pattern: MOV [reg+0x1C0], 1; MOV [reg+0x1C8], 1000
/// Returns (function_start, pattern_addr).
pub(crate) fn find_init_config_function(slice: &Slice<'_>) -> Result<(u64, u64), String> {
    let text = macho::section(slice, "__TEXT", "__text")
        .ok_or("__TEXT,__text not found")?;
    let buf = macho::section_bytes(slice, text)
        .ok_or("__TEXT,__text section data outside file bounds")?;
    let base = text.addr;

    // Search for: C7 8X C8 01 00 00 E8 03 00 00
    // MOV dword [reg+0x1C8], 1000
    let imm_1000: [u8; 4] = 1000u32.to_le_bytes(); // E8 03 00 00
    let mut pos = 0;
    while pos + 10 <= buf.len() {
        if buf[pos] == 0xC7 {
            let modrm = buf[pos + 1];
            if (modrm >> 6) == 2 && (modrm & 7) != 4 {
                // mod=10 (disp32), not SIB
                if buf[pos + 2..pos + 6] == [0xC8, 0x01, 0x00, 0x00] {
                    if buf[pos + 6..pos + 10] == imm_1000 {
                        let reg = modrm & 7;
                        // Check for MOV [same_reg+0x1C0], 1 before this
                        let search_start = pos.saturating_sub(30);
                        for back in search_start..pos {
                            if buf[back] == 0xC7 {
                                let modrm2 = buf[back + 1];
                                if (modrm2 >> 6) == 2 && (modrm2 & 7) == reg {
                                    if buf[back + 2..back + 6] == [0xC0, 0x01, 0x00, 0x00] {
                                        let imm2 = u32::from_le_bytes(
                                            buf[back + 6..back + 10].try_into().unwrap_or([0; 4]),
                                        );
                                        if imm2 == 1 {
                                            let site = base + pos as u64;
                                            let fn_start = function_start(slice, site)?;
                                            return Ok((fn_start, site));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        pos += 1;
    }
    Err("scene init pattern not found (MOV [reg+0x1C0],1; MOV [reg+0x1C8],1000)".to_string())
}

/// Extract version string from __cstring section (same logic as arm64).
pub(crate) fn extract_version(slice: &Slice<'_>) -> Option<String> {
    let cstring = macho::section(slice, "__TEXT", "__cstring")?;
    let buf = macho::section_bytes(slice, cstring)?;
    let hay = String::from_utf8_lossy(buf);
    for part in hay.split('\0') {
        if let Some(ver) = find_version_pattern(part) {
            return Some(ver);
        }
    }
    None
}

fn find_version_pattern(s: &str) -> Option<String> {
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

/// Find scene hook candidates in x86_64.
/// Looks for callers of the init function, then searches for
/// instructions that set up a pointer argument before a CALL.
pub(crate) fn find_launch_scene_hook_candidates(
    slice: &Slice<'_>,
    init_fn: u64,
    verbose: bool,
) -> Result<Vec<crate::config::SceneHookCandidate>, String> {
    let text = macho::section(slice, "__TEXT", "__text")
        .ok_or("__TEXT,__text not found")?;
    let buf = macho::section_bytes(slice, text)
        .ok_or("__TEXT,__text section data outside file bounds")?;
    let base = text.addr;

    // Find all CALL instructions that target init_fn
    let mut callers = Vec::new();
    let mut pos = 0;
    while pos + 5 <= buf.len() {
        if buf[pos] == 0xE8 {
            let disp = i32::from_le_bytes(
                buf[pos + 1..pos + 5].try_into().unwrap_or([0; 4]),
            );
            let rip_after = base + pos as u64 + 5;
            let target = rip_after.wrapping_add(disp as u64);
            if target == init_fn {
                callers.push(base + pos as u64);
            }
        }
        pos += 1;
    }

    if verbose {
        eprintln!(
            "debug: init_fn=0x{init_fn:x}, callers={}",
            callers
                .iter()
                .map(|x| format!("0x{x:x}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let mut candidates = Vec::new();
    for call in callers {
        let Ok((fn_start, fn_end)) = function_bounds(slice, call) else {
            continue;
        };
        if verbose {
            eprintln!("debug: caller 0x{call:x} bounds 0x{fn_start:x}..0x{fn_end:x}");
        }

        // Look backwards from the CALL for LEA reg, [rip+...] instructions
        // that load a pointer argument (this is the "scene config" pointer)
        let call_off = (call - base) as usize;
        let fn_start_off = (fn_start - base) as usize;
        let scan_start = fn_start_off.max(call_off.saturating_sub(200));

        let mut arg_lea = None;
        let mut scan_pos = call_off;
        while scan_pos > scan_start {
            scan_pos -= 1;
            if scan_pos + 7 <= buf.len() && buf[scan_pos] == 0x48 && buf[scan_pos + 1] == 0x8D {
                let modrm = buf[scan_pos + 2];
                if (modrm & 0xC7) == 0x05 {
                    // LEA reg, [rip+disp32] — potential argument setup
                    let reg = (modrm >> 3) & 7;
                    // Look for LEA rdi or LEA rsi (first two args in x86_64 calling convention)
                    if reg == 7 || reg == 6 {
                        // rdi=7, rsi=6
                        let insn_addr = base + scan_pos as u64;
                        arg_lea = Some((insn_addr, reg));
                        break;
                    }
                }
            }
        }

        if let Some((lea_addr, reg)) = arg_lea {
            let reg_names = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
            let arg_name = reg_names.get(reg as usize).unwrap_or(&"?");
            let arg_idx = if reg == 7 { 1 } else { 2 }; // rdi=arg1, rsi=arg2

            candidates.push(crate::config::SceneHookCandidate {
                hook: call,
                arg: arg_idx,
                strategy: if arg_idx == 2 {
                    "launch-applet-x2-config"
                } else {
                    "preload-runtime-x3-config"
                },
                notes: vec![format!(
                    "init 0x{init_fn:x} called at 0x{call:x}; LEA {arg_name} at 0x{lea_addr:x}"
                )],
            });
        }
    }

    candidates.sort_by_key(|c| (c.arg != 2, c.hook));
    candidates.dedup_by_key(|c| (c.hook, c.arg));
    if candidates.is_empty() {
        return Err("LaunchApplet scene hook not found in x86_64".to_string());
    }
    Ok(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macho::Section;

    #[test]
    fn test_is_prologue_push_rbp_mov() {
        // push rbp; mov rbp, rsp
        let buf = [0x55, 0x48, 0x89, 0xE5];
        assert!(is_probable_prologue(&buf, 0));
    }

    #[test]
    fn test_is_prologue_endbr64() {
        // endbr64; push rbp
        let buf = [0xF3, 0x0F, 0x1E, 0xFA, 0x55];
        assert!(is_probable_prologue(&buf, 0));
    }

    #[test]
    fn test_is_prologue_sub_rsp() {
        // sub rsp, 0x20
        let buf = [0x48, 0x83, 0xEC, 0x20];
        assert!(is_probable_prologue(&buf, 0));
    }

    #[test]
    fn test_is_prologue_nop() {
        let buf = [0x90, 0x90, 0x90, 0x90];
        assert!(!is_probable_prologue(&buf, 0));
    }

    #[test]
    fn test_is_prologue_ret() {
        let buf = [0xC3];
        assert!(!is_probable_prologue(&buf, 0));
    }

    #[test]
    fn test_insn_len_call() {
        // E8 xx xx xx xx
        let buf = [0xE8, 0x10, 0x00, 0x00, 0x00];
        assert_eq!(x64_insn_len(&buf, 0), 5);
    }

    #[test]
    fn test_insn_len_push() {
        let buf = [0x55];
        assert_eq!(x64_insn_len(&buf, 0), 1);
    }

    #[test]
    fn test_insn_len_lea_rip() {
        // 48 8D 05 xx xx xx xx
        let buf = [0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00];
        assert_eq!(x64_insn_len(&buf, 0), 7);
    }

    #[test]
    fn test_insn_len_ret() {
        let buf = [0xC3];
        assert_eq!(x64_insn_len(&buf, 0), 1);
    }

    #[test]
    fn test_insn_len_mov_reg_imm64() {
        // 48 B8 xx xx xx xx xx xx xx xx
        let buf = [0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(x64_insn_len(&buf, 0), 10);
    }

    #[test]
    fn test_find_version_pattern_standard() {
        assert_eq!(find_version_pattern("2.4.2.19778"), Some("19778".to_string()));
    }

    #[test]
    fn test_find_version_pattern_no_match() {
        assert_eq!(find_version_pattern("no version"), None);
    }

    #[test]
    fn test_find_lea_rip_refs_basic() {
        // Build a minimal code section with a LEA rip-relative instruction
        // LEA rsi, [rip+0x10] targeting address 0x1017 (base=0x1000, insn at 0x1006, 7 bytes, disp=0x10)
        let mut data = vec![0u8; 256];
        // At offset 6: 48 8D 35 10 00 00 00 (LEA rsi, [rip+0x10])
        data[6] = 0x48;
        data[7] = 0x8D;
        data[8] = 0x35; // rsi, RIP-relative
        // disp32 = target - (insn_addr + 7) = 0x1017 - (0x1006 + 7) = 0x1017 - 0x100D = 0xA
        let disp: i32 = 0x1017 - (0x1000 + 6 + 7);
        data[9..13].copy_from_slice(&disp.to_le_bytes());

        let slice = Slice {
            data: &data,
            sections: vec![Section {
                seg: "__TEXT".to_string(),
                name: "__text".to_string(),
                addr: 0x1000,
                size: 256,
                offset: 0,
            }],
        };
        let refs = find_lea_rip_refs(&slice, 0x1017);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], 0x1006);
    }
}
