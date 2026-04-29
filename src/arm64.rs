use crate::macho::{self, Slice, Xref};

pub(crate) fn sign_extend(value: i64, bits: u32) -> i64 {
    let shift = 64 - bits;
    (value << shift) >> shift
}

pub(crate) fn decode_adrp(insn: u32, pc: u64) -> Option<(u8, u64)> {
    if (insn & 0x9F00_0000) != 0x9000_0000 {
        return None;
    }
    let rd = (insn & 0x1f) as u8;
    let immlo = ((insn >> 29) & 0x3) as i64;
    let immhi = ((insn >> 5) & 0x7ffff) as i64;
    let imm = sign_extend((immhi << 2) | immlo, 21) << 12;
    let page = (pc as i64) & !0xfff;
    Some((rd, (page + imm) as u64))
}

pub(crate) fn decode_add_imm(insn: u32) -> Option<(u8, u8, u64)> {
    if (insn & 0x7F00_0000) != 0x1100_0000 {
        return None;
    }
    let rd = (insn & 0x1f) as u8;
    let rn = ((insn >> 5) & 0x1f) as u8;
    let imm12 = ((insn >> 10) & 0xfff) as u64;
    let shift = ((insn >> 22) & 0x3) as u64;
    if shift > 1 {
        return None;
    }
    Some((rd, rn, imm12 << (shift * 12)))
}

pub(crate) fn decode_ldr_literal(insn: u32, pc: u64) -> Option<(u8, u64)> {
    if (insn & 0x3B00_0000) != 0x1800_0000 {
        return None;
    }
    let rt = (insn & 0x1f) as u8;
    let imm19 = ((insn >> 5) & 0x7ffff) as i64;
    let imm = sign_extend(imm19, 19) << 2;
    Some((rt, (pc as i64 + imm) as u64))
}

pub(crate) fn decode_bl(insn: u32, pc: u64) -> Option<u64> {
    if (insn & 0xFC00_0000) != 0x9400_0000 {
        return None;
    }
    let imm26 = (insn & 0x03ff_ffff) as i64;
    let imm = sign_extend(imm26, 26) << 2;
    Some((pc as i64 + imm) as u64)
}

pub(crate) fn decode_mov_sp(insn: u32) -> Option<(u8, u8)> {
    if (insn & 0x7F00_0000) == 0x1100_0000 {
        let rd = (insn & 0x1f) as u8;
        let rn = ((insn >> 5) & 0x1f) as u8;
        let imm = (insn >> 10) & 0xfff;
        let shift = (insn >> 22) & 0x3;
        if imm == 0 && shift == 0 {
            return Some((rd, rn));
        }
    }
    None
}

pub(crate) fn decode_str_w_imm(insn: u32) -> Option<(u8, u8, u32)> {
    if (insn & 0xFFC0_0000) != 0xB900_0000 {
        return None;
    }
    let rt = (insn & 0x1f) as u8;
    let rn = ((insn >> 5) & 0x1f) as u8;
    let imm = ((insn >> 10) & 0xfff) * 4;
    Some((rt, rn, imm))
}

pub(crate) fn decode_mov_w_imm(insn: u32) -> Option<(u8, u32)> {
    if (insn & 0x7F80_0000) != 0x5280_0000 {
        return None;
    }
    let rd = (insn & 0x1f) as u8;
    let imm16 = (insn >> 5) & 0xffff;
    Some((rd, imm16))
}

pub(crate) fn scan_text_words(slice: &Slice<'_>) -> Result<Vec<(u64, u32)>, String> {
    let text = macho::section(slice, "__TEXT", "__text")
        .ok_or("__TEXT,__text not found in binary")?;
    let buf = macho::section_bytes(slice, text)
        .ok_or("__TEXT,__text section data outside file bounds")?;
    let mut out = Vec::with_capacity(buf.len() / 4);
    for (idx, chunk) in buf.chunks_exact(4).enumerate() {
        let insn = u32::from_le_bytes(chunk.try_into().unwrap());
        out.push((text.addr + (idx as u64 * 4), insn));
    }
    Ok(out)
}

pub(crate) fn find_text_xrefs(slice: &Slice<'_>, target: u64) -> Result<Vec<Xref>, String> {
    let words = scan_text_words(slice)?;
    let mut xrefs = Vec::new();
    for i in 0..words.len() {
        let (pc, insn) = words[i];
        if let Some((reg, base)) = decode_adrp(insn, pc) {
            for &(pc2, insn2) in words.iter().take((i + 8).min(words.len())).skip(i + 1) {
                if let Some((rd, rn, imm)) = decode_add_imm(insn2) {
                    if rn == reg && rd == reg && base + imm == target {
                        xrefs.push(Xref { at: pc2 });
                    }
                }
            }
        }
        if let Some((_rt, lit_addr)) = decode_ldr_literal(insn, pc) {
            if lit_addr == target {
                xrefs.push(Xref { at: pc });
            }
        }
    }
    xrefs.sort_by_key(|x| x.at);
    xrefs.dedup_by_key(|x| x.at);
    Ok(xrefs)
}

pub(crate) fn function_bounds(slice: &Slice<'_>, near: u64) -> Result<(u64, u64), String> {
    let text = macho::section(slice, "__TEXT", "__text")
        .ok_or("__TEXT,__text not found for function bounds")?;
    let start_min = text.addr;
    let end_max = text.addr + text.size;
    let start_scan = near.saturating_sub(0x3000).max(start_min);
    let end_scan = (near + 0x4000).min(end_max);
    let mut starts = Vec::new();
    let mut addr = start_scan & !3;
    while addr + 4 <= end_scan {
        let Some(file_off) = macho::vm_to_file_off(slice, addr) else {
            addr += 4;
            continue;
        };
        let insn = macho::read_u32_le(slice.data, file_off as usize).unwrap_or(0);
        if is_probable_prologue(insn) {
            starts.push(normalize_prologue(slice, addr, insn));
        }
        addr += 4;
    }
    let start = starts
        .into_iter()
        .filter(|s| *s <= near)
        .max()
        .ok_or_else(|| format!(
            "function start not found near 0x{near:x} (scanned 0x{start_scan:x}..0x{end_scan:x})"
        ))?;
    let mut end = end_max;
    addr = start + 4;
    while addr + 4 <= end_scan {
        if addr > near {
            let Some(file_off) = macho::vm_to_file_off(slice, addr) else {
                addr += 4;
                continue;
            };
            let insn = macho::read_u32_le(slice.data, file_off as usize).unwrap_or(0);
            if is_probable_prologue(insn) {
                end = addr;
                break;
            }
        }
        addr += 4;
    }
    Ok((start, end))
}

pub(crate) fn is_probable_prologue(insn: u32) -> bool {
    is_stp_preindex_sp(insn) || is_sub_sp_imm(insn)
}

pub(crate) fn is_stp_preindex_sp(insn: u32) -> bool {
    // stp x?, x?, [sp,#-imm]!
    (insn & 0xFFC0_0000) == 0xA980_0000 && ((insn >> 5) & 0x1f) == 31
}

pub(crate) fn is_sub_sp_imm(insn: u32) -> bool {
    (insn & 0x7F00_0000) == 0x5100_0000 && ((insn >> 5) & 0x1f) == 31 && (insn & 0x1f) == 31
}

fn normalize_prologue(slice: &Slice<'_>, addr: u64, insn: u32) -> u64 {
    if !is_sub_sp_imm(insn) {
        return addr;
    }
    let mut cur = addr.saturating_sub(4);
    let min = addr.saturating_sub(0x30);
    while cur >= min {
        if let Some(file_off) = macho::vm_to_file_off(slice, cur) {
            if let Some(prev) = macho::read_u32_le(slice.data, file_off as usize) {
                if is_stp_preindex_sp(prev) {
                    return cur;
                }
            }
        }
        if cur < 4 {
            break;
        }
        cur -= 4;
    }
    addr
}

pub(crate) fn instructions_in(slice: &Slice<'_>, start: u64, end: u64) -> Vec<(u64, u32)> {
    let mut out = Vec::new();
    let mut addr = start & !3;
    while addr + 4 <= end {
        if let Some(file_off) = macho::vm_to_file_off(slice, addr) {
            if let Some(insn) = macho::read_u32_le(slice.data, file_off as usize) {
                out.push((addr, insn));
            }
        }
        addr += 4;
    }
    out
}

pub(crate) fn first_bl_in(slice: &Slice<'_>, start: u64, end: u64) -> Option<(u64, u64)> {
    instructions_in(slice, start, end)
        .into_iter()
        .find_map(|(pc, insn)| decode_bl(insn, pc).map(|target| (pc, target)))
}

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

pub(crate) fn find_init_config_function(slice: &Slice<'_>) -> Result<(u64, u64), String> {
    let text = scan_text_words(slice)?;
    for win in text.windows(5) {
        let (pc0, i0) = win[0];
        let (_, i1) = win[1];
        let (_, i2) = win[2];
        let (_, i3) = win[3];
        let Some((w8, one)) = decode_mov_w_imm(i0) else {
            continue;
        };
        let Some((rt8, rn8, off1)) = decode_str_w_imm(i1) else {
            continue;
        };
        let Some((w9, scene)) = decode_mov_w_imm(i2) else {
            continue;
        };
        let Some((rt9, rn9, off2)) = decode_str_w_imm(i3) else {
            continue;
        };
        if one == 1
            && scene == 1000
            && w8 == rt8
            && w9 == rt9
            && rn8 == rn9
            && off1 == 0x1c0
            && off2 == 0x1c8
        {
            let start = pc0.saturating_sub(0x40);
            return Ok((start, pc0));
        }
    }
    Err("scene init pattern not found (MOV W8,#1; STR +0x1C0; MOV W9,#1000; STR +0x1C8)".to_string())
}

pub(crate) fn find_launch_scene_hook_candidates(
    slice: &Slice<'_>,
    init_fn: u64,
    verbose: bool,
) -> Result<Vec<crate::config::SceneHookCandidate>, String> {
    let words = scan_text_words(slice)?;
    let callers: Vec<u64> = words
        .iter()
        .filter_map(|(pc, insn)| decode_bl(*insn, *pc).filter(|t| *t == init_fn).map(|_| *pc))
        .collect();
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
        let Ok((start, end)) = function_bounds(slice, call) else {
            continue;
        };
        if verbose {
            eprintln!("debug: caller 0x{call:x} bounds 0x{start:x}..0x{end:x}");
        }
        let instrs = instructions_in(slice, start, end);
        let Some(pos) = instrs.iter().position(|(pc, _)| *pc == call) else {
            continue;
        };
        let window_end = (pos + 180).min(instrs.len());
        for idx in pos..window_end {
            let (pc, insn) = instrs[idx];
            let mov_x2_sp = decode_mov_sp(insn) == Some((2, 31));
            let mov_x3_sp = decode_mov_sp(insn) == Some((3, 31));
            if !mov_x2_sp && !mov_x3_sp {
                continue;
            }
            for &(pc2, insn2) in instrs
                .iter()
                .take((idx + 8).min(instrs.len()))
                .skip(idx + 1)
            {
                if decode_bl(insn2, pc2).is_some() {
                    let arg = if mov_x2_sp { 2 } else { 3 };
                    let strategy = if arg == 2 {
                        "launch-applet-x2-config"
                    } else {
                        "preload-runtime-x3-config"
                    };
                    candidates.push(crate::config::SceneHookCandidate {
                        hook: pc2,
                        arg,
                        strategy,
                        notes: vec![format!(
                            "init 0x{init_fn:x} called at 0x{call:x}; MOV X{arg}, SP at 0x{pc:x}; BL at 0x{pc2:x}"
                        )],
                    }
                    );
                }
            }
        }
    }

    candidates.sort_by_key(|c| (c.arg != 2, c.hook));
    candidates.dedup_by_key(|c| (c.hook, c.arg));
    if candidates.is_empty() {
        return Err("LaunchApplet scene hook not found".to_string());
    }
    Ok(candidates)
}

/// Extract version string from __cstring section.
/// Tries multiple patterns to find a version like "X.Y.Z.NNNNN".
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

/// Look for a version pattern in a string.
/// Matches patterns like:
///   - "2.4.2.19778" -> "19778"
///   - "WeChatAppEx/2.4.2.19778" -> "19778"
///   - "3.8.10.20001" -> "20001"
///   - Any "...X.Y.NNNNN" where NNNNN is 4-6 digits at the end of the string
fn find_version_pattern(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    // Scan for a pattern: digits.digits.digits.(4-6 digits) at the end of the string
    // We look backwards from the end to find the longest valid match
    for end in (4..=len).rev() {
        // Must end with 4-6 digits that extend to the end of the string
        let digit_end = end;
        let mut digit_start = end;
        while digit_start > 0 && bytes[digit_start - 1].is_ascii_digit() {
            digit_start -= 1;
        }
        let digit_len = digit_end - digit_start;
        if !(4..=6).contains(&digit_len) {
            continue;
        }
        // The matched digits must actually be the end of the string
        // (prevents matching "123456" inside "1234567")
        if digit_end < len {
            continue;
        }
        // Must be preceded by a dot
        if digit_start == 0 || bytes[digit_start - 1] != b'.' {
            continue;
        }
        // Count dot-separated groups before the build number.
        // We need at least 2 groups, and the one immediately before
        // the dot must be numeric (the rest can contain non-digit chars
        // like "WeChatAppEx/2.4.2").
        let prefix = &bytes[..digit_start - 1];
        let prefix_str = match std::str::from_utf8(prefix) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let groups: Vec<&str> = prefix_str.split('.').collect();
        if groups.len() < 2 {
            continue;
        }
        // The group immediately before the build number must be all digits
        // (this is the "Z" in "X.Y.Z.NNNNN")
        let last_group = groups.last().unwrap();
        if last_group.is_empty() || !last_group.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        // Found a valid pattern - return just the last segment (the build number)
        return Some(s[digit_start..digit_end].to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macho::Section;

    fn make_slice_with_text(data: &[u8], text_addr: u64) -> Slice<'_> {
        Slice {
            data,
            sections: vec![Section {
                seg: "__TEXT".to_string(),
                name: "__text".to_string(),
                addr: text_addr,
                size: data.len() as u64,
                offset: 0,
            }],
        }
    }

    #[test]
    fn test_sign_extend_positive() {
        // 0b111 in 3-bit two's complement = -1 (bit 2 is set)
        assert_eq!(sign_extend(0b111, 3), -1);
    }

    #[test]
    fn test_sign_extend_negative() {
        // 0b100 in 3-bit two's complement = -4 (bit 2 is set)
        assert_eq!(sign_extend(0b100, 3), -4);
    }

    #[test]
    fn test_sign_extend_zero() {
        assert_eq!(sign_extend(0, 3), 0);
    }

    #[test]
    fn test_sign_extend_21bit() {
        // 21-bit max positive
        assert_eq!(sign_extend(0x0FFFFF, 21), 0x0FFFFF);
        // 21-bit max negative
        assert_eq!(sign_extend(0x100000, 21), -0x100000);
    }

    // ADRP: X0 = PC page + offset
    // Encoding: sf=1(31) immlo(30-29) 10000(28-24) immhi(23-5) rd(4-0)
    // immhi=0, immlo=0 => offset=0 => target = PC page
    #[test]
    fn test_decode_adrp_zero_offset() {
        // ADRP X0, #0 at PC=0x1000
        let (rd, target) = decode_adrp(0x90000000, 0x1000).unwrap();
        assert_eq!(rd, 0);
        assert_eq!(target, 0x1000);
    }

    #[test]
    fn test_decode_adrp_positive_offset() {
        // ADRP X1, +2 pages at PC=0x1000 => target = 0x1000 + 0x2000 = 0x3000
        // rd=1, immhi=0, immlo=2 => 0xD0000001
        let (rd, target) = decode_adrp(0xD0000001, 0x1000).unwrap();
        assert_eq!(rd, 1);
        assert_eq!(target, 0x3000);
    }

    #[test]
    fn test_decode_adrp_negative_offset() {
        // ADRP X0, -1 page at PC=0x2000 => target = 0x2000 - 0x1000 = 0x1000
        // rd=0, immhi=0x7FFFF, immlo=3 => 0xF0FFFFE0
        let (rd, target) = decode_adrp(0xF0FFFFE0, 0x2000).unwrap();
        assert_eq!(rd, 0);
        assert_eq!(target, 0x1000);
    }

    #[test]
    fn test_decode_adrp_not_adrp() {
        // ADD X0, X0, #0 => not ADRP
        assert!(decode_adrp(0x91000000, 0x1000).is_none());
    }

    #[test]
    fn test_decode_add_imm_no_shift() {
        // ADD X0, X0, #4: rd=0, rn=0, imm12=1, sh=0 => 0x91000400
        // Decoder returns raw imm12=1 (the actual immediate is imm12<<shift = 1)
        let (rd, rn, imm) = decode_add_imm(0x91000400).unwrap();
        assert_eq!(rd, 0);
        assert_eq!(rn, 0);
        assert_eq!(imm, 1);
    }

    #[test]
    fn test_decode_add_imm_with_shift() {
        // ADD X1, X2, #0x1000 LSL#12: rd=1, rn=2, imm12=1, sh=1 => 0x91400441
        // Decoder returns 1 << 12 = 0x1000
        let (rd, rn, imm) = decode_add_imm(0x91400441).unwrap();
        assert_eq!(rd, 1);
        assert_eq!(rn, 2);
        assert_eq!(imm, 0x1000);
    }

    #[test]
    fn test_decode_add_imm_shift_2_invalid() {
        // shift=2 is invalid for ADD imm => 0x91800400
        assert!(decode_add_imm(0x91800400).is_none());
    }

    #[test]
    fn test_decode_add_imm_not_add() {
        // ADRP
        assert!(decode_add_imm(0x90000000).is_none());
    }

    #[test]
    fn test_decode_ldr_literal_basic() {
        // LDR X0, [PC, #8] at PC=0x1000: imm19=2, rt=0 => 0x58000040
        let (rt, target) = decode_ldr_literal(0x58000040, 0x1000).unwrap();
        assert_eq!(rt, 0);
        assert_eq!(target, 0x1008);
    }

    #[test]
    fn test_decode_ldr_literal_negative() {
        // LDR X0, [PC, #-4] at PC=0x1000: imm19=0x7FFFF(-1), rt=0 => 0x58FFFFE0
        let (rt, target) = decode_ldr_literal(0x58FFFFE0, 0x1000).unwrap();
        assert_eq!(rt, 0);
        assert_eq!(target, 0x0FFC);
    }

    #[test]
    fn test_decode_ldr_literal_not_ldr() {
        assert!(decode_ldr_literal(0x90000000, 0x1000).is_none());
    }

    #[test]
    fn test_decode_bl_basic() {
        // BL #8 at PC=0x1000
        // imm26 = 2 (8/4)
        // insn = 0b100101_00000000000000000000000010 = 0x94000002
        let target = decode_bl(0x94000002, 0x1000).unwrap();
        assert_eq!(target, 0x1008);
    }

    #[test]
    fn test_decode_bl_negative() {
        // BL #-4 at PC=0x1000
        let target = decode_bl(0x97FFFFFE, 0x1000).unwrap();
        assert_eq!(target, 0x0FF8);
    }

    #[test]
    fn test_decode_bl_not_bl() {
        // B (unconditional branch) instead of BL
        assert!(decode_bl(0x14000002, 0x1000).is_none());
    }

    #[test]
    fn test_decode_mov_sp_basic() {
        // MOV X2, SP = ADD X2, X31, #0: rd=2, rn=31, imm12=0, sh=0 => 0x910003E2
        let (rd, rn) = decode_mov_sp(0x910003E2).unwrap();
        assert_eq!(rd, 2);
        assert_eq!(rn, 31);
    }

    #[test]
    fn test_decode_mov_sp_not_mov() {
        // ADD X2, X31, #1 — non-zero immediate, not MOV => 0x910007E2
        assert!(decode_mov_sp(0x910007E2).is_none());
    }

    #[test]
    fn test_decode_str_w_imm_basic() {
        // STR W0, [X1, #8]: imm=2(8/4), rn=1, rt=0 => 0xB9000820
        let (rt, rn, imm) = decode_str_w_imm(0xB9000820).unwrap();
        assert_eq!(rt, 0);
        assert_eq!(rn, 1);
        assert_eq!(imm, 8);
    }

    #[test]
    fn test_decode_str_w_imm_zero_offset() {
        // STR W5, [X10, #0]: imm=0, rn=10, rt=5 => 0xB9000145
        let (rt, rn, imm) = decode_str_w_imm(0xB9000145).unwrap();
        assert_eq!(rt, 5);
        assert_eq!(rn, 10);
        assert_eq!(imm, 0);
    }

    #[test]
    fn test_decode_str_w_imm_not_str() {
        assert!(decode_str_w_imm(0x90000000).is_none());
    }

    #[test]
    fn test_decode_mov_w_imm_basic() {
        // MOV W0, #1 = 0x52800020
        let (rd, imm) = decode_mov_w_imm(0x52800020).unwrap();
        assert_eq!(rd, 0);
        assert_eq!(imm, 1);
    }

    #[test]
    fn test_decode_mov_w_imm_1000() {
        // MOV W9, #1000 = 0x52807D09
        let (rd, imm) = decode_mov_w_imm(0x52807D09).unwrap();
        assert_eq!(rd, 9);
        assert_eq!(imm, 1000);
    }

    #[test]
    fn test_decode_mov_w_imm_not_mov() {
        assert!(decode_mov_w_imm(0x90000000).is_none());
    }

    #[test]
    fn test_is_stp_preindex_sp_true() {
        // STP X29, X30, [SP, #-0x10]!
        // 0xA9BF7BFD
        assert!(is_stp_preindex_sp(0xA9BF7BFD));
    }

    #[test]
    fn test_is_stp_preindex_sp_wrong_reg() {
        // STP X29, X30, [X0, #-0x10]! — not SP
        let insn: u32 = 0b10_101_001_1_0_1111111111_00000_11101;
        assert!(!is_stp_preindex_sp(insn));
    }

    #[test]
    fn test_is_sub_sp_imm_true() {
        // SUB SP, SP, #0x10
        // 0xD10043FF
        assert!(is_sub_sp_imm(0xD10043FF));
    }

    #[test]
    fn test_is_sub_sp_imm_wrong_reg() {
        // SUB X0, X0, #0x10 — not SP
        let insn: u32 = 0b1_00_1000_010_0_0000000001_00000_00000;
        assert!(!is_sub_sp_imm(insn));
    }

    #[test]
    fn test_is_probable_prologue_stp() {
        assert!(is_probable_prologue(0xA9BF7BFD));
    }

    #[test]
    fn test_is_probable_prologue_sub() {
        assert!(is_probable_prologue(0xD10043FF));
    }

    #[test]
    fn test_is_probable_prologue_nop() {
        assert!(!is_probable_prologue(0xD503201F)); // NOP
    }

    // Integration test: build a minimal code section and verify scan_text_words
    #[test]
    fn test_scan_text_words() {
        // 4 instructions: NOP, NOP, NOP, RET
        let mut data = vec![0u8; 16];
        data[0..4].copy_from_slice(&0xD503201Fu32.to_le_bytes()); // NOP
        data[4..8].copy_from_slice(&0xD503201Fu32.to_le_bytes()); // NOP
        data[8..12].copy_from_slice(&0xD503201Fu32.to_le_bytes()); // NOP
        data[12..16].copy_from_slice(&0xD65F03C0u32.to_le_bytes()); // RET
        let slice = make_slice_with_text(&data, 0x1000);
        let words = scan_text_words(&slice).unwrap();
        assert_eq!(words.len(), 4);
        assert_eq!(words[0], (0x1000, 0xD503201F));
        assert_eq!(words[3], (0x100C, 0xD65F03C0));
    }

    // Test find_version_pattern
    #[test]
    fn test_find_version_pattern_standard() {
        assert_eq!(find_version_pattern("2.4.2.19778"), Some("19778".to_string()));
    }

    #[test]
    fn test_find_version_pattern_longer() {
        assert_eq!(find_version_pattern("3.8.10.20001"), Some("20001".to_string()));
    }

    #[test]
    fn test_find_version_pattern_with_prefix() {
        // "19778" is at the end of the string, prefix before dot is "2.4.2" (valid)
        assert_eq!(
            find_version_pattern("WeChatAppEx/2.4.2.19778"),
            Some("19778".to_string())
        );
    }

    #[test]
    fn test_find_version_pattern_short_build() {
        // 4-digit build number
        assert_eq!(find_version_pattern("1.0.0.1234"), Some("1234".to_string()));
    }

    #[test]
    fn test_find_version_pattern_long_build() {
        // 6-digit build number
        assert_eq!(find_version_pattern("1.0.0.123456"), Some("123456".to_string()));
    }

    #[test]
    fn test_find_version_pattern_no_match() {
        assert_eq!(find_version_pattern("no version here"), None);
    }

    #[test]
    fn test_find_version_pattern_too_short_build() {
        // 3-digit build number - should not match
        assert_eq!(find_version_pattern("1.0.0.123"), None);
    }

    #[test]
    fn test_find_version_pattern_too_long_build() {
        // 7-digit build number - should not match
        assert_eq!(find_version_pattern("1.0.0.1234567"), None);
    }

    #[test]
    fn test_find_version_pattern_two_groups() {
        // Only 2 groups before build - should still match (X.Y.NNNNN)
        assert_eq!(find_version_pattern("2.4.19778"), Some("19778".to_string()));
    }

    #[test]
    fn test_find_version_pattern_single_group() {
        // Only 1 group before build - should not match
        assert_eq!(find_version_pattern("2.19778"), None);
    }
}
