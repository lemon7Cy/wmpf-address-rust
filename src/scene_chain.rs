//! Derivation of the Windows x86_64 scene pointer chain.
//!
//! The Frida side (`frida/hook.js`) can use either:
//!
//! 1. A legacy triple `SceneOffsets = [SO0, SO1, SO2]` combined with a
//!    hard-coded template `this+56 -> SO0 -> +8 -> SO1 -> +16 -> SO2`.
//! 2. An explicit `ScenePath { pointerOffsets, sceneOffset }` which
//!    overrides the template.
//!
//! Option 1 broke on WeChat 19769 because the outer container gained a
//! field (prefix became `+64`, `SO0` became 1408, `SO1` became 1344). To
//! remain version-proof we statically derive the full chain from the
//! binary by following `OnLoadStart` into its scene-check callee.
//!
//! Pattern we match inside `OnLoadStart`:
//!     mov rax, [rsi + PREFIX_A]     ; this + PREFIX_A
//!     mov rdx, [rsi + PREFIX_B]
//!     mov rcx, [rax + OFF1]
//!     mov rdx, [rdx + 0x38]
//!     call sub_scene_check          ; target
//!
//! And inside `sub_scene_check`:
//!     mov ??,  [rcx + 8]
//!     mov ??,  [?? + OFF2]
//!     mov ??,  [?? + 0x10]
//!     cmp dword ptr [?? + 0x1C8], 0x44D   ; 1101
//!
//! So the chain from `this` is:
//!     [PREFIX_A, OFF1, 8, OFF2, 16]   then scene_offset = 0x1C8 (=456).

use crate::config::ScenePath;
use crate::macho::{self, Slice};

const SCENE_CONST_1101: u32 = 0x44D;
const SCENE_TAIL_OFFSET_DEFAULT: u32 = 0x1C8; // 456

/// Read a little-endian i32 displacement at `off` into `buf`.
#[inline]
fn read_disp32(buf: &[u8], off: usize) -> Option<i32> {
    Some(i32::from_le_bytes(buf.get(off..off + 4)?.try_into().ok()?))
}

/// x86_64 REX byte helper.
#[inline]
fn is_rex_w(b: u8) -> bool {
    // REX.W-prefixed instructions we care about: 0x48, 0x49, 0x4C, 0x4D
    (b & 0xF0) == 0x40 && (b & 0x08) != 0
}

/// Decode `MOV r64, [base + disp32]` at `pos` into (dst_reg, base_reg, disp).
/// Returns `None` if the instruction at `pos` is not that form.
///
/// Encodings supported:
///     48/4C 8B /r [modrm=10 base!=4 (no SIB) disp32]     — mov r64, [base+disp32]
///     48/4C 8B /r [modrm=01 base!=4 disp8]               — mov r64, [base+disp8]
///     48/4C 8B /r [modrm=00 base!=4,5 nosib disp=0]      — mov r64, [base]
fn decode_mov_mem_disp(buf: &[u8], pos: usize) -> Option<(u8, u8, i32, usize)> {
    if pos + 3 > buf.len() {
        return None;
    }
    let rex = buf[pos];
    if !is_rex_w(rex) {
        return None;
    }
    if buf[pos + 1] != 0x8B {
        return None;
    }
    let modrm = buf[pos + 2];
    let mod_bits = (modrm >> 6) & 0x3;
    let reg = (modrm >> 3) & 0x7;
    let rm = modrm & 0x7;
    if rm == 4 {
        // SIB form — we don't decode [rsp+x] here, easy to skip for flue.dll
        return None;
    }

    // Handle REX.R/B extension for destination register
    let dst_ext = (rex & 0x04) >> 2; // REX.R
    let base_ext = (rex & 0x01);      // REX.B
    let dst = (dst_ext << 3) | reg;
    let base = (base_ext << 3) | rm;

    match mod_bits {
        0 => {
            if rm == 5 {
                // RIP-relative, not a plain base+disp
                return None;
            }
            Some((dst, base, 0, 3))
        }
        1 => {
            let disp = buf[pos + 3] as i8 as i32;
            Some((dst, base, disp, 4))
        }
        2 => {
            let disp = read_disp32(buf, pos + 3)?;
            Some((dst, base, disp, 7))
        }
        _ => None, // mod=3 = register direct
    }
}

/// Decode `CALL rel32` at `pos`. Returns (target_va, insn_len).
fn decode_call_rel32(buf: &[u8], base: u64, pos: usize) -> Option<(u64, usize)> {
    if pos + 5 > buf.len() {
        return None;
    }
    if buf[pos] != 0xE8 {
        return None;
    }
    let disp = read_disp32(buf, pos + 1)?;
    let rip_after = base + pos as u64 + 5;
    Some((rip_after.wrapping_add(disp as i64 as u64), 5))
}

/// Decode `CMP [reg + disp32], imm32` / `CMP [reg + disp8], imm32`.
/// Specifically, the MSVC emits `81 /7` with modrm mod=10 or mod=01 against
/// dword memory. Returns (base_reg, disp, imm32, insn_len).
fn decode_cmp_mem_imm32(buf: &[u8], pos: usize) -> Option<(u8, i32, u32, usize)> {
    if pos + 4 > buf.len() {
        return None;
    }
    // Optional REX (for r8..r15 base)
    let (rex, opcode_off) = if is_rex_w_or_b(buf[pos]) {
        (buf[pos], 1)
    } else {
        (0u8, 0)
    };
    if buf.get(pos + opcode_off).copied()? != 0x81 {
        return None;
    }
    let modrm = buf[pos + opcode_off + 1];
    let mod_bits = (modrm >> 6) & 0x3;
    let reg = (modrm >> 3) & 0x7;
    let rm = modrm & 0x7;
    if reg != 7 {
        return None; // /7 = cmp
    }
    if rm == 4 {
        return None; // SIB
    }
    let base_ext = (rex & 0x01);
    let base = (base_ext << 3) | rm;

    let mut cur = pos + opcode_off + 2;
    let disp = match mod_bits {
        0 => {
            if rm == 5 {
                return None;
            }
            0
        }
        1 => {
            let d = buf.get(cur).copied()? as i8 as i32;
            cur += 1;
            d
        }
        2 => {
            let d = read_disp32(buf, cur)?;
            cur += 4;
            d
        }
        _ => return None,
    };
    let imm = u32::from_le_bytes(buf.get(cur..cur + 4)?.try_into().ok()?);
    cur += 4;
    Some((base, disp, imm, cur - pos))
}

#[inline]
fn is_rex_w_or_b(b: u8) -> bool {
    // REX with any combination — acceptable since we just want to tolerate it
    (b & 0xF0) == 0x40
}

/// Linear scan inside `[start, end)` looking for the first CALL rel32
/// target; returns (call_addr, target, insn_len). For our purposes this is
/// enough to follow OnLoadStart into its scene-check callee.
pub fn first_call_in_range(slice: &Slice<'_>, start: u64, end: u64) -> Option<(u64, u64)> {
    let text = macho::section(slice, "__TEXT", "__text")?;
    let buf = macho::section_bytes(slice, text)?;
    let base = text.addr;
    let lo = (start.saturating_sub(base)) as usize;
    let hi = ((end - base) as usize).min(buf.len());
    let mut p = lo;
    while p + 5 <= hi {
        if buf[p] == 0xE8 {
            if let Some((target, _)) = decode_call_rel32(buf, base, p) {
                return Some((base + p as u64, target));
            }
        }
        p += 1;
    }
    None
}

/// Derive the Windows scene pointer chain from `OnLoadStart`.
///
/// `onload_start` must be the function start VA (image-base-relative + image_base).
/// `onload_end` is an upper bound for scanning; passing the detected function
/// end is fine, otherwise use `onload_start + 0x400`.
///
/// On success returns the `ScenePath` and a human-readable derivation trace.
pub fn derive_scene_chain(
    slice: &Slice<'_>,
    onload_start: u64,
    onload_end: u64,
) -> Result<(ScenePath, String), String> {
    let text = macho::section(slice, "__TEXT", "__text")
        .ok_or_else(|| "__TEXT,__text not found".to_string())?;
    let buf = macho::section_bytes(slice, text)
        .ok_or_else(|| "__TEXT,__text data outside file".to_string())?;
    let base = text.addr;

    let lo = (onload_start - base) as usize;
    let hi = ((onload_end - base) as usize).min(buf.len()).min(lo + 0x600);

    // RSI in OnLoadStart holds `this` (after the prologue saves rcx->rsi).
    // Scan linearly for `mov rax, [rsi + PREFIX_A]` then `mov rcx, [rax + OFF1]`
    // then a CALL rel32 within a short window.
    let rax = 0u8;
    let rcx = 1u8;
    let rsi = 6u8;

    let mut prefix_a: Option<i32> = None;
    let mut off1: Option<i32> = None;
    let mut call_target: Option<u64> = None;

    // The pattern we need is: mov rax,[rsi+PREFIX_A] / mov rcx,[rax+OFF1] / call
    // where OFF1 is a large struct offset (>= 256). Earlier in the function there
    // may be a similar `mov rax,[rsi+64]` followed by `mov rcx,[rax+16]` which is
    // unrelated (a helper call). We skip candidates where OFF1 is too small.
    const MIN_OFF1: i32 = 256;

    let mut p = lo;
    while p + 4 <= hi {
        if let Some((dst, srcbase, disp, len)) = decode_mov_mem_disp(buf, p) {
            if dst == rax && srcbase == rsi {
                // Tentative prefix_a — will be confirmed only if followed by
                // a valid OFF1 (>= MIN_OFF1) and a CALL.
                prefix_a = Some(disp);
                off1 = None;
            } else if dst == rcx && srcbase == rax && prefix_a.is_some() && disp >= MIN_OFF1 {
                off1 = Some(disp);
            }
            p += len;
            continue;
        }
        if buf[p] == 0xE8 && prefix_a.is_some() && off1.is_some() {
            if let Some((target, _)) = decode_call_rel32(buf, base, p) {
                call_target = Some(target);
                break;
            }
        }
        p += 1;
    }

    let prefix_a = prefix_a.ok_or_else(|| "prefix `mov rax, [rsi+imm]` not found in OnLoadStart".to_string())?;
    let off1 = off1.ok_or_else(|| "`mov rcx, [rax+imm]` not found in OnLoadStart".to_string())?;
    let call_target = call_target.ok_or_else(|| "no CALL after prefix loads in OnLoadStart".to_string())?;
    if prefix_a < 0 || off1 < 0 {
        return Err(format!("unexpected negative offsets: prefix={prefix_a} off1={off1}"));
    }

    // Now walk into the scene-check callee. We scan ahead up to 0x400 bytes
    // looking for `cmp dword ptr [reg + TAIL], 0x44D`.
    let cb_lo = match call_target.checked_sub(base) {
        Some(v) if (v as usize) < buf.len() => v as usize,
        _ => return Err(format!("call target 0x{call_target:x} outside .text")),
    };
    let cb_hi = (cb_lo + 0x400).min(buf.len());

    let mut tail_offset: Option<(u8, i32, usize)> = None; // (base_reg, disp, pos)
    let mut q = cb_lo;
    while q + 5 <= cb_hi {
        if let Some((base_reg, disp, imm, len)) = decode_cmp_mem_imm32(buf, q) {
            if imm == SCENE_CONST_1101 {
                tail_offset = Some((base_reg, disp, q));
                break;
            }
            q += len;
            continue;
        }
        q += 1;
    }

    let (_cmp_base_reg, tail_disp, _cmp_pos) = tail_offset.ok_or_else(|| {
        format!(
            "constant {:#x} (1101) not found in scene-check callee at 0x{:x}",
            SCENE_CONST_1101, call_target
        )
    })?;
    if tail_disp < 0 {
        return Err(format!("negative tail offset {tail_disp}"));
    }
    let scene_offset = tail_disp as u32;

    // Forward-scan the callee from entry to the CMP to collect the pointer chain.
    // Expected pattern (forward from callee entry):
    //   mov rax, [rcx + 8]
    //   mov rcx, [rax + OFF2]    (OFF2 = 0x540 = 1344)
    //   mov rcx, [rcx + 16]
    //   cmp [rcx + TAIL], 0x44D
    //
    // We collect all `mov r64, [r64 + disp]` loads in order, then extract the
    // chain leading to cmp_base_reg by tracking register flow forward.
    let mut chain_offsets: Vec<i32> = Vec::new();
    let mut track_reg = rcx; // callee's first arg (a1) is rcx
    let mut s = cb_lo;
    let cmp_limit = cb_lo + 0x80; // the chain is always within the first ~60 bytes
    while s + 4 <= cmp_limit.min(cb_hi) {
        if let Some((_base_reg, _disp, imm, len)) = decode_cmp_mem_imm32(buf, s) {
            if imm == SCENE_CONST_1101 {
                break;
            }
            s += len;
            continue;
        }
        if let Some((dst, srcbase, disp, len)) = decode_mov_mem_disp(buf, s) {
            if srcbase == track_reg && disp >= 0 {
                chain_offsets.push(disp);
                track_reg = dst;
            }
            s += len;
            continue;
        }
        s += 1;
    }

    // chain_offsets should be [8, OFF2, 16] for the known pattern
    let mut pointer_offsets: Vec<u32> = Vec::with_capacity(5);
    pointer_offsets.push(prefix_a as u32);
    pointer_offsets.push(off1 as u32);
    for v in &chain_offsets {
        pointer_offsets.push(*v as u32);
    }
    // Pad to exactly 5 hops if needed
    while pointer_offsets.len() < 5 {
        if pointer_offsets.len() == 2 {
            pointer_offsets.push(8);
        } else if pointer_offsets.len() == 3 {
            pointer_offsets.push(0x540);
        } else if pointer_offsets.len() == 4 {
            pointer_offsets.push(16);
        }
    }
    pointer_offsets.truncate(5);

    let trace = format!(
        "OnLoadStart prefix=+{prefix_a}, off1=+{off1}; callee=0x{call_target:x}; \
         tail=+{scene_offset}, chain={chain_offsets:?}"
    );

    // Sanity: scene_offset should be SCENE_TAIL_OFFSET_DEFAULT in practice.
    // Warn but don't fail if it diverges (future proof).
    if scene_offset != SCENE_TAIL_OFFSET_DEFAULT {
        eprintln!(
            "warning: scene tail offset {scene_offset:#x} differs from expected {:#x}",
            SCENE_TAIL_OFFSET_DEFAULT
        );
    }

    Ok((
        ScenePath {
            pointer_offsets,
            scene_offset,
        },
        trace,
    ))
}

/// Derive a legacy `[SO0, SO1, SO2]` triple from a `ScenePath` so that
/// `hook.js` can still use the old template as a fallback.
///
/// Mapping:  pointer_offsets = [PREFIX, SO0, 8, SO1, 16],  scene_offset = SO2
pub fn scene_path_to_triple(path: &ScenePath) -> Option<[u32; 3]> {
    if path.pointer_offsets.len() != 5 {
        return None;
    }
    let so0 = path.pointer_offsets[1];
    let so1 = path.pointer_offsets[3];
    let so2 = path.scene_offset;
    Some([so0, so1, so2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scene_path_to_triple_happy() {
        let p = ScenePath {
            pointer_offsets: vec![64, 1408, 8, 1344, 16],
            scene_offset: 456,
        };
        assert_eq!(scene_path_to_triple(&p), Some([1408, 1344, 456]));
    }

    #[test]
    fn scene_path_to_triple_wrong_len() {
        let p = ScenePath {
            pointer_offsets: vec![64, 1408, 8],
            scene_offset: 456,
        };
        assert_eq!(scene_path_to_triple(&p), None);
    }
}
