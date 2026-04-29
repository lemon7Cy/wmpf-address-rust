const FAT_MAGIC: u32 = 0xCAFEBABE;
const FAT_MAGIC_64: u32 = 0xCAFEBABF;
const MH_MAGIC_64: u32 = 0xFEEDFACF;
const CPU_TYPE_ARM64: u32 = 0x0100_000C;
const LC_SEGMENT_64: u32 = 0x19;

#[derive(Debug, Clone)]
pub(crate) struct Section {
    pub seg: String,
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u64,
}

#[derive(Debug)]
pub(crate) struct Slice<'a> {
    pub data: &'a [u8],
    pub sections: Vec<Section>,
}

#[derive(Debug, Clone)]
pub(crate) struct Xref {
    pub at: u64,
}

pub(crate) fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(buf.get(off..off + 4)?.try_into().ok()?))
}

pub(crate) fn read_u32_be(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_be_bytes(buf.get(off..off + 4)?.try_into().ok()?))
}

pub(crate) fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(buf.get(off..off + 8)?.try_into().ok()?))
}

pub(crate) fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

pub(crate) fn parse_slice(data: &[u8]) -> Result<Slice<'_>, String> {
    let magic_be = read_u32_be(data, 0).ok_or("file too small")?;
    if magic_be == FAT_MAGIC || magic_be == FAT_MAGIC_64 {
        let nfat = read_u32_be(data, 4).ok_or("bad fat header")? as usize;
        let arch_size = if magic_be == FAT_MAGIC_64 { 32 } else { 20 };
        for i in 0..nfat {
            let off = 8 + i * arch_size;
            let cputype = read_u32_be(data, off).ok_or(format!("bad fat arch at offset 0x{off:x}"))?;
            if cputype != CPU_TYPE_ARM64 {
                continue;
            }
            let slice_off = if magic_be == FAT_MAGIC_64 {
                u64::from_be_bytes(
                    data.get(off + 8..off + 16)
                        .ok_or(format!("fat offset field outside file at 0x{:x}", off + 8))?
                        .try_into()
                        .map_err(|_| "bad fat offset")?,
                )
            } else {
                read_u32_be(data, off + 8).ok_or(format!("fat offset outside file at 0x{:x}", off + 8))? as u64
            };
            let slice_size = if magic_be == FAT_MAGIC_64 {
                u64::from_be_bytes(
                    data.get(off + 16..off + 24)
                        .ok_or(format!("fat size field outside file at 0x{:x}", off + 16))?
                        .try_into()
                        .map_err(|_| "bad fat size")?,
                )
            } else {
                read_u32_be(data, off + 12).ok_or(format!("fat size outside file at 0x{:x}", off + 12))? as u64
            };
            let start = slice_off as usize;
            let end = start
                .checked_add(slice_size as usize)
                .ok_or(format!("slice size overflow: offset=0x{slice_off:x}, size=0x{slice_size:x}"))?;
            let slice_data = data.get(start..end).ok_or(format!(
                "arm64 slice (0x{slice_off:x}..0x{end:x}) outside file (len=0x{:x})",
                data.len()
            ))?;
            return parse_macho64(slice_data, slice_off);
        }
        return Err("arm64 slice not found in universal binary".to_string());
    }

    parse_macho64(data, 0)
}

pub(crate) fn parse_macho64(data: &[u8], file_offset: u64) -> Result<Slice<'_>, String> {
    let magic = read_u32_le(data, 0).ok_or("file too small for Mach-O header")?;
    if magic != MH_MAGIC_64 {
        return Err(format!("unsupported Mach-O magic: 0x{magic:08x} (expected 0x{MH_MAGIC_64:08x})"));
    }
    let cputype = read_u32_le(data, 4).ok_or("bad mach header: cputype")?;
    if cputype != CPU_TYPE_ARM64 {
        return Err(format!("Mach-O is not arm64, cputype=0x{cputype:x} (expected 0x{CPU_TYPE_ARM64:x})"));
    }
    let ncmds = read_u32_le(data, 16).ok_or("bad mach header: ncmds")? as usize;
    let mut cursor = 32usize;
    let mut sections = Vec::new();
    for cmd_idx in 0..ncmds {
        let cmd = read_u32_le(data, cursor).ok_or(format!("load command {cmd_idx}: outside file at offset 0x{cursor:x}"))?;
        let cmdsize = read_u32_le(data, cursor + 4)
            .ok_or(format!("load command {cmd_idx}: size field outside file"))? as usize;
        if cmdsize < 8 {
            return Err(format!("load command {cmd_idx}: invalid size {cmdsize} (minimum 8)"));
        }
        if cmd == LC_SEGMENT_64 {
            let segname = cstr(
                data.get(cursor + 8..cursor + 24)
                    .ok_or(format!("load command {cmd_idx}: segment name outside file"))?,
            );
            let nsects = read_u32_le(data, cursor + 64)
                .ok_or(format!("load command {cmd_idx}: nsects outside file"))? as usize;
            let mut sect_cursor = cursor + 72;
            for sect_idx in 0..nsects {
                let sectname = cstr(
                    data.get(sect_cursor..sect_cursor + 16)
                        .ok_or(format!("section {cmd_idx}.{sect_idx}: name outside file"))?,
                );
                let sectseg = cstr(
                    data.get(sect_cursor + 16..sect_cursor + 32)
                        .ok_or(format!("section {cmd_idx}.{sect_idx}: seg name outside file"))?,
                );
                let addr = read_u64_le(data, sect_cursor + 32)
                    .ok_or(format!("section {cmd_idx}.{sect_idx}: addr outside file"))?;
                let size = read_u64_le(data, sect_cursor + 40)
                    .ok_or(format!("section {cmd_idx}.{sect_idx}: size outside file"))?;
                let offset = read_u32_le(data, sect_cursor + 48)
                    .ok_or(format!("section {cmd_idx}.{sect_idx}: offset outside file"))?
                    as u64;
                sections.push(Section {
                    seg: if sectseg.is_empty() {
                        segname.clone()
                    } else {
                        sectseg
                    },
                    name: sectname,
                    addr,
                    size,
                    offset,
                });
                sect_cursor += 80;
            }
        }
        cursor = cursor.checked_add(cmdsize).ok_or(format!(
            "load command {cmd_idx}: cursor overflow at 0x{cursor:x} + {cmdsize}"
        ))?;
        if cursor > data.len() {
            return Err(format!(
                "load commands extend beyond file: cursor=0x{cursor:x}, file_len=0x{:x}",
                data.len()
            ));
        }
    }
    let _ = file_offset;
    Ok(Slice { data, sections })
}

pub(crate) fn section<'a>(slice: &'a Slice<'a>, seg: &str, name: &str) -> Option<&'a Section> {
    slice
        .sections
        .iter()
        .find(|s| s.seg == seg && s.name == name)
}

pub(crate) fn section_bytes<'a>(slice: &'a Slice<'a>, sec: &Section) -> Option<&'a [u8]> {
    let start = sec.offset as usize;
    let end = start.checked_add(sec.size as usize)?;
    slice.data.get(start..end)
}

pub(crate) fn vm_to_file_off(slice: &Slice<'_>, vm: u64) -> Option<u64> {
    for sec in &slice.sections {
        if vm >= sec.addr && vm < sec.addr + sec.size {
            return Some(sec.offset + (vm - sec.addr));
        }
    }
    None
}

pub(crate) fn find_string(slice: &Slice<'_>, needle: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let bytes = needle.as_bytes();
    for sec in slice.sections.iter().filter(|s| s.seg == "__TEXT") {
        if let Some(buf) = section_bytes(slice, sec) {
            let mut pos = 0usize;
            while pos + bytes.len() <= buf.len() {
                if &buf[pos..pos + bytes.len()] == bytes {
                    out.push(sec.addr + pos as u64);
                    let mut start = pos;
                    while start > 0 && buf[start - 1] != 0 {
                        start -= 1;
                    }
                    out.push(sec.addr + start as u64);
                    pos += bytes.len();
                } else {
                    pos += 1;
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u32_le_basic() {
        assert_eq!(read_u32_le(&[0x78, 0x56, 0x34, 0x12], 0), Some(0x12345678));
    }

    #[test]
    fn test_read_u32_le_offset() {
        assert_eq!(read_u32_le(&[0xFF, 0x78, 0x56, 0x34, 0x12], 1), Some(0x12345678));
    }

    #[test]
    fn test_read_u32_le_out_of_bounds() {
        assert_eq!(read_u32_le(&[0x01, 0x02], 0), None);
    }

    #[test]
    fn test_read_u32_le_empty() {
        assert_eq!(read_u32_le(&[], 0), None);
    }

    #[test]
    fn test_read_u32_be_basic() {
        assert_eq!(read_u32_be(&[0x12, 0x34, 0x56, 0x78], 0), Some(0x12345678));
    }

    #[test]
    fn test_read_u32_be_out_of_bounds() {
        assert_eq!(read_u32_be(&[0x01], 0), None);
    }

    #[test]
    fn test_read_u64_le_basic() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u64_le(&bytes, 0), Some(0x0807060504030201));
    }

    #[test]
    fn test_read_u64_le_out_of_bounds() {
        assert_eq!(read_u64_le(&[0x01; 4], 0), None);
    }

    #[test]
    fn test_cstr_normal() {
        assert_eq!(cstr(b"hello\0world"), "hello");
    }

    #[test]
    fn test_cstr_no_null() {
        assert_eq!(cstr(b"hello"), "hello");
    }

    #[test]
    fn test_cstr_empty() {
        assert_eq!(cstr(b""), "");
    }

    #[test]
    fn test_cstr_null_at_start() {
        assert_eq!(cstr(b"\0hello"), "");
    }

    #[test]
    fn test_cstr_utf8_lossy() {
        let bytes = [0x68, 0x65, 0x6C, 0x6C, 0x6F, 0xFF, 0x00];
        let s = cstr(&bytes);
        assert!(s.contains("hello"));
    }

    #[test]
    fn test_vm_to_file_off_hit() {
        let slice = Slice {
            data: &[],
            sections: vec![Section {
                seg: "__TEXT".to_string(),
                name: "__text".to_string(),
                addr: 0x1000,
                size: 0x500,
                offset: 0x200,
            }],
        };
        assert_eq!(vm_to_file_off(&slice, 0x1100), Some(0x300));
    }

    #[test]
    fn test_vm_to_file_off_miss() {
        let slice = Slice {
            data: &[],
            sections: vec![Section {
                seg: "__TEXT".to_string(),
                name: "__text".to_string(),
                addr: 0x1000,
                size: 0x500,
                offset: 0x200,
            }],
        };
        assert_eq!(vm_to_file_off(&slice, 0x2000), None);
    }

    #[test]
    fn test_vm_to_file_off_boundary() {
        let slice = Slice {
            data: &[],
            sections: vec![Section {
                seg: "__TEXT".to_string(),
                name: "__text".to_string(),
                addr: 0x1000,
                size: 0x500,
                offset: 0x200,
            }],
        };
        // At start
        assert_eq!(vm_to_file_off(&slice, 0x1000), Some(0x200));
        // At end-1
        assert_eq!(vm_to_file_off(&slice, 0x14FF), Some(0x6FF));
        // At end (exclusive)
        assert_eq!(vm_to_file_off(&slice, 0x1500), None);
    }

    #[test]
    fn test_find_string_basic() {
        // Build a minimal data buffer with a string in it
        let mut data = vec![0u8; 256];
        let s = b"HelloWorld\0";
        data[10..10 + s.len()].copy_from_slice(s);
        let slice = Slice {
            data: &data,
            sections: vec![Section {
                seg: "__TEXT".to_string(),
                name: "__cstring".to_string(),
                addr: 0x1000,
                size: 256,
                offset: 0,
            }],
        };
        let addrs = find_string(&slice, "HelloWorld");
        assert!(!addrs.is_empty());
        // Should find both exact match and string start
        assert!(addrs.contains(&(0x1000 + 10)));
    }

    #[test]
    fn test_find_string_not_found() {
        let data = vec![0u8; 64];
        let slice = Slice {
            data: &data,
            sections: vec![Section {
                seg: "__TEXT".to_string(),
                name: "__cstring".to_string(),
                addr: 0x1000,
                size: 64,
                offset: 0,
            }],
        };
        let addrs = find_string(&slice, "NoSuchString");
        assert!(addrs.is_empty());
    }

    #[test]
    fn test_find_string_multiple_sections() {
        let mut data = vec![0u8; 512];
        let s = b"target\0";
        data[10..10 + s.len()].copy_from_slice(s);
        data[300..300 + s.len()].copy_from_slice(s);
        let slice = Slice {
            data: &data,
            sections: vec![
                Section {
                    seg: "__TEXT".to_string(),
                    name: "__cstring".to_string(),
                    addr: 0x1000,
                    size: 256,
                    offset: 0,
                },
                Section {
                    seg: "__TEXT".to_string(),
                    name: "__const".to_string(),
                    addr: 0x2000,
                    size: 256,
                    offset: 256,
                },
            ],
        };
        let addrs = find_string(&slice, "target");
        assert!(addrs.len() >= 2);
    }

    #[test]
    fn test_section_lookup() {
        let slice = Slice {
            data: &[],
            sections: vec![
                Section {
                    seg: "__TEXT".to_string(),
                    name: "__text".to_string(),
                    addr: 0x1000,
                    size: 0x100,
                    offset: 0,
                },
                Section {
                    seg: "__TEXT".to_string(),
                    name: "__cstring".to_string(),
                    addr: 0x2000,
                    size: 0x100,
                    offset: 0x100,
                },
            ],
        };
        assert!(section(&slice, "__TEXT", "__text").is_some());
        assert!(section(&slice, "__TEXT", "__cstring").is_some());
        assert!(section(&slice, "__DATA", "__data").is_none());
    }

    #[test]
    fn test_section_bytes() {
        let data = vec![0xABu8; 256];
        let slice = Slice {
            data: &data,
            sections: vec![Section {
                seg: "__TEXT".to_string(),
                name: "__text".to_string(),
                addr: 0x1000,
                size: 128,
                offset: 0,
            }],
        };
        let sec = section(&slice, "__TEXT", "__text").unwrap();
        let bytes = section_bytes(&slice, sec).unwrap();
        assert_eq!(bytes.len(), 128);
        assert!(bytes.iter().all(|b| *b == 0xAB));
    }
}
