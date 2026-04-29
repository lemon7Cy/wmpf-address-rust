// PE (Portable Executable) format parser for Windows DLL analysis

const MZ_MAGIC: u16 = 0x5A4D;
const PE_MAGIC: u32 = 0x00004550; // PE\0\0
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
const PE32PLUS_MAGIC: u16 = 0x020B;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86,
    X86_64,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_data_size: u32,
    pub raw_data_offset: u32,
    pub characteristics: u32,
}

#[derive(Debug)]
pub struct PeFile<'a> {
    pub data: &'a [u8],
    pub arch: Arch,
    pub image_base: u64,
    pub entry_point: u32,
    pub sections: Vec<Section>,
}

pub fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(buf.get(off..off + 2)?.try_into().ok()?))
}

pub fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(buf.get(off..off + 4)?.try_into().ok()?))
}

pub fn read_u64_le(buf: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(buf.get(off..off + 8)?.try_into().ok()?))
}

pub fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

pub fn parse_pe(data: &[u8]) -> Result<PeFile<'_>, String> {
    // Check MZ header
    let mz_magic = read_u16_le(data, 0).ok_or("file too small for MZ header")?;
    if mz_magic != MZ_MAGIC {
        return Err(format!("not a PE file: MZ magic=0x{mz_magic:04X}, expected 0x{MZ_MAGIC:04X}"));
    }

    // Get PE header offset
    let pe_offset = read_u32_le(data, 0x3C).ok_or("cannot read PE header offset at 0x3C")? as usize;
    if pe_offset + 24 > data.len() {
        return Err(format!("PE header offset 0x{pe_offset:x} beyond file bounds"));
    }

    // Check PE signature
    let pe_magic = read_u32_le(data, pe_offset).ok_or("cannot read PE signature")?;
    if pe_magic != PE_MAGIC {
        return Err(format!("invalid PE signature: 0x{pe_magic:08X}, expected 0x{PE_MAGIC:08X}"));
    }

    // COFF Header (starts at pe_offset + 4)
    let coff_offset = pe_offset + 4;
    let machine = read_u16_le(data, coff_offset).ok_or("cannot read machine type")?;
    let num_sections = read_u16_le(data, coff_offset + 2).ok_or("cannot read number of sections")? as usize;
    let optional_header_size = read_u16_le(data, coff_offset + 16).ok_or("cannot read optional header size")? as usize;

    let arch = match machine {
        IMAGE_FILE_MACHINE_AMD64 => Arch::X86_64,
        IMAGE_FILE_MACHINE_I386 => Arch::X86,
        _ => return Err(format!("unsupported machine type: 0x{machine:04X}")),
    };

    // Optional Header
    let opt_offset = coff_offset + 20;
    if opt_offset + 2 > data.len() {
        return Err("optional header outside file bounds".to_string());
    }

    let opt_magic = read_u16_le(data, opt_offset).ok_or("cannot read optional header magic")?;
    let (image_base, entry_point) = match opt_magic {
        PE32PLUS_MAGIC => {
            // PE32+ (64-bit)
            let entry = read_u32_le(data, opt_offset + 16).ok_or("cannot read entry point")?;
            let base = read_u64_le(data, opt_offset + 24).ok_or("cannot read image base")?;
            (base, entry)
        }
        0x010B => {
            // PE32 (32-bit)
            let entry = read_u32_le(data, opt_offset + 16).ok_or("cannot read entry point")?;
            let base = read_u32_le(data, opt_offset + 28).ok_or("cannot read image base")? as u64;
            (base, entry)
        }
        _ => return Err(format!("unsupported optional header magic: 0x{opt_magic:04X}")),
    };

    // Section Headers
    let section_offset = opt_offset + optional_header_size;
    let mut sections = Vec::new();

    for i in 0..num_sections {
        let sect_off = section_offset + i * 40;
        if sect_off + 40 > data.len() {
            return Err(format!("section header {i} outside file bounds"));
        }

        let name_bytes = data.get(sect_off..sect_off + 8).ok_or("section name outside file")?;
        let name = cstr(name_bytes);

        let virtual_size = read_u32_le(data, sect_off + 8).ok_or("section virtual_size outside file")?;
        let virtual_address = read_u32_le(data, sect_off + 12).ok_or("section virtual_address outside file")?;
        let raw_data_size = read_u32_le(data, sect_off + 16).ok_or("section raw_data_size outside file")?;
        let raw_data_offset = read_u32_le(data, sect_off + 20).ok_or("section raw_data_offset outside file")?;
        let characteristics = read_u32_le(data, sect_off + 36).ok_or("section characteristics outside file")?;

        sections.push(Section {
            name,
            virtual_size,
            virtual_address,
            raw_data_size,
            raw_data_offset,
            characteristics,
        });
    }

    Ok(PeFile {
        data,
        arch,
        image_base,
        entry_point,
        sections,
    })
}

pub fn section<'a>(pe: &'a PeFile<'a>, name: &str) -> Option<&'a Section> {
    pe.sections.iter().find(|s| s.name == name)
}

pub fn section_bytes<'a>(pe: &'a PeFile<'a>, sec: &Section) -> Option<&'a [u8]> {
    let start = sec.raw_data_offset as usize;
    let size = sec.raw_data_size as usize;
    if size == 0 {
        return None;
    }
    let end = start.checked_add(size)?;
    pe.data.get(start..end)
}

pub fn rva_to_file_offset(pe: &PeFile<'_>, rva: u32) -> Option<u32> {
    for sec in &pe.sections {
        let sec_start = sec.virtual_address;
        let sec_end = sec_start + sec.virtual_size.max(sec.raw_data_size);
        if rva >= sec_start && rva < sec_end {
            let offset = sec.raw_data_offset + (rva - sec_start);
            if (offset as usize) < pe.data.len() {
                return Some(offset);
            }
        }
    }
    None
}

pub fn find_string(pe: &PeFile<'_>, needle: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let bytes = needle.as_bytes();

    // Search in all sections that typically contain strings
    for sec in &pe.sections {
        // .rdata, .data, .rsrc, .rodata, _RDATA sections typically contain strings
        if sec.name == ".rdata" || sec.name == ".data" || sec.name == ".rsrc" ||
           sec.name == ".rodata" || sec.name == "_RDATA" || sec.name == ".text" {
            if let Some(buf) = section_bytes(pe, sec) {
                let base = pe.image_base + sec.virtual_address as u64;
                let mut pos = 0usize;
                while pos + bytes.len() <= buf.len() {
                    if &buf[pos..pos + bytes.len()] == bytes {
                        out.push(base + pos as u64);
                        // Also find the start of the full string (scan backwards for null or start)
                        let mut start = pos;
                        while start > 0 && buf[start - 1] != 0 {
                            start -= 1;
                        }
                        out.push(base + start as u64);
                        pos += bytes.len();
                    } else {
                        pos += 1;
                    }
                }
            }
        }
    }

    out.sort_unstable();
    out.dedup();
    out
}

pub fn find_string_in_section(pe: &PeFile<'_>, section_name: &str, needle: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let bytes = needle.as_bytes();

    if let Some(sec) = section(pe, section_name) {
        if let Some(buf) = section_bytes(pe, sec) {
            let base = pe.image_base + sec.virtual_address as u64;
            let mut pos = 0usize;
            while pos + bytes.len() <= buf.len() {
                if &buf[pos..pos + bytes.len()] == bytes {
                    out.push(base + pos as u64);
                    let mut start = pos;
                    while start > 0 && buf[start - 1] != 0 {
                        start -= 1;
                    }
                    out.push(base + start as u64);
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

/// Get the .text section (code section)
pub fn text_section<'a>(pe: &'a PeFile<'a>) -> Option<&'a Section> {
    section(pe, ".text")
}

/// Get bytes of the .text section
pub fn text_bytes<'a>(pe: &'a PeFile<'a>) -> Option<&'a [u8]> {
    let sec = text_section(pe)?;
    section_bytes(pe, sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u16_le() {
        assert_eq!(read_u16_le(&[0x4D, 0x5A], 0), Some(0x5A4D));
    }

    #[test]
    fn test_read_u32_le() {
        assert_eq!(read_u32_le(&[0x50, 0x45, 0x00, 0x00], 0), Some(0x00004550));
    }

    #[test]
    fn test_cstr() {
        assert_eq!(cstr(b".text\0\0\0"), ".text");
        assert_eq!(cstr(b".rdata\0\0"), ".rdata");
    }

    #[test]
    fn test_section_name_parsing() {
        let name_bytes = b".text\0\0\0";
        assert_eq!(cstr(name_bytes), ".text");
    }
}
