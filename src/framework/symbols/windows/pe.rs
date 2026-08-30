//! Minimal PE parsing, used to identify modules found in memory.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use crate::error::{Result, VolatilityError};

/// `MZ`, at the start of the DOS header.
pub const DOS_MAGIC: &[u8; 2] = b"MZ";
/// `PE\0\0`, at the start of the NT headers.
pub const NT_MAGIC: &[u8; 4] = b"PE\0\0";

/// Offset within the DOS header of the pointer to the NT headers.
const E_LFANEW_OFFSET: usize = 0x3C;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Machine {
    I386,
    Amd64,
    Arm64,
    Other(u16),
}

impl Machine {
    fn parse(value: u16) -> Self {
        match value {
            0x014C => Machine::I386,
            0x8664 => Machine::Amd64,
            0xAA64 => Machine::Arm64,
            other => Machine::Other(other),
        }
    }

    pub fn as_str(&self) -> String {
        match self {
            Machine::I386 => "i386".to_string(),
            Machine::Amd64 => "x64".to_string(),
            Machine::Arm64 => "arm64".to_string(),
            Machine::Other(value) => format!("unknown ({value:#x})"),
        }
    }
}

/// The parts of a PE header that identify a module.
#[derive(Debug, Clone)]
pub struct PeHeader {
    pub machine: Machine,
    /// The machine field as it lies, which is what image descriptions report.
    pub machine_value: u16,
    /// The oldest Windows the image says it runs on.
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub number_of_sections: u16,
    /// Seconds since the Unix epoch, as recorded by the linker.
    pub time_date_stamp: u32,
    pub size_of_image: u32,
    pub image_base: u64,
    pub is_64bit: bool,
}

fn read_u16(data: &[u8], at: usize) -> Result<u16> {
    data.get(at..at + 2)
        .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap()))
        .ok_or_else(|| VolatilityError::Other("Truncated PE header".to_string()))
}

fn read_u32(data: &[u8], at: usize) -> Result<u32> {
    data.get(at..at + 4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        .ok_or_else(|| VolatilityError::Other("Truncated PE header".to_string()))
}

fn read_u64(data: &[u8], at: usize) -> Result<u64> {
    data.get(at..at + 8)
        .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
        .ok_or_else(|| VolatilityError::Other("Truncated PE header".to_string()))
}

/// Parse the headers of a PE image held in `data`.
pub fn parse(data: &[u8]) -> Result<PeHeader> {
    if data.len() < 0x40 || &data[0..2] != DOS_MAGIC {
        return Err(VolatilityError::Other("Not a PE image (no MZ)".to_string()));
    }

    let nt_offset = read_u32(data, E_LFANEW_OFFSET)? as usize;
    if data.get(nt_offset..nt_offset + 4) != Some(NT_MAGIC.as_slice()) {
        return Err(VolatilityError::Other(
            "Not a PE image (no PE signature)".to_string(),
        ));
    }

    // COFF header follows the 4-byte signature.
    let coff = nt_offset + 4;
    let machine = Machine::parse(read_u16(data, coff)?);
    let number_of_sections = read_u16(data, coff + 2)?;
    let time_date_stamp = read_u32(data, coff + 4)?;

    // The optional header's magic distinguishes PE32 from PE32+.
    let optional = coff + 20;
    let magic = read_u16(data, optional)?;
    let is_64bit = magic == 0x20B;

    // SizeOfImage sits at the same offset in both variants. ImageBase does not.
    let size_of_image = read_u32(data, optional + 56)?;
    let image_base = if is_64bit {
        read_u64(data, optional + 24)?
    } else {
        read_u32(data, optional + 28)? as u64
    };

    // Both variants place the operating system version in the same place, past
    // the image base and the two alignments.
    let major_operating_system_version = read_u16(data, optional + 40)?;
    let minor_operating_system_version = read_u16(data, optional + 42)?;

    Ok(PeHeader {
        machine,
        machine_value: read_u16(data, coff)?,
        major_operating_system_version,
        minor_operating_system_version,
        number_of_sections,
        time_date_stamp,
        size_of_image,
        image_base,
        is_64bit,
    })
}

/// One section of a PE image, as its header describes it.
#[derive(Debug, Clone)]
pub struct Section {
    /// The eight-character name, with any padding removed.
    pub name: String,
    /// Where the section sits, relative to the image base.
    pub virtual_address: u32,
    /// How much space it takes once loaded.
    pub virtual_size: u32,
    /// How much of it is stored in the file.
    pub raw_size: u32,
    /// Where it is stored in the file.
    pub raw_address: u32,
}

/// The sections a PE image declares.
pub fn sections(data: &[u8]) -> Result<Vec<Section>> {
    let nt_offset = read_u32(data, E_LFANEW_OFFSET)? as usize;
    let coff = nt_offset + 4;
    let count = read_u16(data, coff + 2)? as usize;
    let optional_size = read_u16(data, coff + 16)? as usize;
    // The section table follows the optional header, whose size the file
    // states rather than implies.
    let mut at = coff + 20 + optional_size;

    let mut found = Vec::with_capacity(count);
    for _ in 0..count {
        let raw_name = data
            .get(at..at + 8)
            .ok_or_else(|| VolatilityError::Other("Section table is truncated".to_string()))?;
        let end = raw_name.iter().position(|byte| *byte == 0).unwrap_or(8);
        found.push(Section {
            name: String::from_utf8_lossy(&raw_name[..end]).to_string(),
            virtual_size: read_u32(data, at + 8)?,
            virtual_address: read_u32(data, at + 12)?,
            raw_size: read_u32(data, at + 16)?,
            raw_address: read_u32(data, at + 20)?,
        });
        at += 40;
    }
    Ok(found)
}

/// Whether `data` starts with a DOS header.
pub fn looks_like_pe(data: &[u8]) -> bool {
    data.len() >= 2 && &data[0..2] == DOS_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but well-formed PE32+ header.
    fn build_pe64() -> Vec<u8> {
        let mut data = vec![0u8; 0x200];
        data[0..2].copy_from_slice(DOS_MAGIC);
        let nt_offset: u32 = 0x80;
        data[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&nt_offset.to_le_bytes());

        let nt = nt_offset as usize;
        data[nt..nt + 4].copy_from_slice(NT_MAGIC);
        let coff = nt + 4;
        data[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        data[coff + 2..coff + 4].copy_from_slice(&6u16.to_le_bytes());
        data[coff + 4..coff + 8].copy_from_slice(&0x6000_0000u32.to_le_bytes());

        let optional = coff + 20;
        data[optional..optional + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        data[optional + 24..optional + 32]
            .copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        data[optional + 56..optional + 60].copy_from_slice(&0x50000u32.to_le_bytes());
        data
    }

    #[test]
    fn parses_a_64_bit_image() {
        let header = parse(&build_pe64()).unwrap();
        assert_eq!(header.machine, Machine::Amd64);
        assert!(header.is_64bit);
        assert_eq!(header.image_base, 0x1_4000_0000);
        assert_eq!(header.size_of_image, 0x50000);
        assert_eq!(header.number_of_sections, 6);
    }

    #[test]
    fn rejects_data_that_is_not_a_pe() {
        assert!(parse(&vec![0u8; 0x100]).is_err());
        assert!(!looks_like_pe(b"XX"));
        assert!(looks_like_pe(b"MZ\x90\x00"));
    }
}

/// The fixed part of a module's version resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionInfo {
    pub major: u16,
    pub minor: u16,
    pub product: u16,
    pub build: u16,
}

/// The signature opening a `VS_FIXEDFILEINFO` structure.
const VS_FIXEDFILEINFO_SIGNATURE: u32 = 0xFEEF_04BD;

/// Recover a module's file version.
///
/// Rather than walking the resource directory, this looks for the fixed
/// structure's signature, which is unique enough to locate directly and avoids
/// depending on a resource tree that may be paged out.
/// Where an image keeps its debug records, as an address relative to its base
/// and a length.
pub fn debug_directory(headers: &[u8]) -> Option<(u32, u32)> {
    let nt_offset = read_u32(headers, E_LFANEW_OFFSET).ok()? as usize;
    let optional = nt_offset + 4 + 20;
    let magic = read_u16(headers, optional).ok()?;
    let directories = optional + if magic == 0x20B { 112 } else { 96 };
    let address = read_u32(headers, directories + 6 * 8).ok()?;
    let size = read_u32(headers, directories + 6 * 8 + 4).ok()?;
    if address == 0 || size == 0 {
        return None;
    }
    Some((address, size))
}

/// Where an image keeps its resources, as an address relative to its base and
/// a length.
pub fn resource_directory(headers: &[u8]) -> Option<(u32, u32)> {
    let nt_offset = read_u32(headers, E_LFANEW_OFFSET).ok()? as usize;
    let optional = nt_offset + 4 + 20;
    let magic = read_u16(headers, optional).ok()?;
    // The data directories follow the optional header, whose length differs
    // between the two forms.
    let directories = optional + if magic == 0x20B { 112 } else { 96 };
    let address = read_u32(headers, directories + 2 * 8).ok()?;
    let size = read_u32(headers, directories + 2 * 8 + 4).ok()?;
    if address == 0 || size == 0 {
        return None;
    }
    Some((address, size))
}

/// Every resource of one kind, as where its data lies relative to the image
/// base and how long it is.
///
/// The directory has three levels (kind, then name, then language), and an
/// image often carries the same resource in several languages, so all of them
/// are returned in the order the directory lists them.
pub fn resource_data(region: &[u8], wanted_kind: u32) -> Vec<(u32, u32)> {
    let Some(by_kind) = directory_entry(region, 0, Some(wanted_kind)) else {
        return Vec::new();
    };

    let mut found = Vec::new();
    for by_name in directory_entries(region, by_kind) {
        for by_language in directory_entries(region, by_name) {
            let (Ok(address), Ok(size)) = (
                read_u32(region, by_language),
                read_u32(region, by_language + 4),
            ) else {
                continue;
            };
            found.push((address, size));
        }
    }
    found
}

/// Where each entry of a directory points, in the order they are listed.
fn directory_entries(region: &[u8], directory: usize) -> Vec<usize> {
    let (Ok(named), Ok(numbered)) = (
        read_u16(region, directory + 12),
        read_u16(region, directory + 14),
    ) else {
        return Vec::new();
    };
    let entries = directory + 16;

    (0..(named as usize + numbered as usize))
        .filter_map(|index| {
            let offset = read_u32(region, entries + index * 8 + 4).ok()?;
            Some((offset & 0x7FFF_FFFF) as usize)
        })
        .collect()
}

/// The kind of resource a version block is.
pub const RT_VERSION: u32 = 16;

/// One entry of a resource directory, followed one level down.
///
/// Returns the offset the entry points at, relative to the directory itself:
/// another directory's entries, or the description of the resource at the last
/// level.
fn directory_entry(region: &[u8], directory: usize, wanted: Option<u32>) -> Option<usize> {
    let named = read_u16(region, directory + 12).ok()? as usize;
    let numbered = read_u16(region, directory + 14).ok()? as usize;
    let entries = directory + 16;

    for index in 0..(named + numbered) {
        let at = entries + index * 8;
        let name = read_u32(region, at).ok()?;
        let offset = read_u32(region, at + 4).ok()?;
        // A named entry is not what any of these levels is looking for.
        if let Some(wanted) = wanted {
            if name & 0x8000_0000 != 0 || name != wanted {
                continue;
            }
        }
        return Some((offset & 0x7FFF_FFFF) as usize);
    }
    None
}

pub fn version_info(data: &[u8]) -> Option<VersionInfo> {
    let needle = VS_FIXEDFILEINFO_SIGNATURE.to_le_bytes();

    // The structure is 4-byte aligned within the resource section.
    for at in (0..data.len().saturating_sub(52)).step_by(4) {
        if data[at..at + 4] != needle {
            continue;
        }

        // The product version follows the file version, each packing a high
        // and a low word with the more significant half second. It is the
        // product's that is reported.
        let product_version_ms = read_u32(data, at + 16).ok()?;
        let product_version_ls = read_u32(data, at + 20).ok()?;

        return Some(VersionInfo {
            major: (product_version_ms >> 16) as u16,
            minor: (product_version_ms & 0xFFFF) as u16,
            product: (product_version_ls >> 16) as u16,
            build: (product_version_ls & 0xFFFF) as u16,
        });
    }
    None
}

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn version_info_is_found_by_its_signature() {
        let mut data = vec![0u8; 256];
        let at = 64;
        data[at..at + 4].copy_from_slice(&VS_FIXEDFILEINFO_SIGNATURE.to_le_bytes());
        // The product version, which is the one reported: 10.0.19041.1288.
        // The file version before it is deliberately different, so a reader of
        // the wrong field would be caught.
        data[at + 8..at + 12].copy_from_slice(&((6u32 << 16) | 3).to_le_bytes());
        data[at + 12..at + 16].copy_from_slice(&((9600u32 << 16) | 17415).to_le_bytes());
        data[at + 16..at + 20].copy_from_slice(&((10u32 << 16)).to_le_bytes());
        data[at + 20..at + 24].copy_from_slice(&((19041u32 << 16) | 1288).to_le_bytes());

        let version = version_info(&data).unwrap();
        assert_eq!(version.major, 10);
        assert_eq!(version.minor, 0);
        assert_eq!(version.product, 19041);
        assert_eq!(version.build, 1288);
    }

    #[test]
    fn absent_version_info_is_reported_as_absent() {
        assert!(version_info(&vec![0u8; 256]).is_none());
    }
}

/// One entry of a module's import table.
#[derive(Debug, Clone)]
pub struct Import {
    /// The module the function is imported from.
    pub library: String,
    /// The function's name, absent when it is imported by ordinal.
    pub function: Option<String>,
    /// The ordinal, meaningful only for a nameless import.
    pub ordinal: u16,
    /// The address currently in the import slot.
    pub address: u64,
    /// Where the slot itself sits, relative to the image base.
    pub slot: u32,
    /// Whether the library's imports were bound when the image was built.
    pub bound: bool,
}

/// The data directory index holding the import table.
const IMPORT_DIRECTORY: usize = 1;

/// Read a NUL-terminated ASCII string from an image.
fn read_cstring(data: &[u8], at: usize) -> Option<String> {
    let slice = data.get(at..)?;
    let end = slice.iter().position(|&byte| byte == 0).unwrap_or(0);
    if end == 0 || end > 512 {
        return None;
    }
    Some(String::from_utf8_lossy(&slice[..end]).to_string())
}

/// Parse a module's import table.
///
/// The image is expected as mapped in memory, so RVAs index it directly.
pub fn imports(data: &[u8]) -> Option<Vec<Import>> {
    let header = parse(data).ok()?;

    let nt_offset = read_u32(data, E_LFANEW_OFFSET).ok()? as usize;
    let optional = nt_offset + 4 + 20;
    // The data directories follow the optional header, whose size differs
    // between the two PE variants.
    let directories = optional + if header.is_64bit { 112 } else { 96 };

    let import_rva = read_u32(data, directories + IMPORT_DIRECTORY * 8).ok()? as usize;
    if import_rva == 0 || import_rva >= data.len() {
        return Some(Vec::new());
    }

    let pointer_size = if header.is_64bit { 8 } else { 4 };
    let mut results = Vec::new();

    // The descriptor array ends with an all-zero entry.
    for index in 0..1024 {
        let descriptor = import_rva + index * 20;
        let original_thunk = read_u32(data, descriptor).ok()? as usize;
        let name_rva = read_u32(data, descriptor + 12).ok()? as usize;
        let first_thunk = read_u32(data, descriptor + 16).ok()? as usize;

        if original_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }

        let library = read_cstring(data, name_rva).unwrap_or_default();
        // A bound library carries the moment it was bound.
        let bound = read_u32(data, descriptor + 4).unwrap_or(0) != 0;
        // The original thunk names the imports. The first thunk holds the
        // addresses they resolved to.
        let names_at = if original_thunk != 0 {
            original_thunk
        } else {
            first_thunk
        };

        // A library's imports are taken as a whole: an entry that names
        // neither a function nor an ordinal means the table is not one, and
        // nothing from it is reported.
        let mut library_imports = Vec::new();
        let mut usable = true;

        for slot in 0..4096 {
            let name_entry = names_at + slot * pointer_size;
            let address_entry = first_thunk + slot * pointer_size;

            let name_value = if header.is_64bit {
                read_u64(data, name_entry).ok()?
            } else {
                read_u32(data, name_entry).ok()? as u64
            };
            if name_value == 0 {
                break;
            }

            let address = if header.is_64bit {
                read_u64(data, address_entry).unwrap_or(0)
            } else {
                read_u32(data, address_entry).unwrap_or(0) as u64
            };

            // The top bit marks an import by ordinal rather than by name.
            let ordinal_flag = if header.is_64bit { 1u64 << 63 } else { 1u64 << 31 };
            let (function, ordinal) = if name_value & ordinal_flag != 0 {
                (None, (name_value & 0xFFFF) as u16)
            } else {
                // Otherwise the value is an address of a hint and a name.
                let hint_name = (name_value & 0x7FFF_FFFF) as usize;
                // The hint has to be there for the name to be looked for at
                // all.
                if data.get(hint_name..hint_name + 2).is_none() {
                    usable = false;
                    break;
                }
                match read_cstring(data, hint_name + 2) {
                    Some(name) if is_function_name(&name) => (Some(name), 0),
                    // A name made of anything else is not one.
                    Some(_) => (Some("*invalid*".to_string()), 0),
                    None => {
                        usable = false;
                        break;
                    }
                }
            };

            library_imports.push(Import {
                library: library.clone(),
                function,
                ordinal,
                address,
                slot: address_entry as u32,
                bound,
            });
        }

        // A library with no name of its own is not reported at all, however
        // many entries its table holds.
        if usable && !library.is_empty() {
            results.extend(library_imports);
        }
    }
    Some(results)
}

/// Whether a name is one a linker would have written.
fn is_function_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._?@$()<>".contains(character))
}

/// One entry of a module's export table.
#[derive(Debug, Clone)]
pub struct Export {
    pub name: String,
    /// The function's address, as an offset within the mapped image.
    pub address: u32,
    pub ordinal: u16,
}

/// The data directory index holding the export table.
const EXPORT_DIRECTORY: usize = 0;

/// Parse a module's exported functions.
///
/// The image is expected as mapped in memory, so RVAs index it directly.
pub fn exports(data: &[u8]) -> Option<Vec<Export>> {
    let header = parse(data).ok()?;

    let nt_offset = read_u32(data, E_LFANEW_OFFSET).ok()? as usize;
    let optional = nt_offset + 4 + 20;
    let directories = optional + if header.is_64bit { 112 } else { 96 };

    let export_rva = read_u32(data, directories + EXPORT_DIRECTORY * 8).ok()? as usize;
    if export_rva == 0 || export_rva >= data.len() {
        return Some(Vec::new());
    }

    let ordinal_base = read_u32(data, export_rva + 16).ok()?;
    let name_count = read_u32(data, export_rva + 24).ok()? as usize;
    let functions_rva = read_u32(data, export_rva + 28).ok()? as usize;
    let names_rva = read_u32(data, export_rva + 32).ok()? as usize;
    let ordinals_rva = read_u32(data, export_rva + 36).ok()? as usize;

    // A table larger than this means the directory was misread.
    if name_count > 0x10000 {
        return Some(Vec::new());
    }

    let mut results = Vec::with_capacity(name_count);
    for index in 0..name_count {
        let name_pointer = read_u32(data, names_rva + index * 4).ok()? as usize;
        let Some(name) = read_cstring(data, name_pointer) else {
            continue;
        };

        // The ordinal array indexes the function array. The base offsets it.
        let ordinal = data
            .get(ordinals_rva + index * 2..ordinals_rva + index * 2 + 2)
            .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap()))?;
        let address = read_u32(data, functions_rva + ordinal as usize * 4).ok()?;

        results.push(Export {
            name,
            address,
            ordinal: ordinal.wrapping_add(ordinal_base as u16),
        });
    }
    Some(results)
}

/// The largest image this framework will write back out.
pub const MAX_EXTRACTION_SIZE: u32 = 1024 * 1024 * 256;

/// Rebuild the file a mapped image came from.
///
/// The loader spreads a file's sections out to the alignment the image asks
/// for, so writing the mapped bytes straight out produces a file whose section
/// table no longer describes it. Each section header is rewritten to point at
/// where the section now sits, and the recorded image base is set to where the
/// image was actually found, which is what makes the result loadable by tools
/// that expect a file on disk.
pub fn reconstruct(
    context: &std::sync::Arc<crate::framework::context::Context>,
    layer: &str,
    base: u64,
) -> Result<Vec<u8>> {
    let headers = context.layers.read(layer, base, 0x1000, false)?;
    if read_u16(&headers, 0)? != 0x5A4D {
        return Err(VolatilityError::Other(
            "e_magic is not a valid DOS signature".to_string(),
        ));
    }
    let nt_offset = read_u32(&headers, E_LFANEW_OFFSET)? as usize;
    let nt_headers = context.layers.read(layer, base + nt_offset as u64, 0x200, false)?;
    if read_u32(&nt_headers, 0)? != 0x4550 {
        return Err(VolatilityError::Other(
            "NT header signature is not valid".to_string(),
        ));
    }

    // The machine, not the optional header's own magic, is what decides which
    // shape of optional header this is.
    let machine = read_u16(&nt_headers, 4)?;
    let is_64bit = machine == 0x8664;
    let number_of_sections = read_u16(&nt_headers, 6)? as usize;
    let size_of_optional_header = read_u16(&nt_headers, 20)? as usize;

    // The optional header follows the four-byte signature and the file header.
    let optional = 24;
    let section_alignment = read_u32(&nt_headers, optional + 32)?;
    let size_of_image = read_u32(&nt_headers, optional + 56)?;
    if size_of_image > MAX_EXTRACTION_SIZE {
        return Err(VolatilityError::Other(format!(
            "The claimed SizeOfImage is too large: {size_of_image}"
        )));
    }

    // Paged-out parts of the image are left as zeroes rather than abandoning
    // an image that is only partly resident.
    let mut data = context
        .layers
        .read(layer, base, size_of_image as usize, true)?;

    // The image base is set to where the image was found, so the file matches
    // the addresses everything else reports.
    let image_base_offset = nt_offset + optional + if is_64bit { 24 } else { 28 };
    let member_size = if is_64bit { 8 } else { 4 };
    let fits = if is_64bit { true } else { base <= u32::MAX as u64 };
    if fits {
        if let Some(slot) = data.get_mut(image_base_offset..image_base_offset + member_size) {
            slot.copy_from_slice(&base.to_le_bytes()[..member_size]);
        }
    } else {
        log::warn!("Unable to fix the image base of the PE at {base:#x}");
    }

    // Each section header is rewritten so that where the section is stored and
    // how much of it is stored match the laid-out image.
    let table = nt_offset + optional + size_of_optional_header;
    for index in 0..number_of_sections {
        let at = table + index * SECTION_HEADER_SIZE;
        let virtual_size = read_u32(&data, at + 8)?;
        let virtual_address = read_u32(&data, at + 12)?;
        let raw_size = read_u32(&data, at + 16)?;
        if virtual_address > size_of_image {
            return Err(VolatilityError::Other(format!(
                "Section VirtualAddress is too large: {virtual_address}"
            )));
        }
        if virtual_size > size_of_image {
            return Err(VolatilityError::Other(format!(
                "Section VirtualSize is too large: {virtual_size}"
            )));
        }
        if raw_size > size_of_image {
            return Err(VolatilityError::Other(format!(
                "Section SizeOfRawData is too large: {raw_size}"
            )));
        }

        // A section occupies whole units of the image's alignment once loaded.
        let size = round_up(virtual_size, section_alignment);
        // The header is re-read from memory, so a header the padded image
        // supplied as zeroes is not written back out as a real one.
        let header = context
            .layers
            .read(layer, base + at as u64, SECTION_HEADER_SIZE, false)?;
        let Some(slot) = data.get_mut(at..at + SECTION_HEADER_SIZE) else {
            continue;
        };
        slot.copy_from_slice(&header);
        slot[8..12].copy_from_slice(&size.to_le_bytes());
        slot[16..20].copy_from_slice(&size.to_le_bytes());
        slot[20..24].copy_from_slice(&virtual_address.to_le_bytes());
    }
    Ok(data)
}

/// How many bytes one section header takes.
const SECTION_HEADER_SIZE: usize = 40;

/// Round `value` up to the next whole multiple of `alignment`.
fn round_up(value: u32, alignment: u32) -> u32 {
    if alignment == 0 || value % alignment == 0 {
        value
    } else {
        value + (alignment - (value % alignment))
    }
}
