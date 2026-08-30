//! Rebuilding a loadable ELF file from a module the kernel has already loaded.
//!
//! The kernel keeps a module's sections where it placed them, but it does not
//! keep the file they came from, and it rewrites parts of the symbol table as
//! it relocates the module. Putting a usable file back together therefore
//! means collecting the sections by address, working out their sizes from the
//! gaps between them, undoing the loader's changes to the symbol table, and
//! writing fresh headers around the result.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::framework::context::{Context, Module};
use crate::framework::objects::utility::pointer_to_string;
use crate::framework::objects::Object;

use super::{module_allocation_range, KernelModule};

/// How far to read for a section name.
const ATTRIBUTE_NAME_MAX_SIZE: usize = 255;

// Symbol binding and type, from the ELF specification.
const STB_LOCAL: u8 = 0;
const STB_GLOBAL: u8 = 1;
const STT_NOTYPE: u8 = 0;
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const STT_SECTION: u8 = 3;

// Section types and flags, likewise.
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_NOTE: u32 = 7;
const SHF_WRITE: u64 = 1;
const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;

/// The size the last section is assumed to have, there being no later section
/// to measure it against.
const LAST_SECTION_SIZE: u64 = 0x10000;

/// A section as it will appear in the rebuilt file.
struct Section {
    name: String,
    address: u64,
    file_offset: u64,
    data: Vec<u8>,
}

/// Rebuild an ELF file for a loaded module, or `None` if it cannot be read.
pub fn extract_module(
    context: &Arc<Context>,
    kernel: &Module,
    module: &KernelModule,
) -> Option<Vec<u8>> {
    // A module structure that is paged out gives nothing to work from.
    // `sect_attrs` is a pointer to the structure holding the section list.
    let attributes = match module
        .object
        .member("sect_attrs")
        .and_then(|attributes| attributes.dereference())
    {
        Ok(attributes) => attributes,
        Err(error) => {
            log::debug!("module {:#x}: no sect_attrs: {error}", module.offset());
            return None;
        }
    };
    if attributes.member("nsections").is_err() && attributes.member("grp").is_err() {
        log::debug!("module {:#x}: sect_attrs is unreadable", module.offset());
        return None;
    }

    let bits = if context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .map(|table| table.pointer_size() == 8)
        .unwrap_or(true)
    {
        64
    } else {
        32
    };
    let (header_type, section_type, symbol_type) = if bits == 64 {
        ("Elf64_Ehdr", "Elf64_Shdr", "Elf64_Sym")
    } else {
        ("Elf32_Ehdr", "Elf32_Shdr", "Elf32_Sym")
    };
    let type_size = |name: &str| -> Option<u64> {
        let template = context.symbol_space.get_type(&kernel.qualified(name)).ok()?;
        context.symbol_space.size_of(&template).ok()
    };
    let (Some(header_size), Some(section_header_size), Some(symbol_size)) = (
        type_size(header_type),
        type_size(section_type),
        type_size(symbol_type),
    ) else {
        log::debug!("module {:#x}: the image's symbols describe no ELF types", module.offset());
        return None;
    };

    let Some((sections, strtab_index, symtab_index)) =
        parse_sections(context, kernel, module, bits, header_size, symbol_size)
    else {
        log::debug!("module {:#x}: sections could not be parsed", module.offset());
        return None;
    };

    // Every loadable module starts with a null section header.
    let mut headers = vec![0u8; section_header_size as usize];
    let mut data = Vec::new();
    // The section name table is a run of null terminated names, starting with
    // the empty one.
    let mut names = vec![0u8];
    let mut name_index = 1u32;
    let mut last_offset = 0;
    let mut last_size = 0;

    for section in &sections {
        headers.extend(section_header(
            bits,
            name_index,
            &section.name,
            section.address,
            section.data.len() as u64,
            section.file_offset,
            strtab_index,
            symtab_index,
        )?);
        name_index += section.name.len() as u32 + 1;
        data.extend_from_slice(&section.data);
        names.extend_from_slice(section.name.as_bytes());
        names.push(0);
        last_offset = section.file_offset;
        last_size = section.data.len() as u64;
    }

    // The name table names itself too, and is written after the last section.
    names.extend_from_slice(b".shstrtab\0");
    headers.extend(section_header(
        bits,
        name_index,
        ".shstrtab",
        0,
        names.len() as u64,
        last_offset + last_size,
        strtab_index,
        symtab_index,
    )?);
    data.extend_from_slice(&names);

    let mut file = elf_header(
        bits,
        header_size + data.len() as u64,
        sections.len() as u64 + 1,
    )?;
    file.extend_from_slice(&data);
    file.extend_from_slice(&headers);
    Some(file)
}

/// Collect the module's sections in load order, with their data.
fn parse_sections(
    context: &Arc<Context>,
    kernel: &Module,
    module: &KernelModule,
    bits: u32,
    header_size: u64,
    symbol_size: u64,
) -> Option<(Vec<Section>, u32, u32)> {
    let (low, high) = module_allocation_range(context, kernel).ok()?;
    let layer = context.layers.get(&kernel.layer_name).ok()?;
    let mask = layer.address_mask();
    let (low, high) = (low & mask, high & mask);

    // Names by address, kept in the order the kernel lists them: the symbol
    // table refers to sections by that position, while the file lays them out
    // by address.
    let mut named: Vec<(u64, String)> = Vec::new();
    for section in module_sections(context, kernel, module) {
        let Ok(address) = section.member("address").and_then(|value| value.as_u64()) else {
            continue;
        };
        // A smeared structure can hold addresses far outside the module area,
        // which would make the size calculation below meaningless.
        if !(low..high).contains(&(address & mask)) {
            continue;
        }
        if let Some(name) = section_name(&section) {
            match named.iter_mut().find(|(known, _)| *known == address) {
                Some((_, existing)) => *existing = name,
                None => named.push((address, name)),
            }
        }
    }
    if named.is_empty() {
        log::debug!("module {:#x}: no sections could be read", module.offset());
        return None;
    }

    let (Some(symbol_count), Some(symbol_table), Some(string_table)) = (
        symbol_table_length(module),
        symbol_table_address(module),
        string_table_address(module),
    ) else {
        log::debug!("module {:#x}: no symbol table", module.offset());
        return None;
    };

    let mut addresses: Vec<u64> = named.iter().map(|(address, _)| *address).collect();
    addresses.sort_unstable();
    let mut sections: Vec<Section> = Vec::new();
    let mut sizes: BTreeMap<u64, u64> = BTreeMap::new();
    let mut file_offset = header_size;
    let mut symtab_address = None;
    let mut strtab_index = 0u32;

    for (index, address) in addresses.iter().enumerate() {
        let name = named
            .iter()
            .find(|(known, _)| known == address)
            .map(|(_, name)| name.clone())?;
        let data = if name == ".strtab" {
            // The kernel does not keep the string table's size, so allow each
            // symbol a generous share and stop at its end.
            let mut data = context
                .layers
                .read(&kernel.layer_name, string_table, (symbol_count * 256) as usize, true)
                .ok()?;
            if let Some(end) = data.windows(2).position(|pair| pair == [0, 0]) {
                data.truncate(end + 1);
            }
            strtab_index = index as u32;
            data
        } else if name == ".symtab" {
            // Handled last: its contents have to be rebuilt from the sections
            // that surround it.
            symtab_address = Some(*address);
            continue;
        } else {
            let size = addresses
                .get(index + 1)
                .map(|next| next - address)
                .unwrap_or(LAST_SECTION_SIZE);
            context
                .layers
                .read(&kernel.layer_name, *address, size as usize, true)
                .ok()?
        };

        sizes.insert(*address, data.len() as u64);
        file_offset += data.len() as u64;
        sections.push(Section {
            name,
            address: *address,
            file_offset: file_offset - data.len() as u64,
            data,
        });
    }

    // Without a symbol table there is nothing worth analysing in the result.
    let symtab_address = symtab_address?;
    let data = fixed_symbol_table(
        context,
        kernel,
        &named,
        &sizes,
        bits,
        symbol_size,
        symbol_table,
        symbol_count,
    )?;
    let symtab_index = sections.len() as u32;
    sections.push(Section {
        name: ".symtab".to_string(),
        address: symtab_address,
        file_offset,
        data,
    });

    Some((sections, strtab_index, symtab_index))
}

/// The `module_sect_attr` entries describing where each section was loaded.
fn module_sections(context: &Arc<Context>, kernel: &Module, module: &KernelModule) -> Vec<Object> {
    let Ok(attributes) = module
        .object
        .member("sect_attrs")
        .and_then(|attributes| attributes.dereference())
    else {
        return Vec::new();
    };
    let count = match attributes.member("nsections").and_then(|value| value.as_u64()) {
        Ok(count) => count,
        // Kernel 6.14 removed the count and terminates the list with a null
        // attribute pointer instead.
        Err(_) => attribute_count(context, kernel, &attributes),
    };
    if count == 0 {
        return Vec::new();
    }

    // The section list is a flexible array member, so the symbols give it no
    // length. It is walked by stepping over one element at a time.
    let Ok(array) = attributes.member("attrs") else {
        return Vec::new();
    };
    let Ok(template) = array.resolved_template() else {
        return Vec::new();
    };
    let subtype = match template.as_ref() {
        crate::framework::symbols::Template::Array { subtype, .. } => subtype.clone(),
        _ => return Vec::new(),
    };
    let Ok(element_size) = context.symbol_space.size_of(&subtype) else {
        return Vec::new();
    };
    (0..count)
        .map(|index| {
            context.object_from_template(
                subtype.clone(),
                array.layer_name(),
                array.offset() + index * element_size,
            )
        })
        .collect()
}

/// Count the sections of a kernel that no longer records the number.
fn attribute_count(context: &Arc<Context>, kernel: &Module, attributes: &Object) -> u64 {
    let Ok(group) = attributes.member("grp") else {
        return 0;
    };
    let (member, kind) = if group.has_member("bin_attrs") {
        ("bin_attrs", "bin_attribute")
    } else {
        ("attrs", "attribute")
    };
    let Ok(pointer) = group.member(member).and_then(|value| value.as_u64()) else {
        return 0;
    };
    let Ok(template) = context
        .symbol_space
        .get_type(&kernel.qualified(kind))
    else {
        return 0;
    };
    let _ = template;

    // The array is a null terminated list of pointers.
    let mut count = 0;
    let mut offset = pointer;
    while let Ok(entry) = context.object(
        &kernel.qualified("pointer"),
        &kernel.layer_name,
        offset,
    ) {
        match entry.as_u64() {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                count += 1;
                offset += 8;
            }
        }
    }
    count
}

/// A section's name, however this kernel version records it.
fn section_name(section: &Object) -> Option<String> {
    if section.has_member("battr") {
        return section
            .member("battr")
            .and_then(|battr| battr.member("attr"))
            .and_then(|attr| attr.member("name"))
            .ok()
            .and_then(|name| pointer_to_string(&name, ATTRIBUTE_NAME_MAX_SIZE).ok());
    }

    let name = section.member("name").ok()?;
    if name.type_name() == "array" {
        if let Ok(text) = name.as_string() {
            return Some(text);
        }
    } else if let Ok(text) = pointer_to_string(&name, ATTRIBUTE_NAME_MAX_SIZE) {
        return Some(text);
    }

    // Older kernels keep the name the sysfs attribute carries instead.
    section
        .member("mattr")
        .and_then(|mattr| mattr.member("attr"))
        .and_then(|attr| attr.member("name"))
        .ok()
        .and_then(|name| pointer_to_string(&name, ATTRIBUTE_NAME_MAX_SIZE).ok())
}

/// Where the module's symbol table lives.
fn symbol_table_address(module: &KernelModule) -> Option<u64> {
    let object = &module.object;
    if object.has_member("kallsyms") {
        return object
            .member("kallsyms")
            .and_then(|kallsyms| kallsyms.dereference())
            .and_then(|kallsyms| kallsyms.member("symtab"))
            .and_then(|value| value.as_u64())
            .ok();
    }
    object.member("symtab").and_then(|value| value.as_u64()).ok()
}

/// How many symbols that table holds.
fn symbol_table_length(module: &KernelModule) -> Option<u64> {
    let object = &module.object;
    if object.has_member("kallsyms") {
        return object
            .member("kallsyms")
            .and_then(|kallsyms| kallsyms.dereference())
            .and_then(|kallsyms| kallsyms.member("num_symtab"))
            .and_then(|value| value.as_u64())
            .ok();
    }
    object
        .member("num_symtab")
        .and_then(|value| value.as_u64())
        .ok()
}

/// Where the strings those symbols are named by live.
fn string_table_address(module: &KernelModule) -> Option<u64> {
    let object = &module.object;
    if object.has_member("kallsyms") {
        return object
            .member("kallsyms")
            .and_then(|kallsyms| kallsyms.dereference())
            .and_then(|kallsyms| kallsyms.member("strtab"))
            .and_then(|value| value.as_u64())
            .ok();
    }
    object.member("strtab").and_then(|value| value.as_u64()).ok()
}

/// Undo the loader's changes to the symbol table.
///
/// The loader rewrites each symbol's value to the address it ended up at, its
/// type to an index the kernel uses internally, and its section index to
/// something meaningful only during loading. Analysis tools expect the values
/// the file originally held: an offset within a section, a type derived from
/// that section, and the section's index in the file being written.
#[allow(clippy::too_many_arguments)]
fn fixed_symbol_table(
    context: &Arc<Context>,
    kernel: &Module,
    named: &[(u64, String)],
    sizes: &BTreeMap<u64, u64>,
    bits: u32,
    symbol_size: u64,
    symbol_table: u64,
    count: u64,
) -> Option<Vec<u8>> {
    // The sections a symbol can point into, with the index each will have in
    // the file. One is added for the leading null section header.
    let lookups: Vec<(String, u32, u64, u64)> = named
        .iter()
        .enumerate()
        .filter(|(_, (_, name))| name.as_str() != ".symtab")
        .map(|(index, (address, name))| {
            (
                name.clone(),
                index as u32 + 1,
                *address,
                sizes.get(address).copied().unwrap_or(0),
            )
        })
        .collect();

    let symbol_type = if bits == 64 { "Elf64_Sym" } else { "Elf32_Sym" };
    let mut table = Vec::new();
    for index in 0..count {
        let symbol = context
            .module_object(kernel, symbol_type, symbol_table + index * symbol_size)
            .ok()?;
        let field = |name: &str| symbol.member(name).and_then(|value| value.as_u64()).ok();
        let (st_name, st_value, st_size, st_other, st_shndx) = (
            field("st_name")?,
            field("st_value")?,
            field("st_size")?,
            field("st_other")?,
            field("st_shndx")?,
        );

        let section = lookups
            .iter()
            .find(|(_, _, address, size)| (*address..address + size).contains(&st_value));
        let (value, shndx) = match section {
            Some((_, section_index, address, _)) => (st_value - address, *section_index as u16),
            // A symbol that points outside the module keeps what it had.
            None => (st_value, st_shndx as u16),
        };
        let info = symbol_info(st_name, st_value, section.map(|(name, ..)| name.as_str()));

        let mut entry = Vec::with_capacity(symbol_size as usize);
        // The two layouts order their fields differently.
        if bits == 32 {
            entry.extend_from_slice(&(st_name as u32).to_le_bytes());
            entry.extend_from_slice(&(value as u32).to_le_bytes());
            entry.extend_from_slice(&(st_size as u32).to_le_bytes());
            entry.push(info);
            entry.push(st_other as u8);
            entry.extend_from_slice(&shndx.to_le_bytes());
        } else {
            entry.extend_from_slice(&(st_name as u32).to_le_bytes());
            entry.push(info);
            entry.push(st_other as u8);
            entry.extend_from_slice(&shndx.to_le_bytes());
            entry.extend_from_slice(&value.to_le_bytes());
            entry.extend_from_slice(&st_size.to_le_bytes());
        }
        if entry.len() as u64 != symbol_size {
            return None;
        }
        table.extend_from_slice(&entry);
    }

    (!table.is_empty()).then_some(table)
}

/// The binding and type byte a symbol should carry.
fn symbol_info(st_name: u64, address: u64, section: Option<&str>) -> u8 {
    let (bind, kind) = if st_name > 0 {
        let kind = match section {
            _ if address == 0 => STT_NOTYPE,
            // Code in a text section is a function. Anything else with a
            // section behind it is data. Relocations only describe code.
            Some(name) if name.contains(".text") && !name.contains(".rela") => STT_FUNC,
            Some(_) => STT_OBJECT,
            None => STT_NOTYPE,
        };
        (STB_GLOBAL, kind)
    } else {
        (STB_LOCAL, STT_SECTION)
    };
    ((bind << 4) & 0xf0) | (kind & 0x0f)
}

/// The file header, written once the sections' total size is known.
fn elf_header(bits: u32, section_headers_at: u64, section_count: u64) -> Option<Vec<u8>> {
    let (identity, machine, header_size, entry_size, width): (&[u8], u16, u16, u16, usize) =
        if bits == 32 {
            (
                b"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                3,
                52,
                40,
                4,
            )
        } else {
            (
                b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                0x3e,
                64,
                64,
                8,
            )
        };

    let mut header = Vec::with_capacity(header_size as usize);
    header.extend_from_slice(identity);
    // Relocatable, which is what a module is.
    header.extend_from_slice(&1u16.to_le_bytes());
    header.extend_from_slice(&machine.to_le_bytes());
    header.extend_from_slice(&1u32.to_le_bytes());
    // No entry point: the initialisation sections are freed after loading.
    header.extend(std::iter::repeat_n(0u8, width));
    // No program headers either.
    header.extend(std::iter::repeat_n(0u8, width));
    header.extend_from_slice(&section_headers_at.to_le_bytes()[..width]);
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&header_size.to_le_bytes());
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&entry_size.to_le_bytes());
    header.extend_from_slice(&((section_count + 1) as u16).to_le_bytes());
    header.extend_from_slice(&(section_count as u16).to_le_bytes());

    (header.len() == header_size as usize).then_some(header)
}

/// One section header, describing where a section sits and what it holds.
#[allow(clippy::too_many_arguments)]
fn section_header(
    bits: u32,
    name_index: u32,
    name: &str,
    address: u64,
    size: u64,
    file_offset: u64,
    strtab_index: u32,
    symtab_index: u32,
) -> Option<Vec<u8>> {
    let (width, header_size) = if bits == 32 { (4, 40) } else { (8, 64) };
    let kind = section_type(name);
    let flags = section_flags(name);
    let link = section_link(name, strtab_index, symtab_index, kind);
    let entry_size = section_entry_size(name, kind, bits);

    // A value too large for the field means the structure was misread.
    let word = |value: u64| -> Option<Vec<u8>> {
        if width == 4 && value > u32::MAX as u64 {
            return None;
        }
        Some(value.to_le_bytes()[..width].to_vec())
    };

    let mut header = Vec::with_capacity(header_size);
    header.extend_from_slice(&name_index.to_le_bytes());
    header.extend_from_slice(&kind.to_le_bytes());
    header.extend(word(flags)?);
    header.extend(word(address)?);
    header.extend(word(file_offset)?);
    header.extend(word(size)?);
    header.extend_from_slice(&link.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend(word(1)?);
    header.extend(word(entry_size)?);

    (header.len() == header_size).then_some(header)
}

/// What kind of section a name implies.
fn section_type(name: &str) -> u32 {
    if name.contains(".rela.") {
        return SHT_RELA;
    }
    match name {
        ".note.gnu.build-id" => SHT_NOTE,
        ".shstrtab" | ".strtab" => SHT_STRTAB,
        ".symtab" => SHT_SYMTAB,
        _ => SHT_PROGBITS,
    }
}

/// The permissions a section name implies.
///
/// Everything read out of memory is allocated. The rest is a best effort, so
/// that a disassembler marks code as code and data as writable.
fn section_flags(name: &str) -> u64 {
    match name {
        ".text" | ".init.text" | ".exit.text" | ".static_call.text" => SHF_ALLOC | SHF_EXECINSTR,
        ".data" | ".init.data" | ".exit.data" | ".bss" | "__tracepoints" | ".data.once"
        | "_ftrace_events" | ".gnu.linkonce.this_module" => SHF_ALLOC | SHF_WRITE,
        _ => SHF_ALLOC,
    }
}

/// The section a header points at: relocations name their symbol table, and a
/// symbol table names its strings.
fn section_link(name: &str, strtab_index: u32, symtab_index: u32, kind: u32) -> u32 {
    if name.contains(".rela.") {
        symtab_index
    } else if kind == SHT_SYMTAB {
        strtab_index
    } else {
        0
    }
}

/// The size of one entry, for the sections that hold fixed size entries.
fn section_entry_size(name: &str, kind: u32, bits: u32) -> u64 {
    if name.contains(".rela.") {
        24
    } else if kind == SHT_SYMTAB {
        if bits == 32 { 16 } else { 24 }
    } else {
        0
    }
}
