//! The kernel keeps its own symbol names in a compressed form: a token table
//! holds common substrings, and each name is a sequence of token indices. That
//! makes the table recoverable from memory without any external symbol file,
//! which is useful when no ISF matches the running kernel.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::objects::utility::{array_to_string, pointer_to_string, walk_list};
use crate::framework::objects::Object;
use crate::framework::symbols::linux::resolver::ModuleResolver;

/// Kallsyms symbols enumeration plugin.
///
/// If no arguments are provided, all symbols are included: core, modules,
/// ftrace, and BPF. Alternatively, you can use any combination of --core,
/// --modules, --ftrace, and --bpf to customize the output.
pub struct Kallsyms;

/// A table larger than this means the count symbol was misread.
///
/// Symbol sizes are calculated using the address of the next non-aliased
/// symbol or the end of the kernel text area `_end`/`_etext`. However, some
/// kernel symbols live beyond that area. For these symbols, the size will be
/// negative, resulting in incorrect values. Unfortunately, there isn't much
/// that can be done in such cases. See comments on `.init.scratch` in
/// arch/x86/kernel/vmlinux.lds.S for details.
const MAX_SYMBOLS: u64 = 500_000;

/// What each `nm` type letter means, worded as the reference implementation does.
///
/// As per the "nm" man page: if lowercase, the symbol is usually local; if
/// uppercase, the symbol is global (external). There are however a few
/// lowercase symbols that are shown for special global symbols ("u", "v" and
/// "w").
fn describe_type(letter: char) -> Option<&'static str> {
    // If a symbol type exists with the original case, get it. Otherwise, use
    // the lowercase version.
    let exact = match letter {
        'N' => Some("Symbol is a debugging symbol"),
        'U' => Some("Symbol is undefined"),
        'V' => Some("Symbol is a weak object, with a default value"),
        'W' => Some(
            "Symbol is a weak symbol but not marked as a weak object symbol, with a default value",
        ),
        _ => None,
    };
    if exact.is_some() {
        return exact;
    }

    match letter.to_ascii_lowercase() {
        'a' => Some("Symbol is absolute and doesn't change during linking"),
        'b' => Some(
            "Symbol in the BSS section, typically holding zero-initialized or uninitialized data",
        ),
        'c' => Some("Symbol is common, typically holding uninitialized data"),
        'd' => Some("Symbol is in the initialized data section"),
        'g' => Some("Symbol is in an initialized data section for small objects"),
        'i' => Some("Symbol is an indirect reference to another symbol"),
        'n' => Some("Symbol is in a non-data, non-code, non-debug read-only section"),
        'p' => Some("Symbol is in a stack unwind section"),
        'r' => Some("Symbol is in a read only data section"),
        's' => Some(
            "Symbol is in an uninitialized or zero-initialized data section for small objects",
        ),
        't' => Some("Symbol is in the text (code) section"),
        'u' => Some("Symbol is a unique global symbol"),
        'v' => Some("Symbol is a weak object"),
        'w' => Some("Symbol is a weak symbol but not marked as a weak object symbol"),
        '?' => Some("Symbol type is unknown"),
        _ => None,
    }
}

impl Plugin for Kallsyms {
    fn name(&self) -> &'static str {
        "linux.kallsyms.Kallsyms"
    }

    fn description(&self) -> &'static str {
        "Kallsyms symbols enumeration plugin."
    }

    fn epilog(&self) -> Option<&'static str> {
        Some(
            "If no arguments are provided, all symbols are included: core, modules, \
             ftrace, and BPF. Alternatively, you can use any combination of --core, \
             --modules, --ftrace, and --bpf to customize the output.",
        )
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "core",
                "Include core symbols",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
            Requirement::new(
                "modules",
                "Include module symbols",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
            Requirement::new(
                "ftrace",
                "Include ftrace symbols",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
            Requirement::new(
                "bpf",
                "Include BPF symbols",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Addr", ColumnType::UInt),
            Column::string("Type"),
            Column::int("Size"),
            Column::bool("Exported"),
            Column::string("SubSystem"),
            Column::string("ModuleName"),
            Column::string("SymbolName"),
            Column::string("Description"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let _resolver = ModuleResolver::new(&context, &kernel).ok();

        // Naming no group at all asks for every group.
        let asked = |name: &str| config.get_bool(name).unwrap_or(false);
        let (mut core, mut modules, mut ftrace, mut bpf) = (
            asked("core"),
            asked("modules"),
            asked("ftrace"),
            asked("bpf"),
        );
        if !(core || modules || ftrace || bpf) {
            core = true;
            modules = true;
            ftrace = true;
            bpf = true;
        }

        // Decoding the compressed table is the expensive part, and only the
        // core group needs it.
        let symbols = if core {
            let table = KallsymsTable::load(&context, &kernel)?;
            table.decode(&context, &kernel)?
        } else {
            Vec::new()
        };

        let mut grid = TreeGrid::new(self.columns());
        let mask = context.layers.address_mask(&kernel.layer_name);
        if core {
            emit_core(&mut grid, &context, &kernel, &symbols, mask)?;
        }
        if modules {
            emit_modules(&mut grid, &context, &kernel, mask)?;
        }
        if ftrace {
            emit_ftrace(&mut grid, &context, &kernel, mask)?;
        }
        if bpf {
            emit_bpf(&mut grid, &context, &kernel, mask)?;
        }
        Ok(grid)
    }
}

/// The core symbols, as `kallsyms_on_each_symbol` walks them.
fn emit_core(
    grid: &mut TreeGrid,
    context: &Arc<Context>,
    kernel: &Module,
    symbols: &[Symbol],
    mask: u64,
) -> Result<()> {
        // Where the kernel image ends, used to size the last symbol in a region.
        let marker = |name: &str| context.symbol_offset(kernel, name).ok().map(|a| a & mask);
        let image_end = marker("_end").or_else(|| marker("_etext"));
        let init_text = (marker("_sinittext"), marker("_einittext"));

        for (index, symbol) in symbols.iter().enumerate() {
            let address = symbol.address & mask;

            // A symbol's size runs to the next symbol at a higher address.
            // Symbols sharing an address are aliases of one another and all take
            // the size of the group.
            let next = symbols[index + 1..]
                .iter()
                .find(|other| (other.address & mask) > address)
                .map(|other| other.address & mask);
            let end = next.or_else(|| {
                match init_text {
                    (Some(start), Some(finish)) if (start..finish).contains(&address) => {
                        Some(finish)
                    }
                    _ => image_end,
                }
            });
            let size = end.map(|end| end as i64 - address as i64).unwrap_or(0);

            grid.push(
                0,
                vec![
                    Value::hex(address),
                    Value::string(symbol.letter.to_string()),
                    // A symbol beyond the end of the image measures negative,
                    // which says nothing useful about its size.
                    if size > 0 {
                        Value::int(size)
                    } else {
                        Value::not_available()
                    },
                    // An upper-case letter marks a globally visible symbol, as
                    // do the three lower-case letters `nm` reserves for them.
                    Value::Bool(
                        symbol.letter.is_ascii_uppercase()
                            || matches!(symbol.letter, 'u' | 'v' | 'w'),
                    ),
                    Value::string("core"),
                    Value::string("kernel"),
                    Value::string(symbol.name.clone()),
                    match describe_type(symbol.letter) {
                        Some(text) => Value::string(text),
                        None => Value::not_available(),
                    },
                ],
            )?;
        }
    Ok(())
}

/// One row, whichever group it came from.
#[allow(clippy::too_many_arguments)]
fn push_symbol(
    grid: &mut TreeGrid,
    address: u64,
    letter: Option<char>,
    size: i64,
    exported: Option<bool>,
    subsystem: &str,
    module_name: &str,
    name: &str,
) -> Result<()> {
    grid.push(
        0,
        vec![
            Value::hex(address),
            match letter {
                Some(letter) => Value::string(letter.to_string()),
                None => Value::not_available(),
            },
            // A size of zero says nothing, and one that came out negative says
            // the symbol sits outside the region it was measured against.
            if size > 0 {
                Value::int(size)
            } else {
                Value::not_available()
            },
            match exported {
                Some(exported) => Value::Bool(exported),
                None => Value::not_available(),
            },
            Value::string(subsystem),
            Value::string(module_name),
            Value::string(name),
            match letter.and_then(describe_type) {
                Some(text) => Value::string(text),
                None => Value::not_available(),
            },
        ],
    )
}

/// The symbols each loaded module carries in its own ELF symbol table.
fn emit_modules(
    grid: &mut TreeGrid,
    context: &Arc<Context>,
    kernel: &Module,
    mask: u64,
) -> Result<()> {
    let Ok(symbol_size) = context
        .symbol_space
        .get_type(&kernel.qualified("kernel_symbol"))
        .and_then(|template| context.symbol_space.size_of(&template))
    else {
        return Ok(());
    };
    let symbol_size = symbol_size as usize;
    // An ELF symbol table entry is laid out differently in the two widths, and
    // which one a module holds follows the kernel's own pointer width.
    let wide = context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .map(|table| table.pointer_size())
        .unwrap_or(8)
        == 8;
    let elf_symbol = if wide { 24 } else { 16 };

    for module in crate::framework::symbols::linux::list_modules(context, kernel)? {
        let object = &module.object;
        let module_name = object
            .member("name")
            .and_then(|name| array_to_string(&name))
            .unwrap_or_default();

        // Kernel 4.5 moved the symbol table bookkeeping into a `kallsyms` of
        // its own, and 5.2 gave the type letters an array of their own.
        let holder = if object.has_member("kallsyms") {
            match object
                .member("kallsyms")
                .and_then(|kallsyms| kallsyms.dereference())
            {
                Ok(kallsyms) => kallsyms,
                Err(_) => continue,
            }
        } else {
            object.clone()
        };
        let Ok(strtab) = holder.member("strtab").and_then(|value| value.as_u64()) else {
            continue;
        };
        let Ok(symtab) = holder.member("symtab").and_then(|value| value.as_u64()) else {
            continue;
        };
        let count = holder
            .member("num_symtab")
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        let typetab = if holder.has_member("typetab") {
            holder.member("typetab").and_then(|value| value.as_u64()).ok()
        } else {
            None
        };
        if strtab == 0 || count < 1 {
            continue;
        }

        let exported_names = ExportedSymbols::of_module(context, kernel, object, symbol_size);

        for index in 0..count {
            let entry = symtab + index * elf_symbol as u64;
            // Elf64_Sym: name, info, other, shndx, value, size.
            // Elf32_Sym: name, value, size, info, other, shndx.
            let Ok(raw) = context
                .layers
                .read(&kernel.layer_name, entry, elf_symbol, false)
            else {
                continue;
            };
            let st_name = u32::from_le_bytes(raw[0..4].try_into().unwrap()) as u64;
            let (st_info, st_value, st_size) = if wide {
                (
                    raw[4],
                    u64::from_le_bytes(raw[8..16].try_into().unwrap()),
                    u64::from_le_bytes(raw[16..24].try_into().unwrap()),
                )
            } else {
                (
                    raw[12],
                    u32::from_le_bytes(raw[4..8].try_into().unwrap()) as u64,
                    u32::from_le_bytes(raw[8..12].try_into().unwrap()) as u64,
                )
            };

            let Ok(name) = read_string(context, &kernel.layer_name, strtab + st_name, 512) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }

            let address = st_value & mask;
            // Before kernel 5.2 the loader rewrote the symbol's info byte to
            // hold the `nm` type letter; after that the letters sit in an array
            // indexed the same way as the symbols.
            let letter = match typetab {
                Some(table) => context
                    .layers
                    .read(&kernel.layer_name, table + index, 1, false)
                    .ok()
                    .map(|byte| byte[0] as char),
                None => Some(st_info as char),
            };
            let exported = exported_names.lookup(&name, address);
            let letter = letter.map(|letter| {
                if exported == Some(true) {
                    letter.to_ascii_uppercase()
                } else {
                    letter.to_ascii_lowercase()
                }
            });

            push_symbol(
                grid,
                address,
                letter,
                st_size as i64,
                exported,
                "module",
                &module_name,
                &name,
            )?;
        }
    }
    Ok(())
}

/// A module's exported-symbol table, searched the way the kernel searches it.
struct ExportedSymbols {
    /// Absent where the module exports nothing, which the reference
    /// implementation answers with a plain "not exported".
    table: Option<(u64, u64, usize)>,
    context: Arc<Context>,
    layer: String,
    table_name: String,
}

impl ExportedSymbols {
    fn of_module(
        context: &Arc<Context>,
        kernel: &Module,
        module: &Object,
        symbol_size: usize,
    ) -> Self {
        let count = module
            .member("num_syms")
            .and_then(|value| value.as_i64())
            .unwrap_or(0);
        let start = module
            .member("syms")
            .and_then(|value| value.pointer_value())
            .unwrap_or(0);
        Self {
            table: (count > 0).then_some((start, count as u64, symbol_size)),
            context: context.clone(),
            layer: kernel.layer_name.clone(),
            table_name: kernel.symbol_table_name.clone(),
        }
    }

    /// Whether a symbol of this name and address is one the module exports.
    ///
    /// The answer is unknown rather than negative when the name is not in the
    /// table at all, which is what the reference implementation reports.
    fn lookup(&self, name: &str, address: u64) -> Option<bool> {
        let Some((start, count, size)) = self.table else {
            return Some(false);
        };
        // The kernel's own binary search over the sorted export table.
        let mut base = start;
        let mut remaining = count;
        while remaining > 0 {
            let pivot = base + (remaining / 2) * size as u64;
            let candidate = self.name_at(pivot)?;
            match name.cmp(&candidate) {
                std::cmp::Ordering::Equal => return Some(self.value_at(pivot) == Some(address)),
                std::cmp::Ordering::Greater => {
                    base = pivot + size as u64;
                    remaining -= 1;
                }
                std::cmp::Ordering::Less => {}
            }
            remaining /= 2;
        }
        None
    }

    /// The name one export table entry holds.
    fn name_at(&self, entry: u64) -> Option<String> {
        match self.name_offset_at(entry) {
            Some(address) => read_string(&self.context, &self.layer, address, 512).ok(),
            None => None,
        }
    }

    /// Where that name lives, which kernels from 4.19 store as an offset from
    /// the entry itself rather than as a pointer.
    fn name_offset_at(&self, entry: u64) -> Option<u64> {
        let template = self
            .context
            .symbol_space
            .get_type(&crate::framework::symbols::join_name(
                self.layer_table().as_str(),
                "kernel_symbol",
            ))
            .ok()?;
        let object = self
            .context
            .object_from_template(template, &self.layer, entry);
        if object.has_member("name_offset") {
            let offset = object.member("name_offset").and_then(|v| v.as_i64()).ok()?;
            Some(entry.wrapping_add(offset as u64))
        } else {
            object.member("name").and_then(|v| v.pointer_value()).ok()
        }
    }

    /// The address that entry exports.
    fn value_at(&self, entry: u64) -> Option<u64> {
        let template = self
            .context
            .symbol_space
            .get_type(&crate::framework::symbols::join_name(
                self.layer_table().as_str(),
                "kernel_symbol",
            ))
            .ok()?;
        let object = self
            .context
            .object_from_template(template, &self.layer, entry);
        if object.has_member("value_offset") {
            let offset = object.member("value_offset").and_then(|v| v.as_i64()).ok()?;
            Some(entry.wrapping_add(offset as u64))
        } else {
            object.member("value").and_then(|v| v.as_u64()).ok()
        }
    }

    fn layer_table(&self) -> String {
        self.table_name.clone()
    }
}


/// The symbols ftrace keeps for the trampolines and modules it owns.
fn emit_ftrace(
    grid: &mut TreeGrid,
    context: &Arc<Context>,
    kernel: &Module,
    mask: u64,
) -> Result<()> {
    // Kernel 4.15 gave ftrace its own record of the module text it owns.
    if context
        .symbol_space
        .has_type(&kernel.qualified("ftrace_mod_map"))
        && context
            .symbol_space
            .has_type(&kernel.qualified("ftrace_mod_func"))
    {
        if let Ok(maps) = context.object_from_symbol(kernel, "ftrace_mod_maps", Some("list_head")) {
            for map in walk_list(&maps, &kernel.qualified("ftrace_mod_map"), "list", true)
                .unwrap_or_default()
            {
                let Ok(head) = map.member("funcs") else {
                    continue;
                };
                for function in walk_list(&head, &kernel.qualified("ftrace_mod_func"), "list", true)
                    .unwrap_or_default()
                {
                    let Ok(name) = function
                        .member("name")
                        .and_then(|name| pointer_to_string(&name, 512))
                    else {
                        continue;
                    };
                    let Ok(address) = function.member("ip").and_then(|ip| ip.as_u64()) else {
                        continue;
                    };
                    let size = function
                        .member("size")
                        .and_then(|size| size.as_i64())
                        .unwrap_or(0);
                    let module_name = map
                        .member("mod")
                        .and_then(|module| module.dereference())
                        .and_then(|module| module.member("name"))
                        .and_then(|name| array_to_string(&name))
                        .unwrap_or_default();
                    push_symbol(
                        grid,
                        address & mask,
                        Some('t'),
                        size,
                        Some(false),
                        "ftrace",
                        &module_name,
                        &name,
                    )?;
                }
            }
        }
    }

    // Kernel 5.9 chained the trampolines ftrace allocates onto a list.
    if !context.symbol_space.has_type(&kernel.qualified("ftrace_ops")) {
        return Ok(());
    }
    let Ok(head) = context.object_from_symbol(kernel, "ftrace_ops_trampoline_list", Some("list_head"))
    else {
        return Ok(());
    };
    for operations in walk_list(&head, &kernel.qualified("ftrace_ops"), "list", true)
        .unwrap_or_default()
    {
        let Ok(address) = operations
            .member("trampoline")
            .and_then(|value| value.as_u64())
        else {
            continue;
        };
        let size = operations
            .member("trampoline_size")
            .and_then(|value| value.as_i64())
            .unwrap_or(0);
        push_symbol(
            grid,
            address,
            Some('t'),
            size,
            Some(false),
            "ftrace",
            "[ftrace]",
            "ftrace_trampoline",
        )?;
    }
    Ok(())
}

/// The symbols the BPF JIT publishes for the programs it has compiled.
fn emit_bpf(
    grid: &mut TreeGrid,
    context: &Arc<Context>,
    kernel: &Module,
    mask: u64,
) -> Result<()> {
    let modern = context.symbol_space.has_type(&kernel.qualified("bpf_ksym"));
    let legacy = context
        .symbol_space
        .has_type(&kernel.qualified("bpf_prog_aux"));
    let (type_name, link) = if modern {
        // kernels >= 5.8
        ("bpf_ksym", "lnode")
    } else if legacy {
        // 3.18 <= kernels < 5.8
        ("bpf_prog_aux", "ksym_lnode")
    } else {
        return Ok(());
    };

    let Ok(head) = context.object_from_symbol(kernel, "bpf_kallsyms", Some("list_head")) else {
        return Ok(());
    };
    for entry in walk_list(&head, &kernel.qualified(type_name), link, true).unwrap_or_default() {
        let (name, address, size) = if modern {
            let Ok(name) = entry.member("name").and_then(|name| array_to_string(&name)) else {
                continue;
            };
            let Ok(start) = entry.member("start").and_then(|value| value.as_u64()) else {
                continue;
            };
            let end = entry
                .member("end")
                .and_then(|value| value.as_u64())
                .unwrap_or(start);
            (name, start, end.wrapping_sub(start) as i64)
        } else {
            let Ok(program) = entry.member("prog").and_then(|prog| prog.dereference()) else {
                continue;
            };
            let name = bpf_program_name(&program);
            let Ok(address) = program.member("bpf_func").and_then(|value| value.as_u64()) else {
                continue;
            };
            let size = program
                .member("jited_len")
                .and_then(|value| value.as_i64())
                .unwrap_or(0);
            (name, address, size)
        };

        push_symbol(
            grid,
            address & mask,
            Some('t'),
            size,
            Some(false),
            "bpf",
            "bpf",
            &name,
        )?;
    }
    Ok(())
}

/// The name a JIT-compiled BPF program is listed under.
///
/// A program that was given a name carries it; one that was not is named after
/// the tag the verifier gave it.
fn bpf_program_name(program: &Object) -> String {
    if let Ok(name) = program
        .member("aux")
        .and_then(|aux| aux.dereference())
        .and_then(|aux| aux.member("name"))
        .and_then(|name| array_to_string(&name))
    {
        if !name.is_empty() {
            return format!("bpf_prog_{name}");
        }
    }
    let tag = program
        .member("tag")
        .and_then(|tag| tag.bytes())
        .map(|bytes| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })
        .unwrap_or_default();
    format!("bpf_prog_{tag}")
}

/// A NUL-terminated string read straight out of a layer.
fn read_string(context: &Arc<Context>, layer: &str, address: u64, limit: usize) -> Result<String> {
    let data = context.layers.read(layer, address, limit, true)?;
    let end = data.iter().position(|byte| *byte == 0).unwrap_or(data.len());
    Ok(String::from_utf8_lossy(&data[..end]).into_owned())
}

/// A decoded symbol.
pub struct Symbol {
    pub address: u64,
    pub letter: char,
    pub name: String,
}

/// The pieces of the kernel's compressed symbol table.
pub struct KallsymsTable {
    count: u64,
    names: u64,
    token_table: u64,
    token_index: u64,
    /// Newer kernels store offsets from a base rather than absolute addresses.
    ///
    /// These markers are usually not in VMCOREINFO and are found during the
    /// bootstrap stage. If an ISF is available, they are fetched from there
    /// instead.
    offsets: Option<u64>,
    relative_base: u64,
    addresses: Option<u64>,
}

impl KallsymsTable {
    /// Locate the table's parts through the kernel's own symbols.
    pub fn load(context: &Arc<Context>, kernel: &Module) -> Result<Self> {
        // kallsyms_num_syms and kallsyms_markers[] types were updated from an
        // unsigned long to unsigned int in 4.20
        // 80ffbaa5b1bd98e80e3239a3b8cfda2da433009a.
        let count = context
            .object_from_symbol(kernel, "kallsyms_num_syms", None)
            .and_then(|value| value.as_u64())
            .map_err(|_| {
                VolatilityError::Other(
                    "This kernel does not export kallsyms_num_syms, so its symbol \
                     table cannot be decoded"
                        .to_string(),
                )
            })?;

        if count == 0 || count > MAX_SYMBOLS {
            return Err(VolatilityError::Other(format!(
                "Implausible kallsyms symbol count {count}"
            )));
        }

        // kernels >= 4.6 store addresses relative to
        // kallsyms_relative_base. It assumes
        // CONFIG_KALLSYMS_BASE_RELATIVE=y and
        // CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y. Earlier ones store absolute
        // addresses. Whichever symbol exists decides how they are read.
        let offsets = context.symbol_offset(kernel, "kallsyms_offsets").ok();
        let addresses = context.symbol_offset(kernel, "kallsyms_addresses").ok();
        let relative_base = context
            .object_from_symbol(kernel, "kallsyms_relative_base", None)
            .and_then(|value| value.as_u64())
            .unwrap_or(0);

        Ok(Self {
            count,
            names: context.symbol_offset(kernel, "kallsyms_names")?,
            token_table: context.symbol_offset(kernel, "kallsyms_token_table")?,
            token_index: context.symbol_offset(kernel, "kallsyms_token_index")?,
            offsets,
            relative_base,
            addresses,
        })
    }

    /// Expand every name and pair it with its address.
    pub fn decode(&self, context: &Arc<Context>, kernel: &Module) -> Result<Vec<Symbol>> {
        let tokens = self.read_tokens(context, kernel)?;

        // The names are packed back to back, each prefixed by its own length,
        // so they are walked in order rather than indexed.
        let mut results = Vec::with_capacity(self.count as usize);
        let mut position = self.names;

        for index in 0..self.count {
            let Ok(header) = context
                .layers
                .read(&kernel.layer_name, position, 1, false)
            else {
                break;
            };
            let length = header[0] as usize;
            position += 1;
            if length == 0 {
                continue;
            }

            let Ok(indices) = context
                .layers
                .read(&kernel.layer_name, position, length, false)
            else {
                break;
            };
            position += length as u64;

            // Each byte indexes the token table. Concatenating the tokens gives
            // the name, whose first character is the symbol's type letter.
            let mut expanded = String::new();
            for token in indices {
                if let Some(text) = tokens.get(token as usize) {
                    expanded.push_str(text);
                }
            }

            let mut characters = expanded.chars();
            let Some(letter) = characters.next() else {
                continue;
            };
            let name: String = characters.collect();

            let Some(address) = self.address_of(context, kernel, index) else {
                continue;
            };
            results.push(Symbol {
                address,
                letter,
                name,
            });
        }

        results.sort_by_key(|symbol| symbol.address);
        Ok(results)
    }

    /// Read the 256-entry token table.
    ///
    /// Preloads the kallsyms_token_index array, whose entries are each two
    /// bytes wide and give the token's offset within the table.
    fn read_tokens(&self, context: &Arc<Context>, kernel: &Module) -> Result<Vec<String>> {
        let raw_index = context
            .layers
            .read(&kernel.layer_name, self.token_index, 256 * 2, false)?;
        let table = context
            .layers
            .read(&kernel.layer_name, self.token_table, 0x4000, true)?;

        let mut tokens = Vec::with_capacity(256);
        for entry in 0..256 {
            let offset =
                u16::from_le_bytes([raw_index[entry * 2], raw_index[entry * 2 + 1]]) as usize;
            let text = table
                .get(offset..)
                .and_then(|slice| {
                    let end = slice.iter().position(|&byte| byte == 0)?;
                    std::str::from_utf8(&slice[..end]).ok()
                })
                .unwrap_or_default();
            tokens.push(text.to_string());
        }
        Ok(tokens)
    }

    /// The address of the symbol at `index`.
    fn address_of(&self, context: &Arc<Context>, kernel: &Module, index: u64) -> Option<u64> {
        if let Some(offsets) = self.offsets {
            let raw = context
                .layers
                .read(&kernel.layer_name, offsets + index * 4, 4, false)
                .ok()?;
            let offset = i32::from_le_bytes(raw.try_into().ok()?);
            // Positive offsets are absolute values. Negative offsets are
            // relative to kallsyms_relative_base - 1, as the kernel's
            // kallsyms_sym_address does.
            return Some(if offset >= 0 {
                offset as u64
            } else {
                self.relative_base
                    .wrapping_sub(1)
                    .wrapping_sub(offset as i64 as u64)
            });
        }

        let addresses = self.addresses?;
        let raw = context
            .layers
            .read(&kernel.layer_name, addresses + index * 8, 8, false)
            .ok()?;
        Some(u64::from_le_bytes(raw.try_into().ok()?))
    }
}
