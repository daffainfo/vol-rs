//! Decode the kernel's built-in symbol table.
//!
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
use crate::framework::symbols::linux::resolver::ModuleResolver;

pub struct Kallsyms;

/// A table larger than this means the count symbol was misread.
const MAX_SYMBOLS: u64 = 500_000;

/// What each `nm` type letter means, worded as the reference implementation does.
fn describe_type(letter: char) -> Option<&'static str> {
    // Case matters for a few letters, so an exact match is tried first.
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

        let table = KallsymsTable::load(&context, &kernel)?;
        let symbols = table.decode(&context, &kernel)?;

        let mut grid = TreeGrid::new(self.columns());
        if !core {
            // Nothing else can be listed, see below, so a request for only the
            // other groups produces nothing at all.
            if modules || ftrace || bpf {
                grid.mark_truncated();
            }
            return Ok(grid);
        }
        let mask = context.layers.address_mask(&kernel.layer_name);

        // Where the kernel image ends, used to size the last symbol in a region.
        let marker = |name: &str| context.symbol_offset(&kernel, name).ok().map(|a| a & mask);
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
                    // An upper-case letter marks a globally visible symbol.
                    Value::Bool(symbol.letter.is_ascii_uppercase()),
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
        // Only the core symbols can be listed. The reference implementation
        // goes on to the module, ftrace and BPF symbols, but on any kernel
        // built with PREL32 relocations it computes a module symbol's name
        // pointer as a plain integer and then rejects it as "not a Pointer",
        // ending its output there without a final newline. Asking for the core
        // symbols alone therefore finishes cleanly. Asking for any of the rest
        // stops where it stops.
        if modules || ftrace || bpf {
            grid.mark_truncated();
        }
        Ok(grid)
    }
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
    offsets: Option<u64>,
    relative_base: u64,
    addresses: Option<u64>,
}

impl KallsymsTable {
    /// Locate the table's parts through the kernel's own symbols.
    pub fn load(context: &Arc<Context>, kernel: &Module) -> Result<Self> {
        let count = context
            .object_from_symbol(kernel, "kallsyms_num_syms", Some("unsigned int"))
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

        // Kernels from 4.6 store relative offsets. Earlier ones store absolute
        // addresses. Whichever symbol exists decides how they are read.
        let offsets = context.symbol_offset(kernel, "kallsyms_offsets").ok();
        let addresses = context.symbol_offset(kernel, "kallsyms_addresses").ok();
        let relative_base = context
            .object_from_symbol(kernel, "kallsyms_relative_base", Some("unsigned long long"))
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
    fn read_tokens(&self, context: &Arc<Context>, kernel: &Module) -> Result<Vec<String>> {
        // The index gives each token's offset within the table.
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
            // With absolute per-cpu symbols a non-negative value is already an
            // address. A negative one counts back from just below the base, as
            // the kernel's kallsyms_sym_address does.
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
