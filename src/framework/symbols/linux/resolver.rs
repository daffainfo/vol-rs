//! Attributing a kernel address to the module that owns it.
//!
//! The `check_*` plugins all work the same way: read a table of function
//! pointers the kernel dispatches through, and report which module each entry
//! belongs to. An entry owned by no module, or by an unexpected one, is a hook.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Context, Module};
use crate::framework::symbols::linux::list_modules;

/// One loaded module's address range.
#[derive(Debug, Clone)]
pub struct ModuleRange {
    pub name: String,
    pub base: u64,
    pub size: u64,
}

impl ModuleRange {
    pub fn contains(&self, address: u64) -> bool {
        address >= self.base && address < self.base.saturating_add(self.size)
    }
}

/// An index of loaded modules plus the kernel's own symbols.
pub struct ModuleResolver {
    modules: Vec<ModuleRange>,
    /// The kernel image itself, spanning `_text` to `_etext`.
    kernel_range: Option<ModuleRange>,
    /// Runtime address of each kernel symbol, keyed as the symbol table records
    /// it relative to the module. Where several symbols share an address the
    /// alphabetically first is kept, which is the one upstream reports.
    symbols: HashMap<u64, String>,
    /// Every kernel symbol address in order, for containment lookups.
    sorted: Vec<(u64, String)>,
    /// Displacement between a symbol's recorded address and its runtime one.
    shift: u64,
    /// The bits the kernel layer actually addresses.
    mask: u64,
}

/// The name upstream gives to the kernel image, to distinguish it from a module.
const KERNEL_NAME: &str = "__kernel__";

impl ModuleResolver {
    pub fn new(context: &Arc<Context>, kernel: &Module) -> Result<Self> {
        let mask = context.layers.address_mask(&kernel.layer_name);
        let shift = if kernel.absolute_symbol_addresses {
            0
        } else {
            kernel.offset
        };

        let mut modules: Vec<ModuleRange> = Vec::new();

        for module in list_modules(context, kernel)? {
            let Ok(name) = module.name() else { continue };
            // The base is where the module's code was loaded, which lives under
            // a layout structure whose name changed across kernel versions.
            let base = ["core_layout", "mem"]
                .iter()
                .find_map(|container| {
                    module
                        .object
                        .member(container)
                        .and_then(|layout| layout.member("base"))
                        .and_then(|base| base.pointer_value())
                        .ok()
                })
                .or_else(|| {
                    module
                        .object
                        .member("module_core")
                        .and_then(|base| base.pointer_value())
                        .ok()
                });

            let (Some(base), Ok(size)) = (base, module.code_size()) else {
                continue;
            };
            if base == 0 || size == 0 {
                continue;
            }
            modules.push(ModuleRange {
                name,
                base: base & mask,
                size,
            });
        }

        modules.sort_by_key(|module| module.base);

        // The kernel image occupies its own range, which is what makes a
        // function pointer into the kernel distinguishable from a stray one.
        let range_end = |name: &str| -> Option<u64> {
            context
                .object_from_symbol(kernel, name, Some("long unsigned int"))
                .ok()
                .map(|object| object.offset())
                .or_else(|| context.symbol_offset(kernel, name).ok().map(|a| a & mask))
        };
        let kernel_range = match (range_end("_text"), range_end("_etext")) {
            (Some(start), Some(end)) if end > start => Some(ModuleRange {
                name: KERNEL_NAME.to_string(),
                base: start,
                size: end - start,
            }),
            _ => None,
        };

        // Index every kernel symbol by the address it sits at once loaded.
        let mut symbols: HashMap<u64, String> = HashMap::new();
        if let Ok(table) = context.symbol_space.table(&kernel.symbol_table_name) {
            for name in table.symbols() {
                let Ok(symbol) = table.get_symbol(name) else {
                    continue;
                };
                let address = symbol.address & mask;
                match symbols.get(&address) {
                    Some(existing) if existing.as_str() <= name => {}
                    _ => {
                        symbols.insert(address, name.to_string());
                    }
                }
            }
        }

        let mut sorted: Vec<(u64, String)> = symbols
            .iter()
            .map(|(address, name)| (*address, name.clone()))
            .collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        Ok(Self {
            modules,
            kernel_range,
            symbols,
            sorted,
            shift,
            mask,
        })
    }

    /// Where the kernel image starts, if its bounds were found.
    pub fn kernel_base(&self) -> Option<u64> {
        self.kernel_range.as_ref().map(|range| range.base)
    }

    pub fn modules(&self) -> &[ModuleRange] {
        &self.modules
    }

    /// The module owning `address`, if a loaded one does.
    pub fn module_for(&self, address: u64) -> Option<&ModuleRange> {
        let index = self.modules.partition_point(|module| module.base <= address);
        if index == 0 {
            return None;
        }
        let candidate = &self.modules[index - 1];
        candidate.contains(address).then_some(candidate)
    }

    /// The kernel symbol whose range contains `address`.
    ///
    /// Unlike an exact lookup this answers "which function is this inside",
    /// which is what a stack walk needs: a return address points into the middle
    /// of a function, not at its entry.
    pub fn symbol_containing(&self, address: u64) -> Option<String> {
        let relative = (address.wrapping_sub(self.shift)) & self.mask;
        let index = self.sorted.partition_point(|(start, _)| *start <= relative);
        if index == 0 {
            return None;
        }
        let (_start, name) = &self.sorted[index - 1];
        // The symbol runs to wherever the next one begins.
        let end = self
            .sorted
            .get(index)
            .map(|(next, _)| *next)
            .unwrap_or(u64::MAX);
        (relative < end).then(|| name.clone())
    }

    /// The kernel symbol sitting exactly at `address`.
    ///
    /// Only an exact hit counts: reporting the nearest preceding symbol plus an
    /// offset would name a function that does not contain the address at all.
    pub fn symbol_for(&self, _context: &Arc<Context>, address: u64) -> Option<String> {
        let relative = (address.wrapping_sub(self.shift)) & self.mask;
        self.symbols.get(&relative).cloned()
    }

    /// Describe an address as `(module, symbol)`.
    ///
    /// An address inside no module belongs to the kernel image itself, which is
    /// reported as `__kernel__` so it is distinguishable from an unowned one.
    pub fn describe(
        &self,
        context: &Arc<Context>,
        address: u64,
    ) -> (Option<String>, Option<String>) {
        if address == 0 {
            return (None, None);
        }
        if let Some(module) = self.module_for(address) {
            return (Some(module.name.clone()), None);
        }
        match &self.kernel_range {
            Some(range) if range.contains(address) => (
                Some(KERNEL_NAME.to_string()),
                self.symbol_for(context, address),
            ),
            _ => (None, None),
        }
    }
}
