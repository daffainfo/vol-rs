//! Attributing an address to the module that owns it.
//!
//! Several plugins report a raw handler address and need to say which driver or
//! DLL it belongs to, a handler that lies outside every loaded module, or
//! inside a different module than expected, is the signal those plugins exist
//! to surface.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Context, Module};
use crate::framework::objects::utility::unicode_string;
use crate::framework::objects::utility::walk_list;

/// One loaded module, reduced to what address attribution needs.
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

/// An index of loaded modules, sorted by base address for binary search.
pub struct ModuleResolver {
    modules: Vec<ModuleRange>,
    /// The symbol table to look symbols up in, when the owning module is the
    /// kernel itself.
    kernel_table: String,
    kernel_base: u64,
}

impl ModuleResolver {
    /// Build an index from the kernel's loaded module list.
    pub fn new(context: &Arc<Context>, kernel: &Module) -> Result<Self> {
        let head =
            context.object_from_symbol(kernel, "PsLoadedModuleList", Some("_LIST_ENTRY"))?;
        let entries = walk_list(
            &head,
            &kernel.qualified("_LDR_DATA_TABLE_ENTRY"),
            "InLoadOrderLinks",
            true,
        )?;

        let mut modules: Vec<ModuleRange> = Vec::new();
        for entry in entries {
            let Ok(base) = entry
                .member("DllBase")
                .and_then(|base| base.pointer_value())
            else {
                continue;
            };
            let size = entry
                .member("SizeOfImage")
                .and_then(|size| size.as_u64())
                .unwrap_or(0);
            if base == 0 || size == 0 {
                continue;
            }
            let name = entry
                .member("BaseDllName")
                .and_then(|name| unicode_string(&name))
                .unwrap_or_default();
            modules.push(ModuleRange { name, base, size });
        }

        modules.sort_by_key(|module| module.base);

        Ok(Self {
            modules,
            kernel_table: kernel.symbol_table_name.clone(),
            kernel_base: kernel.offset,
        })
    }

    pub fn modules(&self) -> &[ModuleRange] {
        &self.modules
    }

    /// The module owning `address`, if any does.
    pub fn module_for(&self, address: u64) -> Option<&ModuleRange> {
        // The candidate is the last module starting at or before the address.
        let index = self.modules.partition_point(|module| module.base <= address);
        if index == 0 {
            return None;
        }
        let candidate = &self.modules[index - 1];
        candidate.contains(address).then_some(candidate)
    }

    /// The nearest preceding kernel symbol to `address`, with its offset.
    ///
    /// Only meaningful for addresses inside the kernel image itself. Other
    /// modules have no symbols loaded.
    pub fn symbol_for(&self, context: &Arc<Context>, address: u64) -> Option<String> {
        let table = context.symbol_space.table(&self.kernel_table).ok()?;

        // Symbol addresses are relative to the kernel's load address.
        let relative = address.checked_sub(self.kernel_base)?;

        let mut best: Option<(u64, String)> = None;
        for name in table.symbols() {
            let Ok(symbol) = table.get_symbol(name) else {
                continue;
            };
            if symbol.address > relative {
                continue;
            }
            // Keep the closest preceding symbol, which is the one containing it.
            match &best {
                Some((address, _)) if *address >= symbol.address => {}
                _ => best = Some((symbol.address, name.to_string())),
            }
        }

        best.map(|(symbol_address, name)| {
            let delta = relative - symbol_address;
            if delta == 0 {
                name
            } else {
                format!("{name}+{delta:#x}")
            }
        })
    }

    /// Render `address` as `(module, symbol)` cells, both absent when it lies
    /// outside every loaded module, which is itself the finding.
    pub fn describe(&self, context: &Arc<Context>, address: u64) -> (Option<String>, Option<String>) {
        let Some(module) = self.module_for(address) else {
            return (None, None);
        };
        let name = module.name.clone();
        // Symbols are only available for the kernel image.
        let symbol = if module.base == self.kernel_base {
            self.symbol_for(context, address)
        } else {
            None
        };
        (Some(name), symbol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver() -> ModuleResolver {
        ModuleResolver {
            modules: vec![
                ModuleRange {
                    name: "ntoskrnl.exe".to_string(),
                    base: 0x1000,
                    size: 0x1000,
                },
                ModuleRange {
                    name: "driver.sys".to_string(),
                    base: 0x5000,
                    size: 0x500,
                },
            ],
            kernel_table: "nt".to_string(),
            kernel_base: 0x1000,
        }
    }

    #[test]
    fn addresses_resolve_to_their_owning_module() {
        let resolver = resolver();
        assert_eq!(resolver.module_for(0x1000).map(|m| m.name.as_str()), Some("ntoskrnl.exe"));
        assert_eq!(resolver.module_for(0x1FFF).map(|m| m.name.as_str()), Some("ntoskrnl.exe"));
        assert_eq!(resolver.module_for(0x5100).map(|m| m.name.as_str()), Some("driver.sys"));
    }

    #[test]
    fn addresses_in_no_module_resolve_to_nothing() {
        let resolver = resolver();
        // Below every module, in the gap between them, and past the last one.
        assert!(resolver.module_for(0x500).is_none());
        assert!(resolver.module_for(0x3000).is_none());
        assert!(resolver.module_for(0x9000).is_none());
        // An address one past a module's end is outside it.
        assert!(resolver.module_for(0x2000).is_none());
    }
}

/// The loaded modules, each treated as a span of memory that the kernel's own
/// symbols are looked up in.
///
/// Several plugins report a handler address by naming the module it falls in
/// and, where the kernel's symbols happen to name that exact address, the
/// symbol too. A module keeps its list order, and a name already taken is
/// given a number, so two drivers with the same base name stay apart.
pub struct ModuleCollection {
    modules: Vec<ModuleRange>,
    kernel_table: String,
}

impl ModuleCollection {
    /// Build the collection from the kernel's loaded module list.
    pub fn build(context: &Arc<Context>, kernel: &Module) -> Result<Self> {
        let head = context.object_from_symbol(kernel, "PsLoadedModuleList", Some("_LIST_ENTRY"))?;
        let entries = walk_list(
            &head,
            &kernel.qualified("_LDR_DATA_TABLE_ENTRY"),
            "InLoadOrderLinks",
            true,
        )?;

        // The kernel module is already known by that name, so a driver of the
        // same name would be numbered rather than replace it.
        let mut taken: Vec<String> = vec!["kernel".to_string()];
        let mut modules = Vec::new();
        for entry in entries {
            // A module with no readable name is of no use for attribution.
            let Ok(full_name) = entry
                .member("BaseDllName")
                .and_then(|name| unicode_string(&name))
            else {
                continue;
            };
            // Modules are named without their extension.
            let stem = match full_name.rfind('.') {
                Some(dot) => full_name[..dot].to_string(),
                None => full_name.clone(),
            };
            let name = free_name(&taken, &stem);
            taken.push(name.clone());

            let base = entry
                .member("DllBase")
                .and_then(|base| base.pointer_value())
                .unwrap_or(0);
            let size = entry
                .member("SizeOfImage")
                .and_then(|size| size.as_u64())
                .unwrap_or(0);
            modules.push(ModuleRange { name, base, size });
        }

        Ok(Self {
            modules,
            kernel_table: kernel.symbol_table_name.clone(),
        })
    }

    /// The modules spanning `address`, each with the symbols named at exactly
    /// that address.
    ///
    /// A module is asked about an address at its very end as well as inside
    /// it, and more than one module can answer.
    pub fn modules_at(&self, context: &Arc<Context>, address: u64) -> Vec<(String, Vec<String>)> {
        let table = context.symbol_space.table(&self.kernel_table).ok();
        self.modules
            .iter()
            .filter(|module| address >= module.base && address <= module.base + module.size)
            .map(|module| {
                let symbols = table
                    .as_ref()
                    .map(|table| table.symbols_at(address - module.base))
                    .unwrap_or_default();
                (module.name.clone(), symbols)
            })
            .collect()
    }
}

/// A name not already taken, numbered from the count of those that are.
fn free_name(taken: &[String], prefix: &str) -> String {
    let matching = taken
        .iter()
        .filter(|name| {
            name.strip_prefix(prefix)
                .map(|rest| rest.chars().all(|character| character.is_ascii_digit()))
                .unwrap_or(false)
        })
        .count();
    if matching == 0 {
        return prefix.to_string();
    }
    let mut count = matching;
    while taken.iter().any(|name| *name == format!("{prefix}{count}")) {
        count += 1;
    }
    format!("{prefix}{count}")
}
