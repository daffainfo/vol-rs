//! The analysis context: the layers, symbols and configuration a run works on.
//!
//! Everything a plugin touches hangs off a `Context`, which is shared behind an
//! `Arc` so objects can hold onto it cheaply. Interior mutability lets automagic
//! add layers and symbol tables after the context exists.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::error::{Result, VolatilityError};
use crate::framework::layers::LayerContainer;
use crate::framework::objects::template::Template;
use crate::framework::objects::Object;
use crate::framework::symbols::{SymbolSpace, SymbolTable};

/// A configuration value, as supplied on the command line or by automagic.
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigValue {
    Int(i64),
    Str(String),
    Bool(bool),
    Bytes(Vec<u8>),
    List(Vec<ConfigValue>),
}

impl ConfigValue {
    pub fn as_int(&self) -> Option<i64> {
        match self {
            ConfigValue::Int(value) => Some(*value),
            ConfigValue::Str(text) => text.parse().ok(),
            ConfigValue::Bool(value) => Some(*value as i64),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            ConfigValue::Str(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ConfigValue::Bool(value) => Some(*value),
            ConfigValue::Int(value) => Some(*value != 0),
            ConfigValue::Str(text) => match text.to_ascii_lowercase().as_str() {
                "true" | "yes" | "1" => Some(true),
                "false" | "no" | "0" => Some(false),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[ConfigValue]> {
        match self {
            ConfigValue::List(values) => Some(values),
            _ => None,
        }
    }
}

/// A hierarchical configuration store, keyed by dotted paths.
#[derive(Default)]
pub struct Configuration {
    values: RwLock<HashMap<String, ConfigValue>>,
}

impl Configuration {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, path: impl Into<String>, value: ConfigValue) {
        self.values.write().unwrap().insert(path.into(), value);
    }

    pub fn get(&self, path: &str) -> Option<ConfigValue> {
        self.values.read().unwrap().get(path).cloned()
    }

    pub fn get_int(&self, path: &str) -> Option<i64> {
        self.get(path).and_then(|value| value.as_int())
    }

    pub fn get_string(&self, path: &str) -> Option<String> {
        self.get(path)
            .and_then(|value| value.as_str().map(str::to_string))
    }

    pub fn get_bool(&self, path: &str) -> Option<bool> {
        self.get(path).and_then(|value| value.as_bool())
    }

    /// Every key under `prefix`, with the prefix stripped.
    pub fn branch(&self, prefix: &str) -> HashMap<String, ConfigValue> {
        let full_prefix = format!("{prefix}.");
        self.values
            .read()
            .unwrap()
            .iter()
            .filter_map(|(key, value)| {
                key.strip_prefix(&full_prefix)
                    .map(|suffix| (suffix.to_string(), value.clone()))
            })
            .collect()
    }

    /// All keys, sorted, for writing a configuration back out.
    pub fn entries(&self) -> Vec<(String, ConfigValue)> {
        let mut entries: Vec<(String, ConfigValue)> = self
            .values
            .read()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    }
}

/// Join configuration path components.
pub fn path_join(parts: &[&str]) -> String {
    parts
        .iter()
        .filter(|part| !part.is_empty())
        .copied()
        .collect::<Vec<&str>>()
        .join(".")
}

/// A symbol table bound to a layer and a load address.
///
/// Modules are how plugins name things: `kernel.object_from_symbol("PsActiveProcessHead")`
/// reads the symbol's address, offsets it by where the module is loaded, and
/// builds an object there.
pub struct Module {
    pub name: String,
    pub symbol_table_name: String,
    pub layer_name: String,
    /// Address the module is loaded at. Symbol addresses are relative to this
    /// when `absolute_symbol_addresses` is false.
    pub offset: u64,
    pub size: Option<u64>,
    /// Linux and Mac ISF files record absolute addresses. Windows PDB-derived
    /// ones record offsets from the module base.
    pub absolute_symbol_addresses: bool,
}

impl Module {
    pub fn new(
        name: impl Into<String>,
        symbol_table_name: impl Into<String>,
        layer_name: impl Into<String>,
        offset: u64,
    ) -> Self {
        Self {
            name: name.into(),
            symbol_table_name: symbol_table_name.into(),
            layer_name: layer_name.into(),
            offset,
            size: None,
            absolute_symbol_addresses: false,
        }
    }

    pub fn with_absolute_addresses(mut self, absolute: bool) -> Self {
        self.absolute_symbol_addresses = absolute;
        self
    }

    pub fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    /// Qualify a bare type name with this module's symbol table.
    pub fn qualified(&self, name: &str) -> String {
        if name.contains(crate::constants::BANG) {
            name.to_string()
        } else {
            crate::framework::symbols::join_name(&self.symbol_table_name, name)
        }
    }
}

/// Everything an analysis run operates on.
pub struct Context {
    pub layers: LayerContainer,
    pub symbol_space: SymbolSpace,
    pub config: Configuration,
    modules: RwLock<HashMap<String, Arc<Module>>>,
    /// Where to find symbol files, so a plugin that needs one of the bundled
    /// tables can load it without being handed the search path.
    symbol_paths: RwLock<Vec<std::path::PathBuf>>,
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context {
    pub fn new() -> Self {
        Self {
            layers: LayerContainer::new(),
            symbol_space: SymbolSpace::new(),
            config: Configuration::new(),
            modules: RwLock::new(HashMap::new()),
            symbol_paths: RwLock::new(Vec::new()),
        }
    }

    pub fn add_symbol_table(&self, table: Arc<SymbolTable>) {
        self.symbol_space.append(table);
    }

    /// Record where symbol files may be found.
    pub fn set_symbol_paths(&self, paths: Vec<std::path::PathBuf>) {
        *self.symbol_paths.write().unwrap() = paths;
    }

    /// A finder over the directories this run searches for symbols.
    pub fn symbol_finder(&self) -> crate::framework::symbols::intermed::SymbolFinder {
        crate::framework::symbols::intermed::SymbolFinder::new(
            self.symbol_paths.read().unwrap().clone(),
        )
    }

    /// Let a second name refer to an existing symbol table.
    ///
    /// The bundled files refer to the kernel's types under a placeholder name,
    /// which has to resolve to whatever this image's kernel table is called.
    pub fn alias_symbol_table(&self, alias: &str, target: &str) -> Result<()> {
        if self.symbol_space.contains(alias) {
            return Ok(());
        }
        let table = self.symbol_space.table(target)?;
        self.symbol_space.append_as(alias, table);
        Ok(())
    }

    /// Load one of the bundled symbol files, if it is not loaded already.
    ///
    /// Several plugins need types the kernel's own symbols do not carry (the
    /// 32-bit view of a process, the layout of a PE header), which ship as
    /// their own small files.
    pub fn ensure_table(&self, name: &str, sub_path: &str, filename: &str) -> Result<()> {
        if self.symbol_space.contains(name) {
            return Ok(());
        }
        let finder = self.symbol_finder();
        let table =
            crate::framework::symbols::intermed::create_from_file(&finder, name, sub_path, filename)?;
        self.add_symbol_table(table);
        Ok(())
    }

    pub fn add_module(&self, module: Module) -> Arc<Module> {
        let module = Arc::new(module);
        self.modules
            .write()
            .unwrap()
            .insert(module.name.clone(), module.clone());
        module
    }

    pub fn module(&self, name: &str) -> Result<Arc<Module>> {
        self.modules
            .read()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or_else(|| VolatilityError::MissingModule(name.to_string()))
    }

    pub fn module_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.modules.read().unwrap().keys().cloned().collect();
        names.sort();
        names
    }

    /// Build an object of type `type_name` at `offset` in `layer_name`.
    pub fn object(
        self: &Arc<Self>,
        type_name: &str,
        layer_name: &str,
        offset: u64,
    ) -> Result<Object> {
        let template = self.symbol_space.get_type(type_name)?;
        Ok(Object::new(self.clone(), template, layer_name, offset))
    }

    /// Build an object from an already-resolved template.
    pub fn object_from_template(
        self: &Arc<Self>,
        template: Arc<Template>,
        layer_name: &str,
        offset: u64,
    ) -> Object {
        Object::new(self.clone(), template, layer_name, offset)
    }

    /// Build an object of a module's type at an offset in the module's layer.
    pub fn module_object(
        self: &Arc<Self>,
        module: &Module,
        type_name: &str,
        offset: u64,
    ) -> Result<Object> {
        self.object(&module.qualified(type_name), &module.layer_name, offset)
    }

    /// Resolve a symbol in a module and build the object it names.
    pub fn object_from_symbol(
        self: &Arc<Self>,
        module: &Module,
        symbol_name: &str,
        type_name: Option<&str>,
    ) -> Result<Object> {
        let symbol = self
            .symbol_space
            .get_symbol(&module.qualified(symbol_name))?;
        let address = self.symbol_address(module, &symbol.address);

        let template = match type_name {
            Some(name) => self.symbol_space.get_type(&module.qualified(name))?,
            None => symbol.type_template.clone().ok_or_else(|| {
                VolatilityError::symbol(
                    Some(module.symbol_table_name.clone()),
                    Some(symbol_name.to_string()),
                    format!("Symbol '{symbol_name}' has no type; supply one explicitly"),
                )
            })?,
        };

        Ok(Object::new(
            self.clone(),
            template,
            module.layer_name.clone(),
            address,
        ))
    }

    /// The address of a symbol in a module, applying the load offset when the
    /// symbol table stores relative addresses.
    pub fn symbol_address(&self, module: &Module, symbol_address: &u64) -> u64 {
        if module.absolute_symbol_addresses {
            *symbol_address
        } else {
            module.offset.wrapping_add(*symbol_address)
        }
    }

    /// Resolve a symbol to its final address within a module.
    pub fn symbol_offset(&self, module: &Module, symbol_name: &str) -> Result<u64> {
        let symbol = self
            .symbol_space
            .get_symbol(&module.qualified(symbol_name))?;
        Ok(self.symbol_address(module, &symbol.address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_branches_strip_their_prefix() {
        let config = Configuration::new();
        config.set("plugins.PsList.pid", ConfigValue::Int(4));
        config.set("plugins.PsList.dump", ConfigValue::Bool(true));
        config.set("other.value", ConfigValue::Int(1));

        let branch = config.branch("plugins.PsList");
        assert_eq!(branch.len(), 2);
        assert_eq!(branch["pid"], ConfigValue::Int(4));
    }

    #[test]
    fn module_addresses_respect_the_addressing_mode() {
        let context = Context::new();
        let relative = Module::new("kernel", "nt", "layer", 0x1000);
        assert_eq!(context.symbol_address(&relative, &0x40), 0x1040);

        let absolute = Module::new("kernel", "nt", "layer", 0x1000)
            .with_absolute_addresses(true);
        assert_eq!(context.symbol_address(&absolute, &0x40), 0x40);
    }

    #[test]
    fn path_join_skips_empty_components() {
        assert_eq!(path_join(&["plugins", "", "PsList"]), "plugins.PsList");
    }
}
