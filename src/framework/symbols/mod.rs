//! Symbol tables and the space that holds them.
//!
//! A `SymbolTable` wraps one parsed ISF file and turns its type descriptors
//! into object templates on demand. A `SymbolSpace` holds several tables and
//! resolves `table!name` references between them.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

pub mod isf;
pub mod native;
pub mod intermed;
pub mod windows;
pub mod linux;
pub mod mac;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::constants::BANG;
use crate::error::{Result, VolatilityError};
use crate::framework::objects::template::{
    EnumTemplate, Encoding, Member, ReferenceKind, StructTemplate, Template,
};
use crate::framework::symbols::isf::{
    BaseKind, Endian, IsfFile, StructKind, SymbolEntry, TypeDescriptor,
};
use crate::framework::symbols::native::NativeTable;

/// Split `table!name` into its parts. A name with no separator belongs to the
/// table doing the lookup.
pub fn split_name(full_name: &str) -> (Option<&str>, &str) {
    match full_name.split_once(BANG) {
        Some((table, name)) => (Some(table), name),
        None => (None, full_name),
    }
}

/// Join a table and a type name into a fully qualified name.
pub fn join_name(table: &str, name: &str) -> String {
    format!("{table}{BANG}{name}")
}

/// A resolved symbol: where it lives and, if known, what type it has.
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub type_template: Option<Arc<Template>>,
    pub constant_data: Option<Vec<u8>>,
}

/// One ISF file, plus the machinery to turn its types into templates.
pub struct SymbolTable {
    /// Where the file was read from, as a URL. Plugins that describe an image
    /// report this, so it has to survive loading.
    source: RwLock<Option<String>>,
    name: String,
    isf: IsfFile,
    /// Base types not defined by the file itself, such as `pointer` on tables
    /// produced by tooling that omits it.
    native: Arc<NativeTable>,
    /// Templates already built, keyed by type name.
    cache: RwLock<HashMap<String, Arc<Template>>>,
    /// Address to symbol names, built lazily because most runs never need it.
    by_address: RwLock<Option<Arc<HashMap<u64, Vec<String>>>>>,
}

impl SymbolTable {
    pub fn new(name: impl Into<String>, isf: IsfFile, native: Arc<NativeTable>) -> Self {
        Self {
            source: RwLock::new(None),
            name: name.into(),
            isf,
            native,
            cache: RwLock::new(HashMap::new()),
            by_address: RwLock::new(None),
        }
    }

    /// Record where this table was read from.
    pub fn set_source(&self, source: impl Into<String>) {
        *self.source.write().unwrap() = Some(source.into());
    }

    /// Where this table was read from, as a URL.
    pub fn source(&self) -> Option<String> {
        self.source.read().unwrap().clone()
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn isf(&self) -> &IsfFile {
        &self.isf
    }

    pub fn metadata(&self) -> &isf::Metadata {
        &self.isf.metadata
    }

    /// The width of a pointer in this table, which decides the architecture's
    /// bitness for most purposes.
    pub fn pointer_size(&self) -> usize {
        self.isf
            .base_types
            .get("pointer")
            .map(|base| base.size)
            .unwrap_or(self.native.pointer_size())
    }

    /// Every type name the table can produce.
    pub fn types(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .isf
            .user_types
            .keys()
            .chain(self.isf.base_types.keys())
            .chain(self.isf.enums.keys())
            .map(String::as_str)
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }

    /// Every symbol name in the table.
    pub fn symbols(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.isf.symbols.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    pub fn has_type(&self, name: &str) -> bool {
        self.isf.user_types.contains_key(name)
            || self.isf.base_types.contains_key(name)
            || self.isf.enums.contains_key(name)
            || self.native.has_type(name)
    }

    pub fn has_symbol(&self, name: &str) -> bool {
        self.isf.symbols.contains_key(name)
    }

    /// Look up a symbol, resolving its type if it has one.
    pub fn get_symbol(&self, name: &str) -> Result<Symbol> {
        let entry = self.isf.symbols.get(name).ok_or_else(|| {
            VolatilityError::symbol(
                Some(self.name.clone()),
                Some(name.to_string()),
                format!("Symbol '{name}' not found in table '{}'", self.name),
            )
        })?;
        self.symbol_from_entry(name, entry)
    }

    fn symbol_from_entry(&self, name: &str, entry: &SymbolEntry) -> Result<Symbol> {
        let type_template = match &entry.type_descriptor {
            Some(descriptor) => Some(self.build_template(descriptor)?),
            None => None,
        };
        Ok(Symbol {
            name: name.to_string(),
            address: entry.address,
            type_template,
            constant_data: entry.constant_data.clone(),
        })
    }

    /// Symbol names at an exact address.
    pub fn symbols_at(&self, address: u64) -> Vec<String> {
        let index = self.address_index();
        index.get(&address).cloned().unwrap_or_default()
    }

    /// Build (once) and return the address-to-name index.
    fn address_index(&self) -> Arc<HashMap<u64, Vec<String>>> {
        if let Some(index) = self.by_address.read().unwrap().as_ref() {
            return index.clone();
        }
        let mut index: HashMap<u64, Vec<String>> = HashMap::new();
        for (name, entry) in &self.isf.symbols {
            index.entry(entry.address).or_default().push(name.clone());
        }
        for names in index.values_mut() {
            names.sort();
        }
        let index = Arc::new(index);
        *self.by_address.write().unwrap() = Some(index.clone());
        index
    }

    /// Resolve a type name into a template, expanding user types and enums.
    pub fn get_type(&self, name: &str) -> Result<Arc<Template>> {
        if let Some(cached) = self.cache.read().unwrap().get(name) {
            return Ok(cached.clone());
        }

        let template = self.build_named_type(name)?;
        self.cache
            .write()
            .unwrap()
            .insert(name.to_string(), template.clone());
        Ok(template)
    }

    fn build_named_type(&self, name: &str) -> Result<Arc<Template>> {
        if let Some(user_type) = self.isf.user_types.get(name) {
            let mut members = Vec::new();
            for (field_name, field) in &user_type.fields {
                // A field whose type cannot be built should not sink the whole
                // struct. Skip it and let member access report the absence.
                match self.build_template(&field.type_descriptor) {
                    Ok(template) => members.push(Member {
                        name: field_name.clone(),
                        offset: field.offset,
                        template,
                        anonymous: field.anonymous,
                    }),
                    Err(error) => {
                        log::debug!("Skipping member '{name}.{field_name}': {error}")
                    }
                }
            }
            members.sort_by(|a, b| a.offset.cmp(&b.offset).then(a.name.cmp(&b.name)));

            let mut index = HashMap::new();
            for (position, member) in members.iter().enumerate() {
                index.insert(member.name.clone(), position);
            }

            return Ok(Arc::new(Template::Struct(Arc::new(StructTemplate {
                name: name.to_string(),
                table: self.name.clone(),
                kind: user_type.kind,
                size: user_type.size,
                members,
                index,
            }))));
        }

        if let Some(enum_type) = self.isf.enums.get(name) {
            let base = self
                .isf
                .base_types
                .get(&enum_type.base)
                .cloned()
                .or_else(|| self.native.base_type(&enum_type.base));
            let (signed, endian) = base
                .map(|base| (base.signed, base.endian))
                .unwrap_or((false, Endian::Little));

            let mut inverse = HashMap::new();
            for (constant_name, value) in &enum_type.constants {
                // Several names can share a value. Keep the first alphabetically
                // so output is stable between runs.
                inverse
                    .entry(*value)
                    .and_modify(|existing: &mut String| {
                        if constant_name < existing {
                            *existing = constant_name.clone();
                        }
                    })
                    .or_insert_with(|| constant_name.clone());
            }

            return Ok(Arc::new(Template::Enumeration(Arc::new(EnumTemplate {
                name: name.to_string(),
                table: self.name.clone(),
                size: enum_type.size,
                signed,
                endian,
                choices: enum_type.constants.clone(),
                inverse,
            }))));
        }

        if let Some(base) = self.isf.base_types.get(name) {
            return Ok(Arc::new(base_template(base)));
        }

        if let Some(template) = self.native.get_type(name) {
            return Ok(template);
        }

        Err(VolatilityError::symbol(
            Some(self.name.clone()),
            Some(name.to_string()),
            format!("Type '{name}' not found in table '{}'", self.name),
        ))
    }

    /// Turn an ISF type descriptor into a template. Named types become lazy
    /// references so recursive types terminate.
    pub fn build_template(&self, descriptor: &TypeDescriptor) -> Result<Arc<Template>> {
        Ok(match descriptor {
            TypeDescriptor::Base { name } => {
                if let Some(base) = self.isf.base_types.get(name) {
                    Arc::new(base_template(base))
                } else if let Some(template) = self.native.get_type(name) {
                    template
                } else {
                    return Err(VolatilityError::symbol(
                        Some(self.name.clone()),
                        Some(name.clone()),
                        format!("Base type '{name}' is not defined"),
                    ));
                }
            }
            TypeDescriptor::Struct { name, .. } => Arc::new(Template::Reference {
                table: self.name.clone(),
                name: name.clone(),
                kind: ReferenceKind::UserType,
            }),
            TypeDescriptor::Enum { name } => Arc::new(Template::Reference {
                table: self.name.clone(),
                name: name.clone(),
                kind: ReferenceKind::Enumeration,
            }),
            TypeDescriptor::Pointer { subtype, base } => {
                let (size, endian) = base
                    .as_ref()
                    .and_then(|base| self.isf.base_types.get(base))
                    .or_else(|| self.isf.base_types.get("pointer"))
                    .map(|base| (base.size, base.endian))
                    .unwrap_or((self.native.pointer_size(), Endian::Little));
                Arc::new(Template::Pointer {
                    size,
                    endian,
                    subtype: self.build_template(subtype)?,
                })
            }
            TypeDescriptor::Array { subtype, count } => Arc::new(Template::Array {
                count: *count,
                subtype: self.build_template(subtype)?,
            }),
            TypeDescriptor::Function => Arc::new(Template::Function),
            TypeDescriptor::Bitfield {
                bit_position,
                bit_length,
                inner,
            } => Arc::new(Template::Bitfield {
                base: self.build_template(inner)?,
                start_bit: *bit_position,
                end_bit: bit_position + bit_length,
            }),
        })
    }
}

/// Turn an ISF base type into the matching template.
fn base_template(base: &isf::BaseType) -> Template {
    match base.kind {
        BaseKind::Void => Template::Void,
        BaseKind::Int => Template::Integer {
            size: base.size,
            signed: base.signed,
            endian: base.endian,
        },
        BaseKind::Float => Template::Float {
            size: base.size,
            endian: base.endian,
        },
        BaseKind::Char => Template::Char {
            size: base.size,
            signed: base.signed,
        },
        BaseKind::Bool => Template::Bool { size: base.size },
    }
}

/// Holds every symbol table in play and resolves references between them.
#[derive(Default)]
pub struct SymbolSpace {
    tables: RwLock<HashMap<String, Arc<SymbolTable>>>,
    /// Struct and enum templates already resolved, keyed by `table!name`.
    resolved: RwLock<HashMap<String, Arc<Template>>>,
}

impl SymbolSpace {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&self, table: Arc<SymbolTable>) {
        let name = table.name().to_string();
        self.resolved.write().unwrap().clear();
        self.tables.write().unwrap().insert(name, table);
    }

    pub fn remove(&self, name: &str) {
        self.resolved.write().unwrap().clear();
        self.tables.write().unwrap().remove(name);
    }

    /// Register `table` under another name as well.
    pub fn append_as(&self, name: &str, table: Arc<SymbolTable>) {
        self.tables
            .write()
            .unwrap()
            .insert(name.to_string(), table);
    }

    pub fn contains(&self, name: &str) -> bool {
        self.tables.read().unwrap().contains_key(name)
    }

    pub fn table(&self, name: &str) -> Result<Arc<SymbolTable>> {
        self.tables
            .read()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or_else(|| {
                VolatilityError::SymbolSpace(format!("Symbol table '{name}' does not exist"))
            })
    }

    pub fn table_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.tables.read().unwrap().keys().cloned().collect();
        names.sort();
        names
    }

    /// A free table name derived from `prefix`.
    pub fn free_table_name(&self, prefix: &str) -> String {
        // Upstream numbers from one and never hands out the bare prefix, and
        // the name reaches the output of at least one plugin, so the numbering
        // is part of what has to match.
        let guard = self.tables.read().unwrap();
        for index in 1.. {
            let candidate = format!("{prefix}{index}");
            if !guard.contains_key(&candidate) {
                return candidate;
            }
        }
        unreachable!()
    }

    /// Resolve a fully qualified `table!type` name into a template.
    /// The names of the symbols at an exact address, across every table.
    ///
    /// The addresses are the ones the symbol file records, so a name is only
    /// found for an address that has not been shifted.
    pub fn symbols_at(&self, address: u64) -> Vec<String> {
        let mut names = Vec::new();
        for table in self.tables.read().unwrap().values() {
            names.extend(table.symbols_at(address));
        }
        names
    }

    pub fn get_type(&self, full_name: &str) -> Result<Arc<Template>> {
        let (table_name, type_name) = split_name(full_name);
        let table_name = table_name.ok_or_else(|| {
            VolatilityError::SymbolSpace(format!(
                "Type name '{full_name}' must be qualified with a table name"
            ))
        })?;
        self.table(table_name)?.get_type(type_name)
    }

    /// Resolve a fully qualified `table!symbol` name.
    pub fn get_symbol(&self, full_name: &str) -> Result<Symbol> {
        let (table_name, symbol_name) = split_name(full_name);
        let table_name = table_name.ok_or_else(|| {
            VolatilityError::SymbolSpace(format!(
                "Symbol name '{full_name}' must be qualified with a table name"
            ))
        })?;
        self.table(table_name)?.get_symbol(symbol_name)
    }

    pub fn has_type(&self, full_name: &str) -> bool {
        let (table_name, type_name) = split_name(full_name);
        match table_name.and_then(|name| self.table(name).ok()) {
            Some(table) => table.has_type(type_name),
            None => false,
        }
    }

    pub fn has_symbol(&self, full_name: &str) -> bool {
        let (table_name, symbol_name) = split_name(full_name);
        match table_name.and_then(|name| self.table(name).ok()) {
            Some(table) => table.has_symbol(symbol_name),
            None => false,
        }
    }

    /// Expand a template until it is no longer a reference.
    ///
    /// This is where recursive types stop being a problem: the reference is
    /// only followed when a caller genuinely needs the members.
    pub fn resolve(&self, template: &Arc<Template>) -> Result<Arc<Template>> {
        let Template::Reference { table, name, .. } = template.as_ref() else {
            return Ok(template.clone());
        };

        // A file may name a type in another table, the bundled ones refer to
        // the kernel's types that way, so a name that carries its own table is
        // resolved against that one.
        let (table, name) = match split_name(name) {
            (Some(other), bare) => (other.to_string(), bare.to_string()),
            (None, bare) => (table.clone(), bare.to_string()),
        };

        let key = join_name(&table, &name);
        if let Some(cached) = self.resolved.read().unwrap().get(&key) {
            return Ok(cached.clone());
        }

        let resolved = self.table(&table)?.get_type(&name)?;
        self.resolved.write().unwrap().insert(key, resolved.clone());
        Ok(resolved)
    }

    /// The size of a template, following references as needed.
    pub fn size_of(&self, template: &Arc<Template>) -> Result<u64> {
        if let Some(size) = template.static_size() {
            return Ok(size);
        }
        match template.as_ref() {
            Template::Reference { .. } => {
                let resolved = self.resolve(template)?;
                self.size_of(&resolved)
            }
            Template::Array { count, subtype } => Ok(count * self.size_of(subtype)?),
            _ => Ok(0),
        }
    }

    /// Look up a member, following anonymous members into their contents.
    ///
    /// Returns the member's offset relative to the start of `template` and its
    /// template, so a member of an anonymous union reads at the right place.
    pub fn find_member(
        &self,
        template: &Arc<Template>,
        member_name: &str,
    ) -> Result<Option<(u64, Arc<Template>)>> {
        let resolved = self.resolve(template)?;
        let Some(structure) = resolved.as_struct() else {
            return Ok(None);
        };

        if let Some(member) = structure.member(member_name) {
            return Ok(Some((member.offset, member.template.clone())));
        }

        // C allows unnamed structs and unions whose members belong to the
        // enclosing type. Search into them.
        for member in &structure.members {
            if !member.anonymous {
                continue;
            }
            if let Some((offset, template)) = self.find_member(&member.template, member_name)? {
                return Ok(Some((member.offset + offset, template)));
            }
        }
        Ok(None)
    }
}

/// A convenient handle for a `String` template with an encoding chosen by the
/// caller.
pub fn string_template(max_length: usize, encoding: Encoding) -> Arc<Template> {
    Arc::new(Template::String {
        max_length,
        encoding,
    })
}

/// Convenience for building a struct-kind reference.
pub fn reference(table: &str, name: &str, kind: StructKind) -> Template {
    let _ = kind;
    Template::Reference {
        table: table.to_string(),
        name: name.to_string(),
        kind: ReferenceKind::UserType,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::symbols::native::x64_native_table;

    const SAMPLE: &str = r#"{
        "metadata": {"format": "6.2.0"},
        "base_types": {
            "int": {"size": 4, "signed": true, "kind": "int", "endian": "little"},
            "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
            "unsigned char": {"size": 1, "signed": false, "kind": "char", "endian": "little"}
        },
        "user_types": {
            "_LIST_ENTRY": {"kind": "struct", "size": 16, "fields": {
                "Flink": {"offset": 0, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}}
            }},
            "_INNER": {"kind": "struct", "size": 8, "fields": {
                "Hidden": {"offset": 4, "type": {"kind": "base", "name": "int"}}
            }},
            "_OUTER": {"kind": "struct", "size": 16, "fields": {
                "Anon": {"offset": 8, "anonymous": true, "type": {"kind": "struct", "name": "_INNER"}}
            }}
        },
        "enums": {
            "_POOL_TYPE": {"size": 4, "base": "int", "constants": {"NonPagedPool": 0, "PagedPool": 1}}
        },
        "symbols": {"PsInitialSystemProcess": {"address": 4096}}
    }"#;

    fn space() -> SymbolSpace {
        let isf = IsfFile::from_slice(SAMPLE.as_bytes()).unwrap();
        let table = SymbolTable::new("nt", isf, x64_native_table());
        let space = SymbolSpace::new();
        space.append(Arc::new(table));
        space
    }

    #[test]
    fn resolves_types_and_symbols_across_the_space() {
        let space = space();
        let list = space.get_type("nt!_LIST_ENTRY").unwrap();
        assert_eq!(space.size_of(&list).unwrap(), 16);
        assert_eq!(space.get_symbol("nt!PsInitialSystemProcess").unwrap().address, 4096);
    }

    #[test]
    fn recursive_types_terminate() {
        let space = space();
        let list = space.get_type("nt!_LIST_ENTRY").unwrap();
        let (offset, flink) = space.find_member(&list, "Flink").unwrap().unwrap();
        assert_eq!(offset, 0);
        // The pointer's subtype is still a reference, so resolution stopped.
        match flink.as_ref() {
            Template::Pointer { subtype, size, .. } => {
                assert_eq!(*size, 8);
                assert!(subtype.is_reference());
            }
            other => panic!("expected a pointer, got {other:?}"),
        }
    }

    #[test]
    fn anonymous_members_are_searched_through() {
        let space = space();
        let outer = space.get_type("nt!_OUTER").unwrap();
        let (offset, _) = space.find_member(&outer, "Hidden").unwrap().unwrap();
        // 8 for the anonymous member's own offset, 4 for the field inside it.
        assert_eq!(offset, 12);
    }

    #[test]
    fn enumerations_render_names_for_known_values() {
        let space = space();
        let pool = space.get_type("nt!_POOL_TYPE").unwrap();
        let template = pool.as_enum().unwrap();
        assert_eq!(template.lookup(1), "PagedPool");
        assert_eq!(template.lookup(99), "0x63");
    }

    #[test]
    fn unqualified_names_are_rejected() {
        let space = space();
        assert!(space.get_type("_LIST_ENTRY").is_err());
    }
}
