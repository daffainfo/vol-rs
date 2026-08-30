//! Native base types.
//!
//! ISF files describe the base types they use, but some producers omit common C
//! types (and `pointer` in particular). A native table supplies those defaults,
//! chosen for the architecture's word size.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::sync::Arc;

use crate::framework::objects::template::{Encoding, Template};
use crate::framework::symbols::isf::{BaseKind, BaseType, Endian};

/// A fallback set of base types.
pub struct NativeTable {
    name: String,
    types: HashMap<String, BaseType>,
    pointer_size: usize,
}

impl NativeTable {
    pub fn new(name: impl Into<String>, types: HashMap<String, BaseType>) -> Self {
        let pointer_size = types.get("pointer").map(|base| base.size).unwrap_or(8);
        Self {
            name: name.into(),
            types,
            pointer_size,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn pointer_size(&self) -> usize {
        self.pointer_size
    }

    pub fn base_type(&self, name: &str) -> Option<BaseType> {
        self.types.get(name).cloned()
    }

    pub fn has_type(&self, name: &str) -> bool {
        self.types.contains_key(name)
            || matches!(
                name,
                "void" | "function" | "array" | "bitfield" | "enum" | "string" | "bytes" | "pointer"
            )
    }

    /// Build a template for a native type name.
    ///
    /// The compound names (`array`, `enum`, and so on) come back in their empty
    /// form. Callers fill in counts and subtypes.
    pub fn get_type(&self, name: &str) -> Option<Arc<Template>> {
        if let Some(base) = self.types.get(name) {
            return Some(Arc::new(match base.kind {
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
            }));
        }

        Some(Arc::new(match name {
            "void" | "function" => Template::Void,
            "string" => Template::String {
                max_length: 0,
                encoding: Encoding::Utf8,
            },
            "bytes" => Template::Bytes { length: 0 },
            "array" => Template::Array {
                count: 0,
                subtype: Arc::new(Template::Void),
            },
            "bitfield" => Template::Bitfield {
                base: Arc::new(Template::Void),
                start_bit: 0,
                end_bit: 0,
            },
            _ => return None,
        }))
    }

    /// Every type name this table can produce.
    pub fn types(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.types.keys().map(String::as_str).collect();
        names.extend(["void", "function", "array", "bitfield", "string", "bytes"]);
        names.sort_unstable();
        names.dedup();
        names
    }
}

fn integer(size: usize, signed: bool) -> BaseType {
    BaseType {
        size,
        signed,
        kind: BaseKind::Int,
        endian: Endian::Little,
    }
}

fn big_endian_integer(size: usize, signed: bool) -> BaseType {
    BaseType {
        size,
        signed,
        kind: BaseKind::Int,
        endian: Endian::Big,
    }
}

fn float(size: usize) -> BaseType {
    BaseType {
        size,
        signed: true,
        kind: BaseKind::Float,
        endian: Endian::Little,
    }
}

/// The C types shared by both architectures.
fn standard_c_types() -> HashMap<String, BaseType> {
    let mut types = HashMap::new();
    types.insert("int".to_string(), integer(4, true));
    types.insert("long".to_string(), integer(4, true));
    types.insert("unsigned long".to_string(), integer(4, false));
    types.insert("unsigned int".to_string(), integer(4, false));
    types.insert(
        "char".to_string(),
        BaseType {
            size: 1,
            signed: true,
            kind: BaseKind::Char,
            endian: Endian::Little,
        },
    );
    types.insert(
        "byte".to_string(),
        BaseType {
            size: 1,
            signed: false,
            kind: BaseKind::Char,
            endian: Endian::Little,
        },
    );
    types.insert("unsigned char".to_string(), integer(1, false));
    types.insert("short".to_string(), integer(2, true));
    types.insert("unsigned short".to_string(), integer(2, false));
    types.insert("unsigned short int".to_string(), integer(2, false));
    types.insert("unsigned be short".to_string(), big_endian_integer(2, false));
    types.insert("long long".to_string(), integer(8, true));
    types.insert("unsigned long long".to_string(), integer(8, false));
    types.insert("float".to_string(), float(4));
    types.insert("double".to_string(), float(8));
    types.insert("wchar".to_string(), integer(2, false));
    types
}

/// Native types for a 32-bit target.
pub fn x86_native_table() -> Arc<NativeTable> {
    let mut types = standard_c_types();
    types.insert("pointer".to_string(), integer(4, false));
    Arc::new(NativeTable::new("native", types))
}

/// Native types for a 64-bit target.
pub fn x64_native_table() -> Arc<NativeTable> {
    let mut types = standard_c_types();
    types.insert("pointer".to_string(), integer(8, false));
    Arc::new(NativeTable::new("native", types))
}

/// Pick the native table matching a pointer width in bytes.
pub fn native_table_for_pointer_size(size: usize) -> Arc<NativeTable> {
    if size == 4 {
        x86_native_table()
    } else {
        x64_native_table()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_width_follows_the_architecture() {
        assert_eq!(x86_native_table().pointer_size(), 4);
        assert_eq!(x64_native_table().pointer_size(), 8);
    }

    #[test]
    fn compound_native_names_resolve() {
        let native = x64_native_table();
        assert!(native.get_type("array").is_some());
        assert!(native.get_type("not-a-type").is_none());
    }
}
