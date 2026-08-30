//! Object templates: a type resolved far enough to lay bytes out in memory.
//!
//! A template is produced from an ISF type descriptor. References to named
//! types stay unresolved (`Template::Reference`), so that a type may refer to
//! itself, `_LIST_ENTRY.Flink` points at another `_LIST_ENTRY`, without the
//! resolution recursing forever. References are expanded through the symbol
//! space only when something actually needs the members or size.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::sync::Arc;

use crate::framework::symbols::isf::{Endian, StructKind};

/// Text encoding used when reading a string object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// One byte per character, decoded leniently.
    Utf8,
    /// Two bytes per character, as Windows uses for `UNICODE_STRING`.
    Utf16Le,
}

/// What kind of named type a reference points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceKind {
    UserType,
    Enumeration,
}

/// A member of a struct or union.
#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    pub offset: u64,
    pub template: Arc<Template>,
    /// Anonymous members contribute their own members to the parent's namespace.
    pub anonymous: bool,
}

/// A resolved struct, union or class.
#[derive(Debug, Clone)]
pub struct StructTemplate {
    pub name: String,
    /// The symbol table the type came from, needed to resolve its members.
    pub table: String,
    pub kind: StructKind,
    pub size: u64,
    pub members: Vec<Member>,
    /// Index into `members` by name, including members hoisted out of
    /// anonymous sub-structures.
    pub index: HashMap<String, usize>,
}

impl StructTemplate {
    pub fn member(&self, name: &str) -> Option<&Member> {
        self.index.get(name).map(|position| &self.members[*position])
    }

    /// Member names, sorted by offset so output reads in declaration order.
    /// The member names, in the order the symbol file lists them, which is by
    /// name rather than by where each one sits.
    pub fn member_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.members.iter().map(|member| member.name.as_str()).collect();
        names.sort_unstable();
        names
    }
}

/// A resolved enumeration.
#[derive(Debug, Clone)]
pub struct EnumTemplate {
    pub name: String,
    pub table: String,
    pub size: usize,
    pub signed: bool,
    pub endian: Endian,
    /// Name to value, as written in the ISF file.
    pub choices: crate::framework::symbols::isf::NameMap<i64>,
    /// Value to name, for rendering. Built once because it is used on every
    /// lookup and a value may have several names.
    pub inverse: HashMap<i64, String>,
}

impl EnumTemplate {
    /// The name for `value`, or a hex rendering when the value is not a
    /// declared member.
    pub fn lookup(&self, value: i64) -> String {
        self.inverse
            .get(&value)
            .cloned()
            .unwrap_or_else(|| format!("{value:#x}"))
    }

    pub fn is_valid_choice(&self, value: i64) -> bool {
        self.inverse.contains_key(&value)
    }
}

/// A type, laid out and ready to read bytes with.
#[derive(Debug, Clone)]
pub enum Template {
    /// A type with no representation. Reading one yields nothing.
    Void,
    /// A function, treated like `Void` for reading purposes.
    Function,
    Integer {
        size: usize,
        signed: bool,
        endian: Endian,
    },
    Float {
        size: usize,
        endian: Endian,
    },
    Char {
        size: usize,
        signed: bool,
    },
    Bool {
        size: usize,
    },
    /// A fixed run of raw bytes.
    Bytes {
        length: usize,
    },
    /// A NUL-terminated string of at most `max_length` characters.
    String {
        max_length: usize,
        encoding: Encoding,
    },
    Pointer {
        size: usize,
        endian: Endian,
        subtype: Arc<Template>,
    },
    Array {
        count: u64,
        subtype: Arc<Template>,
    },
    Struct(Arc<StructTemplate>),
    Enumeration(Arc<EnumTemplate>),
    Bitfield {
        base: Arc<Template>,
        /// Bit offset of the field within its base type.
        start_bit: u32,
        /// One past the last bit of the field.
        end_bit: u32,
    },
    /// A named type not yet looked up in the symbol space.
    Reference {
        table: String,
        name: String,
        kind: ReferenceKind,
    },
}

impl Template {
    /// A human-readable name for the type, as plugins report it.
    pub fn type_name(&self) -> String {
        match self {
            Template::Void => "void".to_string(),
            Template::Function => "function".to_string(),
            Template::Integer { size, signed, .. } => {
                format!("{}int{}", if *signed { "" } else { "u" }, size * 8)
            }
            Template::Float { size, .. } => format!("float{}", size * 8),
            Template::Char { .. } => "char".to_string(),
            Template::Bool { .. } => "bool".to_string(),
            Template::Bytes { length } => format!("bytes[{length}]"),
            Template::String { .. } => "string".to_string(),
            Template::Pointer { subtype, .. } => format!("{}*", subtype.type_name()),
            Template::Array { count, subtype } => format!("{}[{count}]", subtype.type_name()),
            Template::Struct(template) => template.name.clone(),
            Template::Enumeration(template) => template.name.clone(),
            Template::Bitfield { base, .. } => format!("{}:bitfield", base.type_name()),
            Template::Reference { name, .. } => name.clone(),
        }
    }

    /// The size in bytes, for templates that do not need the symbol space to
    /// work it out. References and arrays of references return `None`.
    pub fn static_size(&self) -> Option<u64> {
        Some(match self {
            Template::Void | Template::Function => 0,
            Template::Integer { size, .. }
            | Template::Float { size, .. }
            | Template::Char { size, .. }
            | Template::Bool { size } => *size as u64,
            Template::Bytes { length } => *length as u64,
            Template::String {
                max_length,
                encoding,
            } => match encoding {
                Encoding::Utf8 => *max_length as u64,
                Encoding::Utf16Le => (*max_length as u64) * 2,
            },
            Template::Pointer { size, .. } => *size as u64,
            Template::Array { count, subtype } => count * subtype.static_size()?,
            Template::Struct(template) => template.size,
            Template::Enumeration(template) => template.size as u64,
            Template::Bitfield { base, .. } => base.static_size()?,
            Template::Reference { .. } => return None,
        })
    }

    /// Whether this template still needs resolving against the symbol space.
    pub fn is_reference(&self) -> bool {
        matches!(self, Template::Reference { .. })
    }

    /// The struct this template describes, if it is one.
    pub fn as_struct(&self) -> Option<&Arc<StructTemplate>> {
        match self {
            Template::Struct(template) => Some(template),
            _ => None,
        }
    }

    pub fn as_enum(&self) -> Option<&Arc<EnumTemplate>> {
        match self {
            Template::Enumeration(template) => Some(template),
            _ => None,
        }
    }
}

/// Read a little- or big-endian unsigned integer from `data`.
pub fn read_unsigned(data: &[u8], endian: Endian) -> u64 {
    let mut buffer = [0u8; 8];
    let width = data.len().min(8);
    match endian {
        Endian::Little => buffer[..width].copy_from_slice(&data[..width]),
        // A big-endian value is right-aligned in the buffer so the low bytes
        // land where `from_be_bytes` expects them.
        Endian::Big => buffer[8 - width..].copy_from_slice(&data[data.len() - width..]),
    }
    match endian {
        Endian::Little => u64::from_le_bytes(buffer),
        Endian::Big => u64::from_be_bytes(buffer),
    }
}

/// Read a signed integer, sign-extending from the value's own width.
pub fn read_signed(data: &[u8], endian: Endian) -> i64 {
    let width = data.len().min(8);
    let raw = read_unsigned(data, endian);
    if width == 8 {
        return raw as i64;
    }
    let sign_bit = 1u64 << (width * 8 - 1);
    if raw & sign_bit != 0 {
        // Fill the bits above the value's width with ones.
        (raw | !((1u64 << (width * 8)) - 1)) as i64
    } else {
        raw as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_compose_through_arrays() {
        let element = Arc::new(Template::Integer {
            size: 4,
            signed: true,
            endian: Endian::Little,
        });
        let array = Template::Array {
            count: 8,
            subtype: element,
        };
        assert_eq!(array.static_size(), Some(32));
    }

    #[test]
    fn references_have_no_static_size() {
        let reference = Template::Reference {
            table: "nt".to_string(),
            name: "_EPROCESS".to_string(),
            kind: ReferenceKind::UserType,
        };
        assert_eq!(reference.static_size(), None);
    }

    #[test]
    fn signed_values_sign_extend_from_their_own_width() {
        assert_eq!(read_signed(&[0xFF], Endian::Little), -1);
        assert_eq!(read_signed(&[0xFF, 0xFF], Endian::Little), -1);
        assert_eq!(read_signed(&[0x00, 0x80], Endian::Little), -32768);
        assert_eq!(read_signed(&[0x7F, 0xFF], Endian::Big), 32767);
    }

    #[test]
    fn unsigned_values_respect_endianness() {
        assert_eq!(read_unsigned(&[0x01, 0x02], Endian::Little), 0x0201);
        assert_eq!(read_unsigned(&[0x01, 0x02], Endian::Big), 0x0102);
    }
}
