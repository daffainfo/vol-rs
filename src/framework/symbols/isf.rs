//! Parsing of Intermediate Symbol Format (ISF) files.
//!
//! An ISF file is JSON describing a program's types and symbols: base types,
//! user types (structs, unions, classes), enumerations, and named symbols with
//! their addresses. It is the format Volatility uses to describe a kernel
//! without needing debug tooling at analysis time.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use rayon::prelude::*;
use std::collections::HashMap;

/// Maps keyed by a name, as every section of a symbol file is.
///
/// A kernel declares a few hundred thousand of these, and they are built once
/// and then only read. Nothing about a symbol name is adversarial, so they are
/// hashed for speed rather than for resistance to collision attacks.
pub type NameMap<T> = HashMap<String, T, rustc_hash::FxBuildHasher>;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Result, VolatilityError};

/// A type as written in an ISF file, before it is resolved against a symbol
/// table. Struct and enum references are by name, which is what allows a type
/// to refer to itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TypeDescriptor {
    /// A named base type, resolved against the table's `base_types`.
    Base { name: String },
    /// A struct, union or class, referenced by name.
    Struct { kind: StructKind, name: String },
    /// An enumeration, referenced by name.
    Enum { name: String },
    Pointer {
        subtype: Box<TypeDescriptor>,
        /// The base type giving the pointer's width, when the file says so.
        base: Option<String>,
    },
    Array {
        subtype: Box<TypeDescriptor>,
        count: u64,
    },
    /// A function, which has no readable representation.
    Function,
    Bitfield {
        bit_position: u32,
        bit_length: u32,
        /// The underlying base or enum type the bits are read from.
        inner: Box<TypeDescriptor>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StructKind {
    Struct,
    Union,
    Class,
}

impl StructKind {
    fn parse(kind: &str) -> Option<Self> {
        Some(match kind {
            "struct" => StructKind::Struct,
            "union" => StructKind::Union,
            "class" => StructKind::Class,
            _ => return None,
        })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            StructKind::Struct => "struct",
            StructKind::Union => "union",
            StructKind::Class => "class",
        }
    }
}

/// Byte order of a base type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Endian {
    Little,
    Big,
}

/// What a base type actually holds, which decides how its bytes are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BaseKind {
    Void,
    Int,
    Float,
    Char,
    Bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaseType {
    pub size: usize,
    pub signed: bool,
    pub kind: BaseKind,
    pub endian: Endian,
}

/// One member of a user type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Field {
    pub type_descriptor: TypeDescriptor,
    pub offset: u64,
    /// Anonymous members have their own members hoisted into the parent, which
    /// is how unnamed unions in C headers are represented.
    pub anonymous: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserType {
    pub kind: StructKind,
    pub size: u64,
    pub fields: NameMap<Field>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnumType {
    pub size: usize,
    /// Name of the base type the enumeration is stored as.
    pub base: String,
    pub constants: NameMap<i64>,
}

/// A named symbol: an address, and optionally the type stored there.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SymbolEntry {
    pub address: u64,
    pub linkage_name: Option<String>,
    pub type_descriptor: Option<TypeDescriptor>,
    pub constant_data: Option<Vec<u8>>,
}

/// Metadata describing where the ISF file came from.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Metadata {
    pub format: String,
    pub producer_name: Option<String>,
    pub producer_version: Option<String>,
    /// Windows PDB identity, used to match an ISF file to a kernel.
    pub pdb_guid: Option<String>,
    pub pdb_age: Option<u32>,
    pub pdb_database: Option<String>,
    /// Raw metadata, retained so plugins can inspect fields not modelled here.
    ///
    /// Stored as its own text: a document of arbitrary shape can only be read
    /// back by a format that describes itself, and the cache of parsed symbol
    /// files deliberately does not.
    #[serde(with = "raw_metadata")]
    pub raw: Value,
}

/// A parsed ISF file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsfFile {
    pub metadata: Metadata,
    pub base_types: NameMap<BaseType>,
    pub user_types: NameMap<UserType>,
    pub enums: NameMap<EnumType>,
    pub symbols: NameMap<SymbolEntry>,
}

fn expect_object<'a>(value: &'a Value, what: &str) -> Result<&'a serde_json::Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| VolatilityError::SymbolSpace(format!("ISF {what} must be an object")))
}

fn field_str(map: &serde_json::Map<String, Value>, key: &str) -> Result<String> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| VolatilityError::SymbolSpace(format!("Missing string field '{key}'")))
}

fn field_u64(map: &serde_json::Map<String, Value>, key: &str) -> Result<u64> {
    map.get(key)
        .and_then(|v| {
            v.as_u64()
                // Some producers write addresses as floats or as signed values.
                .or_else(|| v.as_i64().map(|i| i as u64))
                .or_else(|| v.as_f64().map(|f| f as u64))
        })
        .ok_or_else(|| VolatilityError::SymbolSpace(format!("Missing integer field '{key}'")))
}

/// Parse a type descriptor, dispatching on its `kind`.
pub fn parse_type_descriptor(value: &Value) -> Result<TypeDescriptor> {
    let map = expect_object(value, "type descriptor")?;
    let kind = field_str(map, "kind")?;

    Ok(match kind.as_str() {
        "base" => TypeDescriptor::Base {
            name: field_str(map, "name")?,
        },
        "struct" | "union" | "class" => TypeDescriptor::Struct {
            kind: StructKind::parse(&kind).unwrap(),
            name: field_str(map, "name")?,
        },
        "enum" => TypeDescriptor::Enum {
            name: field_str(map, "name")?,
        },
        "pointer" => TypeDescriptor::Pointer {
            subtype: Box::new(parse_type_descriptor(
                map.get("subtype").ok_or_else(|| {
                    VolatilityError::SymbolSpace("Pointer has no subtype".to_string())
                })?,
            )?),
            base: map.get("base").and_then(Value::as_str).map(str::to_string),
        },
        "array" => TypeDescriptor::Array {
            subtype: Box::new(parse_type_descriptor(map.get("subtype").ok_or_else(
                || VolatilityError::SymbolSpace("Array has no subtype".to_string()),
            )?)?),
            count: field_u64(map, "count").unwrap_or(0),
        },
        "function" => TypeDescriptor::Function,
        "bitfield" => TypeDescriptor::Bitfield {
            bit_position: field_u64(map, "bit_position")? as u32,
            bit_length: field_u64(map, "bit_length")? as u32,
            inner: Box::new(parse_type_descriptor(map.get("type").ok_or_else(|| {
                VolatilityError::SymbolSpace("Bitfield has no type".to_string())
            })?)?),
        },
        other => {
            return Err(VolatilityError::SymbolSpace(format!(
                "Unknown type descriptor kind '{other}'"
            )))
        }
    })
}

fn parse_base_type(value: &Value) -> Result<BaseType> {
    let map = expect_object(value, "base type")?;
    let kind = match field_str(map, "kind")?.as_str() {
        "void" => BaseKind::Void,
        "int" => BaseKind::Int,
        "float" => BaseKind::Float,
        "char" => BaseKind::Char,
        "bool" => BaseKind::Bool,
        other => {
            return Err(VolatilityError::SymbolSpace(format!(
                "Unknown base type kind '{other}'"
            )))
        }
    };
    let endian = match field_str(map, "endian")?.as_str() {
        "little" => Endian::Little,
        "big" => Endian::Big,
        other => {
            return Err(VolatilityError::SymbolSpace(format!(
                "Unknown endianness '{other}'"
            )))
        }
    };
    Ok(BaseType {
        size: field_u64(map, "size")? as usize,
        signed: map
            .get("signed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        kind,
        endian,
    })
}

fn parse_user_type(value: &Value) -> Result<UserType> {
    let map = expect_object(value, "user type")?;
    let kind = StructKind::parse(&field_str(map, "kind")?).ok_or_else(|| {
        VolatilityError::SymbolSpace("Unknown user type kind".to_string())
    })?;
    let size = field_u64(map, "size")?;

    let mut fields = NameMap::default();
    if let Some(field_map) = map.get("fields").and_then(Value::as_object) {
        for (name, field_value) in field_map {
            let field_object = expect_object(field_value, "field")?;
            let type_descriptor = parse_type_descriptor(field_object.get("type").ok_or_else(
                || VolatilityError::SymbolSpace(format!("Field '{name}' has no type")),
            )?)?;
            fields.insert(
                name.clone(),
                Field {
                    type_descriptor,
                    offset: field_u64(field_object, "offset")?,
                    anonymous: field_object
                        .get("anonymous")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                },
            );
        }
    }
    Ok(UserType { kind, size, fields })
}

fn parse_enum(value: &Value) -> Result<EnumType> {
    let map = expect_object(value, "enum")?;
    let mut constants = NameMap::default();
    if let Some(constant_map) = map.get("constants").and_then(Value::as_object) {
        for (name, constant) in constant_map {
            let numeric = constant
                .as_i64()
                .or_else(|| constant.as_u64().map(|v| v as i64))
                .ok_or_else(|| {
                    VolatilityError::SymbolSpace(format!("Enum constant '{name}' is not an integer"))
                })?;
            constants.insert(name.clone(), numeric);
        }
    }
    Ok(EnumType {
        size: field_u64(map, "size")? as usize,
        base: field_str(map, "base")?,
        constants,
    })
}

fn parse_symbol(value: &Value) -> Result<SymbolEntry> {
    let map = expect_object(value, "symbol")?;
    let type_descriptor = match map.get("type") {
        Some(type_value) => Some(parse_type_descriptor(type_value)?),
        None => None,
    };
    // `constant_data` is base64 in the file. Decode it eagerly so callers can
    // treat it as bytes.
    let constant_data = map
        .get("constant_data")
        .and_then(Value::as_str)
        .and_then(decode_base64);

    Ok(SymbolEntry {
        address: field_u64(map, "address")?,
        linkage_name: map
            .get("linkage_name")
            .and_then(Value::as_str)
            .map(str::to_string),
        type_descriptor,
        constant_data,
    })
}

/// Minimal base64 decoder, sufficient for ISF `constant_data`.
/// Reads and writes free-form metadata as JSON text.
mod raw_metadata {
    use serde::{Deserialize, Deserializer, Serializer};
    use serde_json::Value;

    pub fn serialize<S: Serializer>(value: &Value, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Value, D::Error> {
        let text = String::deserialize(deserializer)?;
        Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
    }
}

/// Convert one section of a symbol file, entry by entry and in parallel.
///
/// An entry that will not parse is skipped with a note rather than failing the
/// file: one unusable type should not cost the caller every other one.
fn convert_section<T: Send>(
    section: Option<&Value>,
    kind: &str,
    parse: fn(&Value) -> Result<T>,
) -> NameMap<T> {
    let Some(entries) = section.and_then(Value::as_object) else {
        return NameMap::default();
    };
    let entries: Vec<(&String, &Value)> = entries.iter().collect();
    entries
        .par_iter()
        .filter_map(|(name, value)| match parse(value) {
            Ok(parsed) => Some(((*name).clone(), parsed)),
            Err(error) => {
                log::debug!("Skipping {kind} '{name}': {error}");
                None
            }
        })
        .collect()
}

pub fn decode_base64(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (index, byte) in TABLE.iter().enumerate() {
        lookup[*byte as usize] = index as u8;
    }

    let mut output = Vec::new();
    let mut accumulator: u32 = 0;
    let mut bits = 0u32;
    for byte in input.bytes() {
        if byte == b'=' || byte.is_ascii_whitespace() {
            continue;
        }
        let value = lookup[byte as usize];
        if value == 255 {
            return None;
        }
        accumulator = (accumulator << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
        }
    }
    Some(output)
}

fn parse_metadata(value: Option<&Value>) -> Metadata {
    let Some(value) = value else {
        return Metadata::default();
    };
    let map = match value.as_object() {
        Some(map) => map,
        None => return Metadata::default(),
    };

    let producer = map.get("producer").and_then(Value::as_object);
    let windows_pdb = map
        .get("windows")
        .and_then(Value::as_object)
        .and_then(|windows| windows.get("pdb"))
        .and_then(Value::as_object);

    Metadata {
        format: map
            .get("format")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        producer_name: producer
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .map(str::to_string),
        producer_version: producer
            .and_then(|p| p.get("version"))
            .and_then(Value::as_str)
            .map(str::to_string),
        pdb_guid: windows_pdb
            .and_then(|p| p.get("GUID"))
            .and_then(Value::as_str)
            .map(str::to_string),
        pdb_age: windows_pdb
            .and_then(|p| p.get("age"))
            .and_then(Value::as_u64)
            .map(|age| age as u32),
        pdb_database: windows_pdb
            .and_then(|p| p.get("database"))
            .and_then(Value::as_str)
            .map(str::to_string),
        raw: value.clone(),
    }
}

impl IsfFile {
    /// Parse ISF from an already-decoded JSON value.
    pub fn from_value(value: &Value) -> Result<Self> {
        let map = expect_object(value, "file")?;

        let mut base_types = NameMap::default();
        if let Some(types) = map.get("base_types").and_then(Value::as_object) {
            for (name, type_value) in types {
                base_types.insert(name.clone(), parse_base_type(type_value)?);
            }
        }

        // A kernel declares tens of thousands of types and symbols, and each
        // is converted independently of the others, so the work is spread
        // across the machine. A single malformed entry should not make the
        // whole kernel unusable, so it is recorded and skipped.
        let user_types = convert_section(map.get("user_types"), "user type", parse_user_type);
        let enums = convert_section(map.get("enums"), "enum", parse_enum);
        let symbols = convert_section(map.get("symbols"), "symbol", parse_symbol);

        Ok(IsfFile {
            metadata: parse_metadata(map.get("metadata")),
            base_types,
            user_types,
            enums,
            symbols,
        })
    }

    /// Parse ISF from raw JSON bytes.
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        let started = std::time::Instant::now();
        let value: Value = serde_json::from_slice(data)?;
        log::debug!("Reading the JSON document took {:?}", started.elapsed());

        let started = std::time::Instant::now();
        let file = Self::from_value(&value);
        log::debug!("Converting it to symbols took {:?}", started.elapsed());
        file
    }

    /// The major version of the ISF format this file declares.
    pub fn format_major(&self) -> u32 {
        self.metadata
            .format
            .split('.')
            .next()
            .and_then(|major| major.parse().ok())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "metadata": {"format": "6.2.0", "producer": {"name": "test", "version": "1.0"}},
        "base_types": {
            "unsigned long long": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
            "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"}
        },
        "user_types": {
            "_LIST_ENTRY": {"kind": "struct", "size": 16, "fields": {
                "Flink": {"offset": 0, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}},
                "Blink": {"offset": 8, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}}
            }}
        },
        "enums": {
            "_POOL_TYPE": {"size": 4, "base": "unsigned long long", "constants": {"NonPagedPool": 0, "PagedPool": 1}}
        },
        "symbols": {
            "PsActiveProcessHead": {"address": 12345}
        }
    }"#;

    #[test]
    fn parses_a_complete_isf_file() {
        let isf = IsfFile::from_slice(SAMPLE.as_bytes()).unwrap();
        assert_eq!(isf.format_major(), 6);
        assert_eq!(isf.base_types["pointer"].size, 8);
        assert_eq!(isf.user_types["_LIST_ENTRY"].size, 16);
        assert_eq!(isf.enums["_POOL_TYPE"].constants["PagedPool"], 1);
        assert_eq!(isf.symbols["PsActiveProcessHead"].address, 12345);
    }

    #[test]
    fn self_referential_structs_stay_lazy() {
        let isf = IsfFile::from_slice(SAMPLE.as_bytes()).unwrap();
        let flink = &isf.user_types["_LIST_ENTRY"].fields["Flink"];
        // The pointer holds a name, not an expanded copy of the struct, which is
        // what keeps a self-referential type finite.
        match &flink.type_descriptor {
            TypeDescriptor::Pointer { subtype, .. } => assert_eq!(
                **subtype,
                TypeDescriptor::Struct {
                    kind: StructKind::Struct,
                    name: "_LIST_ENTRY".to_string()
                }
            ),
            other => panic!("expected a pointer, got {other:?}"),
        }
    }

    #[test]
    fn decodes_base64_constant_data() {
        assert_eq!(decode_base64("aGVsbG8="), Some(b"hello".to_vec()));
    }
}
