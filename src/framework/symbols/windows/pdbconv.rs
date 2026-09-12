//! Turning a program database into a symbol file.
//!
//! A database describes a binary in Microsoft's own CodeView form. Reading it
//! gives the layout of every structure the binary uses, which is what a plugin
//! needs to make sense of the memory that binary was running in. This builds
//! the same intermediate symbol file the reference implementation produces, so
//! the two describe a kernel identically.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::error::{Result, VolatilityError};

/// A value small enough to be held in the leaf itself rather than after it.
const SMALLEST_EXTENDED: u16 = 0x8000;

/// The leaves this reads. Anything else is stepped over.
mod leaf {
    pub const MODIFIER: u16 = 0x1001;
    pub const POINTER: u16 = 0x1002;
    pub const ARRAY_ST: u16 = 0x1003;
    pub const CLASS_ST: u16 = 0x1004;
    pub const STRUCTURE_ST: u16 = 0x1005;
    pub const PROCEDURE: u16 = 0x1008;
    pub const MFUNCTION: u16 = 0x1009;
    pub const FIELDLIST: u16 = 0x1203;
    pub const BITFIELD: u16 = 0x1205;
    pub const BCLASS: u16 = 0x1400;
    pub const VBCLASS: u16 = 0x1401;
    pub const IVBCLASS: u16 = 0x1402;
    pub const INDEX: u16 = 0x1404;
    pub const MEMBER_ST: u16 = 0x1405;
    pub const VFUNCTAB: u16 = 0x1409;
    pub const ENUMERATE: u16 = 0x1502;
    pub const ARRAY: u16 = 0x1503;
    pub const CLASS: u16 = 0x1504;
    pub const STRUCTURE: u16 = 0x1505;
    pub const UNION: u16 = 0x1506;
    pub const ENUM: u16 = 0x1507;
    pub const MEMBER: u16 = 0x150D;
    pub const STMEMBER: u16 = 0x150E;
    pub const METHOD: u16 = 0x150F;
    pub const NESTTYPE: u16 = 0x1510;
    pub const ONEMETHOD: u16 = 0x1511;
    pub const INTERFACE: u16 = 0x1519;
    pub const CLASS_VS19: u16 = 0x1608;
    pub const STRUCTURE_VS19: u16 = 0x1609;
}

/// A structure that only says a fuller description exists elsewhere.
const FORWARD_REFERENCE: u16 = 0x0080;

/// One member of a structure or union.
struct Member {
    name: String,
    offset: u64,
    type_index: u32,
}

/// One name in an enumeration.
struct Constant {
    name: String,
    value: i64,
}

/// What a field list holds, which depends on what it belongs to.
#[derive(Default)]
struct FieldList {
    members: Vec<Member>,
    constants: Vec<Constant>,
}

/// A type as the database records it.
enum Record {
    Structure {
        name: String,
        kind: &'static str,
        size: u64,
        fields: u32,
        forward: bool,
    },
    Enumeration {
        name: String,
        underlying: u32,
        fields: u32,
        forward: bool,
    },
    Array {
        element: u32,
        size: u64,
    },
    Pointer {
        subtype: u32,
        size: u64,
    },
    Modifier {
        subtype: u32,
    },
    Bitfield {
        underlying: u32,
        length: u8,
        position: u8,
    },
    Fields(FieldList),
    Procedure,
    /// A record of a kind this does not read, kept so indices stay lined up.
    Other,
}

/// Read a little-endian value, or report that the record ran out.
fn u8_at(data: &[u8], at: usize) -> Result<u8> {
    data.get(at)
        .copied()
        .ok_or_else(|| VolatilityError::Other("A type record ended early".to_string()))
}

fn u16_at(data: &[u8], at: usize) -> Result<u16> {
    let bytes = data
        .get(at..at + 2)
        .ok_or_else(|| VolatilityError::Other("A type record ended early".to_string()))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], at: usize) -> Result<u32> {
    let bytes = data
        .get(at..at + 4)
        .ok_or_else(|| VolatilityError::Other("A type record ended early".to_string()))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read a number that is held in the leaf where it is small enough, and after
/// it where it is not. Gives the value and where the next field begins.
fn number_at(data: &[u8], at: usize) -> Result<(i64, usize)> {
    let marker = u16_at(data, at)?;
    if marker < SMALLEST_EXTENDED {
        return Ok((marker as i64, at + 2));
    }
    let body = at + 2;
    match marker {
        0x8000 => Ok((u8_at(data, body)? as i8 as i64, body + 1)),
        0x8001 => Ok((u16_at(data, body)? as i16 as i64, body + 2)),
        0x8002 => Ok((u16_at(data, body)? as i64, body + 2)),
        0x8003 => Ok((u32_at(data, body)? as i32 as i64, body + 4)),
        0x8004 => Ok((u32_at(data, body)? as i64, body + 4)),
        0x8009 | 0x800A => {
            let low = u32_at(data, body)? as u64;
            let high = u32_at(data, body + 4)? as u64;
            Ok((((high << 32) | low) as i64, body + 8))
        }
        other => Err(VolatilityError::Other(format!(
            "A number of kind {other:#06x} is not one this reads"
        ))),
    }
}

/// Read a NUL-terminated name, giving it and where the next field begins.
fn name_at(data: &[u8], at: usize) -> Result<(String, usize)> {
    let rest = data
        .get(at..)
        .ok_or_else(|| VolatilityError::Other("A name ran past its record".to_string()))?;
    let end = rest.iter().position(|byte| *byte == 0).unwrap_or(rest.len());
    let name = String::from_utf8_lossy(&rest[..end]).to_string();
    Ok((name, at + end + 1))
}

/// The names a compiler gives a structure that has none of its own.
const NAMELESS: &[&str] = &[
    "<unnamed-tag>",
    "<anonymous-tag>",
    "__unnamed",
    "__anonymous",
];

/// Name a structure that carries no name of its own, after the index it sits
/// at, which is how the reference implementation names them.
fn name_or_index(name: String, index: u32) -> String {
    if NAMELESS.contains(&name.as_str()) {
        let tag = if name.contains("unnamed") { "unnamed" } else { "anonymous" };
        return format!("__{tag}_{index:x}");
    }
    name
}

/// Read one type record, given its leaf and the bytes after it.
fn read_record(kind: u16, body: &[u8], index: u32) -> Result<Record> {
    match kind {
        leaf::CLASS
        | leaf::STRUCTURE
        | leaf::INTERFACE
        | leaf::CLASS_ST
        | leaf::STRUCTURE_ST
        | leaf::CLASS_VS19
        | leaf::STRUCTURE_VS19 => {
            let properties = u16_at(body, 2)?;
            let fields = u32_at(body, 4)?;
            let (size, after) = number_at(body, 16)?;
            let (name, _) = name_at(body, after)?;
            Ok(Record::Structure {
                name: name_or_index(name, index),
                kind: "struct",
                size: size.max(0) as u64,
                fields,
                forward: properties & FORWARD_REFERENCE != 0,
            })
        }
        leaf::UNION => {
            let properties = u16_at(body, 2)?;
            let fields = u32_at(body, 4)?;
            let (size, after) = number_at(body, 8)?;
            let (name, _) = name_at(body, after)?;
            Ok(Record::Structure {
                name: name_or_index(name, index),
                kind: "union",
                size: size.max(0) as u64,
                fields,
                forward: properties & FORWARD_REFERENCE != 0,
            })
        }
        leaf::ENUM => {
            let properties = u16_at(body, 2)?;
            let underlying = u32_at(body, 4)?;
            let fields = u32_at(body, 8)?;
            let (name, _) = name_at(body, 12)?;
            Ok(Record::Enumeration {
                name: name_or_index(name, index),
                underlying,
                fields,
                forward: properties & FORWARD_REFERENCE != 0,
            })
        }
        leaf::ARRAY | leaf::ARRAY_ST => {
            let element = u32_at(body, 0)?;
            let (size, _) = number_at(body, 8)?;
            Ok(Record::Array {
                element,
                size: size.max(0) as u64,
            })
        }
        leaf::POINTER => {
            let subtype = u32_at(body, 0)?;
            // The attributes say how wide the pointer is, in their low bits
            // after the kind.
            let attributes = u32_at(body, 4)?;
            let size = match (attributes >> 13) & 0xFF {
                0 => match attributes & 0x1F {
                    0x0A | 0x0C => 8,
                    _ => 4,
                },
                width => width as u64,
            };
            Ok(Record::Pointer { subtype, size })
        }
        leaf::MODIFIER => Ok(Record::Modifier {
            subtype: u32_at(body, 0)?,
        }),
        leaf::BITFIELD => Ok(Record::Bitfield {
            underlying: u32_at(body, 0)?,
            length: u8_at(body, 4)?,
            position: u8_at(body, 5)?,
        }),
        leaf::PROCEDURE | leaf::MFUNCTION => Ok(Record::Procedure),
        leaf::FIELDLIST => Ok(Record::Fields(read_field_list(body)?)),
        _ => Ok(Record::Other),
    }
}

/// Read the members a field list holds.
///
/// The list packs one entry after another, each aligned to four bytes by
/// padding that says how much of it there is.
fn read_field_list(body: &[u8]) -> Result<FieldList> {
    let mut list = FieldList::default();
    let mut at = 0usize;

    while at + 2 <= body.len() {
        let kind = u16_at(body, at)?;
        let after_leaf = at + 2;
        let next = match kind {
            leaf::MEMBER | leaf::MEMBER_ST => {
                let type_index = u32_at(body, after_leaf + 2)?;
                let (offset, after) = number_at(body, after_leaf + 6)?;
                let (name, end) = name_at(body, after)?;
                list.members.push(Member {
                    name,
                    offset: offset.max(0) as u64,
                    type_index,
                });
                end
            }
            leaf::ENUMERATE => {
                let (value, after) = number_at(body, after_leaf + 2)?;
                let (name, end) = name_at(body, after)?;
                list.constants.push(Constant { name, value });
                end
            }
            leaf::NESTTYPE => {
                let (_, end) = name_at(body, after_leaf + 6)?;
                end
            }
            leaf::STMEMBER => {
                let (_, end) = name_at(body, after_leaf + 6)?;
                end
            }
            leaf::METHOD => {
                let (_, end) = name_at(body, after_leaf + 6)?;
                end
            }
            leaf::ONEMETHOD => {
                let attributes = u16_at(body, after_leaf)?;
                // A method introducing a virtual carries its table slot too.
                let introduced = matches!((attributes >> 2) & 0x7, 4 | 6);
                let names_at = after_leaf + 6 + if introduced { 4 } else { 0 };
                let (_, end) = name_at(body, names_at)?;
                end
            }
            leaf::BCLASS => {
                let (_, after) = number_at(body, after_leaf + 6)?;
                after
            }
            leaf::VBCLASS | leaf::IVBCLASS => {
                let (_, after) = number_at(body, after_leaf + 10)?;
                let (_, after) = number_at(body, after)?;
                after
            }
            leaf::VFUNCTAB | leaf::INDEX => after_leaf + 6,
            // An entry of a kind this does not read cannot be stepped over
            // safely, so the rest of the list is left alone.
            _ => break,
        };
        at = skip_padding(body, next);
    }
    Ok(list)
}

/// Step over the padding that lines the next entry up on a four-byte boundary.
fn skip_padding(body: &[u8], at: usize) -> usize {
    let mut at = at;
    while let Some(byte) = body.get(at) {
        if *byte <= 0xF0 {
            break;
        }
        at += 1;
    }
    at
}

/// The primitive types the database refers to by a small index.
///
/// The low byte names the type and the third nibble says whether it is a
/// pointer to one, which is how a database spells `char *` without a record.
fn primitive(index: u32) -> Option<(&'static str, Value)> {
    let (name, kind, signed, size) = match index & 0xFF {
        0x03 => ("void", "void", true, 0),
        0x08 => ("HRESULT", "int", false, 4),
        0x10 | 0x70 => ("char", "char", true, 1),
        0x20 => ("unsigned char", "char", false, 1),
        0x68 => ("int8", "int", true, 1),
        0x69 => ("uint8", "int", false, 1),
        0x71 => ("wchar", "int", true, 2),
        0x11 | 0x72 => ("short", "int", true, 2),
        0x21 | 0x73 => ("unsigned short", "int", false, 2),
        0x12 => ("long", "int", true, 4),
        0x22 => ("unsigned long", "int", false, 4),
        0x74 => ("int", "int", true, 4),
        0x75 => ("unsigned int", "int", false, 4),
        0x13 | 0x76 => ("long long", "int", true, 8),
        0x23 | 0x77 => ("unsigned long long", "int", false, 8),
        0x14 | 0x78 => ("int128", "int", true, 16),
        0x24 | 0x79 => ("uint128", "int", false, 16),
        0x46 => ("f16", "float", true, 2),
        0x40 => ("f32", "float", true, 4),
        0x45 => ("f32pp", "float", true, 4),
        0x44 => ("f48", "float", true, 6),
        0x41 => ("double", "float", true, 8),
        0x42 => ("f80", "float", true, 10),
        0x43 => ("f128", "float", true, 16),
        _ => return None,
    };
    Some((
        name,
        json!({"endian": "little", "kind": kind, "signed": signed, "size": size}),
    ))
}

/// The width a pointer to a primitive has, by the nibble that says so.
fn indirection(index: u32) -> Option<(&'static str, u64)> {
    match index & 0xF00 {
        0x100 => Some(("pointer16", 2)),
        0x400 => Some(("pointer32", 4)),
        0x600 => Some(("pointer64", 8)),
        _ => None,
    }
}

/// Everything read out of one database, ready to be written out.
struct Converted {
    records: Vec<Record>,
    first_index: u32,
    base_types: BTreeMap<String, Value>,
    pointer_size: u64,
    /// Where the full description of each named type sits. A database names a
    /// structure before it describes it, so this points at the description.
    by_name: std::collections::HashMap<String, u32>,
}

impl Converted {
    /// The record a type index names, if this read one.
    fn record(&self, index: u32) -> Option<&Record> {
        if index < self.first_index {
            return None;
        }
        self.records.get((index - self.first_index) as usize)
    }

    /// The index that truly describes a type, rather than one that only names
    /// it. A name is looked up to find the description, and a type that only
    /// wraps another is followed through.
    fn described_by(&self, index: u32) -> u32 {
        let mut index = index;
        for _ in 0..32 {
            match self.record(index) {
                Some(Record::Structure { name, .. }) | Some(Record::Enumeration { name, .. }) => {
                    match self.by_name.get(name) {
                        Some(found) if *found != index => index = *found,
                        _ => return index,
                    }
                }
                Some(Record::Modifier { subtype }) => index = *subtype,
                _ => return index,
            }
        }
        index
    }

    /// Describe a type index the way a symbol file does.
    fn describe(&mut self, index: u32, depth: usize) -> Value {
        // A type that refers to itself through too many steps is not one this
        // can describe, and the database should not contain one.
        if depth > 32 {
            return json!({"kind": "base", "name": "void"});
        }

        if index < self.first_index {
            let Some((name, described)) = primitive(index) else {
                return json!({"kind": "base", "name": "void"});
            };
            self.base_types.insert(name.to_string(), described);
            let inner = json!({"kind": "base", "name": name});
            return match indirection(index) {
                Some((pointer_name, size)) => {
                    // A pointer of the machine's own width needs no naming,
                    // which is how the reference implementation writes it.
                    if self.pointer_size == size {
                        json!({"kind": "pointer", "subtype": inner})
                    } else {
                        self.base_types.insert(
                            pointer_name.to_string(),
                            json!({"endian": "little", "kind": "int", "signed": false, "size": size}),
                        );
                        json!({"kind": "pointer", "base": pointer_name, "subtype": inner})
                    }
                }
                None => inner,
            };
        }

        match self.record(index) {
            Some(Record::Structure { name, kind, .. }) => {
                json!({"kind": kind, "name": name})
            }
            Some(Record::Enumeration { name, .. }) => json!({"kind": "enum", "name": name}),
            Some(Record::Array { element, size }) => {
                let (element, size) = (*element, *size);
                // How many elements an array holds is worked out from its
                // whole size, so the element has to be the described one
                // rather than a name standing in for it.
                let each = self.size_of(self.described_by(element), depth + 1).max(1);
                let subtype = self.describe(element, depth + 1);
                json!({"count": size / each, "kind": "array", "subtype": subtype})
            }
            Some(Record::Pointer { subtype, .. }) => {
                let subtype = *subtype;
                let inner = self.describe(subtype, depth + 1);
                json!({"kind": "pointer", "subtype": inner})
            }
            Some(Record::Modifier { subtype }) => {
                let subtype = *subtype;
                self.describe(subtype, depth + 1)
            }
            Some(Record::Bitfield {
                underlying,
                length,
                position,
            }) => {
                let (underlying, length, position) = (*underlying, *length, *position);
                let inner = self.describe(underlying, depth + 1);
                json!({
                    "bit_length": length,
                    "bit_position": position,
                    "kind": "bitfield",
                    "type": inner
                })
            }
            Some(Record::Procedure) => json!({"kind": "function"}),
            _ => json!({"kind": "base", "name": "void"}),
        }
    }

    /// How many bytes a type takes.
    fn size_of(&self, index: u32, depth: usize) -> u64 {
        if depth > 32 {
            return 0;
        }
        if index < self.first_index {
            if indirection(index).is_some() {
                return indirection(index).map(|(_, size)| size).unwrap_or(0);
            }
            return primitive(index)
                .and_then(|(_, described)| described.get("size").and_then(Value::as_u64))
                .unwrap_or(0);
        }
        match self.record(index) {
            Some(Record::Structure { size, .. }) => *size,
            Some(Record::Array { size, .. }) => *size,
            Some(Record::Pointer { size, .. }) => *size,
            Some(Record::Modifier { subtype }) => self.size_of(*subtype, depth + 1),
            Some(Record::Bitfield { underlying, .. }) => self.size_of(*underlying, depth + 1),
            Some(Record::Enumeration { underlying, .. }) => self.size_of(*underlying, depth + 1),
            _ => 0,
        }
    }
}

/// Build a symbol file describing the binary a database was written for.
pub fn to_isf(data: &[u8], database: &str, guid: &str, age: u32) -> Result<Value> {
    let file = super::pdb::MultiStreamFile::parse(data)?;

    // The stream describing the build records which machine the binary was
    // compiled for.
    let machine_type = file
        .stream(3)
        .ok()
        .and_then(|debug| u16_at(&debug, 58).ok())
        .unwrap_or(0) as u64;

    // Stream two holds the types. Its header says where the records start and
    // which index the first of them carries.
    let types = file.stream(2)?;
    if types.len() < 24 {
        return Err(VolatilityError::Other(
            "The database describes no types".to_string(),
        ));
    }
    let header_size = u32_at(&types, 4)? as usize;
    let first_index = u32_at(&types, 8)?;
    let last_index = u32_at(&types, 12)?;
    let record_bytes = u32_at(&types, 16)? as usize;

    let body = types
        .get(header_size..header_size + record_bytes)
        .ok_or_else(|| VolatilityError::Other("The type records are truncated".to_string()))?;

    // Each record says how long it is, then what kind it is.
    let expected = last_index.saturating_sub(first_index) as usize;
    let mut records = Vec::with_capacity(expected);
    let mut at = 0usize;
    while at + 4 <= body.len() {
        let length = u16_at(body, at)? as usize;
        if length < 2 || at + 2 + length > body.len() {
            break;
        }
        let kind = u16_at(body, at + 2)?;
        let index = first_index + records.len() as u32;
        let record =
            read_record(kind, &body[at + 4..at + 2 + length], index).unwrap_or(Record::Other);
        records.push(record);
        at += 2 + length;
    }

    // A pointer's width is the machine's, taken from the first one described.
    let pointer_size = records
        .iter()
        .find_map(|record| match record {
            Record::Pointer { size, .. } => Some(*size),
            _ => None,
        })
        .unwrap_or(8);

    // A name points at the description of a type rather than at a record that
    // only mentions it.
    let mut by_name = std::collections::HashMap::new();
    for (position, record) in records.iter().enumerate() {
        let index = first_index + position as u32;
        match record {
            Record::Structure { name, forward, .. } | Record::Enumeration { name, forward, .. } => {
                if !name.is_empty() && !forward {
                    by_name.insert(name.clone(), index);
                }
            }
            _ => {}
        }
    }

    let mut converted = Converted {
        records,
        first_index,
        base_types: BTreeMap::new(),
        pointer_size,
        by_name,
    };
    converted.base_types.insert(
        "pointer".to_string(),
        json!({"endian": "little", "kind": "int", "signed": false, "size": pointer_size}),
    );

    // Every named structure and enumeration that is described rather than
    // merely referred to.
    let mut user_types = Map::new();
    let mut enums = Map::new();
    for index in 0..converted.records.len() {
        let type_index = first_index + index as u32;
        let (name, kind, size, fields, forward) = match &converted.records[index] {
            Record::Structure {
                name,
                kind,
                size,
                fields,
                forward,
            } => (name.clone(), *kind, *size, *fields, *forward),
            Record::Enumeration {
                name,
                underlying,
                fields,
                forward,
            } => {
                if *forward || name.is_empty() {
                    continue;
                }
                let (name, underlying, fields) = (name.clone(), *underlying, *fields);
                let base = match primitive(underlying) {
                    Some((base_name, described)) => {
                        converted
                            .base_types
                            .insert(base_name.to_string(), described);
                        base_name.to_string()
                    }
                    None => "int".to_string(),
                };
                let mut constants = Map::new();
                if let Some(Record::Fields(list)) = converted.record(fields) {
                    for constant in &list.constants {
                        constants.insert(constant.name.clone(), json!(constant.value));
                    }
                }
                enums.insert(
                    name,
                    json!({
                        "base": base,
                        "constants": Value::Object(constants),
                        "size": converted.size_of(underlying, 0)
                    }),
                );
                continue;
            }
            _ => continue,
        };
        let _ = type_index;
        if forward || name.is_empty() {
            continue;
        }

        let members: Vec<(String, u64, u32)> = match converted.record(fields) {
            Some(Record::Fields(list)) => list
                .members
                .iter()
                .map(|member| (member.name.clone(), member.offset, member.type_index))
                .collect(),
            _ => Vec::new(),
        };

        let mut written = Map::new();
        for (member_name, offset, member_type) in members {
            let described = converted.describe(member_type, 0);
            written.insert(member_name, json!({"offset": offset, "type": described}));
        }
        user_types.insert(
            name,
            json!({"fields": Value::Object(written), "kind": kind, "size": size}),
        );
    }

    let symbols = read_symbols(&file)?;

    let mut base_types = Map::new();
    for (name, described) in converted.base_types {
        base_types.insert(name, described);
    }

    Ok(json!({
        "base_types": Value::Object(base_types),
        "enums": Value::Object(enums),
        "symbols": Value::Object(symbols),
        "user_types": Value::Object(user_types),
        "metadata": {
            "format": "6.1.0",
            "producer": {"name": "vol-rs", "version": env!("CARGO_PKG_VERSION")},
            "windows": {"pdb": {
                "GUID": guid.to_uppercase(),
                "age": age,
                "database": database,
                "machine_type": machine_type
            }}
        }
    }))
}

/// Read every global symbol and where it sits, relative to the image base.
fn read_symbols(file: &super::pdb::MultiStreamFile<'_>) -> Result<Map<String, Value>> {
    let debug = file.stream(3)?;
    if debug.len() < 64 {
        return Err(VolatilityError::Other(
            "The database describes no build information".to_string(),
        ));
    }
    let symbol_stream = u16_at(&debug, 20)? as usize;
    let sizes: [usize; 6] = [
        u32_at(&debug, 24)? as usize,
        u32_at(&debug, 28)? as usize,
        u32_at(&debug, 32)? as usize,
        u32_at(&debug, 36)? as usize,
        u32_at(&debug, 40)? as usize,
        u32_at(&debug, 52)? as usize,
    ];
    let optional_size = u32_at(&debug, 48)? as usize;
    let optional_at = 64 + sizes.iter().sum::<usize>();
    if optional_size < 12 || optional_at + optional_size > debug.len() {
        return Err(VolatilityError::Other(
            "The database describes no section headers".to_string(),
        ));
    }
    let section_stream = u16_at(&debug, optional_at + 10)?;
    let sections = super::pdb::image_sections(&file.stream(section_stream as usize)?);

    let stream = file.stream(symbol_stream)?;
    let mut symbols = Map::new();
    let mut at = 0usize;
    while at + 4 <= stream.len() {
        let length = u16_at(&stream, at)? as usize;
        if length < 2 || at + 2 + length > stream.len() {
            break;
        }
        let kind = u16_at(&stream, at + 2)?;
        // A public symbol or a reference to one, both of which name a section
        // and an offset within it.
        if matches!(kind, 0x110E | 0x1127) && length >= 12 {
            let offset = u32_at(&stream, at + 8)?;
            let segment = u16_at(&stream, at + 12)? as usize;
            if segment >= 1 && segment <= sections.len() {
                let name_at = at + 14;
                let end = stream[name_at..at + 2 + length]
                    .iter()
                    .position(|byte| *byte == 0)
                    .map(|position| name_at + position)
                    .unwrap_or(at + 2 + length);
                let raw = String::from_utf8_lossy(&stream[name_at..end]).to_string();
                let name = strip_name(&raw);
                let address = sections[segment - 1] as u64 + offset as u64;
                let mut described = Map::new();
                described.insert("address".to_string(), json!(address));
                if name != raw {
                    described.insert("linkage_name".to_string(), json!(raw));
                }
                // Two decorated names can strip to the same one, and it is
                // the last of them that is kept.
                symbols.insert(name, Value::Object(described));
            }
        }
        at += 2 + length;
    }
    Ok(symbols)
}

/// Take off the decoration a compiler puts on a name.
///
/// A name carrying the size of its arguments after an `@` keeps only the part
/// before it. A name that looks decorated but is not, such as one holding a
/// constant written in hexadecimal, is left exactly as it was found.
fn strip_name(name: &str) -> String {
    let mut stripped = name;
    if stripped.starts_with(['_', '@', '\u{7f}']) {
        stripped = &stripped[1..];
    }
    let parts: Vec<&str> = stripped.split('@').collect();
    if parts.len() == 2 {
        let decorated = !parts[1].is_empty()
            && parts[1].chars().all(|c| c.is_ascii_digit())
            && !parts[0].starts_with('?');
        return if decorated {
            parts[0].to_string()
        } else {
            name.to_string()
        };
    }
    stripped.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_lose_the_decoration_a_compiler_adds() {
        assert_eq!(strip_name("_KeBugCheck"), "KeBugCheck");
        assert_eq!(strip_name("@KeBugCheck@4"), "KeBugCheck");
        assert_eq!(strip_name("PsActiveProcessHead"), "PsActiveProcessHead");
        // A decorated C++ name keeps everything it carries.
        assert_eq!(strip_name("?Foo@@YAXXZ"), "?Foo@@YAXXZ");
        // A constant written in hexadecimal only looks decorated.
        assert_eq!(strip_name("__xmm@0000000000000000ffffffff"), "__xmm@0000000000000000ffffffff");
        assert_eq!(strip_name("__real@41612a8800000000"), "__real@41612a8800000000");
    }

    #[test]
    fn a_number_is_read_from_the_leaf_or_from_after_it() {
        // Small enough to sit in the leaf itself.
        assert_eq!(number_at(&[0x10, 0x00], 0).unwrap(), (16, 2));
        // A signed byte after the leaf.
        assert_eq!(number_at(&[0x00, 0x80, 0xFF], 0).unwrap(), (-1, 3));
        // Four bytes after the leaf, unsigned.
        assert_eq!(
            number_at(&[0x04, 0x80, 0x00, 0x10, 0x00, 0x00], 0).unwrap(),
            (0x1000, 6)
        );
        // A record that stops before the number it promised.
        assert!(number_at(&[0x03, 0x80, 0xFF], 0).is_err());
    }
}
