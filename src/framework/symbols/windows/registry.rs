//! Walking registry keys and values inside a hive.
//!
//! Cells inside a hive are self-describing: each opens with a two-character
//! signature saying what it is. Keys (`nk`) point at a list of subkeys and a
//! list of values (`vk`). The subkey list is itself a cell, in one of several
//! formats depending on how many subkeys there are.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashSet;
use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::Context;
use crate::framework::layers::registry::RegistryHive;
use crate::framework::layers::DataLayer;
use crate::framework::objects::Object;

/// Guard against a hive whose links form a cycle.
const MAX_KEYS: usize = 500_000;

/// Registry value types, as stored in a `vk` cell's `Type` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    None,
    String,
    ExpandString,
    Binary,
    Dword,
    DwordBigEndian,
    Link,
    MultiString,
    ResourceList,
    FullResourceDescriptor,
    ResourceRequirementsList,
    Qword,
    Unknown(u32),
}

impl ValueType {
    pub fn parse(value: u32) -> Self {
        match value {
            0 => ValueType::None,
            1 => ValueType::String,
            2 => ValueType::ExpandString,
            3 => ValueType::Binary,
            4 => ValueType::Dword,
            5 => ValueType::DwordBigEndian,
            6 => ValueType::Link,
            7 => ValueType::MultiString,
            8 => ValueType::ResourceList,
            9 => ValueType::FullResourceDescriptor,
            10 => ValueType::ResourceRequirementsList,
            11 => ValueType::Qword,
            other => ValueType::Unknown(other),
        }
    }

    /// The name Windows uses for this type.
    pub fn as_str(&self) -> String {
        match self {
            ValueType::None => "REG_NONE".to_string(),
            ValueType::String => "REG_SZ".to_string(),
            ValueType::ExpandString => "REG_EXPAND_SZ".to_string(),
            ValueType::Binary => "REG_BINARY".to_string(),
            ValueType::Dword => "REG_DWORD".to_string(),
            ValueType::DwordBigEndian => "REG_DWORD_BIG_ENDIAN".to_string(),
            ValueType::Link => "REG_LINK".to_string(),
            ValueType::MultiString => "REG_MULTI_SZ".to_string(),
            ValueType::ResourceList => "REG_RESOURCE_LIST".to_string(),
            ValueType::FullResourceDescriptor => "REG_FULL_RESOURCE_DESCRIPTOR".to_string(),
            ValueType::ResourceRequirementsList => "REG_RESOURCE_REQUIREMENTS_LIST".to_string(),
            ValueType::Qword => "REG_QWORD".to_string(),
            ValueType::Unknown(value) => format!("REG_UNKNOWN({value})"),
        }
    }
}

/// A key read out of a hive.
#[derive(Clone)]
pub struct RegistryKey {
    pub object: Object,
    /// The cell index the key was read from.
    pub cell_index: u64,
    /// Path from the hive root, using backslashes.
    pub path: String,
    /// Whether the key lives in the hive's volatile store.
    pub volatile: bool,
}

impl RegistryKey {
    /// The key's own name.
    ///
    /// Names are stored either as Latin-1 bytes or as UTF-16, which a flag bit
    /// distinguishes.
    pub fn name(&self) -> Result<String> {
        read_cell_name(&self.object, "Name", "NameLength", 0x20)
    }

    /// When the key was last written, as a Windows FILETIME.
    pub fn last_write_time(&self) -> Result<u64> {
        self.object
            .member("LastWriteTime")
                        .and_then(|time| time.member("QuadPart"))
            .and_then(|time| time.member("QuadPart").or(Ok(time)))
            .and_then(|time| time.as_u64())
    }

    /// The key's class name.
    ///
    /// Most keys have none. The boot key is stored across four that do, which
    /// is the only reason this matters.
    pub fn class_name(&self, hive: &RegistryHive) -> Option<String> {
        let length = self.object.member("ClassLength").ok()?.as_u64().ok()? as usize;
        if length == 0 || length > 256 {
            return None;
        }

        let cell_index = self.object.member("Class").ok()?.as_u64().ok()?;
        if cell_index == 0 || cell_index == 0xFFFF_FFFF {
            return None;
        }

        // The class sits in its own cell, after the four-byte size header.
        let data = self
            .object
            .context()
            .layers
            .read(hive.name(), cell_index + 4, length, false)
            .ok()?;

        // Class names are UTF-16 even when the key's own name is not.
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        Some(String::from_utf16_lossy(&units))
    }

    pub fn subkey_count(&self) -> u64 {
        self.object
            .member("SubKeyCounts")
            .and_then(|counts| counts.index(0))
            .and_then(|count| count.as_u64())
            .unwrap_or(0)
    }
}

/// A value read out of a hive.
pub struct RegistryValue {
    pub object: Object,
    pub cell_index: u64,
}

impl RegistryValue {
    /// The value's name. An empty name is the key's default value.
    pub fn name(&self) -> Result<String> {
        read_cell_name(&self.object, "Name", "NameLength", 0x01)
    }

    pub fn value_type(&self) -> ValueType {
        ValueType::parse(
            self.object
                .member("Type")
                .and_then(|kind| kind.as_u64())
                .unwrap_or(0) as u32,
        )
    }

    /// The raw bytes of the value's data.
    ///
    /// Data of four bytes or fewer is stored inline in the `Data` field itself,
    /// with the high bit of the length marking that case.
    pub fn data(&self, hive: &RegistryHive) -> Result<Vec<u8>> {
        let raw_length = self.object.member("DataLength")?.as_u64()?;
        let inline = raw_length & 0x8000_0000 != 0;
        let length = (raw_length & 0x7FFF_FFFF) as usize;

        // A length beyond any plausible value means the cell was misread.
        if length > 0x100_0000 {
            return Err(VolatilityError::Other(format!(
                "Implausible registry value length {length}"
            )));
        }

        let data_field = self.object.member("Data")?;
        if inline {
            // The data occupies the Data field's own bytes.
            let bytes = self
                .object
                .context()
                .layers
                .read(self.object.layer_name(), data_field.offset(), 4, true)?;
            return Ok(bytes[..length.min(4)].to_vec());
        }

        let cell_index = data_field.as_u64()?;
        let context = self.object.context().clone();
        // The cell's four-byte size header precedes the data.
        context
            .layers
            .read(hive.name(), cell_index + 4, length, true)
    }

    /// The value's data rendered according to its type.
    pub fn decoded(&self, hive: &RegistryHive) -> Result<String> {
        let data = self.data(hive)?;
        Ok(match self.value_type() {
            ValueType::String | ValueType::ExpandString | ValueType::Link => {
                decode_utf16(&data)
            }
            ValueType::MultiString => decode_utf16(&data)
                .split('\0')
                .filter(|part| !part.is_empty())
                .collect::<Vec<&str>>()
                .join(", "),
            ValueType::Dword if data.len() >= 4 => {
                u32::from_le_bytes(data[..4].try_into().unwrap()).to_string()
            }
            ValueType::DwordBigEndian if data.len() >= 4 => {
                u32::from_be_bytes(data[..4].try_into().unwrap()).to_string()
            }
            ValueType::Qword if data.len() >= 8 => {
                u64::from_le_bytes(data[..8].try_into().unwrap()).to_string()
            }
            _ => hex::encode(&data),
        })
    }
}

pub fn decode_utf16(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\0')
        .to_string()
}

/// Read a cell's name, honouring the flag that says whether it is compressed.
///
/// A "compressed" name is one byte per character (Latin-1). Otherwise it is
/// UTF-16. `compressed_flag` is the bit in the cell's `Flags` that marks it.
fn read_cell_name(
    object: &Object,
    name_member: &str,
    length_member: &str,
    compressed_flag: u64,
) -> Result<String> {
    let length = object.member(length_member)?.as_u64()? as usize;
    if length == 0 {
        return Ok(String::new());
    }
    // A name longer than this means the cell was misread.
    if length > 4096 {
        return Err(VolatilityError::Other(format!(
            "Implausible registry name length {length}"
        )));
    }

    let flags = object
        .member("Flags")
        .and_then(|flags| flags.as_u64())
        .unwrap_or(0);
    let compressed = flags & compressed_flag != 0;

    let name_field = object.member(name_member)?;
    let data = object.context().layers.read(
        object.layer_name(),
        name_field.offset(),
        length,
        true,
    )?;

    Ok(if compressed {
        data.iter().map(|&byte| byte as char).collect()
    } else {
        decode_utf16(&data)
    })
}

/// Read the key at a cell index, if the cell really is a key.
pub fn read_key(
    context: &Arc<Context>,
    hive: &RegistryHive,
    table: &str,
    cell_index: u64,
    path: String,
) -> Result<RegistryKey> {
    let template = context
        .symbol_space
        .get_type(&crate::framework::symbols::join_name(table, "_CM_KEY_NODE"))?;
    // Cells begin with a four-byte size that is not part of the structure.
    let object = context.object_from_template(template, hive.name(), cell_index + 4);

    // Confirm the signature before trusting anything else in the cell.
    let signature = object.member("Signature")?.as_u64()?;
    if signature != u16::from_le_bytes(*b"nk") as u64 {
        return Err(VolatilityError::Other(format!(
            "Cell {cell_index:#x} is not a key node"
        )));
    }

    Ok(RegistryKey {
        object,
        cell_index,
        path,
        volatile: cell_index & 0x8000_0000 != 0,
    })
}

/// The subkeys of a key.
pub fn subkeys(
    context: &Arc<Context>,
    hive: &RegistryHive,
    table: &str,
    key: &RegistryKey,
) -> Result<Vec<RegistryKey>> {
    let mut results = Vec::new();

    // A key has a stable subkey list and a volatile one. The recorded counts
    // are not consulted: a volatile list can hold keys the count does not
    // admit to, and the list itself says when it ends.
    for store in 0..2u64 {
        let Ok(list_index) = key
            .object
            .member("SubKeyLists")
            .and_then(|lists| lists.index(store))
            .and_then(|list| list.as_u64())
        else {
            continue;
        };
        // An empty list is encoded as an all-ones cell index.
        if list_index == 0 || list_index == 0xFFFF_FFFF {
            continue;
        }

        for cell_index in read_subkey_list(context, hive, table, list_index, 0)? {
            let name_path = key.path.clone();
            if let Ok(subkey) = read_key(context, hive, table, cell_index, name_path) {
                let full_path = match subkey.name() {
                    Ok(name) if key.path.is_empty() => name,
                    Ok(name) => format!("{}\\{}", key.path, name),
                    Err(_) => key.path.clone(),
                };
                results.push(RegistryKey {
                    path: full_path,
                    ..subkey
                });
            }
        }
    }
    Ok(results)
}

/// Read a subkey list cell, which may itself point at further lists.
///
/// `lf` and `lh` hold `(cell, hash)` pairs. `li` holds bare cell indices. `ri`
/// holds indices of further lists, so it recurses.
fn read_subkey_list(
    context: &Arc<Context>,
    hive: &RegistryHive,
    table: &str,
    list_index: u64,
    depth: usize,
) -> Result<Vec<u64>> {
    // `ri` lists nest, but never deeply in practice. A deeper chain means the
    // hive is corrupt or hostile.
    if depth > 8 {
        return Ok(Vec::new());
    }

    let signature = context
        .layers
        .read(hive.name(), list_index + 4, 2, false)
        .unwrap_or_default();

    if signature.len() < 2 {
        return Ok(Vec::new());
    }

    let template = context.symbol_space.get_type(
        &crate::framework::symbols::join_name(table, "_CM_KEY_INDEX"),
    )?;
    let index = context.object_from_template(template, hive.name(), list_index + 4);
    let count = index.member("Count")?.as_u64()?.min(0x10000);

    let list = index.member("List")?;
    let entry_base = list.offset();
    let mut results = Vec::new();
    // A listed index beyond the hive's own store never belonged to it: the
    // list was smeared, or was never a list.
    let within = |index: u64| index & 0x7FFF_FFFF <= hive.maximum_index();

    match &signature[..2] {
        // Fast and hash leaves: pairs of (cell index, hash).
        b"lf" | b"lh" => {
            for position in 0..count {
                let at = entry_base + position * 8;
                if let Ok(data) = context.layers.read(hive.name(), at, 4, false) {
                    let entry = u32::from_le_bytes(data.try_into().unwrap()) as u64;
                    if within(entry) {
                        results.push(entry);
                    }
                }
            }
        }
        // An index leaf also holds bare cell indices, but the subkey walk
        // recognises only the hashed and root forms, so such a list yields
        // nothing.
        // A list that is really a key: a store with a single subkey points
        // straight at it rather than at a list of one.
        b"nk" => results.push(list_index),
        // Index root: indices of further lists.
        b"ri" => {
            for position in 0..count {
                let at = entry_base + position * 4;
                if let Ok(data) = context.layers.read(hive.name(), at, 4, false) {
                    let nested = u32::from_le_bytes(data.try_into().unwrap()) as u64;
                    if within(nested) {
                        results.extend(read_subkey_list(context, hive, table, nested, depth + 1)?);
                    }
                }
            }
        }
        _ => {}
    }
    Ok(results)
}

/// The values of a key.
pub fn values(
    context: &Arc<Context>,
    hive: &RegistryHive,
    table: &str,
    key: &RegistryKey,
) -> Result<Vec<RegistryValue>> {
    let count = key
        .object
        .member("ValueList")
        .and_then(|list| list.member("Count"))
        .and_then(|count| count.as_u64())
        .unwrap_or(0)
        .min(0x10000);
    if count == 0 {
        return Ok(Vec::new());
    }

    let list_index = key
        .object
        .member("ValueList")?
        .member("List")?
        .as_u64()?;
    if list_index == 0 || list_index == 0xFFFF_FFFF {
        return Ok(Vec::new());
    }

    let template = context.symbol_space.get_type(
        &crate::framework::symbols::join_name(table, "_CM_KEY_VALUE"),
    )?;

    let mut results = Vec::new();
    for position in 0..count {
        // The value list is an array of cell indices, after the cell's size.
        let at = list_index + 4 + position * 4;
        let Ok(data) = context.layers.read(hive.name(), at, 4, false) else {
            continue;
        };
        let cell_index = u32::from_le_bytes(data.try_into().unwrap()) as u64;
        if cell_index == 0 {
            continue;
        }
        results.push(RegistryValue {
            object: context.object_from_template(
                template.clone(),
                hive.name(),
                cell_index + 4,
            ),
            cell_index,
        });
    }
    Ok(results)
}

/// Walk a hive from `start`, yielding every key reachable from it.
pub fn walk_keys(
    context: &Arc<Context>,
    hive: &RegistryHive,
    table: &str,
    start: RegistryKey,
    recurse: bool,
) -> Result<Vec<RegistryKey>> {
    let mut results = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    let mut pending = vec![start];

    while let Some(key) = pending.pop() {
        if !seen.insert(key.cell_index) || results.len() >= MAX_KEYS {
            continue;
        }
        let children = subkeys(context, hive, table, &key).unwrap_or_default();
        results.push(key);
        if recurse {
            pending.extend(children);
        } else {
            // Without recursion the immediate children are still reported, but
            // their own children are not explored.
            for child in children {
                if seen.insert(child.cell_index) {
                    results.push(child);
                }
            }
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_types_map_to_their_windows_names() {
        assert_eq!(ValueType::parse(1).as_str(), "REG_SZ");
        assert_eq!(ValueType::parse(4).as_str(), "REG_DWORD");
        assert_eq!(ValueType::parse(7).as_str(), "REG_MULTI_SZ");
        assert_eq!(ValueType::parse(99).as_str(), "REG_UNKNOWN(99)");
    }

    #[test]
    fn utf16_decoding_strips_the_terminator() {
        let data: Vec<u8> = "Hi\0".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(decode_utf16(&data), "Hi");
    }
}

/// A registry value rendered the way its type says it should be.
///
/// A number is shown as a number, binary data as a dump, and everything else as
/// the text it is meant to be, falling back to a dump when decoding it would
/// lose data.
pub fn value_cell(kind: ValueType, data: &[u8]) -> crate::framework::renderers::Value {
    use crate::framework::renderers::Value;

    match kind {
        ValueType::Dword | ValueType::DwordBigEndian | ValueType::Qword => {
            let mut raw = [0u8; 8];
            let take = data.len().min(8);
            raw[..take].copy_from_slice(&data[..take]);
            let number = if kind == ValueType::DwordBigEndian {
                u32::from_be_bytes(data.get(..4).and_then(|b| b.try_into().ok()).unwrap_or([0; 4]))
                    as u64
            } else {
                u64::from_le_bytes(raw)
            };
            Value::MultiTypeData(number.to_string().into_bytes())
        }
        ValueType::Binary | ValueType::None => Value::HexDump(data.to_vec()),
        ValueType::MultiString => Value::MultiString(data.to_vec()),
        _ => Value::WideText(data.to_vec()),
    }
}
