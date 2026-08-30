//! Helpers built on top of the object model.
//!
//! The important one is [`walk_list`]: kernel data structures are
//! overwhelmingly doubly-linked lists of `_LIST_ENTRY` nodes embedded *inside*
//! the structure they link, so walking one means repeatedly subtracting the
//! member's offset from the link pointer. The `CONTAINING_RECORD` idiom.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashSet;

use crate::error::{Result, VolatilityError};
use crate::framework::objects::template::Encoding;
use crate::framework::objects::{decode_string, Object};

/// Upper bound on how many nodes a list walk will visit.
///
/// A corrupt or deliberately poisoned list can be circular in a way the seen-set
/// does not catch quickly. This stops a plugin hanging on a hostile image.
pub const MAX_LIST_LENGTH: usize = 1_000_000;

/// Read a fixed-size character array as a string.
pub fn array_to_string(object: &Object) -> Result<String> {
    object.as_string()
}

/// Follow a pointer to a NUL-terminated string.
pub fn pointer_to_string(object: &Object, max_length: usize) -> Result<String> {
    let address = object.pointer_value()?;
    if address == 0 {
        return Ok(String::new());
    }
    let data = object
        .context()
        .layers
        .read(object.layer_name(), address, max_length, true)?;
    Ok(decode_string(&data, Encoding::Utf8))
}

/// Read a Windows `_UNICODE_STRING`, which stores a length in bytes and a
/// pointer to the (not necessarily NUL-terminated) characters.
pub fn unicode_string(object: &Object) -> Result<String> {
    let length = object.member("Length")?.as_u64()? as usize;
    if length == 0 {
        return Ok(String::new());
    }
    let buffer = object.member("Buffer")?;
    let address = buffer.pointer_value()?;
    if address == 0 {
        return Ok(String::new());
    }
    // The length is in bytes but the characters are UTF-16, and an absurd length
    // means the structure was misread rather than that the string is huge.
    if length > 0x10000 {
        return Err(VolatilityError::Other(format!(
            "Implausible UNICODE_STRING length {length}"
        )));
    }
    // The buffer is named by a pointer, so it is read from the layer this
    // structure's pointers refer to.
    let data =
        object
            .context()
            .layers
            .read(buffer.native_layer_name(), address, length, false)?;
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    // Decoded whole, then cut at the first terminator: a byte that is not
    // valid text becomes a replacement character and the string carries on,
    // which is what upstream prints.
    let decoded = String::from_utf16_lossy(&units);
    let end = decoded.find('\0').unwrap_or(decoded.len());
    Ok(decoded[..end].to_string())
}

/// The name of a list node's forward or backward link.
///
/// The two kernels spell these differently, so the name is taken from whichever
/// pair the node actually declares rather than assumed.
fn link_member(node: &Object, forward: bool) -> Result<String> {
    const NAMES: [(&str, &str); 2] = [("Flink", "Blink"), ("next", "prev")];
    for (forward_name, backward_name) in NAMES {
        if node.has_member(forward_name) {
            return Ok(if forward {
                forward_name.to_string()
            } else {
                backward_name.to_string()
            });
        }
    }
    Err(VolatilityError::Other(format!(
        "'{}' does not look like a list node: it has no Flink/next member",
        node.type_name()
    )))
}

/// Walk a doubly-linked list of `_LIST_ENTRY` nodes.
///
/// `head` is the list head, `type_name` the fully qualified type of the objects
/// on the list, and `member` the name of the `_LIST_ENTRY` member inside that
/// type. Each yielded object is the *containing* structure, found by
/// subtracting the member's offset from the link pointer.
///
/// The head itself is not yielded, and the walk stops when it returns to the
/// head, revisits a node, or hits an unreadable address.
pub fn walk_list(
    head: &Object,
    type_name: &str,
    member: &str,
    forward: bool,
) -> Result<Vec<Object>> {
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    walk_list_into(head, type_name, member, forward, &mut seen, &mut results)?;
    Ok(results)
}

/// Walk a list in both directions, as the Linux task list requires.
///
/// A single unreadable node ends a walk, stranding everything beyond it. Walking
/// forward and then backward from the same head reaches those entries from the
/// other side, and the shared seen-set keeps each node to a single appearance.
pub fn walk_list_both(head: &Object, type_name: &str, member: &str) -> Result<Vec<Object>> {
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    walk_list_into(head, type_name, member, true, &mut seen, &mut results)?;
    walk_list_into(head, type_name, member, false, &mut seen, &mut results)?;
    Ok(results)
}

/// The walk itself, appending to `results` and recording every node in `seen`.
///
/// Nodes already in `seen` are skipped rather than re-emitted, which is what
/// lets a second pass in the opposite direction pick up only what the first
/// missed.
fn walk_list_into(
    head: &Object,
    type_name: &str,
    member: &str,
    forward: bool,
    seen: &mut HashSet<u64>,
    results: &mut Vec<Object>,
) -> Result<()> {
    let context = head.context().clone();
    let template = context.symbol_space.get_type(type_name)?;

    // Offset of the link member within the containing structure.
    let member_offset = context
        .symbol_space
        .find_member(&template, member)?
        .map(|(offset, _)| offset)
        .ok_or_else(|| {
            VolatilityError::Other(format!("Type '{type_name}' has no member '{member}'"))
        })?;

    // Windows `_LIST_ENTRY` names its links Flink/Blink. Linux `list_head`
    // names them next/prev. Pick whichever the head actually has.
    let link = link_member(head, forward)?;
    let head_offset = head.offset();
    seen.insert(head_offset);

    let mut current = head.member(&link)?.pointer_value()?;

    while current != 0 && current != head_offset {
        if !seen.insert(current) {
            // Already walked, either earlier in this pass or by the pass in the
            // other direction. Either way there is nothing new beyond it.
            log::debug!("List walk revisited {current:#x}; stopping");
            break;
        }
        if results.len() >= MAX_LIST_LENGTH {
            log::warn!("List walk exceeded {MAX_LIST_LENGTH} entries; truncating");
            break;
        }

        // Step back from the link to the start of the containing structure.
        let containing = current.wrapping_sub(member_offset);
        let object =
            context.object_from_template(template.clone(), head.layer_name(), containing);

        // The structure has to start somewhere readable to be worth yielding.
        if context
            .layers
            .read(head.layer_name(), containing, 1, false)
            .is_err()
        {
            log::debug!("List walk stopped at {current:#x}: object start unreadable");
            break;
        }

        // Yield before following the link: a node whose own contents are
        // readable counts, even when the link out of it is not.
        results.push(object.clone());

        let next = match object.member(member).and_then(|entry| entry.member(&link)) {
            Ok(entry) => match entry.pointer_value() {
                Ok(value) => value,
                Err(error) => {
                    log::debug!("List walk stopped at {current:#x}: {error}");
                    break;
                }
            },
            Err(error) => {
                log::debug!("List walk stopped at {current:#x}: {error}");
                break;
            }
        };

        current = next;
    }

    Ok(())
}

/// Walk a list whose head *is* the first element's link member, as used by
/// Linux `list_head` members that are embedded in a containing struct.
pub fn walk_list_head(
    head: &Object,
    type_name: &str,
    member: &str,
) -> Result<Vec<Object>> {
    walk_list(head, type_name, member, true)
}

/// Follow a singly-linked list through a pointer member.
///
/// Stops on a null pointer, a repeat visit, or an unreadable node.
pub fn walk_singly_linked(
    start: &Object,
    next_member: &str,
    limit: usize,
) -> Result<Vec<Object>> {
    let mut results = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    let mut current = start.clone();

    while results.len() < limit.min(MAX_LIST_LENGTH) {
        if !seen.insert(current.offset()) {
            break;
        }
        let next = match current.member(next_member) {
            Ok(pointer) => match pointer.pointer_value() {
                Ok(0) | Err(_) => {
                    results.push(current);
                    break;
                }
                Ok(address) => address,
            },
            Err(_) => {
                results.push(current);
                break;
            }
        };
        let following = current.at_offset(next);
        results.push(current);
        current = following;
    }
    Ok(results)
}

/// Read an array of pointers, dereferencing each into `type_name`.
///
/// Null and unreadable entries are skipped, which is what callers walking a
/// sparse table (a handle table, a driver's IRP array) want.
pub fn array_of_pointers(array: &Object, type_name: &str) -> Result<Vec<Object>> {
    let context = array.context().clone();
    let template = context.symbol_space.get_type(type_name)?;
    let mut results = Vec::new();

    for element in array.iter_array()? {
        let Ok(address) = element.pointer_value() else {
            continue;
        };
        if address == 0 {
            continue;
        }
        results.push(context.object_from_template(
            template.clone(),
            array.layer_name(),
            address,
        ));
    }
    Ok(results)
}

/// Render bytes as a hex dump, the way `volshell` and dump plugins do.
pub fn hex_dump(data: &[u8], base_offset: u64) -> String {
    let mut output = String::new();
    for (index, chunk) in data.chunks(16).enumerate() {
        let offset = base_offset + (index * 16) as u64;
        let hex: Vec<String> = chunk.iter().map(|byte| format!("{byte:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|&byte| {
                if byte.is_ascii_graphic() || byte == b' ' {
                    byte as char
                } else {
                    '.'
                }
            })
            .collect();
        output.push_str(&format!(
            "{offset:#010x}  {:<47}  {ascii}\n",
            hex.join(" ")
        ));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::context::Context;
    use crate::framework::layers::physical::BufferLayer;
    use crate::framework::symbols::isf::IsfFile;
    use crate::framework::symbols::native::x64_native_table;
    use crate::framework::symbols::SymbolTable;
    use std::sync::Arc;

    /// A type with a `_LIST_ENTRY` at offset 8 and a value at offset 0.
    const ISF: &str = r#"{
        "metadata": {"format": "6.2.0"},
        "base_types": {
            "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
            "unsigned long long": {"size": 8, "signed": false, "kind": "int", "endian": "little"}
        },
        "user_types": {
            "_LIST_ENTRY": {"kind": "struct", "size": 16, "fields": {
                "Flink": {"offset": 0, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}},
                "Blink": {"offset": 8, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}}
            }},
            "_NODE": {"kind": "struct", "size": 24, "fields": {
                "Value": {"offset": 0, "type": {"kind": "base", "name": "unsigned long long"}},
                "Links": {"offset": 8, "type": {"kind": "struct", "name": "_LIST_ENTRY"}}
            }}
        },
        "enums": {}, "symbols": {}
    }"#;

    /// Build three `_NODE`s linked in a ring through a head at 0x100.
    fn build_context() -> (Arc<Context>, u64) {
        let mut memory = vec![0u8; 0x1000];
        let head = 0x100u64;
        let nodes = [0x200u64, 0x300, 0x400];

        let write = |memory: &mut Vec<u8>, at: u64, value: u64| {
            let at = at as usize;
            memory[at..at + 8].copy_from_slice(&value.to_le_bytes());
        };

        // Each node's Links member sits 8 bytes into the node.
        for (index, node) in nodes.iter().enumerate() {
            write(&mut memory, *node, 0xA0 + index as u64);
            let links = node + 8;
            let next = if index + 1 < nodes.len() {
                nodes[index + 1] + 8
            } else {
                head
            };
            let previous = if index == 0 {
                head
            } else {
                nodes[index - 1] + 8
            };
            write(&mut memory, links, next);
            write(&mut memory, links + 8, previous);
        }
        write(&mut memory, head, nodes[0] + 8);
        write(&mut memory, head + 8, nodes[2] + 8);

        let context = Arc::new(Context::new());
        context
            .layers
            .add(Arc::new(BufferLayer::new("mem", memory)));
        let isf = IsfFile::from_slice(ISF.as_bytes()).unwrap();
        context.add_symbol_table(Arc::new(SymbolTable::new(
            "nt",
            isf,
            x64_native_table(),
        )));
        (context, head)
    }

    #[test]
    fn walks_a_list_back_to_its_head() {
        let (context, head) = build_context();
        let head_object = context.object("nt!_LIST_ENTRY", "mem", head).unwrap();

        let nodes = walk_list(&head_object, "nt!_NODE", "Links", true).unwrap();
        assert_eq!(nodes.len(), 3);

        let values: Vec<u64> = nodes
            .iter()
            .map(|node| node.member("Value").unwrap().as_u64().unwrap())
            .collect();
        assert_eq!(values, vec![0xA0, 0xA1, 0xA2]);
        // The containing record is found by stepping back over the link offset.
        assert_eq!(nodes[0].offset(), 0x200);
    }

    #[test]
    fn walking_backwards_reverses_the_order() {
        let (context, head) = build_context();
        let head_object = context.object("nt!_LIST_ENTRY", "mem", head).unwrap();
        let nodes = walk_list(&head_object, "nt!_NODE", "Links", false).unwrap();
        let values: Vec<u64> = nodes
            .iter()
            .map(|node| node.member("Value").unwrap().as_u64().unwrap())
            .collect();
        assert_eq!(values, vec![0xA2, 0xA1, 0xA0]);
    }

    #[test]
    fn a_self_pointing_list_terminates() {
        // A node whose Flink points at itself must not loop forever.
        let mut memory = vec![0u8; 0x1000];
        memory[0x208..0x210].copy_from_slice(&0x208u64.to_le_bytes());
        memory[0x100..0x108].copy_from_slice(&0x208u64.to_le_bytes());

        let context = Arc::new(Context::new());
        context.layers.add(Arc::new(BufferLayer::new("mem", memory)));
        let isf = IsfFile::from_slice(ISF.as_bytes()).unwrap();
        context.add_symbol_table(Arc::new(SymbolTable::new("nt", isf, x64_native_table())));

        let head = context.object("nt!_LIST_ENTRY", "mem", 0x100).unwrap();
        let nodes = walk_list(&head, "nt!_NODE", "Links", true).unwrap();
        assert_eq!(nodes.len(), 1);
    }

    #[test]
    fn hex_dump_lays_out_sixteen_bytes_per_line() {
        let dump = hex_dump(b"ABCDEFGHIJKLMNOP\x00\x01", 0x1000);
        let lines: Vec<&str> = dump.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("0x00001000"));
        assert!(lines[0].ends_with("ABCDEFGHIJKLMNOP"));
        assert!(lines[1].ends_with(".."));
    }
}
