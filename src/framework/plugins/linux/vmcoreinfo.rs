//! The kernel publishes a small set of key/value pairs describing its own
//! layout (structure offsets, the page size, the kernel's load address), so
//! that a crash dump can be interpreted without matching debug symbols.
//! Reading it is often the quickest way to learn how an unfamiliar image is
//! laid out.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::layers::scanners::{scan_layer, BytesScanner};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

/// Enumerate VMCoreInfo tables
pub struct VmCoreInfo;

/// The note's name field, which identifies it among the kernel's ELF notes.
const NOTE_NAME: &[u8] = b"VMCOREINFO\0\0";

/// An ELF note header sits immediately before the name.
const ELF_NOTE_SIZE: u64 = 12;

impl Plugin for VmCoreInfo {
    fn name(&self) -> &'static str {
        "linux.vmcoreinfo.VMCoreInfo"
    }

    fn description(&self) -> &'static str {
        "Enumerate VMCoreInfo tables"
    }

    fn requirements(&self) -> Vec<Requirement> {
        // The note describes the kernel's own layout, so it is readable
        // without any symbols at all. That is the point of it, and it is why
        // this plugin asks only for somewhere to look.
        vec![Requirement::new(
            "primary",
            "Memory layer to scan",
            crate::framework::plugins::RequirementKind::TranslationLayer,
        )]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Offset", ColumnType::UInt),
            Column::string("Key"),
            Column::string("Value"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let layer_name = config
            .get_string("primary")
            .unwrap_or_else(|| crate::framework::plugins::windows::physical_layer(config));
        let mut grid = TreeGrid::new(self.columns());

        // The note is found by searching rather than by symbol: a crashed
        // kernel can leave more than one copy behind, and each is reported.
        for offset in scan_for_note(&context, &layer_name)? {
            // The name is preceded by the note header and followed by the
            // payload. The header says how long that payload is.
            let note = offset - ELF_NOTE_SIZE;
            let Ok(header) = context
                .layers
                .read(&layer_name, note, ELF_NOTE_SIZE as usize, false)
            else {
                continue;
            };
            let name_size = u32::from_le_bytes(header[0..4].try_into().unwrap());
            let payload_size = u32::from_le_bytes(header[4..8].try_into().unwrap());
            let note_type = u32::from_le_bytes(header[8..12].try_into().unwrap());
            // The name length counts the terminator but not the padding.
            if name_size as usize != NOTE_NAME.len() - 1 || note_type != 0 || payload_size == 0 {
                continue;
            }

            let Ok(data) = context.layers.read(
                &layer_name,
                offset + NOTE_NAME.len() as u64,
                payload_size as usize,
                false,
            ) else {
                continue;
            };
            // Every note this recognises opens with the kernel release.
            if !data.starts_with(b"OSRELEASE=") {
                continue;
            }

            let Some(pairs) = parse_note(&data) else {
                continue;
            };
            for (key, value) in pairs {
                grid.push(
                    0,
                    vec![
                        Value::hex(note),
                        Value::string(key),
                        Value::string(value),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// Find the note by searching for its name.
fn scan_for_note(context: &Arc<Context>, layer_name: &str) -> Result<Vec<u64>> {
    let layer = context.layers.get(layer_name)?;
    let scanner = BytesScanner::new(NOTE_NAME.to_vec());

    let mut offsets = Vec::new();
    scan_layer(layer.as_ref(), &context.layers, &scanner, None, |offset| {
        offsets.push(offset)
    })?;
    Ok(offsets)
}

/// Split the note's payload into its key/value pairs.
///
/// The payload is newline-separated `KEY=VALUE` text. A payload with any byte
/// that is not printable is not a note at all, which is how a chance match on
/// the name is rejected. Reading stops at the first blank line, and a key that
/// appears twice keeps the position of its first appearance and the value of
/// its last, which is what a dictionary does with it.
fn parse_note(data: &[u8]) -> Option<Vec<(String, String)>> {
    // Python calls a byte printable if it is a digit, a letter, punctuation or
    // whitespace, which is the printable ASCII range plus five control codes.
    if !data
        .iter()
        .all(|byte| (0x20..0x7F).contains(byte) || b"\t\n\r\x0b\x0c".contains(byte))
    {
        return None;
    }

    let text = String::from_utf8_lossy(data);
    let mut order: Vec<String> = Vec::new();
    let mut values: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for line in crate::framework::objects::utility::python_splitlines(&text) {
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once('=') else {
            // A line with no separator cannot be split, which upstream treats
            // as the note being malformed rather than as a line to skip.
            return None;
        };
        if values.insert(key.to_string(), parse_value(key, value)).is_none() {
            order.push(key.to_string());
        }
    }
    if order.is_empty() {
        return None;
    }
    Some(
        order
            .into_iter()
            .map(|key| {
                let value = values.get(&key).cloned().unwrap_or_default();
                (key, value)
            })
            .collect(),
    )
}

/// One value written the way the reference implementation writes it.
///
/// An address is reported in hexadecimal with its prefix. A count, a length, a
/// size, an offset and the page size are parsed as numbers, which turns a
/// hexadecimal one in the note into a decimal one in the output. Anything else
/// is passed through unchanged.
fn parse_value(key: &str, value: &str) -> String {
    if key.starts_with("SYMBOL(") || key == "KERNELOFFSET" {
        return match u64::from_str_radix(value, 16) {
            Ok(number) => format!("{number:#x}"),
            Err(_) => value.to_string(),
        };
    }
    if key.starts_with("NUMBER(")
        || key.starts_with("LENGTH(")
        || key.starts_with("SIZE(")
        || key.starts_with("OFFSET(")
        || key == "PAGESIZE"
    {
        if let Some(number) = python_int(value) {
            return number.to_string();
        }
    }
    value.to_string()
}

/// Read an integer the way Python's `int(text, 0)` reads one, where the base
/// comes from the prefix.
fn python_int(text: &str) -> Option<i64> {
    let text = text.trim();
    let (sign, rest) = match text.strip_prefix('-') {
        Some(rest) => (-1i64, rest),
        None => (1i64, text.strip_prefix('+').unwrap_or(text)),
    };
    let lowered = rest.to_ascii_lowercase();
    let (base, digits) = if let Some(digits) = lowered.strip_prefix("0x") {
        (16, digits)
    } else if let Some(digits) = lowered.strip_prefix("0o") {
        (8, digits)
    } else if let Some(digits) = lowered.strip_prefix("0b") {
        (2, digits)
    } else {
        (10, lowered.as_str())
    };
    let digits = digits.replace('_', "");
    i64::from_str_radix(&digits, base).ok().map(|value| sign * value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_key_value_payload() {
        let note = b"OSRELEASE=6.8.0-124-generic\nPAGESIZE=4096\nSYMBOL(init_task)=ffffffff82a1a940\n";
        let pairs = parse_note(note).expect("a printable payload is a note");

        assert_eq!(pairs.len(), 3);
        assert_eq!(
            pairs[0],
            ("OSRELEASE".to_string(), "6.8.0-124-generic".to_string())
        );
        assert_eq!(pairs[1], ("PAGESIZE".to_string(), "4096".to_string()));
        // An address is reported in hexadecimal, with its prefix.
        assert_eq!(
            pairs[2],
            (
                "SYMBOL(init_task)".to_string(),
                "0xffffffff82a1a940".to_string()
            )
        );
    }

    #[test]
    fn a_size_written_in_hexadecimal_is_reported_in_decimal() {
        let note = b"OSRELEASE=6.8.0\nSIZE(page)=0x40\nNUMBER(PG_lru)=4\n";
        let pairs = parse_note(note).expect("a printable payload is a note");
        assert_eq!(pairs[1], ("SIZE(page)".to_string(), "64".to_string()));
        assert_eq!(pairs[2], ("NUMBER(PG_lru)".to_string(), "4".to_string()));
    }

    #[test]
    fn a_payload_holding_unprintable_bytes_is_not_a_note() {
        let noise = b"OSRELEASE=6.8.0\n\xff\xfe=\x01\x02\n";
        assert!(parse_note(noise).is_none());
    }

    #[test]
    fn reading_stops_at_the_first_blank_line() {
        let note = b"OSRELEASE=6.8.0\n\nPAGESIZE=4096\n";
        let pairs = parse_note(note).expect("a printable payload is a note");
        assert_eq!(pairs.len(), 1);
    }
}
