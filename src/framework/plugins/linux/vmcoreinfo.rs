//! Report the VMCOREINFO note the kernel leaves for crash tooling.
//!
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
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

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
        // The note is found in the kernel's own address space, so the kernel
        // has to be identified before the search can start.
        vec![Requirement::kernel()]
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
        let kernel = kernel_module(&context, config)?;
        let mut grid = TreeGrid::new(self.columns());

        // The note is found by searching rather than by symbol: a crashed
        // kernel can leave more than one copy behind, and each is reported.
        let mask = context.layers.address_mask(&kernel.layer_name);
        for offset in scan_for_note(&context, &kernel.layer_name)? {
            // The name is preceded by the note header and followed by the
            // payload. The header says how long that payload is.
            let note = offset - ELF_NOTE_SIZE;
            let Ok(header) = context
                .layers
                .read(&kernel.layer_name, note, ELF_NOTE_SIZE as usize, false)
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
                &kernel.layer_name,
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

            for (key, value) in parse_note(&data) {
                // Symbol addresses and the load offset are stored as bare hex
                // and reported with the prefix that says so.
                let value = if key.starts_with("SYMBOL(") || key == "KERNELOFFSET" {
                    match u64::from_str_radix(value.trim(), 16) {
                        Ok(number) => format!("{number:#x}"),
                        Err(_) => value,
                    }
                } else {
                    value
                };
                grid.push(
                    0,
                    vec![
                        Value::hex(note & mask),
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
/// The payload is newline-separated `KEY=VALUE` text following the ELF note
/// header, so the parse starts from the first line that looks like one.
fn parse_note(data: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(data);
    let mut results = Vec::new();

    for line in text.split(['\n', '\0']) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        // The keys are upper-case identifiers with a few punctuation
        // characters. Anything else is the surrounding binary rather than a
        // pair.
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_()-.".contains(&byte))
        {
            continue;
        }
        results.push((key.to_string(), value.to_string()));
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_key_value_payload() {
        let note = b"VMCOREINFO\0OSRELEASE=6.8.0-124-generic\nPAGESIZE=4096\nSYMBOL(init_task)=ffffffff82a1a940\n";
        let pairs = parse_note(note);

        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0], ("OSRELEASE".to_string(), "6.8.0-124-generic".to_string()));
        assert_eq!(pairs[1], ("PAGESIZE".to_string(), "4096".to_string()));
        // Keys may carry a parenthesised argument.
        assert_eq!(pairs[2].0, "SYMBOL(init_task)");
    }

    #[test]
    fn surrounding_binary_is_not_mistaken_for_pairs() {
        // Binary noise containing an '=' must not produce a pair.
        let noise = b"\xff\xfe=\x01\x02\n\x00\x00";
        assert!(parse_note(noise).is_empty());
    }
}
