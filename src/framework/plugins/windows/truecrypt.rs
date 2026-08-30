//! Search memory for TrueCrypt passphrases.
//!
//! TrueCrypt keeps the passphrase in a structure that records its own length
//! ahead of the characters. That length/content pairing is distinctive enough
//! to find by scanning, since a plausible length followed by exactly that many
//! printable bytes is rare in ordinary data.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::utility::{unicode_string, walk_list};
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::pe;

pub struct Passphrase;

const MAX_LENGTH: u32 = 64;

impl Plugin for Passphrase {
    fn name(&self) -> &'static str {
        "windows.truecrypt.Passphrase"
    }

    fn description(&self) -> &'static str {
        "TrueCrypt Cached Passphrase Finder"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel(), Requirement::new("min-length", "Minimum length of passphrases to identify", crate::framework::plugins::RequirementKind::Int)]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Offset", ColumnType::UInt),
            Column::int("Length"),
            Column::string("Password"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let minimum = config.get_int("min-length").unwrap_or(5) as u32;
        let mut grid = TreeGrid::new(self.columns());

        // Cached passphrases live in the driver's own data section, so there
        // is nothing to look at unless the driver is loaded.
        let Some(base) = truecrypt_base(&context, &kernel) else {
            return Ok(grid);
        };

        // The section table says where the data section is and how big it is.
        let Ok(headers) = context
            .layers
            .read(&kernel.layer_name, base, 0x1000, false)
        else {
            return Ok(grid);
        };
        let Some(data_section) = pe::sections(&headers)
            .ok()
            .and_then(|sections| sections.into_iter().find(|section| section.name == ".data"))
        else {
            return Ok(grid);
        };

        let start = base + data_section.virtual_address as u64;
        let size = data_section.virtual_size as usize;
        let Ok(data) = context.layers.read(&kernel.layer_name, start, size, true) else {
            return Ok(grid);
        };

        // Each candidate is a length followed by that many characters, then a
        // terminator and the padding that keeps the structure aligned.
        let mut position = 0usize;
        while position + 4 <= data.len() {
            let length = i32::from_le_bytes(data[position..position + 4].try_into().unwrap());
            position += 4;
            if length < minimum as i32 || length > MAX_LENGTH as i32 {
                continue;
            }
            let length = length as usize;

            let text_at = position;
            let Some(text) = data.get(text_at..text_at + length) else {
                continue;
            };
            // The passphrase is printable throughout.
            if !text.iter().all(|byte| (0x20..0x7F).contains(byte)) {
                continue;
            }
            // Three zero bytes follow the terminator, keeping the structure
            // aligned. Anything else means this is not one.
            let Some(padding) = data.get(text_at + length + 1..text_at + length + 4) else {
                continue;
            };
            if padding.iter().any(|byte| *byte != 0) {
                continue;
            }

            grid.push(
                0,
                vec![
                    Value::hex(start + text_at as u64),
                    Value::int(length as i64),
                    Value::string(String::from_utf8_lossy(text).to_string()),
                ],
            )?;
        }
        Ok(grid)
    }
}

/// Where the TrueCrypt driver is loaded, if it is.
fn truecrypt_base(context: &Arc<Context>, kernel: &Module) -> Option<u64> {
    let head = context
        .object_from_symbol(kernel, "PsLoadedModuleList", Some("_LIST_ENTRY"))
        .ok()?;
    let entries = walk_list(
        &head,
        &kernel.qualified("_LDR_DATA_TABLE_ENTRY"),
        "InLoadOrderLinks",
        true,
    )
    .ok()?;

    entries.into_iter().find_map(|entry| {
        let name = entry
            .member("BaseDllName")
            .and_then(|name| unicode_string(&name))
            .ok()?;
        if !name.eq_ignore_ascii_case("truecrypt.sys") {
            return None;
        }
        entry.member("DllBase").and_then(|base| base.pointer_value()).ok()
    })
}
