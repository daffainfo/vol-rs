//! Find Mac memory regions that look like injected code.
//!
//! As on Windows, code is normally mapped from a file. A region that is both
//! writable and executable, with nothing backing it, was written at runtime.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::mac::list_processes;

pub struct Malfind;

/// How many bytes of each region to show.
const PREVIEW_BYTES: usize = 64;

impl Plugin for Malfind {
    fn name(&self) -> &'static str {
        "mac.malfind.Malfind"
    }

    fn description(&self) -> &'static str {
        "Lists process memory ranges that potentially contain injected code."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel(), Requirement::pid_filter("Filter on specific process IDs")]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Process"),
            Column::new("Start", ColumnType::UInt),
            Column::new("End", ColumnType::UInt),
            Column::string("Protection"),
            Column::bytes("Hexdump"),
            Column::string("Disasm"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let name = process.name().unwrap_or_default();
            let Ok(Some(layer)) = process.process_layer() else {
                continue;
            };

            for entry in process.vm_map_entries().unwrap_or_default() {
                let protection = entry.protection();
                // Writable and executable together is the injection pattern,
                // as is executable memory that no file backs. The reference
                // implementation reports the mappings that are neither.
                let suspicious = protection == "rwx"
                    || (protection == "r-x" && entry.path(&kernel).is_empty());
                if suspicious {
                    continue;
                }

                let Ok(start) = entry.start() else { continue };
                let data = context
                    .layers
                    .read(&layer, start, PREVIEW_BYTES, true)
                    .unwrap_or_default();

                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(name.clone()),
                        Value::hex(start),
                        entry.end().map(Value::hex).unwrap_or_else(|_| Value::unreadable()),
                        Value::string(protection),
                        Value::HexDump(data.clone()),
                        // Disassembly needs a decoder that is not available,
                        // so the bytes are shown as they are.
                        Value::HexPairs(data),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}
