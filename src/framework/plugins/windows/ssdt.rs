//! List the system service descriptor table.
//!
//! The SSDT maps system call numbers to their kernel handlers. Every entry
//! should point inside the kernel image. One that does not has been hooked.
//!
//! On 64-bit Windows the table stores signed 32-bit offsets rather than
//! pointers: each entry's top 28 bits are the handler's displacement from the
//! table base, shifted right by four.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::resolver::ModuleCollection;

pub struct Ssdt;

impl Plugin for Ssdt {
    fn name(&self) -> &'static str {
        "windows.ssdt.SSDT"
    }

    fn description(&self) -> &'static str {
        "Lists the system call table."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("Index"),
            Column::new("Address", ColumnType::UInt),
            Column::string("Module"),
            Column::string("Symbol"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let collection = ModuleCollection::build(&context, &kernel)?;

        // The table itself is named by a symbol, as is the count of entries in
        // it.
        let table = context.symbol_offset(&kernel, "KiServiceTable")?;
        let limit = context
            .object_from_symbol(&kernel, "KiServiceLimit", Some("int"))?
            .as_i64()? as u64;

        let sixty_four_bit = context
            .symbol_space
            .table(&kernel.symbol_table_name)
            .map(|table| table.pointer_size())
            .unwrap_or(8)
            == 8;

        let mut grid = TreeGrid::new(self.columns());
        for index in 0..limit {
            let Ok(raw) = context
                .layers
                .read(&kernel.layer_name, table + index * 4, 4, false)
            else {
                continue;
            };
            let word = u32::from_le_bytes(raw.try_into().unwrap());

            // A 64-bit kernel stores a displacement from the table itself,
            // shifted to leave room for the argument count. A 32-bit one
            // stores the address outright.
            let address = if sixty_four_bit {
                let displacement = (word as i32) >> 4;
                table.wrapping_add(displacement as i64 as u64)
            } else {
                word as u64
            };

            // A service in no loaded module is reported by its absence: no row
            // is produced for it at all.
            for (module, symbols) in collection.modules_at(&context, address) {
                if symbols.is_empty() {
                    grid.push(
                        0,
                        vec![
                            Value::int(index as i64),
                            Value::hex(address),
                            Value::string(module),
                            Value::not_available(),
                        ],
                    )?;
                    continue;
                }
                for symbol in symbols {
                    grid.push(
                        0,
                        vec![
                            Value::int(index as i64),
                            Value::hex(address),
                            Value::string(module.clone()),
                            Value::string(symbol),
                        ],
                    )?;
                }
            }
        }
        Ok(grid)
    }
}
