//! Check the Mach trap table for hooked entries.
//!
//! Mach traps are the kernel's other system call interface, dispatched through
//! their own table. It is hooked the same way and checked the same way.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::mac::ExtensionResolver;

pub struct CheckTrapTable;


impl Plugin for CheckTrapTable {
    fn name(&self) -> &'static str {
        "mac.check_trap_table.Check_trap_table"
    }

    fn description(&self) -> &'static str {
        "Check mach trap table for hooks."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Table Address", ColumnType::UInt),
            Column::string("Table Name"),
            Column::int("Index"),
            Column::new("Handler Address", ColumnType::UInt),
            Column::string("Handler Module"),
            Column::string("Handler Symbol"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let resolver = ExtensionResolver::new(&context, &kernel).ok();

        // The table's length is the one the symbol file declares, which is
        // what the kernel was built with.
        let table = context.object_from_symbol(&kernel, "mach_trap_table", None)?;
        let table_address = table.offset();
        let count = table.count().unwrap_or(0);

        let mut grid = TreeGrid::new(self.columns());
        for index in 0..count {
            let Ok(entry) = table.index(index) else {
                continue;
            };

            let Ok(handler) = entry
                .member("mach_trap_function")
                .and_then(|function| function.pointer_value())
            else {
                continue;
            };
            if handler == 0 {
                continue;
            }

            let (module, symbol) = match &resolver {
                Some(resolver) => resolver.describe(&context, handler),
                None => ("UNKNOWN".to_string(), "N/A".to_string()),
            };

            grid.push(
                0,
                vec![
                    Value::hex(table_address),
                    Value::string("TrapTable"),
                    Value::int(index as i64),
                    Value::hex(handler),
                    Value::string(module),
                    Value::string(symbol),
                ],
            )?;
        }
        Ok(grid)
    }
}
