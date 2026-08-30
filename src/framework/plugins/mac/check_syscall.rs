//! Check the Mac system call table for hooked entries.
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

pub struct CheckSyscall;


impl Plugin for CheckSyscall {
    fn name(&self) -> &'static str {
        "mac.check_syscall.Check_syscall"
    }

    fn description(&self) -> &'static str {
        "Check system call table for hooks."
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
        let table = context.object_from_symbol(&kernel, "sysent", None)?;
        let table_address = table.offset();
        let count = table.count().unwrap_or(0);

        let mut grid = TreeGrid::new(self.columns());
        for index in 0..count {
            let Ok(entry) = table.index(index) else {
                continue;
            };

            let Ok(handler) = entry
                .member("sy_call")
                .and_then(|call| call.pointer_value())
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
                    Value::string("SysCall"),
                    Value::int(index as i64),
                    Value::hex(handler),
                    // A handler owned by nothing known is the hooked case.
                    Value::string(module),
                    Value::string(symbol),
                ],
            )?;
        }
        Ok(grid)
    }
}
