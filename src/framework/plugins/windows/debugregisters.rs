//! Report threads with hardware breakpoints set.
//!
//! The four debug registers let a thread trap on access to a specific address
//! without modifying any code. Debuggers use them, and so does malware that
//! wants to intercept a function without leaving a patch behind, so a thread
//! with them set outside a debugging session is worth explaining.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::walk_list;
use crate::framework::objects::Object;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::list_processes;
use crate::framework::symbols::windows::resolver::ModuleResolver;

pub struct DebugRegisters;

impl Plugin for DebugRegisters {
    fn name(&self) -> &'static str {
        "windows.debugregisters.DebugRegisters"
    }

    fn description(&self) -> &'static str {
        // Upstream has no docstring for this plugin, so its help page carries
        // no description either.
        ""
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        let mut columns = vec![
            Column::string("Process"),
            Column::int("PID"),
            Column::int("TID"),
            Column::int("State"),
            Column::int("Dr7"),
        ];
        // One address, range and symbol per debug register.
        for index in 0..4 {
            columns.push(Column::new(format!("Dr{index}"), ColumnType::UInt));
            columns.push(Column::string(format!("Range{index}")));
            columns.push(Column::string(format!("Symbol{index}")));
        }
        columns
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let resolver = ModuleResolver::new(&context, &kernel).ok();
        let filter = pid_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let name = process.image_file_name().unwrap_or_default();

            let threads = process
                .object
                .member("ThreadListHead")
                .and_then(|head| {
                    walk_list(&head, &kernel.qualified("_ETHREAD"), "ThreadListEntry", true)
                })
                .unwrap_or_default();

            for thread in threads {
                let Some(registers) = read_debug_registers(&thread) else {
                    continue;
                };

                // Dr7 enables the breakpoints. With none enabled the address
                // registers hold stale values that mean nothing.
                if registers.control == 0 {
                    continue;
                }

                let Ok(tid) = thread
                    .member("Cid")
                    .and_then(|cid| cid.member("UniqueThread"))
                    .and_then(|tid| tid.pointer_value())
                else {
                    continue;
                };

                let mut row = vec![
                    Value::string(name.clone()),
                    Value::int(pid as i64),
                    Value::int(tid as i64),
                    thread
                        .member("Tcb")
                        .and_then(|tcb| tcb.member("State"))
                        .and_then(|state| state.as_i64())
                        .map(Value::int)
                        .unwrap_or_else(|_| Value::unreadable()),
                    Value::int(registers.control as i64),
                ];

                for address in registers.addresses {
                    row.push(Value::hex(address));

                    let (module, symbol) = match (&resolver, address) {
                        (Some(resolver), address) if address != 0 => {
                            resolver.describe(&context, address)
                        }
                        _ => (None, None),
                    };
                    // An unset register is not applicable rather than absent.
                    if address == 0 {
                        row.push(Value::not_applicable());
                        row.push(Value::not_applicable());
                    } else {
                        row.push(module.map(Value::string).unwrap_or_else(Value::not_available));
                        row.push(symbol.map(Value::string).unwrap_or_else(Value::not_available));
                    }
                }

                grid.push(0, row)?;
            }
        }
        Ok(grid)
    }
}

/// The debug registers saved in a thread's kernel context.
struct DebugRegisterSet {
    control: u64,
    addresses: [u64; 4],
}

/// Read a thread's saved debug registers.
fn read_debug_registers(thread: &Object) -> Option<DebugRegisterSet> {
    // The registers live on the thread's control block, whose member names are
    // stable across the versions that save them at all.
    let control_block = thread.member("Tcb").ok()?;

    let read = |name: &str| -> u64 {
        control_block
            .member(name)
            .and_then(|value| value.as_u64())
            .unwrap_or(0)
    };

    let control = read("Dr7");
    Some(DebugRegisterSet {
        control,
        addresses: [read("Dr0"), read("Dr1"), read("Dr2"), read("Dr3")],
    })
}
