//! List the kernel's pending timers.
//!
//! A timer gives an extension periodic execution without a thread of its own,
//! which makes it a convenient hiding place for recurring malicious work.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::mac::{walk_queue, ExtensionResolver};

pub struct Timers;


impl Plugin for Timers {
    fn name(&self) -> &'static str {
        "mac.timers.Timers"
    }

    fn description(&self) -> &'static str {
        "Check for malicious kernel timers."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Function", ColumnType::UInt),
            Column::new("Param 0", ColumnType::UInt),
            Column::new("Param 1", ColumnType::UInt),
            Column::int("Deadline"),
            Column::int("Entry Time"),
            Column::string("Module"),
            Column::string("Symbol"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let resolver = ExtensionResolver::new(&context, &kernel).ok();

        // Each processor keeps its own queue of pending timers, reached through
        // the table of processor state.
        let processors = context
            .object_from_symbol(&kernel, "real_ncpus", None)
            .and_then(|count| count.as_u64())
            .unwrap_or(0);

        let table = context.symbol_offset(&kernel, "cpu_data_ptr")?;
        let raw = context.layers.read(&kernel.layer_name, table, 8, false)?;
        let first = u64::from_le_bytes(raw.try_into().unwrap());

        let cpu_template = context.symbol_space.get_type(&kernel.qualified("cpu_data"))?;
        let cpu_size = context.symbol_space.size_of(&cpu_template)?;
        let call_type = kernel.qualified("call_entry");

        let mut grid = TreeGrid::new(self.columns());

        for index in 0..processors {
            let cpu = context.object_from_template(
                cpu_template.clone(),
                &kernel.layer_name,
                first.wrapping_add(index.wrapping_mul(cpu_size)),
            );

            // The queue head anchors the list of calls waiting to run.
            let Ok(head) = cpu
                .member("rtclock_timer")
                .and_then(|timer| timer.member("queue"))
                .and_then(|queue| queue.member("head"))
            else {
                break;
            };

            for call in walk_queue(&head, "q_link", &call_type) {
                // A call with no function to run is not a timer.
                let Ok(function) = call.member("func").and_then(|func| func.pointer_value())
                else {
                    continue;
                };

                let (module, symbol) = match &resolver {
                    Some(resolver) => resolver.describe(&context, function),
                    None => ("UNKNOWN".to_string(), "N/A".to_string()),
                };

                grid.push(
                    0,
                    vec![
                        Value::hex(function),
                        call.member("param0")
                            .and_then(|param| param.as_u64())
                            .map(Value::hex)
                            .unwrap_or_else(|_| Value::unreadable()),
                        call.member("param1")
                            .and_then(|param| param.as_u64())
                            .map(Value::hex)
                            .unwrap_or_else(|_| Value::unreadable()),
                        call.member("deadline")
                            .and_then(|deadline| deadline.as_i64())
                            .map(Value::int)
                            .unwrap_or_else(|_| Value::unreadable()),
                        // Older kernels do not record when a call was queued.
                        if call.has_member("entry_time") {
                            call.member("entry_time")
                                .and_then(|time| time.as_i64())
                                .map(Value::int)
                                .unwrap_or_else(|_| Value::unreadable())
                        } else {
                            Value::int(-1)
                        },
                        Value::string(module),
                        Value::string(symbol),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}
