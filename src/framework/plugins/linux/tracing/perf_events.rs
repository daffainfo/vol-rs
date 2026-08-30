//! List the perf events processes have registered.
//!
//! perf can attach a program to almost any kernel or userspace event. It is the
//! kernel's profiling interface, and equally a way to gain execution on events
//! of interest, so what is attached is worth enumerating.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::walk_list;
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::linux::list_tasks;

pub struct PerfEvents;

/// The event types perf distinguishes.
fn event_type(value: u64) -> String {
    match value {
        0 => "PERF_TYPE_HARDWARE",
        1 => "PERF_TYPE_SOFTWARE",
        2 => "PERF_TYPE_TRACEPOINT",
        3 => "PERF_TYPE_HW_CACHE",
        4 => "PERF_TYPE_RAW",
        5 => "PERF_TYPE_BREAKPOINT",
        other => return format!("PERF_TYPE_{other}"),
    }
    .to_string()
}

impl Plugin for PerfEvents {
    fn name(&self) -> &'static str {
        "linux.tracing.perf_events.PerfEvents"
    }

    fn description(&self) -> &'static str {
        "Lists performance events for each process."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Process"),
            Column::string("Event"),
            Column::string("Short Program Name"),
            Column::string("Full Name"),
            Column::new("Address", ColumnType::UInt),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        for task in list_tasks(&context, &kernel, false)? {
            let Ok(pid) = task.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let comm = task.comm().unwrap_or_default();

            // A task's events hang off its perf context, which most tasks do
            // not have.
            let Ok(perf_context) = task
                .object
                .member("perf_event_ctxp")
                .and_then(|pointer| pointer.dereference())
            else {
                continue;
            };

            let Ok(head) = perf_context.member("event_list") else {
                continue;
            };
            let events = walk_list(
                &head,
                &kernel.qualified("perf_event"),
                "event_entry",
                true,
            )
            .unwrap_or_default();

            for event in events {
                let attributes = event.member("attr");
                let kind = attributes
                    .as_ref()
                    .ok()
                    .and_then(|attr| attr.member("type").ok())
                    .and_then(|kind| kind.as_u64().ok())
                    .map(event_type)
                    .unwrap_or_default();

                // An event with an attached BPF program is the interesting
                // case. Most have none.
                let program = event
                    .member("prog")
                    .and_then(|prog| prog.dereference())
                    .ok();
                let (short_name, full_name, address): (Option<String>, Option<String>, u64) =
                    match &program {
                        Some(program) => (
                            program
                                .member("aux")
                                .and_then(|aux| aux.dereference())
                                .and_then(|aux| aux.member("name"))
                                .and_then(|name| name.as_string())
                                .ok()
                                .filter(|name| !name.is_empty()),
                            None,
                            program.offset(),
                        ),
                        None => (None, None, 0),
                    };

                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(comm.clone()),
                        Value::string(kind),
                        short_name.map(Value::string).unwrap_or_else(Value::not_available),
                        // The full program name needs its BTF description,
                        // which is not decoded here.
                        full_name.map(Value::string).unwrap_or_else(Value::not_available),
                        Value::hex(address),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}
