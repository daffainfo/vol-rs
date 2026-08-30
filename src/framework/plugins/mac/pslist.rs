//! List the processes present in a Mac memory image.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{
    pid_filter, pid_matches, OperatingSystem, Plugin, Requirement,
};
use crate::framework::renderers::conversion::local_naive_value;
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::mac::list_processes_by;

pub struct PsList;

/// The lists the kernel keeps of its processes, in the order the reference
/// implementation offers them.
const PSLIST_METHODS: [&str; 5] = [
    "tasks",
    "allproc",
    "process_group",
    "sessions",
    "pid_hash_table",
];

impl Plugin for PsList {
    fn name(&self) -> &'static str {
        "mac.pslist.PsList"
    }

    fn description(&self) -> &'static str {
        "Lists the processes present in a particular mac memory image."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "pslist_method",
                "Method to determine for processes",
                crate::framework::plugins::RequirementKind::Choice(
                    PSLIST_METHODS.iter().map(|name| name.to_string()).collect(),
                ),
            )
            .with_default(crate::framework::context::ConfigValue::Str(
                PSLIST_METHODS[0].to_string(),
            )),
            Requirement::pid_filter("Filter on specific process IDs"),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("OFFSET", ColumnType::UInt),
            Column::string("NAME"),
            Column::int("PID"),
            Column::int("UID"),
            Column::int("GID"),
            Column::datetime("Start Time"),
            Column::int("PPID"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        // Every list holds the same processes, but a damaged one may hold
        // more of them than another.
        let method = config
            .get_string("pslist_method")
            .unwrap_or_else(|| PSLIST_METHODS[0].to_string());

        for process in list_processes_by(&context, &kernel, &method)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }

            grid.push(
                0,
                vec![
                    Value::hex(process.offset()),
                    or_unreadable(process.name(), Value::string),
                    Value::int(pid as i64),
                    or_unreadable(process.uid(), |value| Value::int(value as i64)),
                    or_unreadable(process.gid(), |value| Value::int(value as i64)),
                    // Upstream builds this one timestamp without a timezone,
                    // so it reads in the machine's own zone and prints with no
                    // zone name after it.
                    process
                        .start_time()
                        .map(|(seconds, microseconds)| {
                            local_naive_value(seconds as f64 + microseconds as f64 / 1e6)
                        })
                        .unwrap_or_else(|_| Value::unreadable()),
                    or_unreadable(process.ppid(), |value| Value::int(value as i64)),
                ],
            )?;
        }
        Ok(grid)
    }
}
