//! Find processes by scanning physical memory for pool allocations, rather than
//! by walking the kernel's list.
//!
//! A process that has been unlinked from the active process list (by a rootkit,
//! or simply by having exited) is invisible to `pslist`, but its pool
//! allocation may still be present in memory. Scanning for the pool tag finds
//! those.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{ConfigValue, Configuration, Context, Module};
use crate::framework::plugins::windows::kernel_module;
use crate::framework::symbols::windows::poolscanner::{builtin_constraints, generate_pool_scan};
use crate::framework::plugins::{
    pid_filter, pid_matches, OperatingSystem, Plugin, Requirement, RequirementKind,
};
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::windows::Process;

use super::pslist::{process_columns, process_row};

pub struct PsScan;

/// The pool tag the kernel allocates `_EPROCESS` structures under. The tag's
/// last byte has its high bit set when the allocation is in non-paged pool.
const PROCESS_POOL_TAGS: [&[u8]; 2] = [b"Proc", b"Pro\xe3"];

impl Plugin for PsScan {
    fn name(&self) -> &'static str {
        "windows.psscan.PsScan"
    }

    fn description(&self) -> &'static str {
        "Scans for processes present in a particular windows memory image."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::pid_filter("Process ID to include (all other processes are excluded)"),
            Requirement::new("dump", "Extract listed processes", RequirementKind::Bool)
                .with_default(ConfigValue::Bool(false)),
            Requirement::new(
                "physical",
                "Display physical offset instead of virtual",
                RequirementKind::Bool,
            )
            .with_default(ConfigValue::Bool(true)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        // The objects come out of whichever layer was scanned, and on a modern
        // kernel that is the kernel's own, so the offsets are virtual.
        process_columns(false)
    }

    fn timeline(
        &self,
        context: Arc<Context>,
        config: &Configuration,
    ) -> Option<crate::framework::plugins::Timeline> {
        use crate::framework::plugins::{TimeKind, Timeline};
        #[allow(unused_imports)]
        use crate::framework::plugins::timeline_helpers::{is_time, number, text};

        let mut timeline = Timeline::new();
        for row in self.run(context, config).ok()?.rows() {
            let values = &row.values;
            let description = format!(
                "Process: {} {} ({})",
                number(&values[0]),
                text(&values[2]),
                number(&values[3])
            );
            timeline.push(description.clone(), TimeKind::Created, values[8].clone());
            timeline.push(description, TimeKind::Modified, values[9].clone());
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);
        let physical_name = crate::framework::plugins::windows::physical_layer(config);
        let dump = config.get_bool("dump").unwrap_or(false);

        let mut grid = TreeGrid::new(self.columns());

        for process in scan_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let offset = process.offset();
            let file_output = if dump {
                // This listing names the file as it opens it, so two
                // processes sharing an image both report the same name even
                // though the second is written beside the first.
                match crate::framework::plugins::windows::pslist::dump_process_image(
                    &context, &physical_name, &process, pid,
                ) {
                    Some((preferred, _)) => Value::string(preferred),
                    None => Value::string("Error outputting file"),
                }
            } else {
                Value::string("Disabled")
            };
            grid.push(0, process_row(&process, pid, offset, file_output))?;
        }
        Ok(grid)
    }
}

/// The processes the pools still hold, whether or not the kernel still lists
/// them.
pub fn scan_processes(context: &Arc<Context>, kernel: &Module) -> Result<Vec<Process>> {
    let constraints = builtin_constraints(&PROCESS_POOL_TAGS);
    Ok(generate_pool_scan(context, kernel, &constraints)?
        .into_iter()
        .map(|hit| Process::new(hit.object))
        .collect())
}
