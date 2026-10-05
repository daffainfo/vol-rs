//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context};
use crate::framework::layers::scanners::{scan_layer, RegExScanner};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{
    pid_filter, pid_matches, OperatingSystem, Plugin, Requirement, RequirementKind,
};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::linux::{list_tasks_filtered, Task};

/// Scans all virtual memory areas for tasks using RegEx.
pub struct VmaRegExScan;

/// How much of a match to show.
///
/// Upstream reapplies the regex in order to extract just the match. Where the
/// match is within the result data it reports the match itself, and where it is
/// not (because it does not fit within `MAXSIZE_DEFAULT`) it reports what was
/// read.
const MATCH_PREVIEW: usize = 128;

impl Plugin for VmaRegExScan {
    fn name(&self) -> &'static str {
        "linux.vmaregexscan.VmaRegExScan"
    }

    fn description(&self) -> &'static str {
        "Scans all virtual memory areas for tasks using RegEx."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::pid_filter("Filter on specific process IDs"),
            Requirement::new(
                "pattern",
                "RegEx pattern",
                RequirementKind::String,
            )
            .required(),
            Requirement::new(
                "maxsize",
                "Maximum size in bytes for displayed context",
                RequirementKind::Int,
            )
            .with_default(crate::framework::context::ConfigValue::Int(
                MATCH_PREVIEW as i64,
            )),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Process"),
            Column::new("Offset", ColumnType::UInt),
            Column::string("Text"),
            Column::bytes("Hex"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let pattern = config.get_string("pattern").ok_or_else(|| {
            VolatilityError::Other("A --pattern is required".to_string())
        })?;
        // The option is declared because upstream declares it, but upstream
        // reads `MAXSIZE_DEFAULT` rather than the configured value here, so
        // the value is accepted and then not used. Only the generic
        // `regexscan` honours it.
        let maxsize = MATCH_PREVIEW;
        let scanner = RegExScanner::new(&pattern)?;
        let filter = pid_filter(config);

        let mut grid = TreeGrid::new(self.columns());

        // Upstream filters on the kernel's own `pid`, which is the thread
        // identifier, and does it while walking the list, so a process that
        // matches brings its threads with it.
        let selected = |task: &Task| match task.tid() {
            Ok(tid) => pid_matches(&filter, tid),
            Err(_) => false,
        };

        for task in list_tasks_filtered(&context, &kernel, false, &selected)? {
            let Ok(pid) = task.pid() else { continue };
            let comm = task.comm().unwrap_or_default();

            // The scan has to run in the process's own address space, because
            // the addresses the areas name are only meaningful there. Attempt
            // to create a process layer for each task and skip those that
            // cannot (e.g. kernel threads), which is also how upstream passes
            // over a task with no `mm`.
            let Ok(Some(layer_name)) = task.process_layer() else {
                continue;
            };

            // get process sections for scanning. Scanning the whole address
            // space would mostly search unmapped memory.
            let mapped = task.vmas().unwrap_or_default();
            let sections: Vec<(u64, u64)> = mapped
                .areas
                .iter()
                .filter_map(|vma| {
                    let start = vma.start().ok()?;
                    let end = vma.end().ok()?;
                    (end > start).then_some((start, end - start))
                })
                .collect();
            if sections.is_empty() {
                continue;
            }

            let layer = context.layers.get(&layer_name)?;
            let mut hits: Vec<u64> = Vec::new();
            scan_layer(
                layer.as_ref(),
                &context.layers,
                &scanner,
                Some(&sections),
                |offset| hits.push(offset),
            )?;

            for offset in hits {
                let data = context
                    .layers
                    .read(&layer_name, offset, maxsize, true)
                    .unwrap_or_default();
                // The pattern is applied a second time at the hit itself so
                // that the match alone is reported. A match too long to fit in
                // what was read leaves the whole of it standing instead.
                let matched = scanner.match_at_start(&data).unwrap_or(data);
                let text = String::from_utf8_lossy(&matched).to_string();

                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(comm.clone()),
                        Value::hex(offset),
                        Value::string(text),
                        Value::Bytes(matched),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}
