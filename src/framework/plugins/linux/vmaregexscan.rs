//! Search a process's mapped memory for a regular expression.
//!
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
use crate::framework::symbols::linux::list_tasks;

pub struct VmaRegExScan;

/// How much of a match to show. A longer one is truncated rather than flooding
/// the output.
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
        let maxsize = config
            .get_int("maxsize")
            .unwrap_or(MATCH_PREVIEW as i64)
            .max(0) as usize;
        let scanner = RegExScanner::new(&pattern)?;
        let filter = pid_filter(config);

        let mut grid = TreeGrid::new(self.columns());

        for task in list_tasks(&context, &kernel, false)? {
            let Ok(pid) = task.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let comm = task.comm().unwrap_or_default();

            // Restrict the scan to the task's own mappings. Scanning the whole
            // address space would mostly search unmapped memory.
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

            let layer = context.layers.get(task.object.layer_name())?;
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
                    .read(task.object.layer_name(), offset, maxsize, true)
                    .unwrap_or_default();
                let text: String = data
                    .iter()
                    .take_while(|byte| byte.is_ascii_graphic() || **byte == b' ')
                    .map(|&byte| byte as char)
                    .collect();

                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(comm.clone()),
                        Value::hex(offset),
                        Value::string(text),
                        Value::Bytes(data),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}
