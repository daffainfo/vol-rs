//! Search a process's virtual address space for a regular expression.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context};
use crate::framework::layers::scanners::{scan_layer, RegExScanner};
use crate::framework::plugins::windows::{kernel_module, physical_layer, vadinfo};
use crate::framework::plugins::{
    pid_filter, pid_matches, OperatingSystem, Plugin, Requirement, RequirementKind,
};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::list_processes;

pub struct VadRegExScan;

/// How much of a match to show.
const MATCH_PREVIEW: usize = 128;

impl Plugin for VadRegExScan {
    fn name(&self) -> &'static str {
        "windows.vadregexscan.VadRegExScan"
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
        OperatingSystem::Windows
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
        let physical = physical_layer(config);
        let pattern = config
            .get_string("pattern")
            .ok_or_else(|| VolatilityError::Other("A --pattern is required".to_string()))?;
        let maxsize = config
            .get_int("maxsize")
            .unwrap_or(MATCH_PREVIEW as i64)
            .max(0) as usize;
        let scanner = RegExScanner::new(&pattern)?;
        let filter = pid_filter(config);

        let mut grid = TreeGrid::new(self.columns());

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let name = process.image_file_name().unwrap_or_default();

            let Ok(layer_name) = process.address_space(&physical) else {
                continue;
            };

            // The VAD tree bounds the search to memory the process has actually
            // reserved.
            let sections: Vec<(u64, u64)> = vadinfo::walk_vad_tree(&context, &kernel, &process)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|vad| {
                    let start = vadinfo::start_vpn(&vad)?;
                    let end = vadinfo::end_vpn(&vad)?;
                    // A region runs to its last byte, so its size counts that
                    // byte in. An empty one says nothing and is left out.
                    let size = (end + 1).saturating_sub(start);
                    (size != 0).then_some((start, size))
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
                        Value::string(name.clone()),
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
