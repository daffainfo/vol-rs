//! Scan each task's mapped memory with YARA rules.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::common::yarascan::{requirements as yara_requirements, Rules};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::linux::list_tasks;

pub struct VmaYaraScan;

/// Scan in blocks rather than reading a whole mapping at once.

impl Plugin for VmaYaraScan {
    fn name(&self) -> &'static str {
        "linux.vmayarascan.VmaYaraScan"
    }

    fn description(&self) -> &'static str {
        "Scans all virtual memory areas for tasks using yara."
    }

    fn requirements(&self) -> Vec<Requirement> {
        let mut requirements = vec![Requirement::kernel()];
        requirements.extend(yara_requirements());
        requirements.push(Requirement::pid_filter(
            "Process IDs to include (all other processes are excluded)",
        ));
        requirements
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Offset", ColumnType::UInt),
            Column::int("PID"),
            Column::string("Rule"),
            Column::string("Component"),
            Column::bytes("Value"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let rules = Rules::from_config(config)?;
        let filter = pid_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        for task in list_tasks(&context, &kernel, false)? {
            let Ok(pid) = task.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            // A task with no address space of its own is a kernel thread and
            // has nothing mapped to search.
            let Ok(Some(layer)) = task.process_layer() else {
                continue;
            };

            let mapped = task.vmas().unwrap_or_default();

            // Each area is read whole and scanned in one piece, so a match is
            // never split by where the reading happened to stop.
            let mut regions: Vec<(u64, u64)> = Vec::new();
            for vma in &mapped.areas {
                let (Ok(start), Ok(end)) = (vma.start(), vma.end()) else {
                    continue;
                };
                if end <= start {
                    continue;
                }
                let size = end - start;
                if size > SANITY_LIMIT {
                    log::debug!("VMA at {start:#x} over sanity-check size, not scanning");
                    continue;
                }
                regions.push((start, size));
            }
            if regions.is_empty() {
                log::warn!("No VMAs were found for task {pid}, not scanning");
                continue;
            }

            for (start, size) in regions {
                let Ok(data) = context.layers.read(&layer, start, size as usize, true) else {
                    continue;
                };
                for found in rules.scan(&data) {
                    let offset = start + found.offset as u64;
                    grid.push(
                        0,
                        vec![
                            Value::hex(offset),
                            Value::int(pid as i64),
                            Value::string(found.rule),
                            Value::string(found.component),
                            crate::framework::plugins::layer_data(
                                &context,
                                &layer,
                                offset,
                                found.data.len() as u64,
                            )
                            .unwrap_or_else(Value::not_available),
                        ],
                    )?;
                }
            }

            // The reference implementation reads the backing inode without
            // checking it resolved, and stops producing output where that
            // fails. Stopping here too keeps the two listings identical.
            if mapped.truncated {
                grid.mark_truncated();
                break;
            }
        }
        Ok(grid)
    }
}

/// A region larger than this is data rather than anything worth searching.
const SANITY_LIMIT: u64 = 1024 * 1024 * 1024;
