//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::common::yarascan::{requirements as yara_requirements, Rules};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::linux::{list_tasks_filtered, Task};

/// Scans all virtual memory areas for tasks using yara.
pub struct VmaYaraScan;

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
            Column::layer_data("Value"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        // The reference implementation reads the rules only once it has begun
        // producing rows, so the header is already out when it finds none, and
        // what follows is an uncaught failure rather than a reported one.
        let rules = match Rules::from_config(config) {
            Ok(rules) => rules,
            Err(error) => {
                eprintln!("ERROR    volatility3.plugins.yarascan: {error}");
                grid.mark_aborted();
                return Ok(grid);
            }
        };

        // Upstream filters on the kernel's own `pid`, which is the thread
        // identifier, and does it while walking the list, so a process that
        // matches brings its threads with it.
        let selected = |task: &Task| match task.tid() {
            Ok(tid) => pid_matches(&filter, tid),
            Err(_) => false,
        };

        for task in list_tasks_filtered(&context, &kernel, false, &selected)? {
            let Ok(pid) = task.pid() else { continue };
            // attempt to create a process layer for each task and skip those
            // that cannot (e.g. kernel threads)
            let Ok(Some(layer)) = task.process_layer() else {
                continue;
            };

            let mapped = task.vmas().unwrap_or_default();

            // Creates a map of start/end addresses for each virtual memory
            // area in the task. Upstream scans the VMA data in one contiguous
            // block rather than in fixed-size pieces, so each area is read
            // whole here too and a match is never split by where the reading
            // happened to stop.
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
/// 1 GB.
const SANITY_LIMIT: u64 = 1024 * 1024 * 1024;
