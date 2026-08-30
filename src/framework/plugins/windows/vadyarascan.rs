//! Scan each process's virtual address space with YARA rules.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::common::yarascan::{requirements as yara_requirements, Rules};
use crate::framework::plugins::windows::{kernel_module, physical_layer, vadinfo};
use crate::framework::plugins::{
    pid_filter, pid_matches, OperatingSystem, Plugin, Requirement,
};
use crate::framework::renderers::conversion::wintime_value;
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::{list_processes, pslist_session_id};

pub struct VadYaraScan;

impl Plugin for VadYaraScan {
    fn name(&self) -> &'static str {
        "windows.vadyarascan.VadYaraScan"
    }

    fn description(&self) -> &'static str {
        "Scans all the Virtual Address Descriptor memory maps using yara."
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
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Offset", ColumnType::UInt),
            Column::int("PID"),
            Column::datetime("CreateTime"),
            Column::int("PPID"),
            Column::string("ImageFileName"),
            Column::int("SessionId"),
            Column::int("Threads"),
            Column::string("Rule"),
            Column::string("Component"),
            Column::bytes("Value"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let rules = Rules::from_config(config)?;
        let filter = pid_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }

            let Ok(layer) = process.address_space(&physical) else {
                continue;
            };

            // Each region is read whole and scanned in one piece, so a match
            // is never split by where the reading happened to stop.
            let mut regions: Vec<(u64, u64)> = Vec::new();
            for vad in vadinfo::walk_vad_tree(&context, &kernel, &process).unwrap_or_default() {
                let (Some(start), Some(end)) =
                    (vadinfo::start_vpn(&vad), vadinfo::end_vpn(&vad))
                else {
                    continue;
                };
                let size = end - start + 1;
                if size > SANITY_LIMIT {
                    log::debug!("VAD at {start:#x} over sanity-check size, not scanning");
                    continue;
                }
                regions.push((start, size));
            }
            if regions.is_empty() {
                log::warn!("No VADs were found for task {pid}, not scanning");
                continue;
            }

            for (start, size) in regions {
                // Padding keeps a partly-resident region scannable. The zeroes
                // it introduces simply will not match.
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
                            process
                                .create_time()
                                .map(wintime_value)
                                .unwrap_or_else(|_| Value::unreadable()),
                            or_unreadable(process.parent_pid(), |value| {
                                Value::int(value as i64)
                            }),
                            or_unreadable(process.image_file_name(), Value::string),
                            pslist_session_id(&process),
                            or_unreadable(process.thread_count(), |value| {
                                Value::int(value as i64)
                            }),
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
        }
        Ok(grid)
    }
}

/// A region larger than this is data rather than anything worth searching.
const SANITY_LIMIT: u64 = 1024 * 1024 * 1024;
