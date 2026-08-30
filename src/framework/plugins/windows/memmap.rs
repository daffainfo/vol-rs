//! Report how a process's virtual address space maps onto physical memory.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{
    pid_filter, pid_matches, OperatingSystem, Plugin, Requirement,
};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::list_processes;

pub struct MemMap;

impl Plugin for MemMap {
    fn name(&self) -> &'static str {
        "windows.memmap.Memmap"
    }

    fn description(&self) -> &'static str {
        "Prints the memory map"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "pid",
                "Process ID to include (all other processes are excluded)",
                crate::framework::plugins::RequirementKind::Int,
            ),
            Requirement::new(
                "dump",
                "Extract listed memory segments",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Virtual", ColumnType::UInt),
            Column::new("Physical", ColumnType::UInt),
            Column::new("Size", ColumnType::UInt),
            Column::new("Offset in File", ColumnType::UInt),
            Column::string("File output"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let filter = pid_filter(config);
        let dump = config.get_bool("dump").unwrap_or(false);

        // This plugin describes one process's map, so a filter selecting exactly
        // one process is what makes the output meaningful.
        let processes: Vec<_> = list_processes(&context, &kernel)?
            .into_iter()
            .filter(|process| {
                process
                    .pid()
                    .map(|pid| pid_matches(&filter, pid))
                    .unwrap_or(false)
            })
            .collect();

        if processes.is_empty() {
            return Err(VolatilityError::Other(
                "No process matched; memmap needs a --pid to describe".to_string(),
            ));
        }

        let mut grid = TreeGrid::new(self.columns());
        for process in processes {
            let Ok(layer_name) = process.address_space(&physical) else {
                continue;
            };
            let layer = context.layers.get(&layer_name)?;

            // The extracted file holds the mapped regions end to end, in the
            // order they are reported, so a row's offset says where in the
            // file its region landed.
            let pid = process.pid().unwrap_or(0);
            let file_name = format!("pid.{pid}.dmp");
            // The rows name the file as it was asked for, while what is
            // written keeps clear of a file of that name already there.
            let mut sink = if dump {
                std::fs::File::create(crate::framework::plugins::free_extracted_name(&file_name))
                    .ok()
                    .map(std::io::BufWriter::new)
            } else {
                None
            };

            // Walk the whole address space a page at a time, reporting the
            // regions that are actually mapped. `ignore_errors` skips the
            // unmapped stretches, which are the vast majority.
            let mut offset_in_file: u64 = 0;
            // The walk is windowed to keep it cheap over sparse space, but a
            // region that runs across a window boundary is still one region,
            // so the last one seen is held back until it is known whether the
            // next continues it.
            let mut pending: Option<crate::framework::layers::MappingEntry> = None;
            let mut address = layer.minimum_address();
            let maximum = layer.maximum_address();

            while address < maximum {
                // A large window keeps the walk cheap over sparse address space.
                let window = 0x1000_0000u64.min(maximum - address);
                let entries = match layer.mapping(&context.layers, address, window, true) {
                    Ok(entries) => entries,
                    Err(_) => break,
                };
                if entries.is_empty() {
                    address += window;
                    continue;
                }

                for entry in entries {
                    match &mut pending {
                        Some(last)
                            if last.offset + last.size == entry.offset
                                && last.mapped_offset + last.mapped_size == entry.mapped_offset
                                && last.layer == entry.layer =>
                        {
                            last.size += entry.size;
                            last.mapped_size += entry.mapped_size;
                        }
                        _ => {
                            if let Some(last) = pending.replace(entry) {
                                let written =
                                    write_region(&context, &layer_name, &last, &mut sink);
                                grid.push(
                                    0,
                                    region_row(&last, offset_in_file, dump, &file_name, written),
                                )?;
                                offset_in_file += last.mapped_size;
                            }
                        }
                    }
                }
                address += window;
            }

            if let Some(last) = pending {
                let written = write_region(&context, &layer_name, &last, &mut sink);
                grid.push(
                    0,
                    region_row(&last, offset_in_file, dump, &file_name, written),
                )?;
            }
        }
        Ok(grid)
    }
}

/// One mapped region, as this plugin reports it.
fn region_row(
    entry: &crate::framework::layers::MappingEntry,
    offset_in_file: u64,
    dump: bool,
    file_name: &str,
    written: bool,
) -> Vec<Value> {
    let output = if !dump {
        "Disabled".to_string()
    } else if written {
        file_name.to_string()
    } else {
        "Error outputting to file".to_string()
    };
    vec![
        Value::hex(entry.offset),
        Value::hex(entry.mapped_offset),
        Value::hex(entry.mapped_size),
        Value::hex(offset_in_file),
        Value::string(output),
    ]
}

/// Append one region's bytes to the file being written, if one is.
fn write_region(
    context: &Arc<Context>,
    layer_name: &str,
    entry: &crate::framework::layers::MappingEntry,
    sink: &mut Option<std::io::BufWriter<std::fs::File>>,
) -> bool {
    use std::io::Write;
    let Some(sink) = sink else { return false };
    let Ok(data) = context
        .layers
        .read(layer_name, entry.offset, entry.size as usize, true)
    else {
        return false;
    };
    sink.write_all(&data).is_ok()
}
