//! Report the ELF images mapped into each task.
//!
//! A mapping whose first bytes are an ELF header is a loaded executable or
//! shared library, which is what distinguishes it from ordinary anonymous
//! memory.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::linux::list_tasks;

pub struct Elfs;

/// The four bytes every ELF image opens with.
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";

impl Plugin for Elfs {
    fn name(&self) -> &'static str {
        "linux.elfs.Elfs"
    }

    fn description(&self) -> &'static str {
        "Lists all memory mapped ELF files for all processes."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::pid_filter("Filter on specific process IDs"),
            Requirement::new(
                "dump",
                "Extract listed processes",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Process"),
            Column::new("Start", ColumnType::UInt),
            Column::new("End", ColumnType::UInt),
            Column::string("File Path"),
            Column::string("File Output"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);
        let dump = config.get_bool("dump").unwrap_or(false);
        let mut grid = TreeGrid::new(self.columns());

        for task in list_tasks(&context, &kernel, false)? {
            let Ok(pid) = task.tid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let comm = task.comm().unwrap_or_default();
            // The ELF headers live in the task's own address space.
            let Ok(Some(layer)) = task.process_layer() else {
                continue;
            };

            let mapped = task.vmas().unwrap_or_default();
            for vma in &mapped.areas {
                let Ok(start) = vma.start() else { continue };

                // Only the first mapping of an image carries the ELF header.
                // The others are further segments of the same file.
                let header = context
                    .layers
                    .read(&layer, start, 4, true)
                    .unwrap_or_default();
                if header.len() < 4 || &header[..4] != ELF_MAGIC {
                    continue;
                }

                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(comm.clone()),
                        Value::hex(start),
                        vma.end().map(Value::hex).unwrap_or_else(|_| Value::unreadable()),
                        match vma.name(&task) {
                            Some(path) => Value::string(path),
                            None => Value::not_available(),
                        },
                        if dump {
                            match dump_elf(&context, &layer, start, pid, &comm) {
                                Some(name) => Value::string(name),
                                None => Value::string("Error outputting file"),
                            }
                        } else {
                            Value::string("Disabled")
                        },
                    ],
                )?;
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

/// The largest image written back out. Anything larger is a misread header.
const MAX_EXTRACTION_SIZE: u64 = 1024 * 1024 * 1024;

/// Write out the ELF mapped at `start`, rebuilt from its own program headers.
///
/// Only the parts the file says are loaded are written, each rounded out to
/// whole pages, which is what makes the result usable by a tool that expects a
/// file rather than a memory image.
fn dump_elf(
    context: &Arc<Context>,
    layer: &str,
    start: u64,
    pid: u64,
    comm: &str,
) -> Option<String> {
    let header = context.layers.read(layer, start, 64, true).ok()?;
    if header.len() < 64 || &header[..4] != ELF_MAGIC {
        return None;
    }
    // Past this point the file is produced whatever the headers say: an image
    // whose program headers cannot be read yields an empty one, which is what
    // the reference implementation leaves behind.
    let name = format!("pid.{pid}.{comm}.{start:#x}.dmp");
    // A 64-bit file puts the program header table at 0x20. A 32-bit one at
    // 0x1c, with narrower entries.
    let sixty_four = header[4] == 2;
    let (table_at, entry_size, count) = if sixty_four {
        (
            u64::from_le_bytes(header[0x20..0x28].try_into().ok()?),
            u16::from_le_bytes(header[0x36..0x38].try_into().ok()?) as u64,
            u16::from_le_bytes(header[0x38..0x3A].try_into().ok()?) as u64,
        )
    } else {
        (
            u32::from_le_bytes(header[0x1C..0x20].try_into().ok()?) as u64,
            u16::from_le_bytes(header[0x2A..0x2C].try_into().ok()?) as u64,
            u16::from_le_bytes(header[0x2C..0x2E].try_into().ok()?) as u64,
        )
    };
    if entry_size == 0 || count == 0 || count > 0x1000 {
        crate::framework::plugins::write_extracted(&name, &[]).ok()?;
        return Some(name);
    }

    // Each loadable segment, as whole pages.
    let mut sections: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
    for index in 0..count {
        let at = start + table_at + index * entry_size;
        let Ok(entry) = context.layers.read(layer, at, entry_size as usize, true) else {
            break;
        };
        if entry.len() < 32 {
            continue;
        }
        let kind = u32::from_le_bytes(entry[0..4].try_into().unwrap());
        if kind != 1 {
            continue;
        }
        let (Some(vaddr), Some(memsz)) = (
            entry
                .get(if sixty_four { 0x10..0x18 } else { 0x08..0x0C })
                .map(read_word),
            entry
                .get(if sixty_four { 0x28..0x30 } else { 0x14..0x18 })
                .map(read_word),
        ) else {
            continue;
        };

        let mut begin = vaddr;
        let Some(mut end) = vaddr.checked_add(memsz) else {
            continue;
        };
        if begin % 0x1000 != 0 {
            begin &= !0xFFF;
        }
        if end % 0x1000 != 0 {
            end = (end & !0xFFF) + 0x1000;
        }
        let Some(size) = end.checked_sub(begin) else {
            continue;
        };
        if size > MAX_EXTRACTION_SIZE {
            log::debug!("The claimed size of the ELF is invalid: {size}");
            return None;
        }
        sections.insert(begin, size);
    }

    let mut data: Vec<u8> = Vec::new();
    for (offset, size) in sections {
        let Ok(piece) = context.layers.read(layer, start + offset, size as usize, true) else {
            break;
        };
        data.extend_from_slice(&piece);
    }

    crate::framework::plugins::write_extracted(&name, &data).ok()?;
    Some(name)
}

/// A word of a program header, whichever width this file uses.
fn read_word(bytes: &[u8]) -> u64 {
    match bytes.len() {
        8 => u64::from_le_bytes(bytes.try_into().unwrap()),
        4 => u32::from_le_bytes(bytes.try_into().unwrap()) as u64,
        _ => 0,
    }
}
