//! List the shared libraries mapped into each task.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashSet;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{pid_matches, pids_filter, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::linux::list_tasks;

pub struct LibraryList;

impl Plugin for LibraryList {
    fn name(&self) -> &'static str {
        "linux.library_list.LibraryList"
    }

    fn description(&self) -> &'static str {
        "Enumerate libraries loaded into processes"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel(), Requirement::pids_filter("Filter on specific process IDs")]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Name"),
            Column::int("Pid"),
            Column::new("LoadAddress", ColumnType::UInt),
            Column::string("Path"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pids_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        for task in list_tasks(&context, &kernel, false)? {
            let Ok(pid) = task.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let comm = task.comm().unwrap_or_default();

            let Ok(Some(layer)) = task.process_layer() else {
                continue;
            };
            let mapped = task.vmas().unwrap_or_default();

            // The dynamic loader records every library it has mapped in a
            // linked list, which is what `ldd` and `/proc/<pid>/maps` agree on.
            // One entry may be reachable from several mappings, so each load
            // address is reported once.
            let mut seen: HashSet<u64> = HashSet::new();

            for vma in &mapped.areas {
                let Ok(start) = vma.start() else { continue };
                for (address, name) in link_maps(&context, &layer, start) {
                    if !seen.insert(address) {
                        continue;
                    }
                    grid.push(
                        0,
                        vec![
                            Value::string(comm.clone()),
                            Value::int(pid as i64),
                            Value::hex(address),
                            Value::string(name),
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

/// ELF constants used to find the loader's link map.
const ELF_MAGIC: &[u8] = b"\x7fELF";
const PT_DYNAMIC: u64 = 2;
const DT_PLTGOT: u64 = 3;
const ET_DYN: u64 = 3;
/// Entries in a dynamic section, beyond which it is treated as corrupt.
const MAX_DYNAMIC_ENTRIES: u64 = 256;
/// Libraries one process is believed to have loaded.
const MAX_LINK_MAPS: usize = 1024;

/// The libraries reachable from an ELF image mapped at `base`.
///
/// The loader keeps a `link_map` list whose head sits in the second entry of
/// the global offset table, and the GOT's address is recorded in the image's
/// dynamic section. So: find PT_DYNAMIC, read DT_PLTGOT out of it, and follow
/// the list from there.
fn link_maps(context: &Arc<Context>, layer: &str, base: u64) -> Vec<(u64, String)> {
    let mut results = Vec::new();

    let read_u64 = |address: u64| -> Option<u64> {
        let bytes = context.layers.read(layer, address, 8, false).ok()?;
        Some(u64::from_le_bytes(bytes.try_into().ok()?))
    };
    let read_u16 = |address: u64| -> Option<u16> {
        let bytes = context.layers.read(layer, address, 2, false).ok()?;
        Some(u16::from_le_bytes(bytes.try_into().ok()?))
    };

    // Only a 64-bit ELF header can start a mapped image here.
    let Ok(header) = context.layers.read(layer, base, 16, false) else {
        return results;
    };
    if header.len() < 5 || &header[..4] != ELF_MAGIC || header[4] != 2 {
        return results;
    }

    let (Some(object_type), Some(phoff), Some(phnum)) = (
        read_u16(base + 16),
        read_u64(base + 32),
        read_u16(base + 56),
    ) else {
        return results;
    };

    for index in 0..phnum as u64 {
        let phdr = base + phoff + index * 56;
        if read_u64(phdr).map(|value| value & 0xFFFF_FFFF) != Some(PT_DYNAMIC) {
            continue;
        }
        let Some(vaddr) = read_u64(phdr + 16) else {
            continue;
        };
        // A shared object's headers hold offsets from where it was loaded.
        let dynamic = if object_type as u64 == ET_DYN {
            base.wrapping_add(vaddr)
        } else {
            vaddr
        };

        for entry in 0..MAX_DYNAMIC_ENTRIES {
            let at = dynamic + entry * 16;
            let Some(tag) = read_u64(at) else { break };
            if tag == DT_PLTGOT {
                if let Some(got) = read_u64(at + 8) {
                    walk_link_maps(&read_u64, got, &mut results, context, layer);
                }
            }
            // A zero tag ends the section.
            if tag == 0 {
                break;
            }
        }
    }

    results
}

/// Follow the loader's link map list, collecting each library's load address
/// and path.
fn walk_link_maps(
    read_u64: &dyn Fn(u64) -> Option<u64>,
    got: u64,
    results: &mut Vec<(u64, String)>,
    context: &Arc<Context>,
    layer: &str,
) {
    // The list head lives in the second global offset table entry.
    let Some(mut current) = read_u64(got + 8) else {
        return;
    };
    let mut seen: HashSet<u64> = HashSet::new();

    while current != 0 && results.len() < MAX_LINK_MAPS {
        if !seen.insert(current) {
            break;
        }
        let (Some(load_address), Some(name_pointer), Some(next)) = (
            read_u64(current),
            read_u64(current + 8),
            read_u64(current + 24),
        ) else {
            break;
        };

        if load_address != 0 && name_pointer != 0 {
            if let Ok(bytes) = context.layers.read(layer, name_pointer, 256, false) {
                let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(0);
                if end > 0 {
                    results.push((
                        load_address,
                        String::from_utf8_lossy(&bytes[..end]).to_string(),
                    ));
                }
            }
        }

        current = next;
    }
}
