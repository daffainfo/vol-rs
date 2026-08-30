//! Report the shim cache, which records the programs Windows has run.
//!
//! The application-compatibility infrastructure keeps a cache of every
//! executable it has examined, in kernel memory rather than the registry. An
//! entry survives the program itself being deleted, which is what makes it
//! worth reading.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::utility::{unicode_string, walk_list};
use crate::framework::objects::Object;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::conversion::wintime_value;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::{pe, versions};

pub struct ShimcacheMem;

/// The modules the cache lives in, newest first.
const CACHE_MODULES: &[&str] = &["ahcache.sys"];
/// Where the cache lived before it moved out of the kernel proper.
const KERNEL_MODULES: &[&str] = &[
    "ntoskrnl.exe",
    "ntkrnlpa.exe",
    "ntkrnlmp.exe",
    "ntkrpamp.exe",
];

impl Plugin for ShimcacheMem {
    fn name(&self) -> &'static str {
        "windows.shimcachemem.ShimcacheMem"
    }

    fn description(&self) -> &'static str {
        "Reads Shimcache entries from the ahcache.sys AVL tree"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("Order"),
            Column::datetime("Last Modified"),
            Column::datetime("Last Update"),
            Column::bool("Exec Flag"),
            Column::new("File Size", ColumnType::UInt),
            Column::string("File Path"),
        ]
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
            if is_time(&values[2]) {
                timeline.push(
                    format!("Shimcache: File {} executed", text(&values[5])),
                    TimeKind::Accessed,
                    values[2].clone(),
                );
            }
            if is_time(&values[1]) {
                timeline.push(
                    format!("Shimcache: File {} modified", text(&values[5])),
                    TimeKind::Modified,
                    values[1].clone(),
                );
            }
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let table = shimcache_table(&context, &kernel)?;
        let mut grid = TreeGrid::new(self.columns());

        // The cache moved into its own driver with Windows 8.1.
        let recent = versions::matches(&context, &kernel, versions::IS_WINDOWS_8_1_OR_LATER)
            || versions::matches(&context, &kernel, versions::IS_WINDOWS_10);
        let names = if recent { CACHE_MODULES } else { KERNEL_MODULES };

        let (Some((data_offset, data_size)), Some((page_offset, page_size))) = (
            module_section(&context, &kernel, names, ".data"),
            module_section(&context, &kernel, names, "PAGE"),
        ) else {
            return Ok(grid);
        };

        // Two handles sit in the driver's data section, and which of them holds
        // the cache depends on the release.
        let handle_type = format!("{table}!SHIM_CACHE_HANDLE");
        let mut heads = Vec::new();
        let mut offset = data_offset;
        while offset < data_offset + data_size {
            if let Some(head) = handle_head(
                &context,
                &kernel,
                &table,
                &handle_type,
                offset,
                page_offset,
                page_offset + page_size,
            ) {
                heads.push(head);
                if heads.len() == 2 {
                    break;
                }
            }
            offset += 8;
        }
        if heads.len() != 2 {
            return Ok(grid);
        }
        // Later releases keep the cache in the second handle.
        let head = if recent {
            heads.remove(1)
        } else {
            heads.remove(0)
        };

        let entry_type = format!("{table}!SHIM_CACHE_ENTRY");
        let Ok(list) = head.member("ListEntry") else {
            return Ok(grid);
        };

        for (order, entry) in walk_list(&list, &entry_type, "ListEntry", true)
            .unwrap_or_default()
            .into_iter()
            .filter(entry_is_valid)
            .enumerate()
        {
            let detail = entry
                .member("ListEntryDetail")
                .and_then(|detail| detail.dereference())
                .ok();

            // The moment the file was last written, which the entry keeps
            // either directly or in its detail.
            let modified = detail
                .as_ref()
                .and_then(|detail| detail.member("LastModified").ok())
                .or_else(|| entry.member("LastModified").ok())
                .and_then(|time| time.member("QuadPart").ok())
                .and_then(|time| time.as_u64().ok())
                .map(wintime_value)
                .unwrap_or_else(Value::unreadable);

            // Later entries carry neither of these, and the reader reports so.
            let updated = match entry
                .member("LastUpdate")
                .and_then(|time| time.member("QuadPart"))
                .and_then(|time| time.as_u64())
            {
                Ok(time) => wintime_value(time),
                Err(_) => Value::not_applicable(),
            };
            let size = match entry.member("FileSize").and_then(|size| size.as_i64()) {
                Ok(size) => Value::hex(size.max(0) as u64),
                Err(_) => Value::not_applicable(),
            };

            grid.push(
                0,
                vec![
                    Value::int(order as i64),
                    modified,
                    updated,
                    // The flag is read but never reported: reading it without
                    // fault is what the reader takes as its answer.
                    exec_flag(&entry, detail.as_ref()),
                    size,
                    file_path(&entry),
                ],
            )?;
        }
        Ok(grid)
    }
}

/// Whether an entry's links hold together.
fn entry_is_valid(entry: &Object) -> bool {
    let Ok(list) = entry.member("ListEntry") else {
        // An entry with no links at all is judged by its contents instead.
        return entry.member("LastModified").is_ok();
    };
    let (Ok(forward), Ok(backward)) = (
        list.member("Flink").and_then(|link| link.pointer_value()),
        list.member("Blink").and_then(|link| link.pointer_value()),
    ) else {
        return false;
    };
    if forward == 0 || forward == backward {
        return false;
    }
    // The entry the forward link names must point back at the same place its
    // own backward link does.
    let Ok(next_back) = list
        .member("Flink")
        .and_then(|link| link.dereference())
        .and_then(|next| next.member("Blink"))
        .and_then(|link| link.pointer_value())
    else {
        return false;
    };
    let Ok(next_back_offset) = list
        .member("Flink")
        .and_then(|link| link.dereference())
        .and_then(|next| next.member("Blink"))
        .and_then(|link| link.dereference())
        .map(|target| target.offset())
    else {
        return false;
    };
    next_back == next_back_offset
}

/// Whether the entry was inserted by a program starting, as far as the reader
/// ever says.
fn exec_flag(entry: &Object, detail: Option<&Object>) -> Value {
    // Reading the flag is attempted for its own sake: an entry whose flag
    // cannot be reached is reported as unreadable, and one whose flag reads is
    // reported as not applicable, which is what upstream's reader does.
    let read = if let Some(detail) = detail {
        if detail.has_member("InsertFlags") {
            detail.member("InsertFlags").and_then(|flags| flags.as_u64()).map(|_| ())
        } else if detail.has_member("BlobBuffer") {
            detail
                .member("BlobBuffer")
                .and_then(|buffer| buffer.as_u64())
                .and_then(|buffer| {
                    let size = detail
                        .member("BlobSize")
                        .and_then(|size| size.as_u64())
                        .unwrap_or(0);
                    entry
                        .context()
                        .layers
                        .read(entry.layer_name(), buffer, size as usize, false)
                        .map(|_| ())
                })
        } else {
            Ok(())
        }
    } else if entry.has_member("InsertFlags") {
        entry.member("InsertFlags").and_then(|flags| flags.as_u64()).map(|_| ())
    } else {
        Ok(())
    };

    match read {
        Ok(()) => Value::not_applicable(),
        Err(_) => Value::unreadable(),
    }
}

/// The path an entry names.
fn file_path(entry: &Object) -> Value {
    let Ok(path) = entry.member("Path") else {
        return Value::unreadable();
    };
    match unicode_string(&path) {
        Ok(text) => Value::string(text),
        Err(_) => Value::unreadable(),
    }
}

/// The head of the cache a handle names, if the handle is one at all.
#[allow(clippy::too_many_arguments)]
fn handle_head(
    context: &Arc<Context>,
    kernel: &Module,
    table: &str,
    handle_type: &str,
    offset: u64,
    page_start: u64,
    page_end: u64,
) -> Option<Object> {
    // The word in the data section is a pointer to the handle.
    let pointer = context
        .object(&kernel.qualified("pointer"), &kernel.layer_name, offset)
        .ok()?;
    let address = pointer.pointer_value().ok()?;
    if address == 0 || !context.layers.is_valid(&kernel.layer_name, address, 1) {
        return None;
    }
    let handle = context.object(handle_type, &kernel.layer_name, address).ok()?;

    // A handle holds a lock and a tree, and both have to hold together.
    let resource = handle.member("eresource").and_then(|resource| resource.pointer_value()).ok()?;
    if !eresource_is_valid(context, kernel, resource) {
        return None;
    }
    let tree_address = handle
        .member("rtl_avl_table")
        .and_then(|tree| tree.pointer_value())
        .ok()?;
    let tree = context
        .object(&format!("{table}!_RTL_AVL_TABLE"), &kernel.layer_name, tree_address)
        .ok()?;
    if !tree_is_valid(&tree, page_start, page_end) {
        return None;
    }

    // The cache itself begins just past the tree.
    let size = context
        .symbol_space
        .get_type(&format!("{table}!_RTL_AVL_TABLE"))
        .and_then(|template| context.symbol_space.size_of(&template))
        .ok()?;
    let head = context
        .object(
            &format!("{table}!SHIM_CACHE_ENTRY"),
            &kernel.layer_name,
            tree_address + size,
        )
        .ok()?;
    if !entry_is_valid(&head) {
        return None;
    }
    Some(head)
}

/// Whether a lock is one the kernel is holding.
fn eresource_is_valid(context: &Arc<Context>, kernel: &Module, address: u64) -> bool {
    if !context.layers.is_valid(&kernel.layer_name, address, 1) {
        return false;
    }
    let Ok(resource) = context.object(&kernel.qualified("_ERESOURCE"), &kernel.layer_name, address)
    else {
        return false;
    };

    let waiters = resource
        .member("SharedWaiters")
        .and_then(|waiters| waiters.pointer_value())
        .unwrap_or(0);
    let semaphore_size = context
        .symbol_space
        .get_type(&kernel.qualified("_KSEMAPHORE"))
        .and_then(|template| context.symbol_space.size_of(&template))
        .unwrap_or(0);
    if waiters != 0 && !context.layers.is_valid(&kernel.layer_name, waiters, semaphore_size) {
        return false;
    }

    // The list a live lock sits on names it from both sides.
    let Ok(list) = resource.member("SystemResourcesList") else {
        return false;
    };
    let (Ok(forward), Ok(backward)) = (
        list.member("Flink").and_then(|link| link.pointer_value()),
        list.member("Blink").and_then(|link| link.pointer_value()),
    ) else {
        return false;
    };
    if forward == backward {
        return false;
    }
    let back_of_forward = list
        .member("Flink")
        .and_then(|link| link.dereference())
        .and_then(|next| next.member("Blink"))
        .and_then(|link| link.pointer_value())
        .unwrap_or(0);
    let forward_of_back = list
        .member("Blink")
        .and_then(|link| link.dereference())
        .and_then(|previous| previous.member("Flink"))
        .and_then(|link| link.pointer_value())
        .unwrap_or(0);
    let shared = resource
        .member("NumberOfSharedWaiters")
        .and_then(|count| count.as_u64())
        .unwrap_or(1);

    back_of_forward == resource.offset() && forward_of_back == resource.offset() && shared == 0
}

/// Whether a tree is one the kernel built.
fn tree_is_valid(tree: &Object, page_start: u64, page_end: u64) -> bool {
    let Ok(root) = tree.member("BalancedRoot") else {
        return false;
    };
    let Ok(parent) = root.member("Parent").and_then(|parent| parent.pointer_value()) else {
        return false;
    };
    if parent != root.offset() {
        return false;
    }

    let routine = |name: &str| -> Option<u64> {
        tree.member(name)
            .and_then(|routine| routine.pointer_value())
            .ok()
    };
    let (Some(allocate), Some(compare), Some(free)) = (
        routine("AllocateRoutine"),
        routine("CompareRoutine"),
        routine("FreeRoutine"),
    ) else {
        return false;
    };
    if !(page_start..=page_end).contains(&allocate) || !(page_start..=page_end).contains(&compare) {
        return false;
    }
    // The three routines are separate fields, so a tree that names the same
    // one twice is not one.
    let offsets = |name: &str| tree.member(name).map(|member| member.offset()).unwrap_or(0);
    let (allocate_at, compare_at, free_at) = (
        offsets("AllocateRoutine"),
        offsets("CompareRoutine"),
        offsets("FreeRoutine"),
    );
    let _ = free;
    allocate_at != compare_at && allocate_at != free_at && compare_at != free_at
}

/// Where a named section of a loaded module sits.
fn module_section(
    context: &Arc<Context>,
    kernel: &Module,
    names: &[&str],
    section: &str,
) -> Option<(u64, u64)> {
    let head = context
        .object_from_symbol(kernel, "PsLoadedModuleList", Some("_LIST_ENTRY"))
        .ok()?;
    let entries = walk_list(
        &head,
        &kernel.qualified("_LDR_DATA_TABLE_ENTRY"),
        "InLoadOrderLinks",
        true,
    )
    .ok()?;

    for entry in entries {
        let Ok(name) = entry
            .member("BaseDllName")
            .and_then(|name| unicode_string(&name))
        else {
            continue;
        };
        if !names.iter().any(|wanted| *wanted == name) {
            continue;
        }
        let base = entry
            .member("DllBase")
            .and_then(|base| base.pointer_value())
            .ok()?;
        let headers = context
            .layers
            .read(&kernel.layer_name, base, 0x1000, true)
            .ok()?;
        let found = pe::sections(&headers)
            .ok()?
            .into_iter()
            .find(|candidate| candidate.name.eq_ignore_ascii_case(section))?;
        return Some((
            base + found.virtual_address as u64,
            found.virtual_size as u64,
        ));
    }
    None
}

/// Load the description of the cache's structures for this release.
fn shimcache_table(context: &Arc<Context>, kernel: &Module) -> Result<String> {
    let sixty_four_bit = context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .map(|table| table.pointer_size())
        .unwrap_or(8)
        == 8;

    let candidates: &[(&[versions::Check], bool, &str)] = &[
        (versions::IS_WINDOWS_10, true, "shimcache-win10-x64"),
        (versions::IS_WINDOWS_10, false, "shimcache-win10-x86"),
        (versions::IS_WINDOWS_8_OR_LATER, true, "shimcache-win8-x64"),
        (versions::IS_WINDOWS_8_OR_LATER, false, "shimcache-win8-x86"),
        (versions::IS_VISTA_OR_LATER, true, "shimcache-vista-x64"),
        (versions::IS_VISTA_OR_LATER, false, "shimcache-vista-x86"),
    ];

    let table = candidates
        .iter()
        .find(|(checks, for_64_bit, _)| {
            *for_64_bit == sixty_four_bit && versions::matches(context, kernel, checks)
        })
        .map(|(_, _, name)| *name)
        .ok_or_else(|| {
            VolatilityError::Other("This version of Windows is not supported".to_string())
        })?;

    context.ensure_table(table, "windows/shimcache", table)?;
    context.alias_symbol_table("nt_symbols", &kernel.symbol_table_name)?;
    Ok(table.to_string())
}
