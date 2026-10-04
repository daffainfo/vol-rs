//! A rootkit that hides a process unlinks it from the kernel's task list. The
//! PID hash table is a separate structure the kernel keeps every identifier in,
//! so walking that finds tasks the ordinary listing misses.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{ConfigValue, Configuration, Context};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::linux::{xarray_entries, Task};

/// Enumerates processes through the PID hash table
pub struct PidHashTable;

impl Plugin for PidHashTable {
    fn name(&self) -> &'static str {
        "linux.pidhashtable.PIDHashTable"
    }

    fn description(&self) -> &'static str {
        "Enumerates processes through the PID hash table"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "decorate_comm",
                "Show `user threads` comm in curly brackets, and `kernel threads` comm in square brackets",
                RequirementKind::Bool,
            )
            .with_default(ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("OFFSET", ColumnType::UInt),
            Column::int("PID"),
            Column::int("TID"),
            Column::int("PPID"),
            Column::string("COMM"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let decorate = config.get_bool("decorate_comm").unwrap_or(false);
        let filter = pid_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        let pid_type = context.symbol_space.get_type(&kernel.qualified("pid"))?;
        let task_type = context.symbol_space.get_type(&kernel.qualified("task_struct"))?;
        // Kernel 4.15 renamed the task's own links, and the one it has says
        // where a task starts relative to the list it is reached through:
        // `pid_links` for kernels >= 4.15, `pids` for 2.6.24 <= kernels < 4.15.
        let links_offset = context
            .symbol_space
            .find_member(&task_type, "pid_links")
            .ok()
            .flatten()
            .or_else(|| {
                context
                    .symbol_space
                    .find_member(&task_type, "pids")
                    .ok()
                    .flatten()
            })
            .map(|(offset, _)| offset)
            .unwrap_or(0);
        // The pid_type enumeration is present since 2.5.37, just in case.
        // Typically PIDTYPE_PID = 0.
        let pid_kind = context
            .symbol_space
            .get_type(&kernel.qualified("pid_type"))
            .ok()
            .and_then(|template| template.as_enum().cloned())
            .and_then(|choices| choices.choices.get("PIDTYPE_PID").copied())
            .unwrap_or(0) as u64;

        // The task behind one `pid`, which the kernel reaches through the first
        // of the lists hanging off it.
        let task_of_pid = |pid_object: &crate::framework::objects::Object| -> Option<Task> {
            let first = pid_object
                .member("tasks")
                .and_then(|tasks| tasks.index(pid_kind))
                .and_then(|head| head.member("first"))
                .and_then(|first| first.pointer_value())
                .ok()?;
            if first == 0 {
                return None;
            }
            Some(Task::new(context.object_from_template(
                task_type.clone(),
                &kernel.layer_name,
                first.wrapping_sub(links_offset),
            )))
        };
        // A task with no identifier, or whose parent cannot be read, is not one.
        let is_valid = |task: &Task| -> bool {
            task.tid().map(|tid| tid > 0).unwrap_or(false)
                && task
                    .object
                    .member("parent")
                    .and_then(|parent| parent.dereference())
                    .map(|parent| parent.is_readable())
                    .unwrap_or(false)
        };

        // The whole listing is sorted before any of it is reported, so a read
        // that fails part-way through discards every row rather than truncating
        // the tail.
        let mut tasks = Vec::new();
        let has_idr = context
            .symbol_space
            .get_type(&kernel.qualified("pid_namespace"))
            .ok()
            .and_then(|template| {
                context
                    .symbol_space
                    .find_member(&template, "idr")
                    .ok()
                    .map(|found| found.is_some())
            })
            .unwrap_or(false);

        if has_idr {
            // kernels >= 4.15 index every pid in an IDR hanging off the initial
            // pid namespace.
            let namespace =
                context.object_from_symbol(&kernel, "init_pid_ns", Some("pid_namespace"))?;
            for entry in xarray_entries(
                &context,
                &kernel,
                &namespace.member("idr")?.member("idr_rt")?,
            )? {
                let pid_object =
                    context.object_from_template(pid_type.clone(), &kernel.layer_name, entry);
                if let Some(task) = task_of_pid(&pid_object) {
                    if is_valid(&task) {
                        tasks.push(task);
                    }
                }
            }
        } else {
            // 2.6.24 <= kernels < 4.15 keep a hash table of `upid` chains, each
            // of which is wrapped in the `pid` it belongs to.
            for upid in hashed_upids(&context, &kernel)? {
                let Some(pid_object) =
                    containing(&context, &kernel, upid, "pid", "numbers")
                else {
                    continue;
                };
                if let Some(task) = task_of_pid(&pid_object) {
                    if is_valid(&task) {
                        tasks.push(task);
                    }
                }
            }
        }

        // Enumerates processes through the PID hash table, in process then
        // thread order.
        tasks.sort_by_key(|task| (task.pid().unwrap_or(0), task.tid().unwrap_or(0)));
        let _ = &grid;

        for task in tasks {

            let Ok(pid) = task.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }

            let comm = match task.comm() {
                Ok(name) if decorate => {
                    if task.is_kernel_thread() {
                        Value::string(format!("[{name}]"))
                    } else if task.is_thread() {
                        Value::string(format!("{{{name}}}"))
                    } else {
                        Value::string(name)
                    }
                }
                Ok(name) => Value::string(name),
                Err(_) => Value::unreadable(),
            };

            grid.push(
                0,
                vec![
                    Value::hex(task.offset()),
                    Value::int(pid as i64),
                    or_unreadable(task.tid(), |value| Value::int(value as i64)),
                    or_unreadable(task.ppid(), |value| Value::int(value as i64)),
                    comm,
                ],
            )?;
        }
        Ok(grid)
    }
}

/// Every `upid` the pid hash table reaches, as the addresses they sit at.
///
/// Each entry in the hlist is a upid which is wrapped in a pid, and each of
/// those is itself chained to the others naming the same process in different
/// namespaces.
fn hashed_upids(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
) -> Result<Vec<u64>> {
    let shift = context
        .object_from_symbol(kernel, "pidhash_shift", None)?
        .as_u64()?;
    let buckets = 1u64 << shift;
    let table = context
        .object_from_symbol(kernel, "pid_hash", None)?
        .pointer_value()?;
    // pidhash is an array of hlist_heads
    let hlist = context
        .symbol_space
        .get_type(&kernel.qualified("hlist_head"))?;
    let bucket_size = context.symbol_space.size_of(&hlist)?;

    let mut seen = std::collections::HashSet::new();
    let mut order = Vec::new();
    for bucket in 0..buckets {
        let head = context.object_from_template(
            hlist.clone(),
            &kernel.layer_name,
            table + bucket * bucket_size,
        );
        let Ok(mut node) = head.member("first").and_then(|first| first.pointer_value()) else {
            continue;
        };
        while node != 0 {
            // upid->pid_chain exists 2.6.24 <= kernel < 4.15
            let Some(upid) = containing(context, kernel, node, "upid", "pid_chain") else {
                break;
            };
            if seen.contains(&upid.offset()) {
                break;
            }
            // The chain out of this one reaches the same process's identifier
            // in each namespace it is visible in.
            let mut current = Some(upid);
            while let Some(entry) = current {
                if !entry.is_readable() || !seen.insert(entry.offset()) {
                    break;
                }
                order.push(entry.offset());
                let next = entry
                    .member("pid_chain")
                    .and_then(|chain| chain.member("next"))
                    .and_then(|next| next.pointer_value())
                    .unwrap_or(0);
                if next == 0 {
                    break;
                }
                current = containing(context, kernel, next, "upid", "pid_chain");
            }

            let Ok(next) = context
                .object_from_template(hlist.clone(), &kernel.layer_name, node)
                .member("next")
                .and_then(|next| next.pointer_value())
            else {
                break;
            };
            node = next;
        }
    }
    Ok(order)
}

/// The structure of the named type that holds `member` at this address.
fn containing(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
    address: u64,
    type_name: &str,
    member: &str,
) -> Option<crate::framework::objects::Object> {
    let template = context
        .symbol_space
        .get_type(&kernel.qualified(type_name))
        .ok()?;
    let offset = context
        .symbol_space
        .find_member(&template, member)
        .ok()?
        .map(|(offset, _)| offset)?;
    Some(context.object_from_template(
        template,
        &kernel.layer_name,
        address.wrapping_sub(offset),
    ))
}
