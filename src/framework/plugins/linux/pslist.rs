//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{ConfigValue, Configuration, Context};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{
    pid_filter, pid_matches, OperatingSystem, Plugin, Requirement, RequirementKind,
};
use crate::framework::renderers::conversion::unixtime_nanos_value;
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::linux::{
    boot_time_seconds, list_tasks_filtered, masked_address, Task,
};

/// Lists the processes present in a particular linux memory image.
pub struct PsList;

impl Plugin for PsList {
    fn name(&self) -> &'static str {
        "linux.pslist.PsList"
    }

    fn description(&self) -> &'static str {
        "Lists the processes present in a particular linux memory image."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::pid_filter("Filter on specific process IDs"),
            Requirement::new(
                "threads",
                "Include user threads",
                RequirementKind::Bool,
            )
            .with_default(ConfigValue::Bool(false)),
            Requirement::new(
                "decorate_comm",
                "Show `user threads` comm in curly brackets, and `kernel threads` comm in square brackets",
                RequirementKind::Bool,
            )
            .with_default(ConfigValue::Bool(false)),
            Requirement::new("dump", "Extract listed processes", RequirementKind::Bool)
                .with_default(ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("OFFSET (V)", ColumnType::UInt),
            Column::int("PID"),
            Column::int("TID"),
            Column::int("PPID"),
            Column::string("COMM"),
            Column::int("UID"),
            Column::int("GID"),
            Column::int("EUID"),
            Column::int("EGID"),
            Column::datetime("CREATION TIME"),
            Column::string("File output"),
        ]
    }

    fn timeline(
        &self,
        context: Arc<Context>,
        config: &Configuration,
    ) -> Option<crate::framework::plugins::Timeline> {
        use crate::framework::plugins::{TimeKind, Timeline};

        let kernel = kernel_module(&context, config).ok()?;
        let filter = pid_filter(config);
        let boot_time = boot_time_seconds(&context, &kernel);
        let pointer_size = context
            .symbol_space
            .table(&kernel.symbol_table_name)
            .map(|table| table.pointer_size())
            .unwrap_or(8);

        // The timeline always covers threads as well, whatever the listing was
        // asked for.
        let mut timeline = Timeline::new();
        // Upstream filters on the kernel's own `pid`, which is the thread
        // identifier, and does it while walking the list.
        let selected = |task: &Task| match task.tid() {
            Ok(tid) => pid_matches(&filter, tid),
            Err(_) => false,
        };
        for task in list_tasks_filtered(&context, &kernel, true, &selected).ok()? {
            let Ok(pid) = task.pid() else { continue };
            let Ok(tid) = task.tid() else { continue };
            let name = task.comm().unwrap_or_default();
            let when = match boot_time {
                Some(boot) => task
                    .creation_time(Some(boot))
                    .map(|(seconds, nanoseconds)| unixtime_nanos_value(seconds, nanoseconds))
                    .unwrap_or_else(|_| Value::not_applicable()),
                None => Value::not_applicable(),
            };
            timeline.push(
                format!(
                    "Process {pid}/{tid} {name} ({})",
                    masked_address(task.offset(), pointer_size)
                ),
                TimeKind::Created,
                when,
            );
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let include_threads = config.get_bool("threads").unwrap_or(false);
        let dump = config.get_bool("dump").unwrap_or(false);
        let decorate = config.get_bool("decorate_comm").unwrap_or(false);
        let filter = pid_filter(config);

        // Task start times count from boot, so the boot moment is what turns
        // them into wall-clock times. Read it once for the whole listing.
        let boot_time = boot_time_seconds(&context, &kernel);
        let pointer_size = context
            .symbol_space
            .table(&kernel.symbol_table_name)
            .map(|table| table.pointer_size())
            .unwrap_or(8);

        let mut grid = TreeGrid::new(self.columns());
        // Upstream filters on the kernel's own `pid`, which is the thread
        // identifier, and does it while walking the list, so a process that
        // matches brings its threads with it.
        let selected = |task: &Task| match task.tid() {
            Ok(tid) => pid_matches(&filter, tid),
            Err(_) => false,
        };
        for task in list_tasks_filtered(&context, &kernel, include_threads, &selected)? {
            let Ok(pid) = task.pid() else { continue };

            let comm = decorated_comm(&task, decorate);

            grid.push(
                0,
                vec![
                    Value::hex(masked_address(task.offset(), pointer_size)),
                    Value::int(pid as i64),
                    or_unreadable(task.tid(), |value| Value::int(value as i64)),
                    or_unreadable(task.ppid(), |value| Value::int(value as i64)),
                    comm.clone(),
                    or_unreadable(task.uid(), |value| Value::int(value as i64)),
                    or_unreadable(task.gid(), |value| Value::int(value as i64)),
                    or_unreadable(task.euid(), |value| Value::int(value as i64)),
                    or_unreadable(task.egid(), |value| Value::int(value as i64)),
                    match boot_time {
                        Some(boot) => task
                            .creation_time(Some(boot))
                            .map(|(seconds, nanoseconds)| {
                                unixtime_nanos_value(seconds, nanoseconds)
                            })
                            .unwrap_or_else(|_| Value::unreadable()),
                        // Without the boot time the offset cannot be turned
                        // into a real time, and reporting 1970 would be worse
                        // than reporting nothing.
                        None => Value::not_available(),
                    },
                    if dump {
                        file_output(&context, &task, pid, &comm)
                    } else {
                        Value::string("Disabled")
                    },
                ],
            )?;
        }
        Ok(grid)
    }
}

/// A task's command name, marked to say what kind of thread it is when the
/// caller asked for that.
///
/// Kernel threads are conventionally shown in brackets and userland threads in
/// braces, so the two are told apart at a glance.
pub fn decorated_comm(
    task: &crate::framework::symbols::linux::Task,
    decorate: bool,
) -> Value {
    match task.comm() {
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
    }
}

/// Write out the process's own executable, and name the file that holds it.
///
/// Find the vma that belongs to the main ELF of the process, which is the
/// mapping that begins where the task says its code does. If we can't build a
/// proc layer we can't extract the elf, which is a statement about the task
/// rather than a failure.
fn file_output(
    context: &Arc<Context>,
    task: &Task,
    pid: u64,
    comm: &Value,
) -> Value {
    let Ok(Some(layer)) = task.process_layer() else {
        return Value::not_applicable();
    };
    let start_code = task
        .mm()
        .ok()
        .flatten()
        .and_then(|mm| mm.member("start_code").ok())
        .and_then(|value| value.as_u64().ok());
    let Some(start_code) = start_code else {
        return Value::string("VMA start matching task start_code not found");
    };

    let name = comm.to_string();
    for vma in &task.vmas().unwrap_or_default().areas {
        let Ok(start) = vma.start() else { continue };
        if start != start_code {
            continue;
        }
        return match crate::framework::plugins::linux::elfs::dump_elf(
            context, &layer, start, pid, &name,
        ) {
            Some(written) => Value::string(written),
            None => Value::string("Error outputting file"),
        };
    }
    Value::string("VMA start matching task start_code not found")
}
