//! List the processes on the kernel's active process list.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{ConfigValue, Configuration, Context};
use crate::framework::plugins::windows::{kernel_module, offset_column_name, process_offset};
use crate::framework::plugins::{
    pid_filter, pid_matches, OperatingSystem, Plugin, Requirement, RequirementKind,
};
use crate::framework::renderers::conversion::wintime_value;
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::{list_processes, Process};

pub struct PsList;

impl Plugin for PsList {
    fn name(&self) -> &'static str {
        "windows.pslist.PsList"
    }

    fn description(&self) -> &'static str {
        "Lists the processes present in a particular windows memory image."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "physical",
                "Display physical offsets instead of virtual",
                RequirementKind::Bool,
            )
            .with_default(ConfigValue::Bool(false)),
            Requirement::pid_filter("Process ID to include (all other processes are excluded)"),
            Requirement::new(
                "dump",
                "Extract listed processes",
                RequirementKind::Bool,
            )
            .with_default(ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        process_columns(false)
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
            let description = format!(
                "Process: {} {} ({})",
                number(&values[0]),
                text(&values[2]),
                number(&values[3])
            );
            timeline.push(description.clone(), TimeKind::Created, values[8].clone());
            timeline.push(description, TimeKind::Modified, values[9].clone());
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = config.get_bool("physical").unwrap_or(false);
        let physical_name = crate::framework::plugins::windows::physical_layer(config);
        let filter = pid_filter(config);
        let dump = config.get_bool("dump").unwrap_or(false);

        let mut grid = TreeGrid::new(process_columns(physical));
        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let offset = process_offset(&context, &process, physical);
            let file_output = if dump {
                // This listing names the file after writing it, so a name
                // already taken shows as the one actually used.
                match dump_process_image(&context, &physical_name, &process, pid) {
                    Some((_, written)) => Value::string(written),
                    None => Value::string("Error outputting file"),
                }
            } else {
                Value::string("Disabled")
            };
            grid.push(0, process_row(&process, pid, offset, file_output))?;
        }
        Ok(grid)
    }
}

/// The column set shared by `pslist` and `psscan`.
///
/// The offset column is named for which address space it refers to, so the
/// reader can tell a virtual offset from a physical one.
pub fn process_columns(physical: bool) -> Vec<Column> {
    vec![
        Column::int("PID"),
        Column::int("PPID"),
        Column::string("ImageFileName"),
        Column::new(offset_column_name(physical), ColumnType::UInt),
        Column::int("Threads"),
        Column::int("Handles"),
        Column::int("SessionId"),
        Column::bool("Wow64"),
        Column::datetime("CreateTime"),
        Column::datetime("ExitTime"),
        Column::string("File output"),
    ]
}

/// The row shared by `pslist` and `psscan`.
pub fn process_row(process: &Process, pid: u64, offset: u64, file_output: Value) -> Vec<Value> {
    vec![
        Value::int(pid as i64),
        or_unreadable(process.parent_pid(), |value| Value::int(value as i64)),
        or_unreadable(process.image_file_name(), Value::string),
        Value::hex(offset),
        or_unreadable(process.thread_count(), |value| Value::int(value as i64)),
        or_unreadable(process.handle_count(), |value| Value::int(value as i64)),
        session_id_value(process),
        Value::Bool(process.is_wow64()),
        process
            .create_time()
            .map(wintime_value)
            .unwrap_or_else(|_| Value::unreadable()),
        process
            .exit_time()
            .map(wintime_value)
            .unwrap_or_else(|_| Value::unreadable()),
        file_output,
    ]
}

/// A process with no session is reported as not applicable rather than as a
/// failed read, since that is a normal state for the system process.
pub fn session_id_value(process: &Process) -> Value {
    match process.session_id() {
        Ok(Some(id)) => Value::int(id as i64),
        Ok(None) => Value::not_applicable(),
        Err(_) => Value::unreadable(),
    }
}

/// Write a process's own image back out, named after the process.
///
/// Two names come back: the one the file was asked for, and the one it was
/// given, which differ when a file of that name was already there. Which of
/// them a listing reports is the listing's own business, and the two upstream
/// listings differ on it.
///
/// A name comes back even when the image could not be rebuilt in full, since a
/// partly recovered file is still what was produced.
pub fn dump_process_image(
    context: &Arc<Context>,
    physical: &str,
    process: &Process,
    pid: u64,
) -> Option<(String, String)> {
    let layer = process.address_space(physical).ok()?;
    let peb = process.peb(&layer).ok()?;
    let base = peb
        .member("ImageBaseAddress")
        .and_then(|value| value.pointer_value())
        .ok()?;
    let name = process.image_file_name().ok()?;
    let file_name = sanitize_filename(&format!("{pid}.{name}.{base:#x}.dmp"));

    let data = crate::framework::symbols::windows::pe::reconstruct(context, &layer, base)
        .unwrap_or_else(|error| {
            log::debug!("Unable to dump PE with pid {pid}: {error}");
            Vec::new()
        });
    let written = crate::framework::plugins::write_extracted(&file_name, &data).ok()?;
    Some((file_name, written))
}

/// Replace anything a file name should not carry.
pub fn sanitize_filename(name: &str) -> String {
    const ALLOWED: &str =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.- ()[]{}!$%^#~,";
    name.chars()
        .map(|character| {
            if ALLOWED.contains(character) {
                character
            } else {
                '_'
            }
        })
        .collect()
}
