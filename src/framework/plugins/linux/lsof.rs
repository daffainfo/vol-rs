//! List the files each task has open.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::conversion::timespec_to_datetime;
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::linux::{
    list_tasks_filtered, path_for_file_of_kind, task_root_readable, OpenFile, Task,
};

pub struct Lsof;

impl Plugin for Lsof {
    fn name(&self) -> &'static str {
        "linux.lsof.Lsof"
    }

    fn description(&self) -> &'static str {
        "Lists open files for each processes."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::pid_filter("Filter on specific process IDs"),
            Requirement::new(
                "files_only",
                "Include only file descriptors of type file",
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
            Column::int("TID"),
            Column::string("Process"),
            Column::int("FD"),
            Column::string("Path"),
            Column::string("Device"),
            Column::int("Inode"),
            Column::string("Type"),
            Column::string("Mode"),
            Column::datetime("Changed"),
            Column::datetime("Modified"),
            Column::datetime("Accessed"),
            Column::int("Size"),
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
        let selected = |task: &Task| match task.tid() {
            Ok(tid) => pid_matches(&filter, tid),
            Err(_) => false,
        };

        let mut timeline = Timeline::new();
        'tasks: for task in list_tasks_filtered(&context, &kernel, true, &selected).ok()? {
            let Ok(pid) = task.pid() else { continue };
            let comm = task.comm().unwrap_or_default();
            let Ok(tid) = task.tid() else { continue };

            for open in task.open_files().unwrap_or_default() {
                let path = match path_for_file_of_kind(&task, &open.file, false) {
                    Some(path) => path,
                    // A task whose root cannot be read stops the walk, and the
                    // timeline is left with what was gathered so far.
                    None if !task_root_readable(&task) => {
                        timeline.failed = true;
                        break 'tasks;
                    }
                    None => String::new(),
                };
                let inode = open.inode();
                let description = format!("Process {comm} ({pid}/{tid}) Open '{path}'");
                timeline.push(
                    description.clone(),
                    TimeKind::Changed,
                    inode_time(&inode, "i_ctime"),
                );
                timeline.push(
                    description.clone(),
                    TimeKind::Modified,
                    inode_time(&inode, "i_mtime"),
                );
                timeline.push(description, TimeKind::Accessed, inode_time(&inode, "i_atime"));
            }
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);
        let files_only = config.get_bool("files_only").unwrap_or(false);
        let mut grid = TreeGrid::new(self.columns());

        // The filter selects processes. A selected process brings its
        // threads with it, whatever their own ids.
        let selected = |task: &Task| match task.tid() {
            Ok(tid) => pid_matches(&filter, tid),
            Err(_) => false,
        };

        'tasks: for task in list_tasks_filtered(&context, &kernel, true, &selected)? {
            let Ok(pid) = task.pid() else { continue };
            let comm = task.comm().unwrap_or_default();

            for open in task.open_files().unwrap_or_default() {
                // A path only means anything relative to the task's own root,
                // which is what supplies any mount prefixes. When that root
                // cannot be read the reference implementation stops here.
                let path = match path_for_file_of_kind(&task, &open.file, files_only) {
                    Some(path) => path,
                    None if !task_root_readable(&task) => {
                        grid.mark_truncated_reported();
                        break 'tasks;
                    }
                    None => String::new(),
                };
                let inode = open.inode();
                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        or_unreadable(task.tid(), |value| Value::int(value as i64)),
                        Value::string(comm.clone()),
                        Value::int(open.descriptor as i64),
                        Value::string(path),
                        device(&open),
                        inode_field(&inode, "i_ino", |value| Value::int(value as i64)),
                        file_type(&inode),
                        Value::string(mode(&inode)),
                        inode_time(&inode, "i_ctime"),
                        inode_time(&inode, "i_mtime"),
                        inode_time(&inode, "i_atime"),
                        inode_field(&inode, "i_size", |value| Value::int(value as i64)),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// The backing device, rendered as `major:minor`.
fn device(open: &OpenFile) -> Value {
    let Some(inode) = open.inode() else {
        return Value::unreadable();
    };
    let raw = inode
        .member("i_sb")
        .and_then(|sb| sb.dereference())
        .and_then(|sb| sb.member("s_dev"))
        .and_then(|dev| dev.as_u64());
    match raw {
        Ok(dev) => Value::string(format!("{}:{}", dev >> 20, dev & 0xFFFFF)),
        Err(_) => Value::unreadable(),
    }
}

fn inode_field<F: Fn(u64) -> Value>(
    inode: &Option<crate::framework::objects::Object>,
    member: &str,
    format: F,
) -> Value {
    match inode
        .as_ref()
        .and_then(|inode| inode.member(member).ok())
        .and_then(|field| field.as_u64().ok())
    {
        Some(value) => format(value),
        None => Value::unreadable(),
    }
}

/// One of the inode's timestamps.
///
/// The kernel changed these from `timespec` to a packed pair of fields, so both
/// spellings are tried.
fn inode_time(inode: &Option<crate::framework::objects::Object>, member: &str) -> Value {
    let Some(inode) = inode else {
        return Value::unreadable();
    };
    // Kernel 6.6 renamed these with a leading underscore, and 6.11 split them
    // into separate seconds and nanoseconds fields.
    let timespec = inode
        .member(&format!("__{member}"))
        .or_else(|_| inode.member(member))
        .ok()
        .and_then(|time| {
            Some((
                time.member("tv_sec").ok()?.as_i64().ok()?,
                time.member("tv_nsec").ok()?.as_i64().ok()?,
            ))
        })
        .or_else(|| {
            Some((
                inode.member(&format!("{member}_sec")).ok()?.as_i64().ok()?,
                inode.member(&format!("{member}_nsec")).ok()?.as_i64().ok()?,
            ))
        });

    match timespec.and_then(|(seconds, nanoseconds)| timespec_to_datetime(seconds, nanoseconds)) {
        Some(when) => Value::DateTime(when),
        None => Value::unreadable(),
    }
}

/// The file type letter, taken from the inode's mode bits.
fn file_type(inode: &Option<crate::framework::objects::Object>) -> Value {
    let Some(mode) = read_mode(inode) else {
        return Value::unparsable();
    };
    // The top four bits of the mode encode the file type. A pseudo-file such as
    // an anonymous inode has none of them set and so has no type to report.
    match mode & 0xF000 {
        0x1000 => Value::string("FIFO"),
        0x2000 => Value::string("CHR"),
        0x4000 => Value::string("DIR"),
        0x6000 => Value::string("BLK"),
        0x8000 => Value::string("REG"),
        0xA000 => Value::string("LNK"),
        0xC000 => Value::string("SOCK"),
        _ => Value::unparsable(),
    }
}

/// The permission bits, rendered the way `ls` shows them.
fn mode(inode: &Option<crate::framework::objects::Object>) -> String {
    let Some(mode) = read_mode(inode) else {
        return "-".to_string();
    };
    let mut text = String::with_capacity(10);
    // The leading character names the kind of file, as `ls -l` shows it.
    text.push(match mode & 0xF000 {
        0x4000 => 'd',
        0x8000 => '-',
        0xA000 => 'l',
        0x1000 => 'p',
        0xC000 => 's',
        0x2000 => 'c',
        0x6000 => 'b',
        _ => '?',
    });
    for shift in [6, 3, 0] {
        let bits = (mode >> shift) & 0x7;
        text.push(if bits & 0x4 != 0 { 'r' } else { '-' });
        text.push(if bits & 0x2 != 0 { 'w' } else { '-' });
        text.push(if bits & 0x1 != 0 { 'x' } else { '-' });
    }
    text
}

fn read_mode(inode: &Option<crate::framework::objects::Object>) -> Option<u64> {
    inode
        .as_ref()?
        .member("i_mode")
        .ok()?
        .as_u64()
        .ok()
}
