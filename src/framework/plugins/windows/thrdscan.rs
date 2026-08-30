//! Scan physical memory for thread objects.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::Object;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::windows::pe_symbols::{
    file_for_address, process_file_ranges, MappedRange,
};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::conversion::wintime_value;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::poolscanner::scan_for_tags;
use crate::framework::symbols::windows::{process_is_valid, Process};

/// The largest identifier the kernel ever hands out.
const MAX_PID: u64 = 0xFFFF_FFFC;

pub struct ThrdScan;

impl Plugin for ThrdScan {
    fn name(&self) -> &'static str {
        "windows.thrdscan.ThrdScan"
    }

    fn description(&self) -> &'static str {
        "Scans for windows threads."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        thread_columns()
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
            // A thread with no creation time is almost always one the system
            // started before it began recording them.
            if !is_time(&values[7]) {
                continue;
            }
            let description = format!(
                "Thread: Tid {} in Pid {} (Offset {})",
                number(&values[2]),
                number(&values[1]),
                number(&values[0])
            );
            timeline.push(description.clone(), TimeKind::Created, values[7].clone());
            if is_time(&values[8]) {
                timeline.push(description, TimeKind::Modified, values[8].clone());
            }
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let threads = scan_threads(&context, &kernel)?;
        report_threads(&context, &kernel, threads)
    }
}

/// The columns every thread listing reports.
pub fn thread_columns() -> Vec<Column> {
    vec![
        Column::new("Offset", ColumnType::UInt),
        Column::int("PID"),
        Column::int("TID"),
        Column::new("StartAddress", ColumnType::UInt),
        Column::string("StartPath"),
        Column::new("Win32StartAddress", ColumnType::UInt),
        Column::string("Win32StartPath"),
        Column::datetime("CreateTime"),
        Column::datetime("ExitTime"),
    ]
}

/// Every thread object the pools still hold.
pub fn scan_threads(context: &Arc<Context>, kernel: &Module) -> Result<Vec<Object>> {
    scan_for_tags(context, kernel, &[b"Thr\xe5", b"Thre"])
}

/// Report a set of threads, naming the file each one starts in.
pub fn report_threads(
    context: &Arc<Context>,
    kernel: &Module,
    threads: Vec<Object>,
) -> Result<TreeGrid> {
        // Reading a process's mapped files is expensive, so each process is
        // read once however many of its threads turn up.
        let mut ranges_by_process: HashMap<u64, Vec<MappedRange>> = HashMap::new();
        let mut grid = TreeGrid::new(thread_columns());

        for thread in threads {
            let cid = thread.member("Cid");
            let (Ok(cid), Ok(start_address), Ok(win32_start)) = (
                cid,
                thread
                    .member("StartAddress")
                    .and_then(|value| value.pointer_value()),
                thread
                    .member("Win32StartAddress")
                    .and_then(|value| value.pointer_value()),
            ) else {
                continue;
            };
            let (Ok(pid), Ok(tid)) = (
                cid.member("UniqueProcess")
                    .and_then(|value| value.pointer_value()),
                cid.member("UniqueThread")
                    .and_then(|value| value.pointer_value()),
            ) else {
                continue;
            };
            let (Ok(created), Ok(exited)) = (
                thread
                    .member("CreateTime")
                    .and_then(|time| time.member("QuadPart"))
                    .and_then(|value| value.as_u64()),
                thread
                    .member("ExitTime")
                    .and_then(|time| time.member("QuadPart"))
                    .and_then(|value| value.as_u64()),
            ) else {
                continue;
            };

            // Identifiers the kernel would never hand out mark an allocation
            // that only looked like a thread.
            if pid > MAX_PID || pid == 0 || pid % 4 != 0 {
                continue;
            }

            // The files a thread starts in are known only through the process
            // that owns it, and the system process maps none.
            let owner = owning_process(&thread, kernel);
            let mut start_path = Value::not_available();
            let mut win32_path = Value::not_available();
            if let Some(owner) = owner {
                let owner_pid = owner.pid().unwrap_or(0);
                if process_is_valid(context, kernel, &owner.object) && owner_pid != 4 {
                    let ranges = ranges_by_process
                        .entry(owner.offset())
                        .or_insert_with(|| process_file_ranges(context, kernel, &owner));
                    if !ranges.is_empty() {
                        if let Some(path) = file_for_address(ranges, start_address) {
                            start_path = Value::string(path);
                        }
                        if let Some(path) = file_for_address(ranges, win32_start) {
                            win32_path = Value::string(path);
                        }
                    }
                }
            }

            grid.push(
                0,
                vec![
                    Value::hex(thread.offset()),
                    Value::int(pid as i64),
                    Value::int(tid as i64),
                    Value::hex(start_address),
                    start_path,
                    Value::hex(win32_start),
                    win32_path,
                    wintime_value(created),
                    wintime_value(exited),
                ],
            )?;
        }
        Ok(grid)
}

/// The process a thread belongs to.
fn owning_process(thread: &Object, kernel: &Module) -> Option<Process> {
    let process = thread
        .member("Tcb")
        .and_then(|tcb| tcb.member("Process"))
        .or_else(|_| thread.member("ThreadsProcess"))
        .and_then(|process| process.dereference_as(&kernel.qualified("_EPROCESS")))
        .ok()?;
    Some(Process::new(process))
}

