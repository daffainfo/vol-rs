//! The goal of this plugin is to report on threads that are suspended.
//!
//! Legitimate programs can start threads suspended but then will later resume
//! them.
//!
//! Subsets of malware techniques, such as EDR evasion and process hollowing,
//! create suspended threads and do not resume them. These are the threads that
//! this plugin is designed to catch.
//!
//! See the whitepaper from our DEF CON 2024 presentation for more details:
//!
//! https://www.volexity.com/wp-content/uploads/2024/08/Defcon24_EDR_Evasion_Detection_White-Paper_Andrew-Case.pdf
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::utility::walk_list;
use crate::framework::objects::Object;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::windows::pe_symbols::{
    file_for_address, process_file_ranges, MappedRange,
};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::{list_processes, Process};

/// Enumerates suspended threads.
pub struct SuspendedThreads;

impl Plugin for SuspendedThreads {
    fn name(&self) -> &'static str {
        "windows.suspended_threads.SuspendedThreads"
    }

    fn description(&self) -> &'static str {
        "Enumerates suspended threads."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Process"),
            Column::int("PID"),
            Column::int("TID"),
            Column::string("StartFile"),
            Column::string("StartSymbol"),
            Column::new("StartAddress", ColumnType::UInt),
            Column::string("Win32StartFile"),
            Column::string("Win32StartSymbol"),
            Column::new("Win32StartAddress", ColumnType::UInt),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let mut grid = TreeGrid::new(self.columns());
        // Only compute this if needed as its expensive and 99.9% of samples
        // will not have suspended threads.
        let mut ranges_by_process: HashMap<u64, Vec<MappedRange>> = HashMap::new();

        for process in list_processes(&context, &kernel)? {
            let threads = process
                .object
                .member("ThreadListHead")
                .and_then(|head| {
                    walk_list(&head, &kernel.qualified("_ETHREAD"), "ThreadListEntry", true)
                })
                .unwrap_or_default();

            for thread in threads {
                let Ok(tcb) = thread.member("Tcb") else {
                    continue;
                };
                // Only a thread something is holding back is of interest.
                let suspended = tcb
                    .member("SuspendCount")
                    .and_then(|count| count.as_i64())
                    .map(|count| count != 0)
                    .unwrap_or(false);
                if !suspended {
                    continue;
                }
                // A terminated thread is suspended in name only.
                let terminated = tcb
                    .member("State")
                    .and_then(|state| state.as_u64())
                    .map(|state| state == 4)
                    .unwrap_or(false);
                if terminated {
                    continue;
                }

                let Some(owner) = owning_process(&thread, &kernel) else {
                    continue;
                };
                let (Ok(pid), Ok(tid)) = (
                    thread
                        .member("Cid")
                        .and_then(|cid| cid.member("UniqueProcess"))
                        .and_then(|value| value.pointer_value()),
                    thread
                        .member("Cid")
                        .and_then(|cid| cid.member("UniqueThread"))
                        .and_then(|value| value.pointer_value()),
                ) else {
                    continue;
                };
                let Ok(name) = owner.image_file_name() else {
                    continue;
                };
                let (Ok(start_address), Ok(win32_start)) = (
                    thread
                        .member("StartAddress")
                        .and_then(|value| value.pointer_value()),
                    thread
                        .member("Win32StartAddress")
                        .and_then(|value| value.pointer_value()),
                ) else {
                    continue;
                };

                // A process with no mapped files at all has been smeared or
                // has already gone.
                let ranges = ranges_by_process
                    .entry(owner.offset())
                    .or_insert_with(|| process_file_ranges(&context, &kernel, &owner));
                if ranges.is_empty() {
                    continue;
                }

                let start_file = file_for_address(ranges, start_address);
                let win32_file = file_for_address(ranges, win32_start);
                // The one thing that legitimately starts suspended and stays
                // that way.
                if start_file.map(ends_in_work_folders).unwrap_or(false)
                    || win32_file.map(ends_in_work_folders).unwrap_or(false)
                {
                    continue;
                }

                let path = |value: Option<&str>| match value {
                    Some(path) => Value::string(path),
                    None => Value::not_available(),
                };
                grid.push(
                    0,
                    vec![
                        Value::string(name),
                        Value::int(pid as i64),
                        Value::int(tid as i64),
                        path(start_file),
                        Value::not_available(),
                        Value::hex(start_address),
                        path(win32_file),
                        Value::not_available(),
                        Value::hex(win32_start),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
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

/// the only false positive found in mass scanning of samples.
fn ends_in_work_folders(path: &str) -> bool {
    path.ends_with("\\WorkFoldersShell.dll")
}
