//! List the threads each process owns, and the kernel threads no module claims.
//!
//! A thread found by walking a process's own list is one the kernel still
//! acknowledges. A kernel thread whose entry point falls in no loaded module
//! is the opposite: nothing on the system admits to having started it, which
//! is what code injected into kernel space looks like.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::Object;
use crate::framework::objects::utility::walk_list;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::windows::thrdscan::{report_threads, scan_threads, thread_columns};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, TreeGrid};
use crate::framework::symbols::windows::list_processes;
use crate::framework::symbols::windows::resolver::ModuleCollection;

/// The process every kernel thread belongs to, directly or through one of its
/// children.
const SYSTEM_PID: u64 = 4;

/// A thread the kernel has finished with.
const TERMINATED: u64 = 4;

pub struct Threads;

impl Plugin for Threads {
    fn name(&self) -> &'static str {
        "windows.threads.Threads"
    }

    fn description(&self) -> &'static str {
        "Lists process threads"
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

        let mut threads = Vec::new();
        for process in list_processes(&context, &kernel)? {
            let Ok(head) = process.object.member("ThreadListHead") else {
                continue;
            };
            // A list that loops back on itself is followed only once. A
            // corrupted link would otherwise be walked forever.
            let mut seen: Vec<u64> = Vec::new();
            for thread in walk_list(
                &head,
                &kernel.qualified("_ETHREAD"),
                "ThreadListEntry",
                true,
            )
            .unwrap_or_default()
            {
                if seen.contains(&thread.offset()) {
                    break;
                }
                seen.push(thread.offset());
                threads.push(thread);
            }
        }
        report_threads(&context, &kernel, threads)
    }
}

/// Kernel threads whose entry point belongs to no loaded module.
pub struct OrphanKernelThreads;

impl Plugin for OrphanKernelThreads {
    fn name(&self) -> &'static str {
        "windows.orphan_kernel_threads.Threads"
    }

    fn description(&self) -> &'static str {
        "Lists process threads"
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
        let collection = ModuleCollection::build(&context, &kernel)?;
        let kernel_space_start =
            crate::framework::plugins::windows::modules::kernel_space_start(&context, &kernel);

        let mut orphans: Vec<Object> = Vec::new();
        for thread in scan_threads(&context, &kernel)? {
            let Some((pid, parent_pid)) = owning_identifiers(&thread, &kernel) else {
                continue;
            };
            let Ok(start) = thread
                .member("StartAddress")
                .and_then(|value| value.pointer_value())
            else {
                continue;
            };

            // Only the kernel's own threads are of interest, and the kernel
            // starts them from the system process or one of its children.
            if pid != SYSTEM_PID && parent_pid != SYSTEM_PID {
                continue;
            }

            let exited = thread
                .member("ExitTime")
                .and_then(|time| time.member("QuadPart"))
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            let state = thread
                .member("Tcb")
                .and_then(|tcb| tcb.member("State"))
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            if exited > 0 || state == TERMINATED {
                continue;
            }

            // A kernel thread starting in user space is a smeared or
            // half-torn-down structure, not a real one.
            if start < kernel_space_start {
                continue;
            }

            if collection.modules_at(&context, start).is_empty() {
                orphans.push(thread);
            }
        }
        report_threads(&context, &kernel, orphans)
    }
}

/// The process a thread belongs to, and that process's own parent.
fn owning_identifiers(
    thread: &Object,
    kernel: &crate::framework::context::Module,
) -> Option<(u64, u64)> {
    let process = thread
        .member("Tcb")
        .and_then(|tcb| tcb.member("Process"))
        .or_else(|_| thread.member("ThreadsProcess"))
        .and_then(|process| process.dereference_as(&kernel.qualified("_EPROCESS")))
        .ok()?;
    let process = crate::framework::symbols::windows::Process::new(process);
    Some((process.pid().ok()?, process.parent_pid().ok()?))
}
