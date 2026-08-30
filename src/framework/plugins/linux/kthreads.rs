//! List kernel threads and the functions they run.
//!
//! A kernel thread's worker function is recorded when the thread is created.
//! A thread whose function lies in a module rather than the kernel image is
//! worth attention, since that is where a malicious worker would live.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::objects::utility::pointer_to_string;
use crate::framework::symbols::linux::list_tasks;
use crate::framework::symbols::linux::resolver::ModuleResolver;

pub struct Kthreads;

impl Plugin for Kthreads {
    fn name(&self) -> &'static str {
        "linux.kthreads.Kthreads"
    }

    fn description(&self) -> &'static str {
        "Enumerates kthread functions"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("TID"),
            Column::string("Thread Name"),
            Column::new("Handler Address", ColumnType::UInt),
            Column::string("Module"),
            Column::string("Symbol"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let resolver = ModuleResolver::new(&context, &kernel).ok();
        let kthread_type = context.symbol_space.get_type(&kernel.qualified("kthread"))?;
        let mut grid = TreeGrid::new(self.columns());

        for task in list_tasks(&context, &kernel, true)? {
            // Only kernel threads have a worker function. A userland task runs
            // its own image instead.
            if !task.is_kernel_thread() {
                continue;
            }

            // Kernel 5.17 gave the kthread pointer its own task member. Before
            // that it shared `set_child_tid`, which a kernel thread never uses
            // for its documented purpose.
            let base = if task.object.has_member("worker_private") {
                task.object.member("worker_private")
            } else {
                task.object.member("set_child_tid")
            };
            let Ok(address) = base.and_then(|pointer| pointer.pointer_value()) else {
                continue;
            };
            if address == 0
                || !context
                    .layers
                    .is_valid(task.object.layer_name(), address, 1)
            {
                continue;
            }

            // The member is a `void *`, so it has to be read as a `kthread`.
            let kthread = context.object_from_template(
                kthread_type.clone(),
                task.object.layer_name(),
                address,
            );
            let Ok(handler) = kthread
                .member("threadfn")
                .and_then(|threadfn| threadfn.pointer_value())
            else {
                continue;
            };
            if handler == 0
                || !context
                    .layers
                    .is_valid(task.object.layer_name(), handler, 1)
            {
                continue;
            }

            // `comm` is capped at 15 characters, so prefer the full name the
            // kthread records separately when the kernel is new enough to have
            // it.
            let mut name = task.comm().unwrap_or_default();
            if kthread.has_member("full_name") {
                if let Ok(full_name) = kthread.member("full_name") {
                    if full_name.pointer_value().unwrap_or(0) != 0 {
                        if let Ok(text) = pointer_to_string(&full_name, 255) {
                            name = text;
                        }
                    }
                }
            }

            let (module, symbol) = match &resolver {
                Some(resolver) => resolver.describe(&context, handler),
                None => (None, None),
            };

            grid.push(
                0,
                vec![
                    or_unreadable(task.tid(), |value| Value::int(value as i64)),
                    Value::string(name),
                    Value::hex(handler),
                    module.map(Value::string).unwrap_or_else(Value::not_available),
                    symbol.map(Value::string).unwrap_or_else(Value::not_available),
                ],
            )?;
        }
        Ok(grid)
    }
}
