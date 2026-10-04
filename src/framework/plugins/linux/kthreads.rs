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

/// Enumerates kthread functions
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

        // Kernel 5.8 moved the worker function into the kthread structure.
        // Before that there is nothing to report, and the reference
        // implementation says so rather than printing an empty listing.
        if context
            .symbol_space
            .find_member(&kthread_type, "threadfn")?
            .is_none()
        {
            grid.mark_failed(crate::error::VolatilityError::Other(
                "Unsupported kthread implementation. This plugin only works with kernels >= 5.8"
                    .to_string(),
            ));
            return Ok(grid);
        }

        for task in list_tasks(&context, &kernel, true)? {
            // Only kernel threads have a worker function. A userland task runs
            // its own image instead.
            if !task.is_kernel_thread() {
                continue;
            }

            // kernels >= 5.17 e32cf5dfbe227b355776948b2c9b5691b84d1cbd gave
            // the kthread pointer its own task member. For
            // 5.8 <= kernels < 5.17, threadfn was added to struct kthread in
            // 52782c92ac85c4e393eb4a903a62e6c24afa633f, and task.set_child_tid
            // is safe on those versions.
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

            // kernels >= 5.17 in d6986ce24fc00b0638bd29efe8fb7ba7619ed2aa
            // added full_name to kthread. `comm` is capped at 15 characters, so
            // prefer the full name where it is there.
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
