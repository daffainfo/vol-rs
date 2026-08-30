//! Report when the system booted.
//!
//! The kernel tracks time since boot separately from wall-clock time. The boot
//! moment is the difference between them. It anchors every other timestamp a
//! Linux image yields.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashSet;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::conversion::timespec_to_datetime;
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::linux::{boot_time_timespec, list_tasks};

pub struct BootTime;

impl Plugin for BootTime {
    fn name(&self) -> &'static str {
        "linux.boottime.Boottime"
    }

    fn description(&self) -> &'static str {
        "Shows the time the system was started"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![Column::int("TIME NS"), Column::datetime("Boot Time")]
    }

    fn timeline(
        &self,
        context: Arc<Context>,
        config: &Configuration,
    ) -> Option<crate::framework::plugins::Timeline> {
        use crate::framework::plugins::{TimeKind, Timeline};

        let mut timeline = Timeline::new();
        for row in self.run(context, config).ok()?.rows() {
            let (Some(namespace), Some(when)) = (row.values.first(), row.values.get(1)) else {
                continue;
            };
            timeline.push(
                format!("System boot time for time namespace {namespace}"),
                TimeKind::Created,
                when.clone(),
            );
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let Some((boot_seconds, boot_nanoseconds)) = boot_time_timespec(&context, &kernel) else {
            return Ok(TreeGrid::new(self.columns()));
        };

        let mut grid = TreeGrid::new(self.columns());
        let mut seen: HashSet<Option<u64>> = HashSet::new();

        // One row per time namespace: tasks in a namespace see a boot time
        // shifted by that namespace's offset, so a container reports its own.
        for task in list_tasks(&context, &kernel, false)? {
            let namespace = task.time_namespace_id();
            if !seen.insert(namespace) {
                continue;
            }

            let (mut seconds, mut nanoseconds) = (boot_seconds, boot_nanoseconds);
            if let Some((offset_seconds, offset_nanoseconds)) =
                task.time_namespace_boottime_offset()
            {
                seconds -= offset_seconds;
                nanoseconds -= offset_nanoseconds;
                // Normalise the borrow the subtraction may have created.
                while nanoseconds < 0 {
                    nanoseconds += 1_000_000_000;
                    seconds -= 1;
                }
                while nanoseconds >= 1_000_000_000 {
                    nanoseconds -= 1_000_000_000;
                    seconds += 1;
                }
            }

            grid.push(
                0,
                vec![
                    namespace
                        .map(|value| Value::int(value as i64))
                        .unwrap_or_else(Value::not_available),
                    match timespec_to_datetime(seconds, nanoseconds) {
                        Some(when) => Value::DateTime(when),
                        // A nonsensical offset means the structure was misread
                        // rather than that the system has no boot time.
                        None => Value::unreadable(),
                    },
                ],
            )?;
        }
        Ok(grid)
    }
}
