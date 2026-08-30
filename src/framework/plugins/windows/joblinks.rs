//! Report the job objects processes belong to.
//!
//! A job groups processes under shared limits. Sandboxes and container runtimes
//! use them, so a process's job membership says something about how it was
//! launched and what constrains it.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{ConfigValue, Configuration, Context};
use crate::framework::objects::utility::walk_list;
use crate::framework::plugins::windows::{kernel_module, offset_column_name, process_offset};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::pslist_session_id;
use crate::framework::symbols::windows::{list_processes, Process};

pub struct JobLinks;

impl Plugin for JobLinks {
    fn name(&self) -> &'static str {
        "windows.joblinks.JobLinks"
    }

    fn description(&self) -> &'static str {
        "Print process job link information"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "physical",
                "Display physical offset instead of virtual",
                RequirementKind::Bool,
            )
            .with_default(ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        columns_for(false)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = config.get_bool("physical").unwrap_or(false);
        let user_layer = crate::framework::plugins::windows::physical_layer(config);

        let mut grid = TreeGrid::new(columns_for(physical));

        for process in list_processes(&context, &kernel)? {
            // A process belonging to no job has nothing to report here.
            let Ok(job) = process
                .object
                .member("Job")
                .and_then(|job| job.dereference())
            else {
                continue;
            };

            let (Ok(pid), Ok(name)) = (process.pid(), process.image_file_name()) else {
                continue;
            };
            let (Ok(session), Ok(total), Ok(active), Ok(terminated)) = (
                job.member("SessionId").and_then(|id| id.as_i64()),
                job.member("TotalProcesses").and_then(|count| count.as_i64()),
                job.member("ActiveProcesses").and_then(|count| count.as_i64()),
                job.member("TotalTerminatedProcesses")
                    .and_then(|count| count.as_i64()),
            ) else {
                continue;
            };

            grid.push(
                0,
                vec![
                    Value::hex(process_offset(&context, &process, physical)),
                    Value::string(name),
                    Value::int(pid as i64),
                    or_unreadable(process.parent_pid(), |value| Value::int(value as i64)),
                    pslist_session_id(&process),
                    Value::int(session),
                    Value::Bool(process.is_wow64()),
                    Value::int(total),
                    Value::int(active),
                    Value::int(terminated),
                    Value::not_applicable(),
                    // The process the job was created around.
                    Value::string("(Original Process)"),
                ],
            )?;

            // The rest of the job's members are listed beneath it, each named
            // by the image it was started from.
            let Ok(head) = job.member("ProcessListHead") else {
                continue;
            };
            for entry in walk_list(&head, &kernel.qualified("_EPROCESS"), "JobLinks", true)
                .unwrap_or_default()
            {
                let member = Process::new(entry);
                let (Ok(pid), Ok(name)) = (member.pid(), member.image_file_name()) else {
                    break;
                };
                let Ok(path) = member
                    .address_space(&user_layer)
                    .and_then(|layer| member.image_path(&layer))
                else {
                    break;
                };

                grid.push(
                    1,
                    vec![
                        Value::hex(process_offset(&context, &member, physical)),
                        Value::string(name),
                        Value::int(pid as i64),
                        or_unreadable(member.parent_pid(), |value| Value::int(value as i64)),
                        pslist_session_id(&member),
                        Value::int(0),
                        Value::Bool(member.is_wow64()),
                        Value::int(0),
                        Value::int(0),
                        Value::int(0),
                        Value::string("Yes"),
                        Value::string(path),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

fn columns_for(physical: bool) -> Vec<Column> {
    vec![
        Column::new(offset_column_name(physical), ColumnType::UInt),
        Column::string("Name"),
        Column::int("PID"),
        Column::int("PPID"),
        Column::int("Sess"),
        Column::int("JobSess"),
        Column::bool("Wow64"),
        Column::int("Total"),
        Column::int("Active"),
        Column::int("Term"),
        Column::string("JobLink"),
        Column::string("Process"),
    ]
}
