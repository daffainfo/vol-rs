//! Report the sessions on the system and which processes belong to them.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::envars::read_environment;
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::conversion::wintime_value;
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::windows::list_processes;

pub struct Sessions;

impl Plugin for Sessions {
    fn name(&self) -> &'static str {
        "windows.sessions.Sessions"
    }

    fn description(&self) -> &'static str {
        "lists Processes with Session information extracted from Environmental Variables"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel(), Requirement::pid_filter("Process IDs to include (all other processes are excluded)")]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("Session ID"),
            Column::string("Session Type"),
            Column::int("Process ID"),
            Column::string("Process"),
            Column::string("User Name"),
            Column::datetime("Create Time"),
        ]
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
            // Without the user context the entry says no more than a process
            // listing already does.
            if values[4].is_absent() {
                continue;
            }
            let description = format!(
                "Process: {} {} started by user {}",
                number(&values[2]),
                text(&values[3]),
                text(&values[4])
            );
            timeline.push(description, TimeKind::Created, values[5].clone());
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let filter = pid_filter(config);

        // Rows are grouped by session and reported a session at a time, in the
        // order the sessions were first seen. A process whose session cannot
        // be named groups with nothing, not even another such process.
        let mut groups: Vec<(Option<u64>, Vec<Vec<Value>>)> = Vec::new();

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }

            let session = process.session_id();
            let session_id = match &session {
                Ok(Some(id)) => Value::int(*id as i64),
                // A process with no session space of its own has no identifier
                // to report, rather than one that could not be read.
                Ok(None) => Value::not_applicable(),
                Err(_) => Value::unreadable(),
            };

            // The session's kind and the user behind it are only recorded in
            // the process's own environment.
            let mut session_type = Value::not_available();
            let (mut domain, mut user) = (String::new(), String::new());
            if let Ok(layer) = process.address_space(&physical) {
                if let Ok((_, variables)) = read_environment(&process, &layer) {
                    for (variable, value) in variables {
                        let variable = variable.to_ascii_lowercase();
                        match variable.as_str() {
                            "username" => user = value,
                            "userdomain" => domain = value,
                            "sessionname" => session_type = Value::string(value),
                            _ => {}
                        }
                    }
                }
            }
            let full_user = format!("{domain}/{user}");
            let user = if full_user == "/" {
                Value::not_available()
            } else {
                Value::string(full_user)
            };

            let row = vec![
                session_id,
                session_type,
                Value::int(pid as i64),
                process
                    .image_file_name()
                    .map(Value::string)
                    .unwrap_or_else(|_| Value::unreadable()),
                user,
                process
                    .create_time()
                    .map(wintime_value)
                    .unwrap_or_else(|_| Value::unreadable()),
            ];

            let key = session.ok().flatten();
            match key.and_then(|id| {
                groups
                    .iter_mut()
                    .find(|(group, _)| *group == Some(id))
                    .map(|(_, rows)| rows)
            }) {
                Some(rows) => rows.push(row),
                None => groups.push((key, vec![row])),
            }
        }

        let mut grid = TreeGrid::new(self.columns());
        for (_, rows) in groups {
            for row in rows {
                grid.push(0, row)?;
            }
        }
        Ok(grid)
    }
}
