//! Recover bash command history from process memory.
//!
//! Bash keeps its history as `hist_entry` structures, each pairing a command
//! line with the time it ran. The timestamps are stored as a `#` followed by a
//! Unix time, which gives a cheap pattern to scan the heap for. A hit is then
//! validated by reading the structure that would contain it.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::layers::scanners::{scan_layer, BytesScanner, MultiStringScanner};
use crate::framework::objects::utility::pointer_to_string;
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::conversion::unixtime_value;
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::intermed::{create_table, SymbolFinder};
use crate::framework::symbols::linux::{list_tasks, Task};

pub struct Bash;

/// Bash writes each history timestamp as `#` followed by the Unix time.
const TIMESTAMP_PREFIX: &[u8] = b"#";

/// A command longer than this is not a real history entry.
const MAX_COMMAND: usize = 1024;

impl Plugin for Bash {
    fn name(&self) -> &'static str {
        "linux.bash.Bash"
    }

    fn description(&self) -> &'static str {
        "Recovers bash command history from memory."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel(), Requirement::pid_filter("Process IDs to include (all other processes are excluded)")]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Process"),
            Column::datetime("CommandTime"),
            Column::string("Command"),
        ]
    }

    fn timeline(
        &self,
        context: Arc<Context>,
        config: &Configuration,
    ) -> Option<crate::framework::plugins::Timeline> {
        use crate::framework::plugins::{TimeKind, Timeline};

        let mut timeline = Timeline::new();
        for row in self.run(context, config).ok()?.rows() {
            let [pid, process, when, command] = &row.values[..] else {
                continue;
            };
            timeline.push(
                format!("{pid} ({process}): \"{command}\""),
                TimeKind::Created,
                when.clone(),
            );
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);

        // The history structures are described by a small bundled symbol file,
        // chosen to match the task's pointer width.
        let finder = SymbolFinder::with_defaults();
        let pointer_size = context
            .symbol_space
            .table(&kernel.symbol_table_name)
            .map(|table| table.pointer_size())
            .unwrap_or(8);
        let bash_file = if pointer_size == 8 { "bash64" } else { "bash32" };

        let bash_table = match finder.find("linux", bash_file) {
            Some(location) => {
                let name = context.symbol_space.free_table_name("bash");
                let table = create_table(&name, location.load()?);
                context.add_symbol_table(table);
                name
            }
            None => {
                return Err(crate::error::VolatilityError::Other(format!(
                    "Could not find the bundled '{bash_file}' symbol file; \
                     bash history cannot be decoded without it"
                )))
            }
        };

        let mut grid = TreeGrid::new(self.columns());
        for task in list_tasks(&context, &kernel, false)? {
            let Ok(pid) = task.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }

            // Only a shell keeps bash history.
            let comm = task.comm().unwrap_or_default();
            if comm != "bash" && comm != "sh" && comm != "dash" {
                continue;
            }

            for entry in recover_history(&context, &task, &bash_table)? {
                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(comm.clone()),
                        unixtime_value(entry.time),
                        Value::string(entry.command),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

struct HistoryEntry {
    time: i64,
    command: String,
}

/// Recover a task's bash history from its heap.
///
/// Done in two passes, as the reference implementation does: first find every
/// `#` on the heap, since a history timestamp is stored as `#<epoch>`. Then
/// search the heap again for pointers to those addresses. Each such pointer is
/// a `hist_entry`'s `timestamp` member, which locates the structure itself.
fn recover_history(
    context: &Arc<Context>,
    task: &Task,
    bash_table: &str,
) -> Result<Vec<HistoryEntry>> {
    let template = context
        .symbol_space
        .get_type(&crate::framework::symbols::join_name(bash_table, "hist_entry"))?;
    // The structure begins this far before its timestamp member.
    let timestamp_offset = context
        .symbol_space
        .find_member(&template, "timestamp")?
        .map(|(offset, _)| offset)
        .unwrap_or(8);

    let Some(layer_name) = task.process_layer()? else {
        return Ok(Vec::new());
    };
    let layer = context.layers.get(&layer_name)?;

    let sections = task.heap_sections()?;
    if sections.is_empty() {
        return Ok(Vec::new());
    }

    // First pass: every '#' on the heap is a candidate timestamp string.
    let mut candidates: Vec<Vec<u8>> = Vec::new();
    scan_layer(
        layer.as_ref(),
        &context.layers,
        &BytesScanner::new(TIMESTAMP_PREFIX.to_vec()),
        Some(&sections),
        |offset| candidates.push(offset.to_le_bytes().to_vec()),
    )?;

    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    // Second pass: find pointers to those candidates.
    let mut results = Vec::new();
    let scanner = MultiStringScanner::new(candidates)?;
    let mut hits: Vec<u64> = Vec::new();
    scan_layer(
        layer.as_ref(),
        &context.layers,
        &scanner,
        Some(&sections),
        |offset| hits.push(offset),
    )?;

    for hit in hits {
        let entry = context.object_from_template(
            template.clone(),
            &layer_name,
            hit.wrapping_sub(timestamp_offset),
        );
        if let Some(parsed) = validate_entry(&entry) {
            results.push(parsed);
        }
    }

    results.sort_by_key(|entry| entry.time);
    Ok(results)
}

/// Confirm a candidate really is a history entry.
///
/// A genuine entry points at a command string and at a timestamp written as a
/// `#` followed by the epoch seconds, at least ten digits for any plausible
/// date, and nothing but digits.
fn validate_entry(entry: &crate::framework::objects::Object) -> Option<HistoryEntry> {
    let command = pointer_to_string(&entry.member("line").ok()?, MAX_COMMAND).ok()?;
    if command.is_empty() {
        return None;
    }

    let stamp = pointer_to_string(&entry.member("timestamp").ok()?, MAX_COMMAND).ok()?;
    if stamp.len() < 10 || !stamp.starts_with('#') {
        return None;
    }
    let time: i64 = stamp[1..].parse().ok()?;

    Some(HistoryEntry { time, command })
}
