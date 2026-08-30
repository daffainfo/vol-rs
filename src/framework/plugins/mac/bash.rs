//! Recover bash command history from Mac process memory.
//!
//! Bash keeps its history the same way on Mac as on Linux, so the same
//! two-pass scan applies: find every `#` on the heap, then find the pointers to
//! those addresses, each of which is a history entry's timestamp.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context};
use crate::framework::layers::scanners::{scan_layer, BytesScanner, MultiStringScanner};
use crate::framework::objects::utility::pointer_to_string;
use crate::framework::objects::Object;
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::conversion::unixtime_value;
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::intermed::{create_table, SymbolFinder};
use crate::framework::symbols::mac::{list_processes, Proc};

pub struct Bash;

/// Bash writes each history timestamp as `#` followed by the Unix time.
const TIMESTAMP_PREFIX: &[u8] = b"#";

/// A command longer than this is not a real history entry.
const MAX_COMMAND: usize = 1024;

impl Plugin for Bash {
    fn name(&self) -> &'static str {
        "mac.bash.Bash"
    }

    fn description(&self) -> &'static str {
        "Recovers bash command history from memory."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel(), Requirement::pid_filter("Filter on specific process IDs")]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Process"),
            Column::datetime("CommandTime"),
            Column::string("Command"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);

        // Mac is 64-bit throughout, so only the 64-bit description applies.
        let finder = SymbolFinder::with_defaults();
        let bash_table = match finder.find("linux", "bash64") {
            Some(location) => {
                let name = context.symbol_space.free_table_name("bash");
                context.add_symbol_table(create_table(&name, location.load()?));
                name
            }
            None => {
                return Err(VolatilityError::Other(
                    "Could not find the bundled 'bash64' symbol file; \
                     bash history cannot be decoded without it"
                        .to_string(),
                ))
            }
        };

        let template = context.symbol_space.get_type(
            &crate::framework::symbols::join_name(&bash_table, "hist_entry"),
        )?;
        // The structure begins this far before its timestamp member.
        let timestamp_offset = context
            .symbol_space
            .find_member(&template, "timestamp")?
            .map(|(offset, _)| offset)
            .unwrap_or(8);

        let mut grid = TreeGrid::new(self.columns());

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }

            // Only a shell keeps bash history.
            let name = process.name().unwrap_or_default();
            if name != "bash" && name != "sh" && name != "dash" {
                continue;
            }

            for entry in recover(&context, &process, &template, timestamp_offset)? {
                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(name.clone()),
                        unixtime_value(entry.0),
                        Value::string(entry.1),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// Scan a process's heap for history entries.
///
/// Done in two passes, as the reference implementation does: first find every
/// `#` on the heap, since a history timestamp is stored as `#<epoch>`. Then
/// search the heap again for pointers to those addresses. Each such pointer is
/// a `hist_entry`'s `timestamp` member, which locates the structure itself.
fn recover(
    context: &Arc<Context>,
    process: &Proc,
    template: &Arc<crate::framework::objects::template::Template>,
    timestamp_offset: u64,
) -> Result<Vec<(i64, String)>> {
    let Some(layer_name) = process.process_layer()? else {
        return Ok(Vec::new());
    };
    let layer = context.layers.get(&layer_name)?;

    // Only the heap is searched, which is where the shell keeps its history.
    let sections: Vec<(u64, u64)> = process
        .vm_map_entries()?
        .into_iter()
        .filter(|entry| entry.special_path() == "[heap]")
        .filter_map(|entry| {
            let start = entry.start().ok()?;
            let end = entry.end().ok()?;
            Some((start, end.wrapping_sub(start)))
        })
        .collect();

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
    let scanner = MultiStringScanner::new(candidates)?;
    let mut hits: Vec<u64> = Vec::new();
    scan_layer(
        layer.as_ref(),
        &context.layers,
        &scanner,
        Some(&sections),
        |offset| hits.push(offset),
    )?;

    let mut results = Vec::new();
    for hit in hits {
        let entry = context.object_from_template(
            template.clone(),
            &layer_name,
            hit.wrapping_sub(timestamp_offset),
        );
        if let Some(parsed) = validate(&entry) {
            results.push(parsed);
        }
    }

    results.sort_by_key(|(time, _)| *time);
    Ok(results)
}

/// Confirm a candidate really is a history entry.
///
/// A genuine entry points at a command string and at a timestamp written as a
/// `#` followed by the epoch seconds, at least ten digits for any plausible
/// date, and nothing but digits.
fn validate(entry: &Object) -> Option<(i64, String)> {
    let command = pointer_to_string(&entry.member("line").ok()?, MAX_COMMAND).ok()?;
    if command.is_empty() {
        return None;
    }

    let stamp = pointer_to_string(&entry.member("timestamp").ok()?, MAX_COMMAND).ok()?;
    if stamp.len() < 10 || !stamp.starts_with('#') {
        return None;
    }
    let time: i64 = stamp[1..].parse().ok()?;

    Some((time, command))
}
