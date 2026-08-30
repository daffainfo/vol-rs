//! Show processes as a tree, each child nested under its parent.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::pslist::session_id_value;
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::conversion::wintime_value;
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::pyset::PythonSet;
use crate::framework::symbols::windows::{list_processes, Process};

pub struct PsTree;

/// One process, reduced to what the tree needs.
struct Node {
    pid: u64,
    ppid: u64,
    process: Process,
}

impl Plugin for PsTree {
    fn name(&self) -> &'static str {
        "windows.pstree.PsTree"
    }

    fn description(&self) -> &'static str {
        "Plugin for listing processes in a tree based on their parent process ID."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "physical",
                "Display physical offsets instead of virtual",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
            Requirement::pid_filter("Process ID to include (with ancestors and descendants, all other processes are excluded)"),
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
        let physical = physical_layer(config);
        let show_physical = config.get_bool("physical").unwrap_or(false);
        let filter = pid_filter(config);

        // Processes are held by identifier, so a repeat keeps the place of the
        // first and the details of the last.
        let mut nodes: Vec<Node> = Vec::new();
        let mut position: HashMap<u64, usize> = HashMap::new();
        for process in list_processes(&context, &kernel)? {
            let (Ok(pid), Ok(ppid)) = (process.pid(), process.parent_pid()) else {
                continue;
            };
            let node = Node { pid, ppid, process };
            match position.get(&pid) {
                Some(at) => nodes[*at] = node,
                None => {
                    position.insert(pid, nodes.len());
                    nodes.push(node);
                }
            }
        }

        // How deep each process sits, and who each one's children are. The
        // walk goes upwards from every process, so a parent learns of a child
        // the first time that child is reached from anywhere.
        let mut levels: Vec<(u64, u64)> = Vec::new();
        let mut children: HashMap<u64, PythonSet> = HashMap::new();
        let mut ancestors: HashSet<u64> = HashSet::new();

        for node in &nodes {
            let pid = node.pid;
            let wanted = pid_matches(&filter, pid);
            let mut seen: HashSet<u64> = HashSet::from([pid]);
            let mut level = 0;
            let mut current = Some(pid);

            while let Some(at) = current.and_then(|pid| position.get(&pid)) {
                let walked = &nodes[*at];
                if seen.contains(&walked.ppid) {
                    break;
                }
                // Only a process that survives the filter counts as an
                // ancestor worth showing.
                if wanted {
                    ancestors.insert(walked.pid);
                }
                children
                    .entry(walked.ppid)
                    .or_default()
                    .insert(walked.pid);
                seen.insert(walked.ppid);
                current = Some(walked.ppid);
                level += 1;
            }
            levels.push((pid, level));
        }

        let mut grid = TreeGrid::new(columns_for(show_physical));
        let mut reported: HashSet<u64> = HashSet::new();
        // A process at level one has no parent in the list, so the tree is
        // grown from each of those in turn.
        for (pid, level) in levels.clone() {
            if level == 1 {
                report(
                    &context,
                    &physical,
                    show_physical,
                    &nodes,
                    &position,
                    &children,
                    &levels,
                    &ancestors,
                    &filter,
                    pid,
                    false,
                    &mut reported,
                    &mut grid,
                )?;
            }
        }
        Ok(grid)
    }
}

/// The columns, named for the address space the offsets belong to.
fn columns_for(physical: bool) -> Vec<Column> {
    vec![
        Column::int("PID"),
        Column::int("PPID"),
        Column::string("ImageFileName"),
        Column::new(
            crate::framework::plugins::windows::offset_column_name(physical),
            crate::framework::renderers::ColumnType::UInt,
        ),
        Column::int("Threads"),
        Column::int("Handles"),
        Column::int("SessionId"),
        Column::bool("Wow64"),
        Column::datetime("CreateTime"),
        Column::datetime("ExitTime"),
        Column::string("Audit"),
        Column::string("Cmd"),
        Column::string("Path"),
    ]
}

/// Report a process and, beneath it, everything descended from it.
#[allow(clippy::too_many_arguments)]
fn report(
    context: &Arc<Context>,
    physical: &str,
    show_physical: bool,
    nodes: &[Node],
    position: &HashMap<u64, usize>,
    children: &HashMap<u64, PythonSet>,
    levels: &[(u64, u64)],
    ancestors: &HashSet<u64>,
    filter: &Option<Vec<u64>>,
    pid: u64,
    descendant: bool,
    reported: &mut HashSet<u64>,
    grid: &mut TreeGrid,
) -> Result<()> {
    // A process already reported is one arm of a cycle in the parentage.
    if !reported.insert(pid) {
        return Ok(());
    }
    // Outside the filtered tree unless it descends from something inside it.
    if !ancestors.contains(&pid) && !descendant {
        return Ok(());
    }
    let Some(at) = position.get(&pid) else {
        return Ok(());
    };
    let node = &nodes[*at];
    let depth = levels
        .iter()
        .find(|(candidate, _)| *candidate == pid)
        .map(|(_, level)| level.saturating_sub(1))
        .unwrap_or(0);

    emit(context, physical, show_physical, node, depth as usize, grid)?;

    let wanted = pid_matches(filter, pid);
    if let Some(child_pids) = children.get(&pid) {
        for child in child_pids.iter().collect::<Vec<_>>() {
            report(
                context,
                physical,
                show_physical,
                nodes,
                position,
                children,
                levels,
                ancestors,
                filter,
                child,
                descendant || wanted,
                reported,
                grid,
            )?;
        }
    }
    Ok(())
}

fn emit(
    context: &Arc<Context>,
    physical: &str,
    show_physical: bool,
    node: &Node,
    depth: usize,
    grid: &mut TreeGrid,
) -> Result<()> {
    let process = &node.process;

    // The command line and image path live in user space, so they need the
    // process's own address space. A process that has exited has none.
    let user_space = process.address_space(physical);
    let (cmd, path) = match &user_space {
        Ok(layer) => (
            process
                .command_line(layer)
                .map(Value::string)
                .unwrap_or_else(|_| Value::unreadable()),
            process
                .image_path(layer)
                .map(Value::string)
                .unwrap_or_else(|_| Value::unreadable()),
        ),
        Err(_) => (Value::unreadable(), Value::unreadable()),
    };

    grid.push(
        depth,
        vec![
            Value::int(node.pid as i64),
            Value::int(node.ppid as i64),
            or_unreadable(process.image_file_name(), Value::string),
            Value::hex(crate::framework::plugins::windows::process_offset(
                context,
                process,
                show_physical,
            )),
            or_unreadable(process.thread_count(), |value| Value::int(value as i64)),
            or_unreadable(process.handle_count(), |value| Value::int(value as i64)),
            session_id_value(process),
            Value::Bool(process.is_wow64()),
            process
                .create_time()
                .map(wintime_value)
                .unwrap_or_else(|_| Value::unreadable()),
            process
                .exit_time()
                .map(wintime_value)
                .unwrap_or_else(|_| Value::unreadable()),
            // An empty audit path means the field was never populated, which is
            // reported as unavailable rather than as an empty string.
            match process.audit_image_file_name() {
                Ok(name) if !name.is_empty() => Value::string(name),
                _ => Value::not_available(),
            },
            cmd,
            path,
        ],
    )?;

    Ok(())
}
