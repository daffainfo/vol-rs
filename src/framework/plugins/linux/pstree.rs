//! Show Linux tasks as a tree.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{ConfigValue, Configuration, Context};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{
    pid_filter, pid_matches, OperatingSystem, Plugin, Requirement, RequirementKind,
};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::linux::{list_tasks, Task};

pub struct PsTree;

struct Node {
    pid: u64,
    tid: u64,
    ppid: u64,
    task: Task,
}

impl Plugin for PsTree {
    fn name(&self) -> &'static str {
        "linux.pstree.PsTree"
    }

    fn description(&self) -> &'static str {
        "Plugin for listing processes in a tree based on their parent process ID."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::pid_filter("Filter on specific process IDs"),
            Requirement::new(
                "threads",
                "Include user threads",
                RequirementKind::Bool,
            )
            .with_default(ConfigValue::Bool(false)),
            Requirement::new(
                "decorate_comm",
                "Show `user threads` comm in curly brackets, and `kernel threads` comm in square brackets",
                RequirementKind::Bool,
            )
            .with_default(ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("OFFSET (V)", ColumnType::UInt),
            Column::int("PID"),
            Column::int("TID"),
            Column::int("PPID"),
            Column::string("COMM"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let include_threads = config.get_bool("threads").unwrap_or(false);
        let decorate = config.get_bool("decorate_comm").unwrap_or(false);
        let filter = pid_filter(config);

        // Tasks are held by thread id, since that is what a parent names: a
        // thread's parent is the process it belongs to, and a process's parent
        // is the process that started it.
        let mut order: Vec<u64> = Vec::new();
        let mut tasks: HashMap<u64, Node> = HashMap::new();
        for task in list_tasks(&context, &kernel, include_threads)? {
            let (Ok(pid), Ok(tid), Ok(ppid)) = (task.pid(), task.tid(), task.ppid()) else {
                continue;
            };
            if !pid_matches(&filter, pid) {
                continue;
            }
            if tasks.insert(tid, Node { pid, tid, ppid, task }).is_none() {
                order.push(tid);
            }
        }

        // How deep each task sits, found by climbing to the top and counting.
        // The climb also records who each task's children are.
        let mut levels: HashMap<u64, usize> = HashMap::new();
        let mut children: HashMap<u64, BTreeSet<u64>> = HashMap::new();
        for start in &order {
            let mut seen_parents: HashSet<u64> = HashSet::new();
            let mut seen_offsets: HashSet<u64> = HashSet::new();
            let mut level = 0usize;
            let mut current = Some(*start);

            while let Some(tid) = current {
                let Some(node) = tasks.get(&tid) else { break };
                // The idle task is the list's head, not a process.
                if node.tid == 0 {
                    break;
                }
                let parent = if node.tid == node.pid {
                    node.ppid
                } else {
                    node.pid
                };
                if seen_parents.contains(&parent) || seen_offsets.contains(&node.task.offset()) {
                    break;
                }
                // Only the first two processes may be children of the idle
                // task. Anything else claiming that is smeared.
                if parent == 0 && node.tid > 2 {
                    log::debug!(
                        "Smeared process with parent PID of 0 and PID greater than 2 ({}) is being skipped.",
                        node.tid
                    );
                    break;
                }
                seen_parents.insert(parent);
                seen_offsets.insert(node.task.offset());
                children.entry(parent).or_default().insert(node.tid);
                current = Some(parent);
                level += 1;
            }
            levels.insert(*start, level);
        }

        // A task reachable from two roots would be printed twice, so a row
        // that has already been printed ends the branch it appeared in.
        let mut grid = TreeGrid::new(self.columns());
        let mut seen: HashSet<String> = HashSet::new();
        for tid in &order {
            if levels.get(tid) != Some(&1) {
                continue;
            }
            let mut rows = Vec::new();
            collect(&tasks, &levels, &children, *tid, decorate, &mut rows);
            for (depth, row) in rows {
                if !seen.insert(format!("{row:?}")) {
                    break;
                }
                grid.push(depth, row)?;
            }
        }
        Ok(grid)
    }
}

/// Gather a task and everything under it, deepest last.
fn collect(
    tasks: &HashMap<u64, Node>,
    levels: &HashMap<u64, usize>,
    children: &HashMap<u64, BTreeSet<u64>>,
    tid: u64,
    decorate: bool,
    rows: &mut Vec<(usize, Vec<Value>)>,
) {
    let Some(node) = tasks.get(&tid) else { return };
    let depth = levels.get(&tid).copied().unwrap_or(1).saturating_sub(1);
    rows.push((
        depth,
        vec![
            Value::hex(node.task.offset()),
            Value::int(node.pid as i64),
            Value::int(node.tid as i64),
            Value::int(node.ppid as i64),
            crate::framework::plugins::linux::pslist::decorated_comm(&node.task, decorate),
        ],
    ));

    let mut seen: HashSet<u64> = HashSet::new();
    for child in children.get(&tid).into_iter().flatten() {
        if !seen.insert(*child) {
            break;
        }
        collect(tasks, levels, children, *child, decorate, rows);
    }
}

