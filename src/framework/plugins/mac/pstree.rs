//! Show Mac processes as a tree.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::mac::kernel_module;
use crate::framework::pyset::PythonSet;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::mac::{list_processes, Proc};

pub struct PsTree;

impl Plugin for PsTree {
    fn name(&self) -> &'static str {
        "mac.pstree.PsTree"
    }

    fn description(&self) -> &'static str {
        "Plugin for listing processes in a tree based on their parent process ID."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![Column::int("PID"), Column::int("PPID"), Column::string("COMM")]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;

        // Processes in the order the list walk found them, with a later entry
        // for a process id replacing an earlier one.
        let mut order: Vec<u64> = Vec::new();
        let mut processes: HashMap<u64, Proc> = HashMap::new();
        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if processes.insert(pid, process).is_none() {
                order.push(pid);
            }

        }

        // How deep each process sits, counted by walking up to a parent that
        // is missing, absent or the process itself. Walking it also records
        // each process against its parent.
        let mut levels: Vec<(u64, usize)> = Vec::new();
        let mut children: HashMap<u64, PythonSet> = HashMap::new();
        let total = processes.len();
        for pid in &order {
            let mut level = 0;
            let mut current = Some(*pid);
            while let Some(here) = current {
                // No process can sit deeper than there are processes, so a
                // chain longer than that has looped back on itself.
                if level > total {
                    break;
                }
                let Some(process) = processes.get(&here) else {
                    break;
                };
                let parent = process.ppid().unwrap_or(0);
                // The walk stops at the process it started from, which is the
                // only value the reference implementation remembers.
                if process.object.offset() == 0 || parent == 0 || parent == *pid {
                    break;
                }
                children.entry(parent).or_default().insert(here);
                current = Some(parent);
                level += 1;
                if processes.get(&parent).is_none() {
                    break;
                }
            }
            levels.push((*pid, level));
        }

        let depth_of: HashMap<u64, usize> = levels.iter().copied().collect();
        let mut grid = TreeGrid::new(self.columns());
        // A process one step below a parent that is not itself listed is where
        // the reference implementation starts, and it prints that process at
        // the top level.
        for (pid, level) in &levels {
            if *level == 1 {
                emit(&processes, &children, &depth_of, *pid, &mut grid)?;
            }
        }
        Ok(grid)
    }

}

fn emit(
    processes: &HashMap<u64, Proc>,
    children: &HashMap<u64, PythonSet>,
    depth_of: &HashMap<u64, usize>,
    pid: u64,
    grid: &mut TreeGrid,
) -> Result<()> {
    let Some(process) = processes.get(&pid) else {
        return Ok(());
    };
    // Depth is counted from the level below the root, so a root prints flat.
    let depth = depth_of.get(&pid).copied().unwrap_or(1).saturating_sub(1);
    grid.push(
        depth,
        vec![
            Value::int(pid as i64),
            or_unreadable(process.ppid(), |ppid| Value::int(ppid as i64)),
            or_unreadable(process.name(), Value::string),
        ],
    )?;

    if let Some(descendants) = children.get(&pid) {
        // The children were collected in a set, so they come back in the order
        // that set hands them over.
        for child in descendants.iter() {
            emit(processes, children, depth_of, child, grid)?;
        }
    }
    Ok(())
}
