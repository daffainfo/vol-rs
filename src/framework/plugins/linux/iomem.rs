//! Report the kernel's physical address map.
//!
//! `iomem` describes which device or subsystem owns each region of physical
//! address space, which is how an unexpected claim on memory becomes visible.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashSet;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::pointer_to_string;
use crate::framework::objects::Object;
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

pub struct IoMem;

/// Guard against a corrupt tree.
const MAX_RESOURCES: usize = 100_000;

impl Plugin for IoMem {
    fn name(&self) -> &'static str {
        "linux.iomem.IOMem"
    }

    fn description(&self) -> &'static str {
        "Generates an output similar to /proc/iomem on a running system."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Name"),
            Column::new("Start", ColumnType::UInt),
            Column::new("End", ColumnType::UInt),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;

        // The resource tree is rooted at iomem_resource. Children nest inside
        // their parent's range, which the output shows by indentation.
        let root = context.object_from_symbol(&kernel, "iomem_resource", Some("resource"))?;

        let mut grid = TreeGrid::new(self.columns());
        let mut count = 0usize;
        emit(&root, 0, &mut grid, &mut count)?;
        Ok(grid)
    }
}

/// Emit a resource and everything nested beneath it.
fn emit(resource: &Object, depth: usize, grid: &mut TreeGrid, count: &mut usize) -> Result<()> {
    if *count >= MAX_RESOURCES || depth > 16 {
        return Ok(());
    }
    *count += 1;

    let name = resource
        .member("name")
        .and_then(|name| pointer_to_string(&name, 128))
        .unwrap_or_default();

    grid.push(
        depth,
        vec![
            Value::string(name),
            resource
                .member("start")
                .and_then(|start| start.as_u64())
                .map(Value::hex)
                .unwrap_or_else(|_| Value::unreadable()),
            resource
                .member("end")
                .and_then(|end| end.as_u64())
                .map(Value::hex)
                .unwrap_or_else(|_| Value::unreadable()),
        ],
    )?;

    // Descend into the first child, then follow its siblings.
    let Ok(child_address) = resource.member("child").and_then(|child| child.pointer_value())
    else {
        return Ok(());
    };
    if child_address == 0 {
        return Ok(());
    }

    let mut seen: HashSet<u64> = HashSet::new();
    let mut current = child_address;
    while current != 0 && *count < MAX_RESOURCES {
        if !seen.insert(current) {
            break;
        }
        let child = resource.at_offset(current);
        emit(&child, depth + 1, grid, count)?;
        current = child
            .member("sibling")
            .and_then(|sibling| sibling.pointer_value())
            .unwrap_or(0);
    }
    Ok(())
}
