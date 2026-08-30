//! Scan physical memory for pool allocations of every known tag.
//!
//! Where the individual `*scan` plugins each look for one kind of object, this
//! reports every tagged allocation it recognises, which is useful for surveying
//! what a capture contains before deciding what to look at closely.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::objects::utility::unicode_string;
use crate::framework::symbols::windows::poolscanner::{builtin_constraints, generate_pool_scan};

pub struct PoolScanner;

impl Plugin for PoolScanner {
    fn name(&self) -> &'static str {
        "windows.poolscanner.PoolScanner"
    }

    fn description(&self) -> &'static str {
        "A generic pool scanner plugin."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Tag"),
            Column::new("Offset", ColumnType::UInt),
            Column::string("Layer"),
            Column::string("Name"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let constraints = builtin_constraints(&[]);
        let mut grid = TreeGrid::new(self.columns());

        for hit in generate_pool_scan(&context, &kernel, &constraints)? {
            // A name for the object, where its kind has one worth showing.
            let name = match hit.constraint.object_type {
                Some("Process") => hit
                    .object
                    .member("ImageFileName")
                    .and_then(|field| field.as_string())
                    .ok(),
                Some("File") => hit
                    .object
                    .member("FileName")
                    .ok()
                    .and_then(|field| unicode_string(&field).ok()),
                // Only those two kinds carry a name worth showing here.
                _ => None,
            };

            grid.push(
                0,
                vec![
                    Value::string(kernel.qualified(&hit.constraint.type_name)),
                    Value::hex(hit.header.offset()),
                    Value::string(hit.header.layer_name().to_string()),
                    match name {
                        Some(name) => Value::string(name),
                        None => Value::not_applicable(),
                    },
                ],
            )?;
        }
        Ok(grid)
    }
}
