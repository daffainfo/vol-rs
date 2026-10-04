//! Useful before symbols are available: the banner names the exact kernel
//! build, which is what a symbol file has to match.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::automagic::symbol_finder::scan_for_banners;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, TreeGrid, Value};

/// Attempts to identify potential linux banners in an image
///
/// Identifies banners from a memory image by looking for likely linux and mac
/// banners.
pub struct Banners;

impl Plugin for Banners {
    fn name(&self) -> &'static str {
        "banners.Banners"
    }

    fn description(&self) -> &'static str {
        "Attempts to identify potential linux banners in an image"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::new(
            "primary",
            "Memory layer to scan",
            RequirementKind::TranslationLayer,
        )]
    }

    fn columns(&self) -> Vec<Column> {
        vec![Column::uint("Offset"), Column::string("Banner")]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Any
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let named = config
            .get_string("primary")
            .or_else(|| config.get_string("physical_layer"))
            .unwrap_or_else(|| "base".to_string());
        // A banner lives in memory rather than in an address space, so a
        // translation layer is stepped through to the one it rests on.
        let layer_name = match context.layers.get(&named) {
            Ok(layer)
                if layer.class_module() == "volatility3.framework.layers.intel" =>
                layer
                .dependencies()
                .into_iter()
                .next()
                .unwrap_or_else(|| named.clone()),
            _ => named,
        };

        let mut grid = TreeGrid::new(self.columns());
        for found in scan_for_banners(&context, &layer_name)? {
            grid.push(
                0,
                vec![Value::hex(found.offset), Value::string(found.banner)],
            )?;
        }
        // A Windows image carries no banner of that kind, but it does name the
        // database describing its kernel, which is reported the same way.
        for record in
            crate::framework::automagic::pdbscan::pdb_records(&context, &layer_name)?
        {
            grid.push(
                0,
                vec![
                    Value::hex(record.signature_offset),
                    Value::string(format!(
                        "{}|{}|{}",
                        record.pdb_name, record.guid, record.age
                    )),
                ],
            )?;
        }
        Ok(grid)
    }
}
