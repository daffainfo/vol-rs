//! Report version banners found in an image.
//!
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
            "The layer to scan",
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
        let layer_name = config
            .get_string("primary")
            .or_else(|| config.get_string("physical_layer"))
            .unwrap_or_else(|| "base".to_string());

        let mut grid = TreeGrid::new(self.columns());
        for found in scan_for_banners(&context, &layer_name)? {
            grid.push(
                0,
                vec![Value::hex(found.offset), Value::string(found.banner)],
            )?;
        }
        Ok(grid)
    }
}
