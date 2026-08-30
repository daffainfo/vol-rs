//! Search a layer for a regular expression.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{ConfigValue, Configuration, Context};
use crate::framework::layers::scanners::{scan_layer, RegExScanner};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

pub struct RegExScan;

impl Plugin for RegExScan {
    fn name(&self) -> &'static str {
        "regexscan.RegExScan"
    }

    fn description(&self) -> &'static str {
        "Scans kernel memory using RegEx patterns."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new(
                "primary",
                "Memory layer for the kernel",
                RequirementKind::TranslationLayer,
            )
            .for_architectures(&["Intel32", "Intel64"]),
            Requirement::new(
                "pattern",
                "RegEx pattern",
                RequirementKind::String,
            )
            .required(),
            Requirement::new(
                "maxsize",
                "Maximum size in bytes for displayed context",
                RequirementKind::Int,
            )
            .with_default(ConfigValue::Int(128)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Any
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Offset", ColumnType::UInt),
            Column::string("Text"),
            Column::bytes("Hex"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        // The plugin works on whichever layer automagic settled on, falling
        // back to the physical one when no kernel layer was built.
        let layer_name = config
            .get_string("primary")
            .or_else(|| config.get_string("physical_layer"))
            .unwrap_or_else(|| "base".to_string());

        let pattern = config
            .get_string("pattern")
            .ok_or_else(|| VolatilityError::Other("A --pattern is required".to_string()))?;
        let context_bytes = config.get_int("maxsize").unwrap_or(128).max(1) as usize;

        let scanner = RegExScanner::new(&pattern)?;
        let layer = context.layers.get(&layer_name)?;

        let mut offsets: Vec<u64> = Vec::new();
        scan_layer(layer.as_ref(), &context.layers, &scanner, None, |offset| {
            offsets.push(offset)
        })?;

        let mut grid = TreeGrid::new(self.columns());
        for offset in offsets {
            let data = layer
                .read(&context.layers, offset, context_bytes, true)
                .unwrap_or_default();

            // The pattern is applied a second time to what was read, so the
            // match alone is reported. A match too long to fit in the context
            // leaves the whole of it standing instead.
            let matched = scanner.first_match(&data).unwrap_or(data);
            let text = String::from_utf8_lossy(&matched).to_string();

            grid.push(
                0,
                vec![
                    Value::hex(offset),
                    Value::string(text),
                    Value::Bytes(matched),
                ],
            )?;
        }
        Ok(grid)
    }
}
