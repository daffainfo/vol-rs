//! Scan a whole layer with YARA rules.
//!
//! Where the per-process variants scan one address space at a time, this scans
//! the layer as a whole, which finds matches in memory belonging to no live
//! process.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::common::yarascan::{
    requirements as yara_requirements, Rules, YaraScanner,
};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

pub struct YaraScan;

impl Plugin for YaraScan {
    fn name(&self) -> &'static str {
        "yarascan.YaraScan"
    }

    fn description(&self) -> &'static str {
        "Scans kernel memory using yara rules (string or file)."
    }

    fn requirements(&self) -> Vec<Requirement> {
        let mut requirements = vec![Requirement::new(
            "primary",
            "Memory layer for the kernel",
            crate::framework::plugins::RequirementKind::TranslationLayer,
        )
        .for_architectures(&["Intel32", "Intel64"])];
        requirements.extend(yara_requirements());
        requirements
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Any
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Offset", ColumnType::UInt),
            Column::string("Rule"),
            Column::string("Component"),
            Column::bytes("Value"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        // The kernel's own address space is what this searches. The physical
        // layer stands in only where no kernel was identified.
        let layer_name = config
            .get_string("primary")
            .or_else(|| config.get_string("physical_layer"))
            .unwrap_or_else(|| "base".to_string());

        let rules = Rules::from_config(config)?;
        let layer = context.layers.get(&layer_name)?;
        let scanner = YaraScanner::new(&rules);

        let mut hits: Vec<u64> = Vec::new();
        crate::framework::layers::scanners::scan_layer(
            layer.as_ref(),
            &context.layers,
            &scanner,
            None,
            |offset| hits.push(offset),
        )?;

        let mut grid = TreeGrid::new(self.columns());
        for offset in hits {
            // The match is looked at again where it was found, so the rule and
            // the bytes reported are the ones at that place.
            let Ok(data) = context.layers.read(&layer_name, offset, MAX_MATCH, true) else {
                continue;
            };
            for found in rules.scan(&data) {
                if found.offset != 0 {
                    continue;
                }
                grid.push(
                    0,
                    vec![
                        Value::hex(offset),
                        Value::string(found.rule),
                        Value::string(found.component),
                        crate::framework::plugins::layer_data(
                            &context,
                            &layer_name,
                            offset,
                            found.data.len() as u64,
                        )
                        .unwrap_or_else(Value::not_available),
                    ],
                )?;
                break;
            }
        }
        Ok(grid)
    }
}

/// How much is read back at a hit to recover the match itself.
const MAX_MATCH: usize = 0x1000;
