//! Write a layer's contents out to a file.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::io::Write;
use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::{Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, TreeGrid, Value};

pub struct LayerWriter;

/// Copy in blocks rather than reading a whole image into memory.
const DEFAULT_BLOCK_SIZE: usize = 0x500000;

impl Plugin for LayerWriter {
    fn name(&self) -> &'static str {
        "layerwriter.LayerWriter"
    }

    fn description(&self) -> &'static str {
        "Runs the automagics and writes out the primary layer produced by the stacker."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new(
                "primary",
                "Memory layer for the kernel",
                RequirementKind::TranslationLayer,
            ),
            Requirement::new(
                "block_size",
                "Size of blocks to copy over",
                RequirementKind::Int,
            )
            .with_default(crate::framework::context::ConfigValue::Int(
                DEFAULT_BLOCK_SIZE as i64,
            )),
            Requirement::new("list", "List available layers", RequirementKind::Bool)
                .with_default(crate::framework::context::ConfigValue::Bool(false)),
            Requirement::new(
                "layers",
                "Names of layers to write (defaults to the highest non-mapped layer)",
                RequirementKind::List(Box::new(RequirementKind::String)),
            ),
        ]
    }

    fn needs_kernel(&self) -> bool {
        // The layer this writes out is the one the kernel's paging describes,
        // so the whole stack has to be built before it can be named.
        true
    }

    fn columns(&self) -> Vec<Column> {
        // The listing and the writing report different things entirely.
        vec![Column::string("Status")]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        if config.get_bool("list").unwrap_or(false) {
            let mut grid = TreeGrid::new(vec![
                Column::string("Layer name"),
                Column::string("Layer type"),
            ]);
            for name in context.layers.names() {
                let Ok(layer) = context.layers.get(&name) else {
                    continue;
                };
                grid.push(
                    0,
                    vec![Value::string(name), Value::string(layer.kind())],
                )?;
            }
            return Ok(grid);
        }

        let block_size = config
            .get_int("block_size")
            .map(|value| value as usize)
            .unwrap_or(DEFAULT_BLOCK_SIZE);

        // With no layer named, the most recently added one that is not a
        // mapping of another is written.
        let requested: Vec<String> = config
            .get("layers")
            .and_then(|value| {
                value.as_list().map(|list| {
                    list.iter()
                        .filter_map(|entry| entry.as_str().map(str::to_string))
                        .collect::<Vec<String>>()
                })
            })
            .filter(|names| !names.is_empty())
            .unwrap_or_else(|| {
                context
                    .layers
                    .names()
                    .into_iter()
                    // A layer that maps another is a view of it, not a thing
                    // to write out.
                    .rfind(|name| {
                        context
                            .layers
                            .get(name)
                            .map(|layer| !layer.metadata().contains_key("mapped"))
                            .unwrap_or(false)
                    })
                    .into_iter()
                    .collect()
            });

        let mut grid = TreeGrid::new(self.columns());
        for name in requested {
            let Ok(layer) = context.layers.get(&name) else {
                grid.push(0, vec![Value::string(format!("Layer Name {name} does not exist"))])?;
                continue;
            };

            let output = crate::framework::plugins::free_extracted_name(&format!("{name}.raw"));
            match write_layer(&context, layer.as_ref(), &output, block_size) {
                Ok(()) => grid.push(
                    0,
                    vec![Value::string(format!("Layer has been written to {output}"))],
                )?,
                Err(error) => grid.push(
                    0,
                    vec![Value::string(format!(
                        "Layer cannot be written to {output}: {error}"
                    ))],
                )?,
            }
        }
        Ok(grid)
    }
}

/// Copy a whole layer out, block by block.
fn write_layer(
    context: &Arc<Context>,
    layer: &dyn crate::framework::layers::DataLayer,
    output: &str,
    block_size: usize,
) -> Result<()> {
    let mut file = std::fs::File::create(output)
        .map_err(|error| VolatilityError::Io(format!("{error}")))?;
    let end = layer.maximum_address();
    let mut offset = 0u64;
    while offset < end {
        let length = block_size.min((end + 1 - offset) as usize);
        // Holes in the address space are written as zeros rather than ending
        // the copy.
        let data = layer.read(&context.layers, offset, length, true)?;
        file.write_all(&data)?;
        offset += length as u64;
    }
    Ok(())
}
