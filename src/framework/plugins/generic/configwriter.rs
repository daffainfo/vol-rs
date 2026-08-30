//! Report the configuration a run resolved to.
//!
//! Everything a run worked out for itself (which layers were stacked, where the
//! kernel is, which page table its address space was built on) is written out
//! in the form that would rebuild it, so an image identified once can be opened
//! again without repeating the search.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{ConfigValue, Configuration, Context};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, TreeGrid, Value};

pub struct ConfigWriter;

impl Plugin for ConfigWriter {
    fn name(&self) -> &'static str {
        "configwriter.ConfigWriter"
    }

    fn description(&self) -> &'static str {
        "Runs the automagics and both prints and outputs configuration in the output directory."
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
                "extra",
                "Outputs whole configuration tree",
                RequirementKind::Bool,
            )
            .with_default(ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Any
    }

    fn columns(&self) -> Vec<Column> {
        vec![Column::string("Key"), Column::string("Value")]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let mut entries: Vec<(String, String)> = Vec::new();

        // The plugin's own options come first, then the layer's, which is the
        // order a configuration written as nested dictionaries is walked in:
        // each level's own values, then each of its children in turn.
        entries.push((
            "extra".to_string(),
            json_bool(config.get_bool("extra").unwrap_or(false)),
        ));

        if let Some(primary) = config.get_string("primary") {
            describe_layer(&context, config, &primary, "primary", &mut entries);
        }

        // The same thing is written out as a file, so a later run can be told
        // to use it instead of working it out again.
        let document = format!(
            "{{\n{}\n}}",
            entries
                .iter()
                .map(|(key, value)| format!("  {}: {value}", json_string(key)))
                .collect::<Vec<String>>()
                .join(",\n")
        );
        let _ = crate::framework::plugins::write_extracted("config.json", document.as_bytes());

        let mut grid = TreeGrid::new(self.columns());
        for (key, value) in entries {
            grid.push(0, vec![Value::string(key), Value::string(value)])?;
        }
        Ok(grid)
    }
}

/// Describe one layer and everything beneath it.
///
/// A layer's own settings are listed first and its class last, then the layers
/// it was built from, each under its own name.
pub fn describe_layer(
    context: &Arc<Context>,
    config: &Configuration,
    layer_name: &str,
    prefix: &str,
    entries: &mut Vec<(String, String)>,
) {
    let Ok(layer) = context.layers.get(layer_name) else {
        return;
    };
    let mut children: Vec<(String, String)> = Vec::new();

    if let Some(intel) = layer
        .as_any()
        .downcast_ref::<crate::framework::layers::intel::IntelLayer>()
    {
        // An address space can be built over swap, and says so even when none
        // was supplied.
        entries.push((format!("{prefix}.swap_layers"), "true".to_string()));
        entries.push((
            format!("{prefix}.page_map_offset"),
            intel.page_map_offset().to_string(),
        ));
        if let Some(offset) = context.config.get_int("automagic.kernel_virtual_offset") {
            entries.push((
                format!("{prefix}.kernel_virtual_offset"),
                offset.to_string(),
            ));
        }
        if let Some(banner) = context.config.get_string("automagic.kernel_banner") {
            entries.push((format!("{prefix}.kernel_banner"), json_string(&banner)));
        }
        entries.push((
            format!("{prefix}.class"),
            json_string(&layer.class_path()),
        ));
        children.push((
            "memory_layer".to_string(),
            intel.base_layer_name().to_string(),
        ));
    } else if let Some(file) = layer
        .as_any()
        .downcast_ref::<crate::framework::layers::physical::FileLayer>()
    {
        entries.push((
            format!("{prefix}.location"),
            json_string(&format!("file://{}", file.location().display())),
        ));
        entries.push((
            format!("{prefix}.class"),
            json_string(&layer.class_path()),
        ));
    } else {
        entries.push((
            format!("{prefix}.class"),
            json_string(&layer.class_path()),
        ));
        if let Some(base) = layer.dependencies().first() {
            children.push(("base_layer".to_string(), base.clone()));
        }
    }

    for (name, layer_name) in children {
        describe_layer(context, config, &layer_name, &format!("{prefix}.{name}"), entries);
    }

    // The list of swap layers is a level of its own, and is written after the
    // layers the address space was actually built from.
    if layer
        .as_any()
        .downcast_ref::<crate::framework::layers::intel::IntelLayer>()
        .is_some()
    {
        entries.push((
            format!("{prefix}.swap_layers.number_of_elements"),
            "0".to_string(),
        ));
    }
}

/// The configuration each plugin ran with, as a JSON document.
///
/// Every plugin is recorded under its own name, with the options it was given
/// and the layers and symbols it was built on.
pub fn record_configuration(
    context: &Arc<Context>,
    config: &Configuration,
    ran: &[(String, std::sync::Arc<dyn Plugin>)],
) -> String {
    use crate::framework::plugins::RequirementKind;

    let mut entries: Vec<(String, String)> = Vec::new();
    for (class, plugin) in ran {
        for requirement in plugin.requirements() {
            // A single plugin's own configuration carries no prefix.
            let key = if class.is_empty() {
                requirement.name.clone()
            } else {
                format!("{class}.{}", requirement.name)
            };
            match &requirement.kind {
                RequirementKind::Kernel => {
                    // A module is described by the layer and symbols it was
                    // built from, and where the kernel sits in them.
                    entries.push((
                        format!("{key}.class"),
                        json_string("volatility3.framework.contexts.Module"),
                    ));
                    if let Some(layer) = config.get_string("primary") {
                        describe_layer(
                            context,
                            config,
                            &layer,
                            &format!("{key}.layer_name"),
                            &mut entries,
                        );
                    }
                    if let Some(offset) =
                        context.config.get_int("automagic.kernel_virtual_offset")
                    {
                        entries.push((format!("{key}.offset"), offset.to_string()));
                    }
                    if let Some(kernel) = config.get_string("kernel") {
                        if let Ok(module) = context.module(&kernel) {
                            entries.push((
                                format!("{key}.symbol_table_name.class"),
                                json_string(symbol_table_class(config)),
                            ));
                            if let Some(url) = context
                                .symbol_space
                                .table(&module.symbol_table_name)
                                .ok()
                                .and_then(|table| table.source())
                            {
                                entries.push((
                                    format!("{key}.symbol_table_name.isf_url"),
                                    json_string(&url),
                                ));
                            }
                            entries.push((
                                format!("{key}.symbol_table_name.symbol_mask"),
                                context
                                    .layers
                                    .address_mask(&module.layer_name)
                                    .to_string(),
                            ));
                        }
                    }
                }
                RequirementKind::TranslationLayer => {
                    // A layer requirement is recorded as the layer it was
                    // satisfied with, described in full.
                    if let Some(layer) = config.get_string("primary") {
                        describe_layer(context, config, &layer, &key, &mut entries);
                    }
                }
                RequirementKind::Bool => entries.push((
                    key,
                    json_bool(
                        config
                            .get_bool(&requirement.name)
                            .unwrap_or(matches!(
                                requirement.default,
                                Some(crate::framework::context::ConfigValue::Bool(true))
                            )),
                    ),
                )),
                RequirementKind::List(_) => {
                    let values = config
                        .get(&requirement.name)
                        .and_then(|value| value.as_list().map(<[_]>::to_vec))
                        .unwrap_or_default();
                    entries.push((
                        key,
                        format!(
                            "[{}]",
                            values
                                .iter()
                                .map(|entry| match entry {
                                    crate::framework::context::ConfigValue::Str(text) =>
                                        json_string(text.as_str()),
                                    crate::framework::context::ConfigValue::Int(number) =>
                                        number.to_string(),
                                    crate::framework::context::ConfigValue::Bool(value) =>
                                        json_bool(*value),
                                    _ => "null".to_string(),
                                })
                                .collect::<Vec<String>>()
                                .join(", ")
                        ),
                    ));
                }
                RequirementKind::Int => {
                    if let Some(number) = config.get_int(&requirement.name) {
                        entries.push((key, number.to_string()));
                    }
                }
                _ => {
                    if let Some(text) = config.get_string(&requirement.name) {
                        entries.push((key, json_string(&text)));
                    }
                }
            }
        }
    }

    entries.sort_by(|left, right| left.0.cmp(&right.0));
    format!(
        "{{\n{}\n}}",
        entries
            .iter()
            .map(|(key, value)| format!("  {}: {value}", json_string(key)))
            .collect::<Vec<String>>()
            .join(",\n")
    )
}

/// The class that reads the kernel's symbols, which differs per system.
fn symbol_table_class(config: &Configuration) -> &'static str {
    match config.get_string("operating_system").as_deref() {
        Some("windows") => "volatility3.framework.symbols.windows.WindowsKernelIntermedSymbols",
        Some("mac") => "volatility3.framework.symbols.mac.MacKernelIntermedSymbols",
        _ => "volatility3.framework.symbols.linux.LinuxKernelIntermedSymbols",
    }
}

/// A boolean as a configuration file spells it.
pub fn json_bool(value: bool) -> String {
    if value { "true" } else { "false" }.to_string()
}

/// A string as a configuration file spells it: quoted, with the characters a
/// document cannot carry written as escapes.
pub fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if (character as u32) < 0x20 || character == '\u{7F}' => {
                out.push_str(&format!("\\u{:04x}", character as u32))
            }
            character => out.push(character),
        }
    }
    out.push('"');
    out
}
