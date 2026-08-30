//! Report the framework's own version and capabilities.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::{Plugin, Requirement};
use crate::framework::renderers::{Column, TreeGrid, Value};

pub struct FrameworkInfo;

impl Plugin for FrameworkInfo {
    fn name(&self) -> &'static str {
        "frameworkinfo.FrameworkInfo"
    }

    fn description(&self) -> &'static str {
        "Plugin to list the various modular components of Volatility"
    }

    fn requirements(&self) -> Vec<Requirement> {
        Vec::new()
    }

    fn columns(&self) -> Vec<Column> {
        vec![Column::string("Data")]
    }

    fn run(&self, _context: Arc<Context>, _config: &Configuration) -> Result<TreeGrid> {
        let mut grid = TreeGrid::new(self.columns());

        // Each category names the parts this build is made of. The categories
        // are the ones the reference implementation lists. What falls under
        // them describes this port, since that is what the question is about.
        let categories: [(&str, Vec<String>); 7] = [
            ("Automagic", automagics()),
            ("Requirement", requirement_kinds()),
            ("Layer", layer_kinds()),
            ("LayerStacker", stackers()),
            ("Object", object_kinds()),
            ("Plugin", plugin_names()),
            ("Renderer", renderers()),
        ];

        for (category, members) in categories {
            grid.push(0, vec![Value::string(category)])?;
            for member in members {
                grid.push(1, vec![Value::string(member)])?;
            }
        }
        Ok(grid)
    }
}

/// The steps that work out what an image is before a plugin runs.
fn automagics() -> Vec<String> {
    ["LayerStacker", "SymbolCache", "WindowsDetector", "LinuxDetector", "MacDetector"]
        .iter()
        .map(|name| name.to_string())
        .collect()
}

/// The kinds of option a plugin can declare.
fn requirement_kinds() -> Vec<String> {
    [
        "IntRequirement",
        "StringRequirement",
        "BooleanRequirement",
        "BytesRequirement",
        "ListRequirement",
        "ChoiceRequirement",
        "ModuleRequirement",
        "TranslationLayerRequirement",
    ]
    .iter()
    .map(|name| name.to_string())
    .collect()
}

/// The layer implementations this build carries.
fn layer_kinds() -> Vec<String> {
    [
        "FileLayer",
        "BufferDataLayer",
        "SegmentedLayer",
        "Intel",
        "IntelPAE",
        "Intel32e",
        "WindowsIntel",
        "WindowsIntelPAE",
        "WindowsIntel32e",
        "RegistryHive",
    ]
    .iter()
    .map(|name| name.to_string())
    .collect()
}

/// The image formats that can be recognised and stacked on.
fn stackers() -> Vec<String> {
    [
        "ElfStacker",
        "LimeStacker",
        "AVMLStacker",
        "QemuStacker",
        "VmwareStacker",
        "WindowsCrashDumpStacker",
    ]
    .iter()
    .map(|name| name.to_string())
    .collect()
}

/// The shapes a value read out of memory can take.
fn object_kinds() -> Vec<String> {
    [
        "Integer",
        "Boolean",
        "Float",
        "Char",
        "Bytes",
        "String",
        "Pointer",
        "Enumeration",
        "Array",
        "StructType",
        "Union",
        "BitField",
    ]
    .iter()
    .map(|name| name.to_string())
    .collect()
}

/// Everything that can be run against an image.
fn plugin_names() -> Vec<String> {
    let registry = crate::framework::plugins::PluginRegistry::new();
    let mut names: Vec<String> = registry
        .all()
        .iter()
        .map(|plugin| plugin.name().to_string())
        .collect();
    names.sort();
    names
}

/// The ways a table can be written out.
fn renderers() -> Vec<String> {
    ["QuickTextRenderer", "PrettyTextRenderer", "CSVRenderer", "JsonRenderer", "NestedJsonRenderer"]
        .iter()
        .map(|name| name.to_string())
        .collect()
}
