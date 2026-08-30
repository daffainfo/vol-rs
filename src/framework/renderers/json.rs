//! JSON rendering, both as a nested tree and as a flat list of records.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::io::Write;

use serde_json::{json, Map, Value as JsonValue};

use crate::error::Result;
use crate::framework::renderers::{Renderer, TreeGrid, Value};

/// Convert a cell into JSON, preserving its type rather than stringifying it.
fn to_json(value: &Value) -> JsonValue {
    match value {
        Value::Absent(_) => JsonValue::Null,
        Value::Bool(inner) => json!(inner),
        Value::Int(inner, _) => json!(inner),
        Value::UInt(inner, _) => json!(inner),
        Value::Float(inner) => json!(inner),
        Value::Str(inner) => json!(inner),
        Value::Bytes(inner)
        | Value::MultiTypeData(inner)
        | Value::HexDump(inner)
        | Value::LayerDump { bytes: inner, .. }
        | Value::WideText(inner)
        | Value::MultiString(inner)
        | Value::HexPairs(inner) => {
            json!(hex::encode(inner))
        }
        // Python writes a timestamp with six decimal places, or with none at
        // all when it falls on a whole second.
        Value::DateTime(inner) => {
            use chrono::{SecondsFormat, Timelike};
            let precision = if inner.nanosecond() % 1_000_000_000 == 0 {
                SecondsFormat::Secs
            } else {
                SecondsFormat::Micros
            };
            json!(inner.to_rfc3339_opts(precision, false))
        }
        // A timestamp with no zone is written the way Python's isoformat()
        // writes one, which is without an offset.
        Value::NaiveDateTime(inner) => {
            use chrono::Timelike;
            let text = if inner.nanosecond() % 1_000_000_000 == 0 {
                inner.format("%Y-%m-%dT%H:%M:%S").to_string()
            } else {
                inner.format("%Y-%m-%dT%H:%M:%S%.6f").to_string()
            };
            json!(text)
        }
        Value::Disassembly { data, offset, .. } => {
            json!({"offset": offset, "data": hex::encode(data)})
        }
    }
}

/// Emits the grid as a tree of objects, each with its children inside it.
///
/// The keys of every object are sorted, and a value that is absent is written
/// as null.
#[derive(Default)]
pub struct JsonRenderer {
    /// Whether to write one object per line rather than one indented document.
    pub lines: bool,
    pub options: crate::framework::renderers::filter::RenderOptions,
}

impl JsonRenderer {
    /// Build the tree of records the grid describes.
    fn records(&self, grid: &TreeGrid) -> Vec<JsonValue> {
        let ignored = self.options.ignored(grid);
        let mut roots: Vec<JsonValue> = Vec::new();
        // The object most recently seen at each depth, so a row can be added to
        // the one above it.
        let mut path: Vec<usize> = Vec::new();
        let mut nodes: Vec<JsonValue> = Vec::new();
        let mut parents: Vec<Option<usize>> = Vec::new();

        for row in grid.rows() {
            let rendered: Vec<String> =
                row.values.iter().map(|value| value.to_string()).collect();
            if self.options.filtered(&rendered) {
                continue;
            }

            let mut object = Map::new();
            for (index, (column, value)) in
                grid.columns().iter().zip(row.values.iter()).enumerate()
            {
                if ignored.contains(&index) {
                    continue;
                }
                object.insert(column.name.clone(), to_json(value));
            }
            object.insert("__children".to_string(), json!([]));

            // A row belongs to the last row shallower than it.
            while path.len() > row.depth {
                path.pop();
            }
            let parent = path.last().copied();
            nodes.push(JsonValue::Object(object));
            parents.push(parent);
            path.push(nodes.len() - 1);
        }

        // A row always follows its parent, so working backwards means a node
        // is complete before it is placed inside the one above it.
        for index in (0..nodes.len()).rev() {
            let Some(parent) = parents[index] else {
                continue;
            };
            let node = nodes[index].take();
            if let Some(children) = nodes[parent]
                .get_mut("__children")
                .and_then(|children| children.as_array_mut())
            {
                children.insert(0, node);
            }
        }
        for (index, node) in nodes.into_iter().enumerate() {
            if parents[index].is_none() {
                roots.push(node);
            }
        }
        roots
    }
}

impl Renderer for JsonRenderer {
    fn render(&self, grid: &TreeGrid, output: &mut dyn Write) -> Result<()> {
        use crate::framework::renderers::Truncation;

        writeln!(output)?;
        // A plugin that stopped part way through leaves this renderer with
        // nothing to write: it holds every row until the end, and the end never
        // came. Where the failure was reported, two blank lines mark it.
        match grid.truncation() {
            Truncation::None => {}
            Truncation::Abrupt => return Ok(()),
            Truncation::Reported => {
                write!(output, "\n\n")?;
                return Ok(());
            }
        }
        let records = self.records(grid);
        if self.lines {
            for record in &records {
                writeln!(output, "{}", compact(record))?;
            }
        } else {
            writeln!(output, "{}", indented(&JsonValue::Array(records), 0))?;
        }
        Ok(())
    }
}

/// One record on a line, with the spacing Python's `json.dumps` uses.
fn compact(value: &JsonValue) -> String {
    match value {
        JsonValue::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            format!(
                "{{{}}}",
                keys.iter()
                    .map(|key| format!("{}: {}", scalar(&json!(key)), compact(&map[*key])))
                    .collect::<Vec<String>>()
                    .join(", ")
            )
        }
        JsonValue::Array(items) => format!(
            "[{}]",
            items.iter().map(compact).collect::<Vec<String>>().join(", ")
        ),
        other => scalar(other),
    }
}

/// The same, laid out over several lines with two spaces of indent per level.
fn indented(value: &JsonValue, depth: usize) -> String {
    let pad = "  ".repeat(depth + 1);
    let closing = "  ".repeat(depth);
    match value {
        JsonValue::Object(map) if !map.is_empty() => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            format!(
                "{{\n{}\n{closing}}}",
                keys.iter()
                    .map(|key| format!(
                        "{pad}{}: {}",
                        scalar(&json!(key)),
                        indented(&map[*key], depth + 1)
                    ))
                    .collect::<Vec<String>>()
                    .join(",\n")
            )
        }
        JsonValue::Array(items) if !items.is_empty() => format!(
            "[\n{}\n{closing}]",
            items
                .iter()
                .map(|item| format!("{pad}{}", indented(item, depth + 1)))
                .collect::<Vec<String>>()
                .join(",\n")
        ),
        JsonValue::Object(_) => "{}".to_string(),
        JsonValue::Array(_) => "[]".to_string(),
        other => scalar(other),
    }
}

/// A scalar as a JSON document spells it.
fn scalar(value: &JsonValue) -> String {
    value.to_string()
}

