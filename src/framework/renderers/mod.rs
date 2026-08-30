//! The tree grid: the single output format every plugin produces.
//!
//! A plugin yields rows, each at some depth in a tree, with one value per
//! declared column. Renderers then turn that into text, CSV, JSON or anything
//! else without needing to know what the plugin was doing.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

pub mod text;
pub mod json;
pub mod csv;
pub mod conversion;
pub mod filter;
pub mod format_hints;

use std::fmt;

use crate::error::{Result, VolatilityError};

/// Render bytes as a hex dump, matching `hex_bytes_as_text`.
///
/// The dump opens with a newline, then each line holds `width` bytes as
/// two-digit hex followed by their printable equivalents. A final short line is
/// padded so the text column still lines up.
/// Decode bytes written in the wide encoding, replacing what will not decode.
fn decode_wide(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

fn hex_dump(bytes: &[u8], width: usize) -> String {
    let mut output = String::from("\n");
    let mut printables = String::new();

    for (count, byte) in bytes.iter().enumerate() {
        output.push_str(&format!("{byte:02x} "));
        printables.push(if (0x20..=0x7E).contains(byte) {
            *byte as char
        } else {
            '.'
        });
        if count % width == width - 1 {
            output.push_str(&printables);
            if count < bytes.len() - 1 {
                output.push('\n');
            }
            printables.clear();
        }
    }

    if !printables.is_empty() {
        let padding = width - printables.len();
        output.push_str(&"   ".repeat(padding));
        output.push_str(&printables);
        output.push_str(&" ".repeat(padding));
    }
    output
}

/// A hex dump in which absent bytes are marked rather than shown as zeroes.
fn layer_dump(bytes: &[u8], missing: &[usize], width: usize) -> String {
    let mut output = String::from("\n");
    let mut printables = String::new();

    for (count, byte) in bytes.iter().enumerate() {
        if missing.contains(&count) {
            output.push_str("__ ");
            printables.push('.');
        } else {
            output.push_str(&format!("{byte:02x} "));
            printables.push(if (0x20..=0x7E).contains(byte) {
                *byte as char
            } else {
                '.'
            });
        }
        if count % width == width - 1 {
            output.push_str(&printables);
            if count < bytes.len() - 1 {
                output.push('\n');
            }
            printables.clear();
        }
    }

    if !printables.is_empty() {
        let padding = width - printables.len();
        output.push_str(&"   ".repeat(padding));
        output.push_str(&printables);
        output.push_str(&" ".repeat(padding));
    }
    output
}

/// Why a cell has no value.
///
/// Distinguishing these matters: "we could not read the memory" is a different
/// statement from "this field does not apply to this row", and analysts read
/// them differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbsentValue {
    /// The underlying memory could not be read.
    Unreadable,
    /// The bytes were read but could not be interpreted.
    Unparsable,
    /// The field does not apply to this row.
    NotApplicable,
    /// The information is not available in this run, but might be in another --
    /// missing symbols, typically.
    NotAvailable,
}

impl fmt::Display for AbsentValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Upstream singles out "not applicable". Every other kind of
            // absence renders as a bare dash.
            AbsentValue::NotApplicable => write!(f, "N/A"),
            AbsentValue::Unreadable | AbsentValue::Unparsable | AbsentValue::NotAvailable => {
                write!(f, "-")
            }
        }
    }
}

/// How a numeric value should be rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberFormat {
    Decimal,
    /// Rendered as `0x...`, which is how addresses and offsets are read.
    Hex,
    /// Rendered as a binary literal.
    Binary,
    /// Rendered in octal.
    Octal,
}

/// One cell of output.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Absent(AbsentValue),
    Bool(bool),
    Int(i64, NumberFormat),
    UInt(u64, NumberFormat),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
    /// Bytes shown as text where they decode cleanly and as a hex dump where
    /// they do not, which is how `format_hints.MultiTypeData` renders.
    MultiTypeData(Vec<u8>),
    /// Bytes shown as a hex dump: sixteen per line with their printable
    /// equivalents alongside, which is how `format_hints.HexBytes` renders.
    HexDump(Vec<u8>),
    /// A run of bytes read out of a layer, dumped the same way, except that
    /// bytes the layer does not actually hold are shown as `__` rather than as
    /// the zeroes padding supplied.
    LayerDump { bytes: Vec<u8>, missing: Vec<usize> },
    /// Bytes that are meant to be text in the wide encoding, shown as such
    /// when decoding them loses nothing and as a dump when it would.
    WideText(Vec<u8>),
    /// A run of wide strings, one per line.
    MultiString(Vec<u8>),
    /// Bytes shown as plain space-separated hex, which is what a disassembly
    /// column falls back to when no instruction decoder is available.
    HexPairs(Vec<u8>),
    /// A point in time, held as a UTC timestamp.
    DateTime(chrono::DateTime<chrono::Utc>),
    /// A timestamp with no timezone attached, which upstream builds only in
    /// `mac.pslist` and renders without a zone name.
    NaiveDateTime(chrono::NaiveDateTime),
    /// A raw byte block to be disassembled by the renderer.
    Disassembly {
        data: Vec<u8>,
        offset: u64,
        architecture: String,
    },
}

impl Value {
    /// A hexadecimal integer, the common case for addresses.
    pub fn hex(value: u64) -> Self {
        Value::UInt(value, NumberFormat::Hex)
    }

    pub fn uint(value: u64) -> Self {
        Value::UInt(value, NumberFormat::Decimal)
    }

    pub fn int(value: i64) -> Self {
        Value::Int(value, NumberFormat::Decimal)
    }

    pub fn string(value: impl Into<String>) -> Self {
        Value::Str(value.into())
    }

    pub fn unreadable() -> Self {
        Value::Absent(AbsentValue::Unreadable)
    }

    /// The bytes were read but could not be interpreted.
    pub fn unparsable() -> Self {
        Value::Absent(AbsentValue::Unparsable)
    }

    pub fn not_applicable() -> Self {
        Value::Absent(AbsentValue::NotApplicable)
    }

    pub fn not_available() -> Self {
        Value::Absent(AbsentValue::NotAvailable)
    }

    pub fn is_absent(&self) -> bool {
        matches!(self, Value::Absent(_))
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Absent(absent) => write!(f, "{absent}"),
            Value::Bool(value) => write!(f, "{}", if *value { "True" } else { "False" }),
            Value::Int(value, format) => write_number(f, *value < 0, value.unsigned_abs(), *format),
            Value::UInt(value, format) => write_number(f, false, *value, *format),
            Value::Float(value) => write!(f, "{value}"),
            Value::Str(text) => write!(f, "{text}"),
            Value::Bytes(bytes) => {
                // A plain byte column is shown as space-separated hex.
                let pairs: Vec<String> = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
                write!(f, "{}", pairs.join(" "))
            }
            Value::MultiTypeData(bytes) => {
                // Shown as text when almost nothing is lost by cutting at the
                // first NUL (a trailing terminator is fine, a field of padding
                // is not), and as a hex dump otherwise.
                let text = String::from_utf8_lossy(bytes);
                let head = text.split('\0').next().unwrap_or_default();
                let total = text.chars().count();
                if total.saturating_sub(1) <= head.chars().count() {
                    write!(f, "{head}")
                } else {
                    write!(f, "{}", hex_dump(bytes, 16))
                }
            }
            Value::HexDump(bytes) => write!(f, "{}", hex_dump(bytes, 16)),
            Value::LayerDump { bytes, missing } => {
                write!(f, "{}", layer_dump(bytes, missing, 16))
            }
            Value::WideText(bytes) => {
                let text = decode_wide(bytes);
                // Shown as text only when cutting at the first terminator
                // leaves all but that terminator behind.
                let head = text.split('\0').next().unwrap_or_default();
                if text.chars().count().saturating_sub(1) <= head.chars().count() {
                    write!(f, "{head}")
                } else {
                    write!(f, "{}", hex_dump(bytes, 16))
                }
            }
            Value::MultiString(bytes) => {
                let text = decode_wide(bytes);
                let halved = bytes.len() / 2;
                if halved.saturating_sub(1) <= text.chars().count() && text.chars().count() <= halved
                {
                    write!(f, "{}", text.split('\0').collect::<Vec<&str>>().join("\n"))
                } else {
                    write!(f, "{}", hex_dump(bytes, 16))
                }
            }
            Value::HexPairs(bytes) => {
                let pairs: Vec<String> = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
                write!(f, "{}", pairs.join(" "))
            }
            Value::DateTime(when) => {
                // Always six decimal places: upstream renders every datetime
                // with strftime("%Y-%m-%d %H:%M:%S.%f %Z"), which pads rather
                // than dropping a zero fraction.
                write!(f, "{}", when.format("%Y-%m-%d %H:%M:%S%.6f UTC"))
            }
            Value::NaiveDateTime(when) => {
                // The same format, but `%Z` has nothing to print for a
                // timestamp that carries no zone, which leaves a trailing
                // space where the zone name would be.
                write!(f, "{} ", when.format("%Y-%m-%d %H:%M:%S%.6f"))
            }
            Value::Disassembly { data, offset, .. } => {
                write!(f, "{} bytes at {offset:#x}", data.len())
            }
        }
    }
}

fn write_number(
    f: &mut fmt::Formatter<'_>,
    negative: bool,
    magnitude: u64,
    format: NumberFormat,
) -> fmt::Result {
    let sign = if negative { "-" } else { "" };
    match format {
        NumberFormat::Decimal => write!(f, "{sign}{magnitude}"),
        NumberFormat::Hex => write!(f, "{sign}{magnitude:#x}"),
        NumberFormat::Binary => write!(f, "{sign}{magnitude:#b}"),
        NumberFormat::Octal => write!(f, "{sign}{magnitude:#o}"),
    }
}

/// The type a column holds, declared up front so renderers can align and
/// serialise sensibly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnType {
    Bool,
    Int,
    UInt,
    Float,
    Str,
    Bytes,
    DateTime,
    Disassembly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub column_type: ColumnType,
}

impl Column {
    pub fn new(name: impl Into<String>, column_type: ColumnType) -> Self {
        Self {
            name: name.into(),
            column_type,
        }
    }

    pub fn string(name: impl Into<String>) -> Self {
        Self::new(name, ColumnType::Str)
    }

    pub fn uint(name: impl Into<String>) -> Self {
        Self::new(name, ColumnType::UInt)
    }

    pub fn int(name: impl Into<String>) -> Self {
        Self::new(name, ColumnType::Int)
    }

    pub fn bool(name: impl Into<String>) -> Self {
        Self::new(name, ColumnType::Bool)
    }

    pub fn bytes(name: impl Into<String>) -> Self {
        Self::new(name, ColumnType::Bytes)
    }

    pub fn datetime(name: impl Into<String>) -> Self {
        Self::new(name, ColumnType::DateTime)
    }
}

/// One row: how deep it sits in the tree, and its cells.
#[derive(Debug, Clone)]
pub struct Row {
    /// Zero for a top-level row. Each increment nests it under the previous row
    /// at one less depth.
    pub depth: usize,
    pub values: Vec<Value>,
}

impl Row {
    pub fn new(depth: usize, values: Vec<Value>) -> Self {
        Self { depth, values }
    }

    /// A top-level row.
    pub fn top(values: Vec<Value>) -> Self {
        Self { depth: 0, values }
    }
}

/// A plugin's complete output.
#[derive(Debug, Clone)]
pub struct TreeGrid {
    columns: Vec<Column>,
    rows: Vec<Row>,
    /// How row production ended, when it ended early.
    truncation: Truncation,
}

/// How a listing ended.
///
/// The reference implementation stops early in two distinguishable ways, and
/// the trailing bytes differ between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Truncation {
    /// Every row was produced.
    #[default]
    None,
    /// The process died part-way through writing, leaving the last row without
    /// its newline.
    Abrupt,
    /// The error was caught and reported: the last row is left unterminated and
    /// a blank line follows on standard output.
    Reported,
}

impl TreeGrid {
    pub fn new(columns: Vec<Column>) -> Self {
        Self {
            columns,
            rows: Vec::new(),
            truncation: Truncation::None,
        }
    }

    /// Record that row production stopped early, as upstream's does.
    pub fn mark_truncated(&mut self) {
        self.truncation = Truncation::Abrupt;
    }

    /// Record that row production stopped on a reported error.
    pub fn mark_truncated_reported(&mut self) {
        self.truncation = Truncation::Reported;
    }

    pub fn truncation(&self) -> Truncation {
        self.truncation
    }

    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Append a row, checking it against the declared columns.
    ///
    /// A mismatch is a plugin bug rather than a data problem, so it is reported
    /// rather than silently padded.
    pub fn add_row(&mut self, row: Row) -> Result<()> {
        if row.values.len() != self.columns.len() {
            return Err(VolatilityError::Render(format!(
                "Row has {} values but the grid has {} columns",
                row.values.len(),
                self.columns.len()
            )));
        }
        self.rows.push(row);
        Ok(())
    }

    pub fn push(&mut self, depth: usize, values: Vec<Value>) -> Result<()> {
        self.add_row(Row::new(depth, values))
    }

    /// Visit every row in order, with its depth.
    pub fn visit<F: FnMut(&Row)>(&self, mut visitor: F) {
        for row in &self.rows {
            visitor(row);
        }
    }

    /// Sort top-level rows by a column, keeping each row's descendants with it.
    pub fn sort_by_column(&mut self, column_index: usize, descending: bool) {
        if column_index >= self.columns.len() {
            return;
        }

        // Group each root row with the subtree that follows it, so re-ordering
        // roots does not detach children from their parents.
        let mut groups: Vec<Vec<Row>> = Vec::new();
        for row in self.rows.drain(..) {
            if row.depth == 0 || groups.is_empty() {
                groups.push(vec![row]);
            } else {
                groups.last_mut().unwrap().push(row);
            }
        }

        groups.sort_by(|left, right| {
            let ordering = compare_values(&left[0].values[column_index], &right[0].values[column_index]);
            if descending {
                ordering.reverse()
            } else {
                ordering
            }
        });

        self.rows = groups.into_iter().flatten().collect();
    }
}

/// Order two cells, putting absent values last.
fn compare_values(left: &Value, right: &Value) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (left, right) {
        (Value::Absent(_), Value::Absent(_)) => Ordering::Equal,
        (Value::Absent(_), _) => Ordering::Greater,
        (_, Value::Absent(_)) => Ordering::Less,
        (Value::UInt(a, _), Value::UInt(b, _)) => a.cmp(b),
        (Value::Int(a, _), Value::Int(b, _)) => a.cmp(b),
        (Value::Float(a), Value::Float(b)) => a.partial_cmp(b).unwrap_or(Ordering::Equal),
        (Value::Bool(a), Value::Bool(b)) => a.cmp(b),
        (Value::DateTime(a), Value::DateTime(b)) => a.cmp(b),
        (Value::NaiveDateTime(a), Value::NaiveDateTime(b)) => a.cmp(b),
        _ => left.to_string().cmp(&right.to_string()),
    }
}

/// Renders a completed grid to some output.
pub trait Renderer {
    fn render(&self, grid: &TreeGrid, output: &mut dyn std::io::Write) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_must_match_the_declared_columns() {
        let mut grid = TreeGrid::new(vec![Column::uint("PID"), Column::string("Name")]);
        assert!(grid.push(0, vec![Value::uint(4)]).is_err());
        assert!(grid
            .push(0, vec![Value::uint(4), Value::string("System")])
            .is_ok());
    }

    #[test]
    fn sorting_keeps_children_with_their_parents() {
        let mut grid = TreeGrid::new(vec![Column::uint("PID")]);
        grid.push(0, vec![Value::uint(9)]).unwrap();
        grid.push(1, vec![Value::uint(99)]).unwrap();
        grid.push(0, vec![Value::uint(1)]).unwrap();
        grid.push(1, vec![Value::uint(11)]).unwrap();

        grid.sort_by_column(0, false);
        let order: Vec<String> = grid.rows().iter().map(|r| r.values[0].to_string()).collect();
        assert_eq!(order, vec!["1", "11", "9", "99"]);
    }

    #[test]
    fn absent_values_sort_last_and_render_distinctly() {
        assert_eq!(Value::unreadable().to_string(), "-");
        assert_eq!(Value::not_applicable().to_string(), "N/A");
        // Only "not applicable" is N/A. "not available" is a dash upstream.
        assert_eq!(Value::not_available().to_string(), "-");
        assert_eq!(
            compare_values(&Value::unreadable(), &Value::uint(1)),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn hex_values_render_with_a_prefix() {
        assert_eq!(Value::hex(0xDEAD).to_string(), "0xdead");
        assert_eq!(Value::int(-5).to_string(), "-5");
    }
}
