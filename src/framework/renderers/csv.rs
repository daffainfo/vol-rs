//! CSV rendering.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::io::Write;

use crate::error::Result;
use crate::framework::renderers::{Renderer, TreeGrid};

/// Renders the grid as RFC 4180 CSV, with the tree depth as its own column so
/// no structure is lost in the flattening.
#[derive(Default)]
pub struct CsvRenderer {
    pub include_depth: bool,
    pub options: crate::framework::renderers::filter::RenderOptions,
}

impl CsvRenderer {
    pub fn new() -> Self {
        Self {
            include_depth: true,
            options: Default::default(),
        }
    }
}

/// Quote a field when it contains anything that would otherwise break parsing.
///
/// A quote inside a quoted field is doubled, and a backslash is escaped with
/// another, since that is the escape character the reference implementation's
/// writer is given.
fn escape(field: &str) -> String {
    let field = field.replace('\\', "\\\\");
    if field.contains(['"', ',', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field
    }
}

impl Renderer for CsvRenderer {
    fn render(&self, grid: &TreeGrid, output: &mut dyn Write) -> Result<()> {
        let ignored = self.options.ignored(grid);
        let mut headers: Vec<String> = vec!["TreeDepth".to_string()];
        headers.extend(
            grid.columns()
                .iter()
                .enumerate()
                .filter(|(index, _)| !ignored.contains(index))
                .map(|(_, column)| escape(&column.name)),
        );
        writeln!(output, "{}", headers.join(","))?;

        for row in grid.rows() {
            let rendered: Vec<String> =
                row.values.iter().map(|value| value.to_string()).collect();
            if self.options.filtered(&rendered) {
                continue;
            }
            let mut cells: Vec<String> = vec![row.depth.to_string()];
            cells.extend(
                rendered
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| !ignored.contains(index))
                    .map(|(_, value)| escape(value)),
            );
            writeln!(output, "{}", cells.join(","))?;
        }
        match grid.truncation() {
            // The listing ends with an empty line.
            crate::framework::renderers::Truncation::None => writeln!(output)?,
            // A plugin that died mid-listing wrote no more than its rows.
            crate::framework::renderers::Truncation::Abrupt => {}
            // A plugin whose failure was reported leaves two blank lines behind
            // it, written where the error was caught rather than by the table.
            crate::framework::renderers::Truncation::Reported => write!(output, "\n\n")?,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::renderers::{Column, TreeGrid, Value};

    #[test]
    fn escapes_separators_and_quotes() {
        let mut grid = TreeGrid::new(vec![Column::string("Command")]);
        grid.push(0, vec![Value::string("cmd.exe /c \"dir\", now")])
            .unwrap();

        let mut buffer = Vec::new();
        CsvRenderer::new().render(&grid, &mut buffer).unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("\"cmd.exe /c \"\"dir\"\", now\""));
    }
}
