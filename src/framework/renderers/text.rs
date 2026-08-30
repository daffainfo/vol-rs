//! Plain-text rendering: an aligned table, or a "quick" mode that streams rows
//! without buffering to measure column widths.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::io::Write;

use crate::error::Result;
use crate::framework::renderers::{Renderer, TreeGrid, Truncation};

/// Renders a table with every column padded to its widest cell.
///
/// The tree is shown by a leading column of asterisks, and each column is right
/// aligned and separated by a pipe. A cell holding several lines is written
/// across as many rows, with the other columns left blank.
#[derive(Default)]
pub struct PrettyTextRenderer {
    pub options: crate::framework::renderers::filter::RenderOptions,
}

impl PrettyTextRenderer {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Renderer for PrettyTextRenderer {
    fn render(&self, grid: &TreeGrid, output: &mut dyn Write) -> Result<()> {
        // Nothing is written for a plugin that stopped part way, since the
        // table cannot be laid out until every row is in.
        match grid.truncation() {
            Truncation::None => {}
            Truncation::Abrupt => return Ok(()),
            Truncation::Reported => {
                write!(output, "\n\n")?;
                return Ok(());
            }
        }
        let ignored = self.options.ignored(grid);
        let shown = |index: usize| !ignored.contains(&index);

        // Rows are gathered first, since a column is only as wide as its widest
        // cell and the tree column only as wide as the deepest row.
        let mut depth_width = 0;
        let mut widths: Vec<usize> = grid
            .columns()
            .iter()
            .map(|column| column.name.chars().count())
            .collect();
        let mut body: Vec<(usize, Vec<Vec<String>>)> = Vec::new();

        for row in grid.rows() {
            let cells: Vec<String> = row.values.iter().map(|value| value.to_string()).collect();
            if self.options.filtered(&cells) {
                continue;
            }
            depth_width = depth_width.max(row.depth + 1);

            let mut lines: Vec<Vec<String>> = Vec::new();
            for (index, cell) in cells.iter().enumerate() {
                let parts: Vec<String> = cell.split('\n').map(tab_stop).collect();
                let widest = parts.iter().map(|part| part.chars().count()).max().unwrap_or(0);
                widths[index] = widths[index].max(widest);
                lines.push(parts);
            }
            body.push((row.depth, lines));
        }

        // The header's own tree column is empty.
        let mut header: Vec<String> = vec![String::new()];
        header.extend(
            grid.columns()
                .iter()
                .enumerate()
                .filter(|(index, _)| shown(*index))
                .map(|(_, column)| column.name.clone()),
        );
        write_row(output, &header, depth_width, &widths, &ignored)?;

        for (depth, lines) in body {
            let height = lines.iter().map(|parts| parts.len()).max().unwrap_or(1);
            for line in 0..height {
                // A row's depth is counted from one, so even a top level row
                // carries a single mark.
                let mut cells: Vec<String> = vec![if line == 0 {
                    "*".repeat(depth + 1)
                } else {
                    " ".repeat(depth + 1)
                }];
                cells.extend(
                    lines
                        .iter()
                        .enumerate()
                        .filter(|(index, _)| shown(*index))
                        .map(|(_, parts)| parts.get(line).cloned().unwrap_or_default()),
                );
                write_row(output, &cells, depth_width, &widths, &ignored)?;
            }
        }
        Ok(())
    }
}

/// Write one line of the pretty table: the tree column left aligned, then every
/// visible column right aligned to its own width.
fn write_row(
    output: &mut dyn Write,
    cells: &[String],
    depth_width: usize,
    widths: &[usize],
    ignored: &[usize],
) -> Result<()> {
    let mut line = format!("{:<depth_width$}", cells[0]);
    let mut cell = 1;
    for (index, width) in widths.iter().enumerate() {
        if ignored.contains(&index) {
            continue;
        }
        let text = cells.get(cell).cloned().unwrap_or_default();
        let padding = width.saturating_sub(text.chars().count());
        line.push_str(" | ");
        line.push_str(&" ".repeat(padding));
        line.push_str(&text);
        cell += 1;
    }
    writeln!(output, "{line}")?;
    Ok(())
}

/// Expand tabs to the next eight column stop, as the reference implementation
/// does before measuring a cell.
fn tab_stop(line: &str) -> String {
    let mut text = line.to_string();
    while let Some(position) = text.find('\t') {
        let padding = " ".repeat(8 - (position % 8));
        text = text.replacen('\t', &padding, 1);
    }
    text
}

/// Streams rows as they arrive, without aligning columns.
///
/// Useful for long-running plugins where seeing partial output early matters
/// more than a tidy table.
pub struct QuickTextRenderer {
    pub separator: String,
    pub options: crate::framework::renderers::filter::RenderOptions,
}

impl Default for QuickTextRenderer {
    fn default() -> Self {
        Self {
            separator: "\t".to_string(),
            options: Default::default(),
        }
    }
}

impl Renderer for QuickTextRenderer {
    fn render(&self, grid: &TreeGrid, output: &mut dyn Write) -> Result<()> {
        let ignored = self.options.ignored(grid);
        let headers: Vec<String> = grid
            .columns()
            .iter()
            .enumerate()
            .filter(|(index, _)| !ignored.contains(index))
            .map(|(_, column)| column.name.clone())
            .collect();
        // Upstream writes a newline, the header, then a newline before each
        // row. That leaves a blank line above and below the header, and is why
        // a listing cut short ends without its final newline, and why a run
        // that fails before rendering prints nothing but the banner.
        write!(output, "\n{}\n", headers.join(&self.separator))?;

        for row in grid.rows() {
            let rendered: Vec<String> =
                row.values.iter().map(|value| value.to_string()).collect();
            if self.options.filtered(&rendered) {
                continue;
            }
            let cells: Vec<String> = rendered
                .into_iter()
                .enumerate()
                .filter(|(index, _)| !ignored.contains(index))
                .map(|(index, value)| {
                    if index == 0 && row.depth > 0 {
                        // One asterisk per level of nesting, separated from the
                        // value by a single space.
                        format!("{} {value}", "*".repeat(row.depth))
                    } else {
                        value
                    }
                })
                .collect();
            write!(output, "\n{}", cells.join(&self.separator))?;
        }

        match grid.truncation() {
            // The run finished, so the last line is terminated.
            Truncation::None => writeln!(output)?,
            // The process died mid-write, leaving the last line unterminated.
            Truncation::Abrupt => {}
            // The error was reported, which leaves a blank line behind it.
            Truncation::Reported => write!(output, "\n\n")?,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::renderers::{Column, TreeGrid, Value};

    fn sample_grid() -> TreeGrid {
        let mut grid = TreeGrid::new(vec![Column::uint("PID"), Column::string("ImageFileName")]);
        grid.push(0, vec![Value::uint(4), Value::string("System")])
            .unwrap();
        grid.push(1, vec![Value::uint(400), Value::string("smss.exe")])
            .unwrap();
        grid
    }

    #[test]
    fn aligns_columns_and_indents_children() {
        let mut buffer = Vec::new();
        PrettyTextRenderer::new()
            .render(&sample_grid(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        // The tree column comes first, then every column right aligned to its
        // widest cell.
        assert_eq!(lines[0], "   | PID | ImageFileName");
        assert_eq!(lines[1], "*  |   4 |        System");
        assert_eq!(lines[2], "** | 400 |      smss.exe");
    }

    #[test]
    fn quick_mode_skips_alignment() {
        let mut buffer = Vec::new();
        QuickTextRenderer::default()
            .render(&sample_grid(), &mut buffer)
            .unwrap();
        let text = String::from_utf8(buffer).unwrap();
        assert!(text.contains("PID\tImageFileName"));
        // A blank line separates the header from the rows.
        assert!(text.contains("PID\tImageFileName\n\n"));
        // Upstream writes one asterisk per level and then a single space:
        // `"*" * (path_depth - 1) + " "`.
        assert!(text.contains("* 400\tsmss.exe"));
    }
}
