//! Choosing which rows and columns are rendered.
//!
//! The command line can hide columns by prefix and keep or drop rows by what
//! their cells contain. Both are applied by the renderer, so every output
//! format treats them alike.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use crate::framework::renderers::TreeGrid;

/// One `[+-]column,pattern[!]` rule.
struct Rule {
    /// The column it looks at, or every column when it names none.
    column: Option<usize>,
    pattern: String,
    /// Whether the pattern is a regular expression rather than a substring.
    regex: Option<regex::Regex>,
    /// Whether a match means the row is unwanted rather than wanted.
    exclude: bool,
}

/// What the renderer was told to leave out.
#[derive(Default)]
pub struct RenderOptions {
    /// Column name prefixes to hide. `None` means nothing was asked for, which
    /// is not the same as an empty list.
    pub hidden: Option<Vec<String>>,
    rules: Vec<Rule>,
}

impl Clone for RenderOptions {
    fn clone(&self) -> Self {
        RenderOptions {
            hidden: self.hidden.clone(),
            rules: self
                .rules
                .iter()
                .map(|rule| Rule {
                    column: rule.column,
                    pattern: rule.pattern.clone(),
                    regex: rule.regex.clone(),
                    exclude: rule.exclude,
                })
                .collect(),
        }
    }
}

impl RenderOptions {
    /// Work out which columns each rule refers to, now that the grid is known.
    pub fn prepare(&mut self, grid: &TreeGrid, filters: &[String]) {
        self.rules.clear();
        for filter in filters {
            let mut text = filter.as_str();
            let mut exclude = false;
            if let Some(rest) = text.strip_prefix('-') {
                exclude = true;
                text = rest;
            } else if let Some(rest) = text.strip_prefix('+') {
                text = rest;
            }

            // Everything after the first comma is the pattern, so a pattern may
            // contain commas of its own.
            let (name, pattern) = match text.split_once(',') {
                // A rule that names no column looks at every one of them.
                Some((name, pattern)) => (
                    (!name.is_empty()).then_some(name),
                    pattern.to_string(),
                ),
                None => (None, text.to_string()),
            };
            // A pattern ending in an exclamation mark is a regular expression.
            let (pattern, is_regex) = match pattern.strip_suffix('!') {
                Some(pattern) => (pattern.to_string(), true),
                None => (pattern, false),
            };
            if pattern.is_empty() {
                continue;
            }

            let column = name.and_then(|name| {
                grid.columns().iter().position(|column| {
                    column.name.to_lowercase().contains(&name.to_lowercase())
                })
            });
            self.rules.push(Rule {
                column,
                regex: is_regex.then(|| regex::Regex::new(&pattern).ok()).flatten(),
                pattern,
                exclude,
            });
        }
    }

    /// The columns to leave out of the output.
    pub fn ignored(&self, grid: &TreeGrid) -> Vec<usize> {
        let Some(hidden) = &self.hidden else {
            return Vec::new();
        };
        grid.columns()
            .iter()
            .enumerate()
            .filter(|(_, column)| {
                hidden.iter().any(|prefix| {
                    column
                        .name
                        .to_lowercase()
                        .starts_with(&prefix.to_lowercase())
                })
            })
            .map(|(index, _)| index)
            .collect()
    }

    /// Whether a row should be left out.
    ///
    /// With no rules nothing is filtered. Otherwise a row has to satisfy at
    /// least one rule to be kept.
    pub fn filtered(&self, cells: &[String]) -> bool {
        if self.rules.is_empty() {
            return false;
        }
        !self.rules.iter().any(|rule| rule.matches(cells))
    }
}

impl Rule {
    fn matches(&self, cells: &[String]) -> bool {
        let found = match self.column {
            Some(column) => cells.get(column).is_some_and(|cell| self.find(cell)),
            None => cells.iter().any(|cell| self.find(cell)),
        };
        if self.exclude {
            !found
        } else {
            found
        }
    }

    fn find(&self, cell: &str) -> bool {
        match &self.regex {
            Some(regex) => regex.is_match(cell),
            None => cell.contains(&self.pattern),
        }
    }
}
