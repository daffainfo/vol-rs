//! Recover the kernel message buffer.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::pointer_to_string;
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, TreeGrid, Value};

pub struct Dmesg;

/// The buffer is a few hundred kilobytes at most. A larger size means the

impl Plugin for Dmesg {
    fn name(&self) -> &'static str {
        "mac.dmesg.Dmesg"
    }

    fn description(&self) -> &'static str {
        "Prints the kernel log buffer."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![Column::string("line")]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;

        // The buffer is described by a small header holding its address, its
        // size, and how far the kernel has written into it.
        let buffer = context
            .object_from_symbol(&kernel, "msgbufp", None)?
            .dereference()?;

        let size = buffer.member("msg_size")?.as_u64()?;
        let mut written = buffer.member("msg_bufx")?.as_u64()?;
        let text = pointer_to_string(&buffer.member("msg_bufc")?, size as usize)?;

        // The buffer is written in a circle, so once it has filled up the
        // oldest message is the one at the write position.
        if written > size {
            written = 0;
        }
        let split = text
            .char_indices()
            .nth(written as usize)
            .map(|(index, _)| index)
            .unwrap_or(text.len());
        let log = format!("{}{}", &text[split..], &text[..split]);

        let mut grid = TreeGrid::new(self.columns());
        for line in split_lines(&log) {
            grid.push(0, vec![Value::string(line)])?;
        }
        Ok(grid)
    }
}

/// Split text into lines the way Python does, which breaks on more than just
/// the newline character and drops a trailing break.
fn split_lines(text: &str) -> Vec<String> {
    const BREAKS: &[char] = &[
        '\n', '\r', '\u{b}', '\u{c}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{85}', '\u{2028}',
        '\u{2029}',
    ];

    let mut lines = Vec::new();
    let mut line = String::new();
    let mut characters = text.chars().peekable();

    while let Some(character) = characters.next() {
        if BREAKS.contains(&character) {
            // A carriage return followed by a newline is one break, not two.
            if character == '\r' && characters.peek() == Some(&'\n') {
                characters.next();
            }
            lines.push(std::mem::take(&mut line));
        } else {
            line.push(character);
        }
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}
