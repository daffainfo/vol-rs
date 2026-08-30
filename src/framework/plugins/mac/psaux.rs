//! Report each process's command line arguments.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::mac::list_processes;

pub struct PsAux;

impl Plugin for PsAux {
    fn name(&self) -> &'static str {
        "mac.psaux.Psaux"
    }

    fn description(&self) -> &'static str {
        "Recovers program command line arguments."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel(), Requirement::pid_filter("Filter on specific process IDs")]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Process"),
            Column::int("Argc"),
            Column::string("Arguments"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }

            // The arguments live in the process's own address space, so a
            // process whose page tables cannot be read is passed over.
            let Ok(Some(layer)) = process.process_layer() else {
                continue;
            };

            let read = |name: &str| -> Option<u64> {
                process.object.member(name).ok()?.as_u64().ok()
            };
            let (Some(stack), Some(length), Some(count)) = (
                read("user_stack"),
                read("p_argslen"),
                read("p_argc"),
            ) else {
                continue;
            };

            let mut position = stack.wrapping_sub(length);
            if !context.layers.is_valid(&layer, position, 1) || length == 0 || count == 0 {
                continue;
            }

            // One more than the count, because the first two entries are
            // usually the same string twice.
            let mut remaining = count + 1;
            if remaining > 1024 {
                continue;
            }

            let mut arguments: Vec<Vec<u8>> = Vec::new();
            while remaining > 0 {
                let Ok(chunk) = context.layers.read(&layer, position, 256, false) else {
                    break;
                };
                let argument = match chunk.iter().position(|byte| *byte == 0) {
                    Some(end) => &chunk[..end],
                    None => &chunk[..],
                };

                // Upstream advances by the length of the argument's Python
                // representation rather than of the argument itself, which is
                // longer by the quotes, the prefix and any escapes.
                position += python_bytes_repr_length(argument) as u64 + 1;

                if arguments.is_empty() {
                    // The first argument is preceded by padding, which is
                    // stepped over one byte at a time.
                    while position < stack {
                        match context.layers.read(&layer, position, 1, false) {
                            Ok(byte) if byte.first() == Some(&0) => position += 1,
                            _ => break,
                        }
                    }
                    arguments.push(argument.to_vec());
                } else if argument != arguments[0].as_slice() {
                    arguments.push(argument.to_vec());
                }
                remaining -= 1;
            }

            let joined = arguments
                .iter()
                .map(|argument| String::from_utf8_lossy(argument).to_string())
                .collect::<Vec<String>>()
                .join(" ");

            grid.push(
                0,
                vec![
                    Value::int(pid as i64),
                    or_unreadable(process.name(), Value::string),
                    Value::int(count as i64),
                    Value::string(joined),
                ],
            )?;
        }
        Ok(grid)
    }

}

/// The length of `str(bytes)` in Python, which is the representation: a `b`,
/// the quotes around it, and any escapes inside.
///
/// One plugin upstream advances through the argument block by this length
/// rather than by the argument's own, so reproducing its output means
/// reproducing the arithmetic.
fn python_bytes_repr_length(bytes: &[u8]) -> usize {
    // A single quote inside the value switches the surrounding quotes to
    // double ones, so that the value itself needs no escaping.
    let quote = if bytes.contains(&b'\'') && !bytes.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };

    let mut length = 3;
    for byte in bytes {
        length += match byte {
            b'\\' | b'\t' | b'\n' | b'\r' => 2,
            byte if *byte == quote => 2,
            0x20..=0x7e => 1,
            _ => 4,
        };
    }
    length
}

#[cfg(test)]
mod tests {
    use super::python_bytes_repr_length;

    #[test]
    fn matches_pythons_representation_of_bytes() {
        // b'foo'
        assert_eq!(python_bytes_repr_length(b"foo"), 6);
        // b''
        assert_eq!(python_bytes_repr_length(b""), 3);
        // b'a\\x00b' is not reachable here, but a high byte is: b'\\xff'
        assert_eq!(python_bytes_repr_length(b"\xff"), 7);
        // b"it's" keeps the value unescaped by switching quotes
        assert_eq!(python_bytes_repr_length(b"it's"), 7);
        // b'say "hi"' keeps single quotes and leaves the double ones alone
        assert_eq!(python_bytes_repr_length(b"say \"hi\""), 11);
    }
}
