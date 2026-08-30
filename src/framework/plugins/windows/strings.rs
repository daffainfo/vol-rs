//! Map strings found in an image back to the processes that own them.
//!
//! Given a list of `offset: text` pairs, which is what the `strings` utility
//! writes for a raw image, this reports which process or kernel region each
//! physical offset belongs to. That turns a flat list of interesting text into
//! attributed evidence.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::{kernel_module, physical_layer};
use crate::framework::plugins::{
    pid_filter, pid_matches, OperatingSystem, Plugin, Requirement, RequirementKind,
};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::list_processes;

pub struct Strings;

impl Plugin for Strings {
    fn name(&self) -> &'static str {
        "windows.strings.Strings"
    }

    fn description(&self) -> &'static str {
        "Reads output from the strings command and indicates which process(es) each string belongs to."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::pid_filter("Process ID to include (all other processes are excluded)"),
            Requirement::new("strings_file", "Strings file", RequirementKind::String).required(),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("String"),
            Column::new("Physical Address", ColumnType::UInt),
            Column::string("Result"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let filter = pid_filter(config);

        let path = config.get_string("strings_file").ok_or_else(|| {
            VolatilityError::Other("A --strings-file is required".to_string())
        })?;
        let entries = read_strings_file(&path)?;

        // Only the pages the strings actually land on are ever asked about, so
        // only those are remembered: the walk still has to visit every page to
        // know what maps where, but nothing else needs writing down.
        let wanted: HashSet<u64> = entries.iter().map(|(offset, _)| offset >> 12).collect();
        let owners = build_reverse_map(&context, &kernel, &physical, &filter, &wanted);

        let mut grid = TreeGrid::new(self.columns());
        for (offset, text) in entries {
            let result = match owners.pages.get(&(offset >> 12)) {
                Some(found) => found
                    .iter()
                    .map(|(owner, at)| format!("{}:{at:#x}", owners.names[*owner as usize]))
                    .collect::<Vec<String>>()
                    .join(", "),
                // A page nothing has mapped is unallocated, which is itself the
                // answer.
                None => "FREE MEMORY".to_string(),
            };

            grid.push(
                0,
                vec![
                    Value::string(text),
                    Value::hex(offset),
                    Value::string(result),
                ],
            )?;
        }
        Ok(grid)
    }
}

/// Parse a `strings`-style file into `(offset, text)` pairs.
///
/// A line is an offset in decimal followed by the text found there. The text
/// runs to the end of the line and keeps the line ending, which is what the
/// reference implementation's own pattern captures and is visible in its
/// output.
fn read_strings_file(path: &str) -> Result<Vec<(u64, String)>> {
    let file = std::fs::File::open(path)
        .map_err(|e| VolatilityError::Io(format!("Could not open {path}: {e}")))?;

    let mut entries = Vec::new();
    let mut count = 0u64;
    for line in BufReader::new(file).split(b'\n') {
        let Ok(mut line) = line else { continue };
        count += 1;
        line.push(b'\n');
        match parse_line(&line) {
            Some(entry) => entries.push(entry),
            None => log::error!("Line in unrecognized format: line {count}"),
        }
    }
    Ok(entries)
}

/// Read one line of a strings file.
///
/// The first run of digits that is preceded only by non-word characters is the
/// offset, and the text is what follows once any further non-word characters
/// are passed over.
fn parse_line(line: &[u8]) -> Option<(u64, String)> {
    let mut at = 0usize;
    while at < line.len() {
        // The offset must be preceded by non-word characters only.
        let mut cursor = at;
        while cursor < line.len() && !is_word(line[cursor]) {
            cursor += 1;
        }
        let digits_start = cursor;
        while cursor < line.len() && line[cursor].is_ascii_digit() {
            cursor += 1;
        }
        if cursor == digits_start {
            at += 1;
            continue;
        }
        let offset: u64 = std::str::from_utf8(&line[digits_start..cursor])
            .ok()?
            .parse()
            .ok()?;

        // Whatever separates the offset from the text is passed over, and the
        // text itself must begin with a word character.
        let mut text_start = cursor;
        while text_start < line.len() && !is_word(line[text_start]) {
            text_start += 1;
        }
        if text_start >= line.len() || line.len() - text_start < 2 {
            at = digits_start + 1;
            continue;
        }
        // The bytes are a byte per character, which is how the reference
        // implementation decodes them.
        let text: String = line[text_start..].iter().map(|byte| *byte as char).collect();
        return Some((offset, text));
    }
    None
}

/// Whether a byte is one of the characters a word is made of.
fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80
}

/// Map each page to what has it mapped.
///
/// The kernel's own space is recorded by the physical page each of its pages
/// resolves to. A process's space is recorded by its *virtual* page instead,
/// which is what the reference implementation does, the loop writing the
/// entries keys them on the mapping's start rather than on the page it is
/// walking, so a process only ever answers for a string whose physical address
/// happens to coincide with one of its virtual pages.
///
/// Neighbouring pages that stay contiguous in both address spaces count as one
/// mapping, so every page of such a run is attributed to where the run starts.
///
/// Only the pages in `wanted` are kept. The walk is the same either way, but a
/// whole image maps tens of millions of pages and the answer needs a few
/// hundred of them.
fn build_reverse_map(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
    physical: &str,
    filter: &Option<Vec<u64>>,
    wanted: &HashSet<u64>,
) -> Owners {
    let mut owners = Owners::default();

    if let Ok(layer) = context.layers.get(&kernel.layer_name) {
        let started = std::time::Instant::now();
        let maximum = layer.maximum_address();
        let owner = owners.name_of("kernel");
        let mut runs = Runs::default();
        let _ = layer.walk_mapping(&context.layers, 0, maximum, true, &mut |entry| {
            runs.add(entry, &mut |virtual_offset, physical_offset, size| {
                let mut page = physical_offset;
                while page < physical_offset + size.max(1) {
                    owners.record(wanted, page >> 12, owner, virtual_offset);
                    page += 0x1000;
                }
            });
        });
        runs.flush(&mut |virtual_offset, physical_offset, size| {
            let mut page = physical_offset;
            while page < physical_offset + size.max(1) {
                owners.record(wanted, page >> 12, owner, virtual_offset);
                page += 0x1000;
            }
        });
        log::debug!("Mapping the kernel space took {:?}", started.elapsed());
    }

    // A process contributes one entry per mapping, keyed on the page that
    // mapping starts at, so the only pages worth asking about are the ones a
    // string landed on. Asking about those directly answers the same question
    // as walking the whole address space, and a process maps far too much of a
    // 128TB space to walk it for a few hundred answers.
    let started = std::time::Instant::now();
    for process in list_processes(context, kernel).unwrap_or_default() {
        let Ok(pid) = process.pid() else { continue };
        if !pid_matches(filter, pid) {
            continue;
        }
        let Ok(layer_name) = process.address_space(physical) else {
            continue;
        };
        let Ok(layer) = context.layers.get(&layer_name) else {
            continue;
        };
        let owner = owners.name_of(&format!("Process {pid}"));

        let mut pages: Vec<u64> = wanted.iter().copied().collect();
        pages.sort_unstable();
        for page in pages {
            let Some((mapped, layer_of)) = mapped_at(context, layer.as_ref(), page) else {
                continue;
            };
            // A mapping only counts where it begins, and it begins here unless
            // the page before it runs straight into this one.
            let follows = page
                .checked_sub(1)
                .and_then(|before| mapped_at(context, layer.as_ref(), before))
                .is_some_and(|(before, before_layer)| {
                    before + 0x1000 == mapped && before_layer == layer_of
                });
            if !follows {
                owners.record(wanted, page, owner, mapped);
            }
        }
    }

    log::debug!("Asking the processes about those pages took {:?}", started.elapsed());
    owners
}

/// Where a page of an address space lands, and in which layer.
fn mapped_at(
    context: &Arc<Context>,
    layer: &dyn crate::framework::layers::DataLayer,
    page: u64,
) -> Option<(u64, String)> {
    let mut found = None;
    let _ = layer.walk_mapping(&context.layers, page << 12, 0x1000, true, &mut |entry| {
        if found.is_none() {
            found = Some((entry.mapped_offset, entry.layer.clone()));
        }
    });
    found
}

/// What has each page mapped.
///
/// The owners' names are held once and referred to by number, since the same
/// handful of names is recorded against a great many pages.
#[derive(Default)]
struct Owners {
    names: Vec<String>,
    pages: HashMap<u64, Vec<(u32, u64)>>,
}

impl Owners {
    /// The number standing for a name, adding it if it is new.
    fn name_of(&mut self, name: &str) -> u32 {
        match self.names.iter().position(|held| held == name) {
            Some(index) => index as u32,
            None => {
                self.names.push(name.to_string());
                (self.names.len() - 1) as u32
            }
        }
    }

    /// Note that a page belongs to something, without repeating an owner.
    fn record(&mut self, wanted: &HashSet<u64>, page: u64, owner: u32, offset: u64) {
        if !wanted.contains(&page) {
            return;
        }
        let list = self.pages.entry(page).or_default();
        if !list.contains(&(owner, offset)) {
            list.push((owner, offset));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn a_line_is_an_offset_and_the_text_after_it() {
        let path = std::env::temp_dir().join(format!("vol3-strings-{}", std::process::id()));
        let mut file = std::fs::File::create(&path).unwrap();
        writeln!(file, "   4096 hello world").unwrap();
        writeln!(file, "8192: third").unwrap();
        writeln!(file, "----").unwrap();
        drop(file);

        let entries = read_strings_file(path.to_str().unwrap()).unwrap();
        assert_eq!(entries.len(), 2);
        // The text keeps the line ending, which is what the reference
        // implementation's own pattern captures.
        assert_eq!(entries[0], (4096, "hello world\n".to_string()));
        assert_eq!(entries[1], (8192, "third\n".to_string()));

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_hexadecimal_offset_is_read_as_the_digits_in_it() {
        // The reference implementation matches decimal digits only, so a
        // `0x`-prefixed offset is read as the leading zero.
        assert_eq!(parse_line(b"0x2000 second\n").unwrap().0, 0);
    }
}

/// Joins the pieces of a mapping that follow one another in both address
/// spaces, which is what a layer reports when asked for a whole range at once.
#[derive(Default)]
struct Runs {
    held: Option<(u64, u64, u64, String)>,
}

impl Runs {
    fn add(
        &mut self,
        entry: &crate::framework::layers::MappingEntry,
        emit: &mut dyn FnMut(u64, u64, u64),
    ) {
        match &mut self.held {
            Some((offset, mapped, size, layer))
                if *offset + *size == entry.offset
                    && *mapped + *size == entry.mapped_offset
                    && *layer == entry.layer =>
            {
                *size += entry.size;
            }
            _ => {
                if let Some((offset, mapped, size, _)) = self.held.take() {
                    emit(offset, mapped, size);
                }
                self.held = Some((
                    entry.offset,
                    entry.mapped_offset,
                    entry.size,
                    entry.layer.clone(),
                ));
            }
        }
    }

    fn flush(&mut self, emit: &mut dyn FnMut(u64, u64, u64)) {
        if let Some((offset, mapped, size, _)) = self.held.take() {
            emit(offset, mapped, size);
        }
    }
}
