//! Report the UserAssist records, which track programs a user has launched.
//!
//! Explorer records each launched program under a per-category GUID key, with
//! the program's path as the value name. The names are ROT13-encoded (an
//! obfuscation, not encryption), and the data holds a run count and timestamps.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::conversion::wintime_value;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::registry::{read_key, subkeys, values};

pub struct UserAssist;

/// Where Explorer keeps the records, below a user's hive root.
const USERASSIST_PATH: &[&str] = &[
    "Software",
    "Microsoft",
    "Windows",
    "CurrentVersion",
    "Explorer",
    "UserAssist",
];

/// Decode a ROT13-obfuscated value name.
///
/// Only ASCII letters are rotated. Everything else, including the path
/// separators and drive letters' colons, passes through.
fn rot13(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            other => other,
        })
        .collect()
}

impl Plugin for UserAssist {
    fn name(&self) -> &'static str {
        "windows.registry.userassist.UserAssist"
    }

    fn description(&self) -> &'static str {
        "Print userassist registry keys and information."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new("offset", "Hive Offset", RequirementKind::Int),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Hive Offset", ColumnType::UInt),
            Column::string("Hive Name"),
            Column::string("Path"),
            Column::datetime("Last Write Time"),
            Column::string("Type"),
            Column::string("Name"),
            Column::int("ID"),
            Column::int("Count"),
            Column::int("Focus Count"),
            Column::string("Time Focused"),
            Column::datetime("Last Updated"),
            Column::bytes("Raw Data"),
        ]
    }

    fn timeline(
        &self,
        context: Arc<Context>,
        config: &Configuration,
    ) -> Option<crate::framework::plugins::Timeline> {
        use crate::framework::plugins::{TimeKind, Timeline};
        #[allow(unused_imports)]
        use crate::framework::plugins::timeline_helpers::{is_time, number, text};

        let mut timeline = Timeline::new();
        for row in self.run(context, config).ok()?.rows() {
            let values = &row.values;
            // Both the name and the timestamp have to be there for the entry
            // to say anything.
            if values[5].is_absent() || values[10].is_absent() {
                continue;
            }
            let description = format!(
                "UserAssist: {} {} ({})",
                text(&values[5]),
                text(&values[2]),
                number(&values[7])
            );
            timeline.push(description, TimeKind::Modified, values[10].clone());
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let table = kernel.symbol_table_name.clone();
        let requested = config.get_int("offset").map(|value| value as u64);

        // The record's shape changed with Windows 7, and the structures for
        // both ship as their own small file.
        context.ensure_table("registry", "windows", "registry")?;
        let win7 = context
            .symbol_space
            .get_type(&kernel.qualified("_KUSER_SHARED_DATA"))
            .ok()
            .map(|template| {
                context
                    .symbol_space
                    .find_member(&template, "CookiePad")
                    .map(|found| found.is_some())
                    .unwrap_or(false)
            });
        let layout = win7.and_then(|win7| Layout::new(&context, win7));

        let mut grid = TreeGrid::new(self.columns());

        for hive_object in super::list_hives(&context, &kernel)? {
            if let Some(offset) = requested {
                if hive_object.offset() != offset {
                    continue;
                }
            }
            let hive_offset = hive_object.offset();

            let Ok(hive) = super::open_hive(&context, &kernel, hive_object) else {
                continue;
            };
            let hive_name = hive.hive_name().unwrap_or_default().to_string();
            // Only a user's own hive records what that user launched.
            if !hive_name.to_ascii_lowercase().contains("ntuser.dat") {
                continue;
            }
            // A key names itself from the hive's last component down.
            let root_name = hive_name
                .rsplit('\\')
                .next()
                .unwrap_or(&hive_name)
                .to_string();

            let Ok(root) = read_key(&context, &hive, &table, hive.root_cell_offset(), String::new())
            else {
                continue;
            };
            // The path is spelled as the hive spells it, not as it was
            // looked up.
            let mut base_path = root_name;
            let mut current = root;
            let mut found = true;
            for component in USERASSIST_PATH {
                let children = subkeys(&context, &hive, &table, &current).unwrap_or_default();
                match children.into_iter().find(|child| {
                    child
                        .name()
                        .map(|name| name.eq_ignore_ascii_case(component))
                        .unwrap_or(false)
                }) {
                    Some(child) => {
                        base_path = format!("{base_path}\\{}", child.name().unwrap_or_default());
                        current = child;
                    }
                    None => {
                        found = false;
                        break;
                    }
                }
            }
            if !found {
                continue;
            }
            let userassist = current;

            // Each GUID key groups one category of launches, and holds a Count
            // key with the records themselves.
            for guid_key in subkeys(&context, &hive, &table, &userassist).unwrap_or_default() {
                let Ok(guid_name) = guid_key.name() else {
                    continue;
                };
                for count_key in subkeys(&context, &hive, &table, &guid_key).unwrap_or_default() {
                    let Ok(count_name) = count_key.name() else {
                        continue;
                    };
                    let path = format!("{base_path}\\{guid_name}\\{count_name}");
                    let last_write = count_key
                        .last_write_time()
                        .map(wintime_value)
                        .unwrap_or_else(|_| Value::unreadable());

                    grid.push(
                        0,
                        vec![
                            Value::hex(hive_offset),
                            Value::string(hive_name.clone()),
                            Value::string(path.clone()),
                            last_write.clone(),
                            Value::string("Key"),
                            Value::not_applicable(),
                            Value::not_applicable(),
                            Value::not_applicable(),
                            Value::not_applicable(),
                            Value::not_applicable(),
                            Value::not_applicable(),
                            Value::not_applicable(),
                        ],
                    )?;

                    for subkey in subkeys(&context, &hive, &table, &count_key).unwrap_or_default() {
                        grid.push(
                            1,
                            vec![
                                Value::hex(hive_offset),
                                Value::string(hive_name.clone()),
                                Value::string(path.clone()),
                                last_write.clone(),
                                Value::string("Subkey"),
                                subkey
                                    .name()
                                    .map(Value::string)
                                    .unwrap_or_else(|_| Value::unreadable()),
                                Value::not_applicable(),
                                Value::not_applicable(),
                                Value::not_applicable(),
                                Value::not_applicable(),
                                Value::not_applicable(),
                                Value::not_applicable(),
                            ],
                        )?;
                    }

                    for value in values(&context, &hive, &table, &count_key).unwrap_or_default() {
                        // The names are turned about by thirteen letters, and
                        // the folders they sit in are named by identifier.
                        let name = match value.name() {
                            Ok(name) => {
                                let name = rot13(&name);
                                Value::string(match win7 {
                                    Some(true) => expand_folder(&name),
                                    _ => name,
                                })
                            }
                            Err(_) => Value::unreadable(),
                        };

                        let data = value.data(&hive).unwrap_or_default();
                        let record = layout
                            .as_ref()
                            .and_then(|layout| layout.parse(&data));

                        let mut row = vec![
                            Value::hex(hive_offset),
                            Value::string(hive_name.clone()),
                            Value::string(path.clone()),
                            last_write.clone(),
                            Value::string("Value"),
                            name,
                        ];
                        match record {
                            Some(record) => {
                                row.push(record.id);
                                row.push(record.count);
                                row.push(record.focus_count);
                                row.push(record.time_focused);
                                row.push(record.last_updated);
                            }
                            None => {
                                // Without a record only the bytes themselves
                                // can be reported.
                                for _ in 0..5 {
                                    row.push(Value::unparsable());
                                }
                            }
                        }
                        row.push(Value::HexDump(data));
                        grid.push(1, row)?;
                    }
                }
            }
        }
        Ok(grid)
    }
}

/// Where the fields of a record sit, which differs between Windows versions.
struct Layout {
    win7: bool,
    size: usize,
    fields: std::collections::HashMap<String, u64>,
}

impl Layout {
    fn new(context: &Arc<Context>, win7: bool) -> Option<Self> {
        let type_name = if win7 {
            "registry!_VOL_USERASSIST_TYPES_7"
        } else {
            "registry!_VOL_USERASSIST_TYPES_XP"
        };
        let template = context.symbol_space.get_type(type_name).ok()?;
        let size = context.symbol_space.size_of(&template).ok()? as usize;

        let mut fields = std::collections::HashMap::new();
        for name in [
            "ID",
            "Count",
            "CountStartingAtFive",
            "FocusCount",
            "FocusTime",
            "LastUpdated",
        ] {
            if let Ok(Some((offset, _))) = context.symbol_space.find_member(&template, name) {
                fields.insert(name.to_string(), offset);
            }
        }
        Some(Self { win7, size, fields })
    }

    /// Read the record out of a value's data, if the data is long enough to
    /// hold one.
    fn parse(&self, data: &[u8]) -> Option<Record> {
        if data.len() < self.size {
            return None;
        }
        let word = |name: &str| -> Option<u32> {
            let at = *self.fields.get(name)? as usize;
            data.get(at..at + 4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
        };
        let quad = |name: &str| -> Option<u64> {
            let at = *self.fields.get(name)? as usize;
            data.get(at..at + 8)
                .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
        };

        let last_updated = quad("LastUpdated")
            .map(wintime_value)
            .unwrap_or_else(Value::unparsable);

        if self.win7 {
            let focus_time = word("FocusTime").unwrap_or(0);
            return Some(Record {
                // Later records carry no identifier at all.
                id: Value::not_applicable(),
                count: word("Count")
                    .map(|count| Value::int(count as i64))
                    .unwrap_or_else(Value::unparsable),
                focus_count: word("FocusCount")
                    .map(|count| Value::int(count as i64))
                    .unwrap_or_else(Value::unparsable),
                // The time is recorded in milliseconds and reported as a span.
                time_focused: Value::string(duration_text(focus_time)),
                last_updated,
            });
        }

        let count = word("CountStartingAtFive").unwrap_or(0);
        Some(Record {
            id: word("ID")
                .map(|id| Value::int(id as i64))
                .unwrap_or_else(Value::unparsable),
            // The count starts at five rather than zero.
            count: Value::int(if count < 5 { count as i64 } else { count as i64 - 5 }),
            focus_count: Value::not_applicable(),
            time_focused: Value::not_applicable(),
            last_updated,
        })
    }
}

/// A span of milliseconds, written the way the interpreter writes one.
///
/// The value is rounded to the nearest half-second before being turned into a
/// span, which is what upstream does.
fn duration_text(milliseconds: u32) -> String {
    let seconds = (milliseconds as f64 + 500.0) / 1000.0;
    let whole = seconds.trunc() as i64;
    let micro = ((seconds - whole as f64) * 1_000_000.0).round() as i64;

    let days = whole / 86_400;
    let rest = whole % 86_400;
    let (hours, minutes, secs) = (rest / 3600, (rest % 3600) / 60, rest % 60);

    let mut text = String::new();
    if days > 0 {
        text.push_str(&format!(
            "{days} day{}, ",
            if days == 1 { "" } else { "s" }
        ));
    }
    text.push_str(&format!("{hours}:{minutes:02}:{secs:02}"));
    if micro != 0 {
        text.push_str(&format!(".{micro:06}"));
    }
    text
}

/// The name of the folder an identifier stands for, where one is known.
fn expand_folder(name: &str) -> String {
    let Some(guid) = name.split('\\').next() else {
        return name.to_string();
    };
    match folder_names().get(guid) {
        Some(folder) => name.replacen(guid, folder, 1),
        None => name.to_string(),
    }
}

/// The identifiers Windows gives its own folders.
fn folder_names() -> &'static std::collections::HashMap<String, String> {
    static FOLDERS: std::sync::OnceLock<std::collections::HashMap<String, String>> =
        std::sync::OnceLock::new();
    FOLDERS.get_or_init(|| {
        serde_json::from_str(include_str!("../../../../../data/userassist_folders.json"))
            .unwrap_or_default()
    })
}

/// A decoded record, as its cells.
struct Record {
    id: Value,
    count: Value,
    focus_count: Value,
    time_focused: Value,
    last_updated: Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rot13_round_trips_and_leaves_punctuation_alone() {
        let encoded = "P:\\Jvaqbjf\\flfgrz32\\pzq.rkr";
        assert_eq!(rot13(encoded), "C:\\Windows\\system32\\cmd.exe");
        // Applying it twice returns the original, as a rotation of 13 should.
        assert_eq!(rot13(&rot13(encoded)), encoded);
    }

    #[test]
    fn a_span_of_milliseconds_reads_as_the_interpreter_writes_it() {
        // Half a second is added before the value is turned into a span.
        assert_eq!(duration_text(0), "0:00:00.500000");
        assert_eq!(duration_text(500), "0:00:01");
        assert_eq!(duration_text(17_797_448), "4:56:37.948000");
        assert_eq!(duration_text(90_000_000), "1 day, 1:00:00.500000");
    }

    #[test]
    fn a_known_folder_identifier_is_replaced_by_its_name() {
        let name = "{6D809377-6AF0-444B-8957-A3773F02200E}\\Everything\\Everything.exe";
        assert!(expand_folder(name).ends_with("Everything\\Everything.exe"));
        // A name that carries no identifier is left exactly as it is.
        assert_eq!(expand_folder("C:\\Windows\\cmd.exe"), "C:\\Windows\\cmd.exe");
    }
}
