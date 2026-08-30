//! Report the AmCache, which records the programs and drivers a system has seen.
//!
//! Windows keeps a hive of its own describing every executable and driver it
//! has come across, whether or not it still exists on disk. That makes it one
//! of the few records that survives a program deleting itself.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::layers::registry::RegistryHive;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::conversion::wintime_value;
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::windows::registry::{
    read_key, subkeys, values, RegistryKey, RegistryValue, ValueType,
};

pub struct Amcache;

/// One record, in the order its columns are reported.
#[derive(Clone)]
struct Entry {
    kind: &'static str,
    path: Value,
    company: Value,
    last_modified: Value,
    last_modified_2: Value,
    installed: Value,
    compiled: Value,
    sha1: Value,
    service: Value,
    product: Value,
    version: Value,
}

impl Entry {
    /// A record with nothing yet known about it. Every field is one this kind
    /// of record does not carry.
    fn new(kind: &'static str) -> Self {
        Self {
            kind,
            path: Value::not_applicable(),
            company: Value::not_applicable(),
            last_modified: Value::not_applicable(),
            last_modified_2: Value::not_applicable(),
            installed: Value::not_applicable(),
            compiled: Value::not_applicable(),
            sha1: Value::not_applicable(),
            service: Value::not_applicable(),
            product: Value::not_applicable(),
            version: Value::not_applicable(),
        }
    }

    fn row(self) -> Vec<Value> {
        vec![
            Value::string(self.kind),
            self.path,
            self.company,
            self.last_modified,
            self.last_modified_2,
            self.installed,
            self.compiled,
            self.sha1,
            self.service,
            self.product,
            self.version,
        ]
    }
}

impl Plugin for Amcache {
    fn name(&self) -> &'static str {
        "windows.registry.amcache.Amcache"
    }

    fn description(&self) -> &'static str {
        "Extract information on executed applications from the AmCache."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("EntryType"),
            Column::string("Path"),
            Column::string("Company"),
            Column::datetime("LastModifyTime"),
            Column::datetime("LastModifyTime2"),
            Column::datetime("InstallTime"),
            Column::datetime("CompileTime"),
            Column::string("SHA1"),
            Column::string("Service"),
            Column::string("ProductName"),
            Column::string("ProductVersion"),
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
            let (kind, path) = (text(&values[0]), text(&values[1]));
            if is_time(&values[3]) {
                timeline.push(
                    format!("Amcache: {kind} {path} registry key modified"),
                    TimeKind::Modified,
                    values[3].clone(),
                );
            }
            if is_time(&values[4]) {
                timeline.push(
                    format!("Amcache: {kind} {path} STANDARD_INFORMATION create time"),
                    TimeKind::Created,
                    values[4].clone(),
                );
            }
            if is_time(&values[5]) {
                timeline.push(
                    format!("Amcache: {kind} {path} installed"),
                    TimeKind::Created,
                    values[5].clone(),
                );
            }
            if is_time(&values[6]) {
                timeline.push(
                    format!("Amcache: {kind} {path} compiled (PE metadata)"),
                    TimeKind::Modified,
                    values[6].clone(),
                );
            }
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let table = kernel.symbol_table_name.clone();
        let mut grid = TreeGrid::new(self.columns());

        // Only the machine's own AmCache hive holds any of this.
        let mut hive = None;
        for hive_object in super::list_hives(&context, &kernel)? {
            let Ok(candidate) = super::open_hive(&context, &kernel, hive_object) else {
                continue;
            };
            if candidate
                .hive_name()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .contains("amcache")
            {
                hive = Some(candidate);
                break;
            }
        }
        let Some(hive) = hive else {
            return Ok(grid);
        };

        let Ok(root) = read_key(&context, &hive, &table, hive.root_cell_offset(), String::new())
        else {
            return Ok(grid);
        };
        let reader = Reader {
            context: &context,
            hive: &hive,
            table: &table,
        };

        // Drivers first, each standing on its own.
        if let Some(key) = reader.key(&root, &["Root", "InventoryDriverBinary"]) {
            for entry in reader.driver_binaries(&key) {
                grid.push(0, entry.row())?;
            }
        }

        // Then the two generations of program-and-file records, each of which
        // nests its files under the program they belong to.
        for (program_path, file_path, generation) in [
            (
                ["Root", "Programs"],
                ["Root", "File"],
                Generation::WindowsEight,
            ),
            (
                ["Root", "InventoryApplication"],
                ["Root", "InventoryApplicationFile"],
                Generation::WindowsTen,
            ),
        ] {
            let mut programs: Vec<(String, Entry)> = reader
                .key(&root, &program_path)
                .map(|key| match generation {
                    Generation::WindowsEight => reader.programs(&key),
                    Generation::WindowsTen => reader.inventory_applications(&key),
                })
                .unwrap_or_default();

            let mut files: Vec<(Option<String>, Entry)> = reader
                .key(&root, &file_path)
                .map(|key| match generation {
                    Generation::WindowsEight => reader.files(&key),
                    Generation::WindowsTen => reader.inventory_files(&key),
                })
                .unwrap_or_default();
            // Files are grouped by the program they belong to, and a file
            // whose program is unknown sorts first.
            files.sort_by(|left, right| {
                left.0
                    .clone()
                    .unwrap_or_default()
                    .cmp(&right.0.clone().unwrap_or_default())
            });

            let mut index = 0;
            while index < files.len() {
                let program_id = files[index].0.clone();
                let mut end = index;
                while end < files.len() && files[end].0 == program_id {
                    end += 1;
                }

                // A file whose program is listed is reported beneath it, and
                // the program is only reported once.
                let mut depth = 0;
                if let Some(program_id) = &program_id {
                    let wanted = program_id.trim().trim_matches('\0').to_string();
                    if let Some(position) = programs.iter().position(|(id, _)| *id == wanted) {
                        let (_, program) = programs.remove(position);
                        grid.push(0, program.row())?;
                        depth = 1;
                    }
                }
                for (_, entry) in &files[index..end] {
                    grid.push(depth, entry.clone().row())?;
                }
                index = end;
            }

            // A program none of the files named is still worth reporting.
            for (_, program) in programs {
                grid.push(0, program.row())?;
            }
        }
        Ok(grid)
    }
}

/// Which generation of records a key holds.
enum Generation {
    WindowsEight,
    WindowsTen,
}

/// Reads records out of the AmCache hive.
struct Reader<'a> {
    context: &'a Arc<Context>,
    hive: &'a RegistryHive,
    table: &'a str,
}

impl Reader<'_> {
    /// Follow a path of subkey names.
    fn key(&self, root: &RegistryKey, path: &[&str]) -> Option<RegistryKey> {
        let mut current = root.clone();
        for component in path {
            let children = subkeys(self.context, self.hive, self.table, &current).ok()?;
            current = children.into_iter().find(|child| {
                child
                    .name()
                    .map(|name| name.eq_ignore_ascii_case(component))
                    .unwrap_or(false)
            })?;
        }
        Some(current)
    }

    /// The values of a key, by name.
    fn values(&self, key: &RegistryKey) -> HashMap<String, RegistryValue> {
        let mut found = HashMap::new();
        for value in values(self.context, self.hive, self.table, key).unwrap_or_default() {
            if let Ok(name) = value.name() {
                found.insert(name, value);
            }
        }
        found
    }

    /// A value read as text.
    fn text(&self, values: &HashMap<String, RegistryValue>, name: &str) -> Value {
        let Some(value) = values.get(name) else {
            // A record that never carried this is not the same as one whose
            // value could not be read.
            return Value::not_available();
        };
        // Only the string kinds hold text. A number here is not one.
        if matches!(
            value.value_type(),
            ValueType::Dword | ValueType::DwordBigEndian | ValueType::Qword
        ) {
            return Value::unparsable();
        }
        let Ok(data) = value.data(self.hive) else {
            return Value::unparsable();
        };
        Value::string(decode_utf16(&data))
    }

    /// A value read as text, kept as a string for matching.
    fn text_string(&self, values: &HashMap<String, RegistryValue>, name: &str) -> Option<String> {
        match self.text(values, name) {
            Value::Str(text) => Some(text),
            _ => None,
        }
    }

    /// A value read as a Windows timestamp.
    fn filetime(&self, values: &HashMap<String, RegistryValue>, name: &str) -> Value {
        match self.number(values, name) {
            Ok(Some(number)) => wintime_value(number),
            Ok(None) => Value::not_available(),
            Err(()) => Value::unparsable(),
        }
    }

    /// A value read as seconds since the Unix epoch.
    fn epoch(&self, values: &HashMap<String, RegistryValue>, name: &str) -> Value {
        match self.number(values, name) {
            Ok(Some(number)) => match chrono::DateTime::from_timestamp(number as i64, 0) {
                Some(time) => Value::DateTime(time),
                None => Value::unparsable(),
            },
            Ok(None) => Value::not_available(),
            Err(()) => Value::unparsable(),
        }
    }

    /// A value that holds a number rather than text.
    fn number(
        &self,
        values: &HashMap<String, RegistryValue>,
        name: &str,
    ) -> std::result::Result<Option<u64>, ()> {
        let Some(value) = values.get(name) else {
            return Ok(None);
        };
        let data = value.data(self.hive).map_err(|_| ())?;
        match value.value_type() {
            ValueType::Dword if data.len() == 4 => {
                Ok(Some(u32::from_le_bytes(data.try_into().unwrap()) as u64))
            }
            ValueType::DwordBigEndian if data.len() == 4 => {
                Ok(Some(u32::from_be_bytes(data.try_into().unwrap()) as u64))
            }
            ValueType::Qword if data.len() == 8 => {
                Ok(Some(u64::from_le_bytes(data.try_into().unwrap())))
            }
            _ => Err(()),
        }
    }

    /// The drivers the system has installed.
    fn driver_binaries(&self, key: &RegistryKey) -> Vec<Entry> {
        let mut found = Vec::new();
        for binary in subkeys(self.context, self.hive, self.table, key).unwrap_or_default() {
            let values = self.values(&binary);
            let name = binary.name().unwrap_or_default();

            // Depending on the release the key is named after the driver or
            // after its hash.
            let (driver_name, sha1) = if name.contains('/') {
                (Value::string(name), self.text(&values, "DriverId"))
            } else {
                (self.text(&values, "DriverName"), Value::string(name))
            };

            let mut entry = Entry::new("Driver");
            entry.path = driver_name;
            entry.company = self.text(&values, "DriverCompany");
            entry.last_modified = binary
                .last_write_time()
                .map(wintime_value)
                .unwrap_or_else(|_| Value::unparsable());
            entry.compiled = self.epoch(&values, "DriverTimeStamp");
            entry.sha1 = trim_hash(sha1, true);
            entry.service = self.text(&values, "Service");
            entry.product = self.text(&values, "Product");
            found.push(entry);
        }
        found
    }

    /// The Windows 8 program records.
    fn programs(&self, key: &RegistryKey) -> Vec<(String, Entry)> {
        let mut found = Vec::new();
        for program in subkeys(self.context, self.hive, self.table, key).unwrap_or_default() {
            let Ok(program_id) = program.name() else {
                continue;
            };
            let values = self.values(&program);

            let mut entry = Entry::new("Program");
            entry.product = self.text(&values, "0");
            entry.version = self.text(&values, "1");
            entry.company = self.text(&values, "2");
            entry.installed = self.epoch(&values, "a");
            entry.last_modified = program
                .last_write_time()
                .map(wintime_value)
                .unwrap_or_else(|_| Value::unparsable());
            found.push((program_id.trim().trim_matches('\0').to_string(), entry));
        }
        found
    }

    /// The Windows 8 file records.
    fn files(&self, key: &RegistryKey) -> Vec<(Option<String>, Entry)> {
        let mut found = Vec::new();
        for group in subkeys(self.context, self.hive, self.table, key).unwrap_or_default() {
            for file in subkeys(self.context, self.hive, self.table, &group).unwrap_or_default() {
                let values = self.values(&file);

                let mut entry = Entry::new("File");
                entry.path = self.text(&values, "15");
                entry.company = self.text(&values, "1");
                entry.last_modified = self.filetime(&values, "11");
                entry.last_modified_2 = self.filetime(&values, "17");
                entry.installed = self.filetime(&values, "12");
                entry.compiled = self.epoch(&values, "f");
                entry.sha1 = trim_hash(self.text(&values, "101"), false);
                entry.product = self.text(&values, "0");
                found.push((self.text_string(&values, "100"), entry));
            }
        }
        found
    }

    /// The Windows 10 program records.
    fn inventory_applications(&self, key: &RegistryKey) -> Vec<(String, Entry)> {
        let mut found = Vec::new();
        for program in subkeys(self.context, self.hive, self.table, key).unwrap_or_default() {
            let Ok(program_id) = program.name() else {
                continue;
            };
            let values = self.values(&program);

            let name = self.text(&values, "Name");
            let mut entry = Entry::new("Program");
            entry.path = self.text(&values, "RootDirPath");
            entry.company = self.text(&values, "Publisher");
            entry.last_modified = program
                .last_write_time()
                .map(wintime_value)
                .unwrap_or_else(|_| Value::unparsable());
            // The install date is recorded as text, which is never read back
            // as a time.
            entry.installed = match values.contains_key("InstallDate") {
                true => Value::unparsable(),
                false => Value::not_available(),
            };
            entry.product = match name {
                Value::Str(name) => Value::string(name),
                _ => Value::string("UNKNOWN"),
            };
            entry.version = self.text(&values, "Version");
            found.push((program_id.trim().trim_matches('\0').to_string(), entry));
        }
        found
    }

    /// The Windows 10 file records.
    fn inventory_files(&self, key: &RegistryKey) -> Vec<(Option<String>, Entry)> {
        let mut found = Vec::new();
        for file in subkeys(self.context, self.hive, self.table, key).unwrap_or_default() {
            let values = self.values(&file);

            let mut entry = Entry::new("File");
            entry.path = self.text(&values, "LowerCaseLongPath");
            entry.company = self.text(&values, "Publisher");
            entry.last_modified = file
                .last_write_time()
                .map(wintime_value)
                .unwrap_or_else(|_| Value::unparsable());
            entry.compiled = match values.contains_key("LinkDate") {
                true => Value::unparsable(),
                false => Value::not_available(),
            };
            entry.sha1 = trim_hash(self.text(&values, "FileId"), false);
            entry.product = self.text(&values, "ProductName");
            entry.version = self.text(&values, "ProductVersion");
            found.push((self.text_string(&values, "ProgramId"), entry));
        }
        found
    }
}

/// A hash as the cache stores it, with the padding it is written with removed.
///
/// A driver's hash has a four-character prefix cut from it before the leading
/// zeros are stripped. A file's has only the zeros.
fn trim_hash(value: Value, driver: bool) -> Value {
    let Value::Str(text) = value else {
        return value;
    };
    let text = if driver && text.starts_with("0000") {
        text[4..].to_string()
    } else {
        text
    };
    Value::string(text.trim_start_matches('0').to_string())
}

/// Decode a value's bytes as the wide text they are, dropping the terminator.
fn decode_utf16(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&units)
        .trim_end_matches('\0')
        .to_string()
}
