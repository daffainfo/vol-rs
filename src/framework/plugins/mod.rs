//! The plugin interface and registry.
//!
//! A plugin declares what configuration it needs, what columns it produces, and
//! how to fill them in. Everything else (argument parsing, layer stacking,
//! rendering) is handled by the framework around it.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

pub mod windows;
pub mod linux;
pub mod mac;
pub mod generic;
pub mod common;

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{ConfigValue, Configuration, Context};
use crate::framework::renderers::{Column, TreeGrid, Value};

/// The type of a configuration option a plugin accepts.
#[derive(Debug, Clone, PartialEq)]
pub enum RequirementKind {
    Int,
    String,
    Bool,
    Bytes,
    /// Repeated values of the inner kind.
    List(Box<RequirementKind>),
    /// A string restricted to a fixed set.
    Choice(Vec<String>),
    /// The kernel module and symbols the plugin operates on, supplied by
    /// automagic rather than by the user.
    Kernel,
    /// A layer name, likewise supplied by automagic.
    TranslationLayer,
}

/// One configuration option.
#[derive(Debug, Clone)]
pub struct Requirement {
    pub name: String,
    pub description: String,
    pub kind: RequirementKind,
    pub optional: bool,
    pub default: Option<ConfigValue>,
    /// The architectures a layer requirement will accept, where it insists on
    /// any. A requirement that names them needs a layer the processor's own
    /// paging describes, not merely the bytes of the image.
    pub architectures: Option<&'static [&'static str]>,
}

impl Requirement {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        kind: RequirementKind,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            kind,
            optional: true,
            default: None,
            architectures: None,
        }
    }

    /// Restrict a layer requirement to the architectures it can work with.
    pub fn for_architectures(mut self, architectures: &'static [&'static str]) -> Self {
        self.architectures = Some(architectures);
        self
    }

    /// Mark the requirement as one the plugin cannot run without.
    pub fn required(mut self) -> Self {
        self.optional = false;
        self
    }

    pub fn with_default(mut self, default: ConfigValue) -> Self {
        self.default = Some(default);
        self
    }

    /// The kernel requirement almost every OS plugin declares.
    pub fn kernel() -> Self {
        Requirement::new(
            "kernel",
            "The kernel module and its symbol table",
            RequirementKind::Kernel,
        )
        .required()
    }

    /// The same filter under the name upstream gives it in some plugins.
    ///
    /// The wording of the description varies from plugin to plugin upstream,
    /// so each caller supplies its own.
    pub fn pids_filter(description: &str) -> Self {
        Requirement::new(
            "pids",
            description,
            RequirementKind::List(Box::new(RequirementKind::Int)),
        )
    }

    /// The conventional `--pid` filter.
    pub fn pid_filter(description: &str) -> Self {
        Requirement::new(
            "pid",
            description,
            RequirementKind::List(Box::new(RequirementKind::Int)),
        )
    }
}

/// The four kinds of timestamp a timeline distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeKind {
    Created,
    Modified,
    Accessed,
    Changed,
}

/// The timestamps a plugin contributes to the timeline.
///
/// `failed` records that the plugin stopped early, which matters because the
/// timeline plugin treats a plugin that raised differently from one that simply
/// had nothing to say.
pub struct Timeline {
    pub entries: Vec<(String, TimeKind, Value)>,
    pub failed: bool,
}

impl Timeline {
    pub fn new() -> Self {
        Timeline {
            entries: Vec::new(),
            failed: false,
        }
    }

    pub fn push(&mut self, description: impl Into<String>, kind: TimeKind, when: Value) {
        self.entries.push((description.into(), kind, when));
    }
}

impl Default for Timeline {
    fn default() -> Self {
        Timeline::new()
    }
}

/// Small helpers for reading a plugin's own rows back when building a timeline.
///
/// The descriptions a timeline carries are built from the same values the
/// plugin printed, and the reference implementation renders them there with
/// Python's own formatting: a number is written in decimal even where the
/// column shows it in hexadecimal.
pub mod timeline_helpers {
    use super::Value;

    /// A value as its plain text, without the column's formatting.
    ///
    /// An absent value is written the way its own class prints itself, which is
    /// not always how the renderer shows it in a column: a value that was never
    /// available prints as `N/A` here but as a dash in a table.
    pub fn text(value: &Value) -> String {
        match value {
            Value::Absent(crate::framework::renderers::AbsentValue::NotAvailable) => {
                "N/A".to_string()
            }
            Value::Absent(crate::framework::renderers::AbsentValue::Unparsable) => {
                "-".to_string()
            }
            other => other.to_string(),
        }
    }

    /// A number in decimal, whatever base its column displays it in.
    pub fn number(value: &Value) -> String {
        match value {
            Value::Int(number, _) => number.to_string(),
            Value::UInt(number, _) => number.to_string(),
            other => text(other),
        }
    }

    /// Whether a value is a timestamp rather than an absent value.
    pub fn is_time(value: &Value) -> bool {
        matches!(value, Value::DateTime(_))
    }
}

/// What a plugin needs and what it produces.
pub trait Plugin: Send + Sync {
    /// The dotted name the plugin is invoked by, such as `windows.pslist.PsList`.
    fn name(&self) -> &'static str;

    /// One line describing what the plugin reports.
    fn description(&self) -> &'static str;

    /// The rest of the plugin's documentation, printed after its options.
    ///
    /// Upstream takes the first paragraph of a plugin's docstring as its one
    /// line description and everything after it as this trailing note.
    fn epilog(&self) -> Option<&'static str> {
        None
    }

    /// Configuration options the plugin accepts.
    fn requirements(&self) -> Vec<Requirement>;

    /// The columns the plugin's output has.
    fn columns(&self) -> Vec<Column>;

    /// Produce the plugin's output.
    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid>;

    /// The timestamps this plugin can contribute to a timeline.
    ///
    /// A plugin that reports no times returns nothing and is left out of the
    /// timeline entirely.
    fn timeline(&self, _context: Arc<Context>, _config: &Configuration) -> Option<Timeline> {
        None
    }

    /// Operating system the plugin applies to, used to filter the plugin list
    /// for an image once its OS is known.
    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Any
    }

    /// Whether the image's kernel has to be identified before the plugin runs,
    /// for a plugin that declares no kernel of its own because it runs others.
    fn needs_kernel(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatingSystem {
    Windows,
    Linux,
    Mac,
    /// Applies regardless of the image's operating system.
    Any,
}

impl OperatingSystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            OperatingSystem::Windows => "windows",
            OperatingSystem::Linux => "linux",
            OperatingSystem::Mac => "mac",
            OperatingSystem::Any => "any",
        }
    }
}

/// Exposes a plugin under a second name.
///
/// Several Linux plugins moved into a `malware` sub-package but kept their
/// original path working, so upstream registers both. An alias delegates
/// everything except the name, so the two entries cannot drift apart.
pub struct Alias<P: Plugin> {
    inner: P,
    name: &'static str,
    description: Option<&'static str>,
    epilog: Option<&'static str>,
}

impl<P: Plugin> Alias<P> {
    pub fn new(inner: P, name: &'static str) -> Self {
        Self {
            inner,
            name,
            description: None,
            epilog: None,
        }
    }

    /// Describe the alias in its own words.
    ///
    /// A plugin that moved keeps working under its old name, and upstream
    /// marks that older name as deprecated in its description.
    pub fn with_description(mut self, description: &'static str) -> Self {
        self.description = Some(description);
        self
    }

    /// Give the alias its own trailing note.
    pub fn with_epilog(mut self, epilog: &'static str) -> Self {
        self.epilog = Some(epilog);
        self
    }
}

impl<P: Plugin> Plugin for Alias<P> {
    fn name(&self) -> &'static str {
        self.name
    }

    fn description(&self) -> &'static str {
        self.description.unwrap_or_else(|| self.inner.description())
    }

    fn epilog(&self) -> Option<&'static str> {
        self.epilog.or_else(|| self.inner.epilog())
    }

    fn requirements(&self) -> Vec<Requirement> {
        self.inner.requirements()
    }

    fn columns(&self) -> Vec<Column> {
        self.inner.columns()
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        self.inner.run(context, config)
    }

    fn timeline(&self, context: Arc<Context>, config: &Configuration) -> Option<Timeline> {
        self.inner.timeline(context, config)
    }

    fn operating_system(&self) -> OperatingSystem {
        self.inner.operating_system()
    }

    fn needs_kernel(&self) -> bool {
        self.inner.needs_kernel()
    }
}

/// Every plugin the binary knows about.
pub struct PluginRegistry {
    plugins: Vec<Arc<dyn Plugin>>,
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRegistry {
    /// Build the registry with every built-in plugin registered.
    pub fn new() -> Self {
        let mut registry = Self {
            plugins: Vec::new(),
        };
        generic::register(&mut registry);
        windows::register(&mut registry);
        linux::register(&mut registry);
        mac::register(&mut registry);
        registry.plugins.sort_by_key(|plugin| plugin.name());
        registry
    }

    pub fn add(&mut self, plugin: Arc<dyn Plugin>) {
        self.plugins.push(plugin);
    }

    pub fn all(&self) -> &[Arc<dyn Plugin>] {
        &self.plugins
    }

    /// Look up a plugin by its exact name, or by a unique case-insensitive
    /// suffix so `pslist` finds `windows.pslist.PsList`.
    pub fn get(&self, name: &str) -> Option<Arc<dyn Plugin>> {
        if let Some(exact) = self.plugins.iter().find(|plugin| plugin.name() == name) {
            return Some(exact.clone());
        }

        let lowered = name.to_ascii_lowercase();
        let matches: Vec<&Arc<dyn Plugin>> = self
            .plugins
            .iter()
            .filter(|plugin| plugin.name().to_ascii_lowercase() == lowered)
            .collect();
        if matches.len() == 1 {
            return Some(matches[0].clone());
        }
        None
    }

    /// Plugins whose name contains `needle`, for the listing command.
    pub fn search(&self, needle: &str) -> Vec<Arc<dyn Plugin>> {
        let lowered = needle.to_ascii_lowercase();
        self.plugins
            .iter()
            .filter(|plugin| plugin.name().to_ascii_lowercase().contains(&lowered))
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }
}

/// Read the conventional `pid` filter from configuration.
/// The process filter for plugins that name the option `pids`.
pub fn pids_filter(config: &Configuration) -> Option<Vec<u64>> {
    read_pid_list(config, "pids")
}

pub fn pid_filter(config: &Configuration) -> Option<Vec<u64>> {
    read_pid_list(config, "pid")
}

fn read_pid_list(config: &Configuration, name: &str) -> Option<Vec<u64>> {
    let value = config.get(name)?;
    match value {
        ConfigValue::List(values) => {
            let pids: Vec<u64> = values
                .iter()
                .filter_map(|entry| entry.as_int())
                .map(|pid| pid as u64)
                .collect();
            (!pids.is_empty()).then_some(pids)
        }
        other => other.as_int().map(|pid| vec![pid as u64]),
    }
}

/// Whether a PID passes the configured filter.
pub fn pid_matches(filter: &Option<Vec<u64>>, pid: u64) -> bool {
    match filter {
        Some(pids) => pids.contains(&pid),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_resolves_plugins_by_name() {
        let registry = PluginRegistry::new();
        assert!(!registry.is_empty());
        // Every registered plugin is retrievable by its own name.
        for plugin in registry.all() {
            assert!(registry.get(plugin.name()).is_some());
        }
    }

    #[test]
    fn plugin_names_are_unique() {
        let registry = PluginRegistry::new();
        let mut names: Vec<&str> = registry.all().iter().map(|p| p.name()).collect();
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "duplicate plugin names registered");
    }

    #[test]
    fn pid_filter_accepts_a_single_value_or_a_list() {
        let config = Configuration::new();
        assert!(pid_filter(&config).is_none());

        config.set("pid", ConfigValue::Int(4));
        assert_eq!(pid_filter(&config), Some(vec![4]));

        config.set(
            "pid",
            ConfigValue::List(vec![ConfigValue::Int(4), ConfigValue::Int(8)]),
        );
        let filter = pid_filter(&config);
        assert!(pid_matches(&filter, 8));
        assert!(!pid_matches(&filter, 9));
        // No filter means everything passes.
        assert!(pid_matches(&None, 12345));
    }
}

/// Write a file a plugin has extracted, without overwriting an earlier one.
///
/// A run can produce two files that want the same name (the same executable
/// running as several processes, say), so a name already taken gains a counter.
/// The name actually written is returned: a plugin that reports its files after
/// writing them reports that one, while a plugin that reports them as it opens
/// them reports the name it asked for.
pub fn write_extracted(name: &str, data: &[u8]) -> std::io::Result<String> {
    let chosen = free_extracted_name(name);
    std::fs::write(output_path(&chosen), data)?;
    Ok(chosen)
}

/// Where files plugins produce are written.
fn output_directory() -> &'static std::sync::RwLock<Option<std::path::PathBuf>> {
    static DIRECTORY: std::sync::OnceLock<std::sync::RwLock<Option<std::path::PathBuf>>> =
        std::sync::OnceLock::new();
    DIRECTORY.get_or_init(|| std::sync::RwLock::new(None))
}

/// Write extracted files somewhere other than the working directory.
pub fn set_output_directory(path: std::path::PathBuf) {
    *output_directory().write().unwrap() = Some(path);
}

/// The full path a named output file takes.
pub fn output_path(name: &str) -> std::path::PathBuf {
    match output_directory().read().unwrap().clone() {
        Some(directory) => directory.join(name),
        None => std::path::PathBuf::from(name),
    }
}

/// The name an extracted file will actually take, given what is already there.
pub fn free_extracted_name(name: &str) -> String {
    if !output_path(name).exists() {
        return name.to_string();
    }
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, extension)) => (stem, format!(".{extension}")),
        None => (name, String::new()),
    };
    for counter in 1.. {
        let candidate = format!("{stem}-{counter}{extension}");
        if !output_path(&candidate).exists() {
            return candidate;
        }
    }
    unreachable!()
}

/// A run of bytes read out of a layer, rendered as the reference implementation
/// renders one.
///
/// Bytes the layer does not actually hold are marked rather than shown as the
/// zeroes a padded read supplies, so a match recovered in part is visibly
/// different from one recovered whole.
pub fn layer_data(
    context: &std::sync::Arc<Context>,
    layer: &str,
    offset: u64,
    length: u64,
) -> Option<crate::framework::renderers::Value> {
    let bytes = context
        .layers
        .read(layer, offset, length as usize, true)
        .ok()?;
    if bytes.is_empty() {
        return None;
    }
    Some(crate::framework::renderers::Value::LayerDump {
        missing: unmapped_bytes(context, layer, offset, length),
        bytes,
    })
}

/// Which of a range's bytes the layer has no memory behind.
fn unmapped_bytes(
    context: &std::sync::Arc<Context>,
    layer: &str,
    start: u64,
    length: u64,
) -> Vec<usize> {
    let Ok(handle) = context.layers.get(layer) else {
        return Vec::new();
    };
    let entries = handle
        .mapping(&context.layers, start, length, true)
        .unwrap_or_default();
    if entries.is_empty() {
        return Vec::new();
    }

    let mut missing = Vec::new();
    let mut index = 0usize;
    let mut current = &entries[0];
    for address in start..start + length {
        if address < current.offset {
            missing.push((address - start) as usize);
        }
        if address > current.offset + current.size && index + 1 < entries.len() {
            index += 1;
            current = &entries[index];
        }
        if address > current.offset + current.size {
            missing.push((address - start) as usize);
        }
    }
    missing.dedup();
    missing
}
