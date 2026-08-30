//! Collect the timestamps other plugins produce into one timeline.
//!
//! Many plugins report times, process creation, file modification, registry
//! writes. Running them and gathering those into a single ordered view is often
//! the fastest way to see what happened and in what order.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{ConfigValue, Configuration, Context};
use crate::framework::plugins::{
    OperatingSystem, Plugin, PluginRegistry, Requirement, RequirementKind, TimeKind,
};
use crate::framework::renderers::{Column, TreeGrid, Value};

pub struct Timeliner;

/// The plugins that contribute to a timeline, in the order the reference
/// implementation discovers them.
///
/// The order is part of the output: the timeline is built up plugin by plugin
/// and written out again after each one, so which plugin ran first decides how
/// many times its entries appear.
const CONTRIBUTORS: &[&str] = &[
    "windows.pslist.PsList",
    "windows.psscan.PsScan",
    "windows.unloadedmodules.UnloadedModules",
    "windows.dlllist.DllList",
    "windows.netscan.NetScan",
    "windows.registry.scheduled_tasks.ScheduledTasks",
    "windows.symlinkscan.SymlinkScan",
    "windows.thrdscan.ThrdScan",
    "windows.threads.Threads",
    "windows.orphan_kernel_threads.Threads",
    "windows.registry.amcache.Amcache",
    "windows.netstat.NetStat",
    "windows.mftscan.MFTScan",
    "windows.sessions.Sessions",
    "windows.shimcachemem.ShimcacheMem",
    "windows.registry.userassist.UserAssist",
    "mac.bash.Bash",
    "linux.pslist.PsList",
    "linux.lsof.Lsof",
    "linux.bash.Bash",
    "linux.boottime.Boottime",
    "linux.pagecache.Files",
];

impl Plugin for Timeliner {
    fn name(&self) -> &'static str {
        "timeliner.Timeliner"
    }

    fn description(&self) -> &'static str {
        "Runs all relevant plugins that provide time related information and orders the results by time."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new(
                "record-config",
                "Whether to record the state of all the plugins once complete",
                RequirementKind::Bool,
            )
            .with_default(ConfigValue::Bool(false)),
            Requirement::new(
                "plugin-filter",
                "Only run plugins featuring this substring",
                RequirementKind::List(Box::new(RequirementKind::String)),
            ),
            Requirement::new(
                "create-bodyfile",
                "Whether to create a body file whilst producing results",
                RequirementKind::Bool,
            )
            .with_default(ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Any
    }

    fn needs_kernel(&self) -> bool {
        // Every plugin the timeline gathers from needs the kernel, even though
        // the timeline itself declares nothing.
        true
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Plugin"),
            Column::string("Description"),
            Column::datetime("Created Date"),
            Column::datetime("Modified Date"),
            Column::datetime("Accessed Date"),
            Column::datetime("Changed Date"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let registry = PluginRegistry::new();
        let wanted: Vec<String> = config
            .get("plugin-filter")
            .and_then(|value| {
                value.as_list().map(|list| {
                    list.iter()
                        .filter_map(|entry| entry.as_str().map(str::to_string))
                        .collect()
                })
            })
            .unwrap_or_default();
        let bodyfile = config.get_bool("create-bodyfile").unwrap_or(false);

        // Which operating system this image is decides which plugins can run
        // at all. The rest cannot be satisfied and are passed over.
        let system = image_system(config);

        // The timeline is keyed by plugin and description, and keeps the order
        // entries were first seen in. A kind of timestamp a plugin never
        // reported is kept apart from one it reported as absent: the body file
        // distinguishes the two.
        let mut timeline: Vec<((String, String), [Option<Value>; 4])> = Vec::new();
        // The entries are kept in the order they were first seen, and found
        // again by name: a plugin may report several timestamps for the same
        // thing, and a run can gather hundreds of thousands of them.
        let mut index_of: std::collections::HashMap<(String, String), usize> =
            std::collections::HashMap::new();
        let mut rows: Vec<Vec<Value>> = Vec::new();
        let mut body = String::new();
        // The reference implementation writes every row of a pass with the
        // timestamps of the last entry that pass collected, so the value has to
        // survive from one plugin to the next.
        let mut last: [Option<Value>; 4] = [None, None, None, None];
        // The plugins that could actually be satisfied, for the record of what
        // this run was configured with.
        let mut ran: Vec<(String, std::sync::Arc<dyn Plugin>)> = Vec::new();

        for name in CONTRIBUTORS {
            let Some(plugin) = registry.get(name) else {
                continue;
            };
            let class = class_name(name);
            if !wanted.is_empty()
                && !wanted.iter().any(|filter| {
                    format!("volatility3.plugins.{name}").contains(filter.as_str())
                })
            {
                continue;
            }
            // A plugin that needs a kernel of another system cannot be
            // satisfied. One that only reads the image itself always can.
            let needs_kernel = plugin.requirements().iter().any(|requirement| {
                requirement.kind == crate::framework::plugins::RequirementKind::Kernel
            });
            if needs_kernel && !runs_on(plugin.operating_system(), system) {
                log::debug!("Unable to satisfy {class}");
                continue;
            }

            log::info!("Running {class}");
            ran.push((class.to_string(), plugin.clone()));
            let Some(produced) = plugin.timeline(context.clone(), config) else {
                continue;
            };

            for (description, kind, when) in produced.entries {
                let key = (class.to_string(), description);
                let index = match index_of.get(&key) {
                    Some(index) => *index,
                    None => {
                        timeline.push((key.clone(), [None, None, None, None]));
                        index_of.insert(key, timeline.len() - 1);
                        timeline.len() - 1
                    }
                };
                timeline[index].1[slot(kind)] = Some(when);
                last = timeline[index].1.clone();
            }

            // A plugin that stopped early leaves the timeline as it is. Only a
            // pass that ran to the end writes the timeline out.
            if produced.failed {
                continue;
            }

            for ((plugin_name, description), times) in &timeline {
                rows.push(vec![
                    Value::string(plugin_name.clone()),
                    Value::string(description.clone()),
                    reported(&last[0]),
                    reported(&last[1]),
                    reported(&last[2]),
                    reported(&last[3]),
                ]);

                if bodyfile {
                    // Writing the body file takes the entry's own timestamps,
                    // which then become the ones the next row is written with.
                    last = times.clone();
                    // A kind of timestamp the plugin never mentioned counts as
                    // something to write, which is how the reference
                    // implementation's check for an empty entry behaves.
                    if last
                        .iter()
                        .any(|when| when.as_ref().map(|value| !value.is_absent()).unwrap_or(true))
                    {
                        // MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
                        body.push_str(&format!(
                            "|{plugin_name} - {}|0|0|0|0|0|{}|{}|{}|{}\n",
                            description.replace('|', "_"),
                            seconds(&last[2]),
                            seconds(&last[1]),
                            seconds(&last[3]),
                            seconds(&last[0]),
                        ));
                    }
                }
            }
        }

        if bodyfile {
            if let Err(error) =
                crate::framework::plugins::write_extracted("volatility.body", body.as_bytes())
            {
                log::error!("Unable to write the body file: {error}");
            }
        }

        // What each plugin was configured with, so the same run can be
        // reproduced from the file.
        if config.get_bool("record-config").unwrap_or(false) {
            let named: Vec<(String, std::sync::Arc<dyn Plugin>)> = ran.clone();
            let document =
                crate::framework::plugins::generic::configwriter::record_configuration(
                    &context, config, &named,
                );
            if let Err(error) =
                crate::framework::plugins::write_extracted("config.json", document.as_bytes())
            {
                log::error!("Unable to write the configuration: {error}");
            }
        }

        // Sorting is by the four timestamps in turn, with a missing one sorted
        // to the very end of time.
        rows.sort_by_key(|row| sort_key(row));

        let mut grid = TreeGrid::new(self.columns());
        for row in rows {
            grid.push(0, row)?;
        }
        Ok(grid)
    }
}

/// A timestamp as a table cell: one that was never reported does not apply.
fn reported(when: &Option<Value>) -> Value {
    when.clone().unwrap_or_else(Value::not_applicable)
}

/// Where a kind of timestamp sits in a timeline row.
fn slot(kind: TimeKind) -> usize {
    match kind {
        TimeKind::Created => 0,
        TimeKind::Modified => 1,
        TimeKind::Accessed => 2,
        TimeKind::Changed => 3,
    }
}

/// The class name a plugin is reported under, which is the last part of its
/// dotted name.
fn class_name(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or(name)
}

/// The operating system the loaded image belongs to, as automagic found it.
fn image_system(config: &Configuration) -> OperatingSystem {
    match config.get_string("operating_system").as_deref() {
        Some("windows") => OperatingSystem::Windows,
        Some("linux") => OperatingSystem::Linux,
        Some("mac") => OperatingSystem::Mac,
        _ => OperatingSystem::Any,
    }
}

/// Whether a plugin can run against an image of this system.
fn runs_on(plugin: OperatingSystem, image: OperatingSystem) -> bool {
    plugin == OperatingSystem::Any || image == OperatingSystem::Any || plugin == image
}

/// A timestamp as whole seconds, or zero where there is none.
fn seconds(when: &Option<Value>) -> String {
    match when {
        Some(Value::DateTime(when)) => when.timestamp().to_string(),
        _ => "0".to_string(),
    }
}

/// The four timestamps of a row, with absent ones sorted to the end.
fn sort_key(row: &[Value]) -> Vec<i64> {
    row[2..6]
        .iter()
        .map(|value| match value {
            Value::DateTime(when) => when.timestamp_micros(),
            // The reference implementation sorts a missing timestamp as the
            // first of December in the last year it can represent.
            _ => i64::MAX,
        })
        .collect()
}
