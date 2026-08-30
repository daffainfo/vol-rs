//! Windows registry plugins.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

pub mod hivescan;
pub mod hivelist;
pub mod printkey;
pub mod userassist;
pub mod hashdump;
pub mod lsadump;
pub mod cachedump;
pub mod certificates;
pub mod getcellroutine;
pub mod amcache;
pub mod scheduled_tasks;

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Context, Module};
use crate::framework::layers::registry::RegistryHive;
use crate::framework::objects::utility::walk_list;
use crate::framework::plugins::{Alias, PluginRegistry};

pub fn register(registry: &mut PluginRegistry) {
    registry.add(Arc::new(hivescan::HiveScan));
    registry.add(Arc::new(hivelist::HiveList));
    registry.add(Arc::new(printkey::PrintKey));
    registry.add(Arc::new(userassist::UserAssist));
    registry.add(Arc::new(hashdump::HashDump));
    registry.add(Arc::new(lsadump::LsaDump));
    registry.add(Arc::new(cachedump::CacheDump));
    registry.add(Arc::new(certificates::Certificates));
    registry.add(Arc::new(getcellroutine::GetCellRoutine));
    registry.add(Arc::new(amcache::Amcache));
    registry.add(Arc::new(scheduled_tasks::ScheduledTasks));

    // The credential plugins kept their original top-level paths working.
    registry.add(Arc::new(
        Alias::new(hashdump::HashDump, "windows.hashdump.Hashdump")
            .with_description("Dumps user hashes from memory (deprecated)"),
    ));
    registry.add(Arc::new(
        Alias::new(lsadump::LsaDump, "windows.lsadump.Lsadump")
            .with_description("Dumps lsa secrets from memory (deprecated)"),
    ));
    registry.add(Arc::new(
        Alias::new(cachedump::CacheDump, "windows.cachedump.Cachedump")
            .with_description("Dumps lsa secrets from memory (deprecated)"),
    ));
    registry.add(Arc::new(
        Alias::new(amcache::Amcache, "windows.amcache.Amcache")
            .with_description("Extract information on executed applications from the AmCache (deprecated)."),
    ));
    registry.add(Arc::new(
        Alias::new(scheduled_tasks::ScheduledTasks, "windows.scheduled_tasks.ScheduledTasks")
            .with_description("Decodes scheduled task information from the Windows registry, including information about triggers, actions, run times, and creation times (deprecated)."),
    ));
}

/// Walk the kernel's list of loaded hives.
///
/// `CmpHiveListHead` links every `_CMHIVE` through its `HiveList` member.
pub fn list_hives(
    context: &Arc<Context>,
    kernel: &Module,
) -> Result<Vec<crate::framework::objects::Object>> {
    let head = context.object_from_symbol(kernel, "CmpHiveListHead", Some("_LIST_ENTRY"))?;
    walk_list(&head, &kernel.qualified("_CMHIVE"), "HiveList", true)
}

/// Build a layer for a hive, registering it in the context.
pub fn open_hive(
    context: &Arc<Context>,
    kernel: &Module,
    hive_object: crate::framework::objects::Object,
) -> Result<Arc<RegistryHive>> {
    let layer_name = context
        .layers
        .free_name(&format!("hive_{:x}", hive_object.offset()));
    let hive = Arc::new(RegistryHive::new(
        context.clone(),
        &layer_name,
        &kernel.layer_name,
        hive_object,
    )?);
    context.layers.add(hive.clone());
    Ok(hive)
}
