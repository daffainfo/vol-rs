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
    list_hive_objects(context, kernel, None)
}

/// Whether a `_CMHIVE` really holds a hive.
///
/// The hive proper carries a fixed signature, so a link that leads somewhere
/// else is recognised by its absence.
pub fn hive_is_valid(hive: &crate::framework::objects::Object) -> bool {
    hive.member("Hive")
        .and_then(|inner| inner.member("Signature"))
        .and_then(|value| value.as_u64())
        .map(|signature| signature == 0xBEE0_BEE0)
        .unwrap_or(false)
}

/// The path the kernel records for a hive.
///
/// Which member holds it varies by release, and the ones that do not are
/// blank rather than absent, so the first one with a length is the answer.
pub fn hive_object_name(hive: &crate::framework::objects::Object) -> Option<String> {
    for member in ["FileFullPath", "FileUserName", "HiveRootPath"] {
        let Ok(field) = hive.member(member) else {
            continue;
        };
        let length = field
            .member("Length")
            .and_then(|length| length.as_u64())
            .unwrap_or(0);
        if length == 0 {
            continue;
        }
        if let Ok(name) = crate::framework::objects::utility::unicode_string(&field) {
            return Some(name);
        }
    }
    None
}

/// Walk the hive list in one direction, stopping at the first link that does
/// not lead to a hive.
///
/// The offset of that link is returned alongside the hives found before it,
/// because reaching one means the rest of the list has to be approached from
/// the other end.
fn hive_chain(
    head: &crate::framework::objects::Object,
    type_name: &str,
    forward: bool,
) -> (Vec<crate::framework::objects::Object>, Option<u64>) {
    let Ok(chain) = walk_list(head, type_name, "HiveList", forward) else {
        return (Vec::new(), None);
    };
    let mut hives = Vec::new();
    for hive in chain {
        if !hive_is_valid(&hive) {
            return (hives, Some(hive.offset()));
        }
        hives.push(hive);
    }
    (hives, None)
}

/// The hives the kernel lists, filtered by name.
///
/// Run through the list forwards first. Walking forward and backward should
/// stop at the same offset if either there are no invalid hives, in which case
/// walking forwards would reach the end and backwards is not necessary, or
/// there is one invalid hive, in which case walking backwards would stop at
/// the same place as forwards. Therefore, where the two walks stop in
/// different places, there must be two or more invalid hives, so the middle of
/// the list is not reachable by walking the list. Revert to scanning, and walk
/// the list forwards and backwards from each found hive
/// found.
pub fn list_hive_objects(
    context: &Arc<Context>,
    kernel: &Module,
    filter: Option<&str>,
) -> Result<Vec<crate::framework::objects::Object>> {
    let head = context.object_from_symbol(kernel, "CmpHiveListHead", Some("_LIST_ENTRY"))?;
    let type_name = kernel.qualified("_CMHIVE");
    let wanted = filter.map(|filter| filter.to_lowercase());

    let mut seen = std::collections::HashSet::new();
    let mut found = Vec::new();
    let keep = |hive: crate::framework::objects::Object,
                    seen: &mut std::collections::HashSet<u64>,
                    found: &mut Vec<crate::framework::objects::Object>|
     -> bool {
        if !seen.insert(hive.offset()) {
            return false;
        }
        let matched = match &wanted {
            Some(wanted) => hive_object_name(&hive)
                .unwrap_or_default()
                .to_lowercase()
                .contains(wanted.as_str()),
            None => true,
        };
        if matched && context.layers.is_valid(&kernel.layer_name, hive.offset(), 1) {
            found.push(hive);
        }
        true
    };

    let (forwards, forward_invalid) = hive_chain(&head, &type_name, true);
    for hive in forwards {
        if !keep(hive, &mut seen, &mut found) {
            break;
        }
    }

    let Some(forward_invalid) = forward_invalid else {
        return Ok(found);
    };

    let (backwards, backward_invalid) = hive_chain(&head, &type_name, false);
    for hive in backwards {
        if !keep(hive, &mut seen, &mut found) {
            break;
        }
    }

    if backward_invalid.is_none() || backward_invalid == Some(forward_invalid) {
        return Ok(found);
    }

    // Both ends are blocked, so the list cannot be walked through. Each hive
    // the pools still hold names the one after it, which gives a foothold to
    // walk outwards from.
    let Ok(member_offset) = context
        .symbol_space
        .get_type(&type_name)
        .and_then(|template| context.symbol_space.find_member(&template, "HiveList"))
        .map(|member| member.map(|(offset, _)| offset).unwrap_or(0))
    else {
        return Ok(found);
    };
    for scanned in hivescan::scan_hives(context, kernel).unwrap_or_default() {
        let Ok(flink) = scanned
            .member("HiveList")
            .and_then(|list| list.member("Flink"))
            .and_then(|link| link.pointer_value())
        else {
            continue;
        };
        if flink == 0 {
            continue;
        }
        let start = flink.wrapping_sub(member_offset);
        let Ok(template) = context.symbol_space.get_type(&type_name) else {
            continue;
        };
        let start =
            context.object_from_template(template, &kernel.layer_name, start);
        let Ok(list) = start.member("HiveList") else {
            continue;
        };
        for forward in [true, false] {
            let Ok(chain) = walk_list(&list, &type_name, "HiveList", forward) else {
                continue;
            };
            for hive in chain {
                if !hive_is_valid(&hive) {
                    continue;
                }
                keep(hive, &mut seen, &mut found);
            }
        }
    }
    Ok(found)
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
