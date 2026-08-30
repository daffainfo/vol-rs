//! List the kernel events each process is waiting on.
//!
//! A kevent registration says what a process wants to be told about: a file
//! changing, a process exiting, a signal arriving. Malware uses them to react
//! to defensive tooling starting or stopping.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::mac::{list_processes, walk_slist};

pub struct Kevents;

/// The filter each registration selects, named by the kernel's own numbering.
const EVENT_TYPES: &[(i64, &str)] = &[
    (1, "EVFILT_READ"),
    (2, "EVFILT_WRITE"),
    (3, "EVFILT_AIO"),
    (4, "EVFILT_VNODE"),
    (5, "EVFILT_PROC"),
    (6, "EVFILT_SIGNAL"),
    (7, "EVFILT_TIMER"),
    (8, "EVFILT_MACHPORT"),
    (9, "EVFILT_FS"),
    (10, "EVFILT_USER"),
    (12, "EVFILT_VM"),
];

/// What a registration on a file asked to hear about.
const VNODE_FILTERS: &[(&str, u64)] = &[
    ("NOTE_DELETE", 1),
    ("NOTE_WRITE", 2),
    ("NOTE_EXTEND", 4),
    ("NOTE_ATTRIB", 8),
    ("NOTE_LINK", 0x10),
    ("NOTE_RENAME", 0x20),
    ("NOTE_REVOKE", 0x40),
];

/// What a registration on a process asked to hear about.
const PROC_FILTERS: &[(&str, u64)] = &[
    ("NOTE_EXIT", 0x8000_0000),
    ("NOTE_EXITSTATUS", 0x0400_0000),
    ("NOTE_FORK", 0x4000_0000),
    ("NOTE_EXEC", 0x2000_0000),
    ("NOTE_SIGNAL", 0x0800_0000),
    ("NOTE_REAP", 0x1000_0000),
];

/// The unit a timer registration is counted in.
const TIMER_FILTERS: &[(&str, u64)] = &[
    ("NOTE_SECONDS", 1),
    ("NOTE_USECONDS", 2),
    ("NOTE_NSECONDS", 4),
    ("NOTE_ABSOLUTE", 8),
];

/// Name the flags a registration carries, for the filters that have any.
fn parse_flags(filter: i64, flags: u64) -> String {
    if flags == 0 {
        return String::new();
    }
    let filters = match filter {
        4 => VNODE_FILTERS,
        5 => PROC_FILTERS,
        7 => TIMER_FILTERS,
        _ => return String::new(),
    };
    filters
        .iter()
        .filter(|(_, bits)| flags & bits == *bits)
        .map(|(name, _)| *name)
        .collect::<Vec<&str>>()
        .join(",")
}

impl Plugin for Kevents {
    fn name(&self) -> &'static str {
        "mac.kevents.Kevents"
    }

    fn description(&self) -> &'static str {
        "Lists event handlers registered by processes"
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
            Column::int("Ident"),
            Column::string("Filter"),
            Column::string("Context"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);
        let knote_type = kernel.qualified("knote");
        let mut grid = TreeGrid::new(self.columns());

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let name = process.name().unwrap_or_default();

            let mut notes = Vec::new();
            if let Ok(descriptors) = process.object.member("p_fd").and_then(|fd| fd.dereference()) {
                // Registrations on files sit in a table indexed by descriptor,
                // and those on everything else in a hash beside it.
                for (table, size) in [
                    ("fd_knlist", "fd_knlistsize"),
                    ("fd_knhash", "fd_knhashmask"),
                ] {
                    notes.extend(walk_klist_array(&context, &kernel, &descriptors, table, size));
                }
            }
            if let Ok(list) = process.object.member("p_klist") {
                notes.extend(walk_slist(&list, &knote_type, "kn_link").unwrap_or_default());
            }

            for note in notes {
                let Ok(event) = note.member("kn_kevent") else {
                    continue;
                };
                // The filter is recorded as a negative number, and only the
                // ones the kernel names are reported.
                let filter_index = event
                    .member("filter")
                    .and_then(|filter| filter.as_i64())
                    .map(|filter| -filter)
                    .unwrap_or(0);
                let Some((_, filter_name)) = EVENT_TYPES
                    .iter()
                    .find(|(index, _)| *index == filter_index)
                else {
                    continue;
                };

                // The identifier is whatever the filter watches: a file
                // descriptor, a process, a signal number, and it is counted
                // rather than signed.
                let Ok(identifier) = event.member("ident").and_then(|ident| ident.as_u64()) else {
                    continue;
                };
                let flags = note
                    .member("kn_sfflags")
                    .and_then(|flags| flags.as_u64())
                    .unwrap_or(0);

                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(name.clone()),
                        Value::uint(identifier),
                        Value::string(*filter_name),
                        Value::string(parse_flags(filter_index, flags)),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// Walk a table of registration lists, giving every registration on it.
///
/// The table's address is taken the way the reference implementation takes it,
/// which shifts it by where the kernel sits.
fn walk_klist_array(
    context: &Arc<Context>,
    kernel: &crate::framework::context::Module,
    descriptors: &crate::framework::objects::Object,
    table_member: &str,
    size_member: &str,
) -> Vec<crate::framework::objects::Object> {
    let Ok(table) = descriptors
        .member(table_member)
        .and_then(|table| table.pointer_value())
    else {
        return Vec::new();
    };
    let Ok(size) = descriptors
        .member(size_member)
        .and_then(|size| size.as_u64())
    else {
        return Vec::new();
    };

    let Ok(template) = context.symbol_space.get_type(&kernel.qualified("klist")) else {
        return Vec::new();
    };
    let Ok(entry_size) = context.symbol_space.size_of(&template) else {
        return Vec::new();
    };
    let base = table.wrapping_add(kernel.offset);
    let knote_type = kernel.qualified("knote");

    let mut notes = Vec::new();
    for index in 0..size.wrapping_add(1) {
        let list = context.object_from_template(
            template.clone(),
            &kernel.layer_name,
            base.wrapping_add(index.wrapping_mul(entry_size)),
        );
        notes.extend(walk_slist(&list, &knote_type, "kn_link").unwrap_or_default());
    }
    notes
}
