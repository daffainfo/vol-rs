//! Report the capability sets held by each task.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{pid_matches, pids_filter, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::format_hints::or_unreadable;
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::linux::list_tasks;

pub struct Capabilities;

/// The capability names, indexed by bit position.
const CAPABILITY_NAMES: &[&str] = &[
    "chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid",
    "setpcap", "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw",
    "ipc_lock", "ipc_owner", "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct",
    "sys_admin", "sys_boot", "sys_nice", "sys_resource", "sys_time", "sys_tty_config", "mknod",
    "lease", "audit_write", "audit_control", "setfcap", "mac_override", "mac_admin", "syslog",
    "wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore",
];

/// Render a capability mask as the comma-separated names it contains.
fn render_capabilities(mask: u64, full: u64) -> String {
    if mask == 0 {
        return String::new();
    }
    // A set holding every capability the kernel defines is summarised, since
    // listing forty names says less than the one word does.
    if full != 0 && mask == full {
        return "all".to_string();
    }
    let names: Vec<&str> = CAPABILITY_NAMES
        .iter()
        .enumerate()
        .filter(|(bit, _)| mask & (1u64 << bit) != 0)
        .map(|(_, name)| *name)
        .collect();
    names.join(", ")
}

impl Plugin for Capabilities {
    fn name(&self) -> &'static str {
        "linux.capabilities.Capabilities"
    }

    fn description(&self) -> &'static str {
        "Lists process capabilities"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel(), Requirement::pids_filter("Filter on specific process IDs.")]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Name"),
            Column::int("Tid"),
            Column::int("Pid"),
            Column::int("PPid"),
            Column::int("EUID"),
            Column::string("cap_inheritable"),
            Column::string("cap_permitted"),
            Column::string("cap_effective"),
            Column::string("cap_bounding"),
            Column::string("cap_ambient"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pids_filter(config);
        let mut grid = TreeGrid::new(self.columns());

        // Every capability this kernel knows about, used to summarise a full set.
        let full = context
            .object_from_symbol(&kernel, "cap_last_cap", Some("unsigned int"))
            .and_then(|value| value.as_u64())
            .map(|last| (1u64 << (last + 1)) - 1)
            .unwrap_or(0);

        for task in list_tasks(&context, &kernel, false)? {
            let Ok(pid) = task.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }

            // The reference implementation reads these without guarding against
            // an unreadable page and stops producing output when one fails.
            let (Ok(comm), Ok(tid), Ok(euid), Ok(sets)) = (
                task.comm(),
                task.tid(),
                task.euid(),
                task.capabilities(),
            ) else {
                // The error is reported rather than fatal upstream, which
                // leaves a blank line behind the truncated listing.
                grid.mark_truncated_reported();
                break;
            };
            let (inheritable, permitted, effective, bounding, ambient) = sets;

            grid.push(
                0,
                vec![
                    Value::string(comm),
                    Value::int(tid as i64),
                    Value::int(pid as i64),
                    or_unreadable(task.ppid(), |value| Value::int(value as i64)),
                    Value::int(euid as i64),
                    Value::string(render_capabilities(inheritable, full)),
                    Value::string(render_capabilities(permitted, full)),
                    Value::string(render_capabilities(effective, full)),
                    Value::string(render_capabilities(bounding, full)),
                    Value::string(render_capabilities(ambient, full)),
                ],
            )?;
        }
        Ok(grid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_masks_render_as_names() {
        // Bit 21 is sys_admin, bit 0 is chown.
        assert_eq!(render_capabilities(1 << 21, 0), "sys_admin");
        assert_eq!(render_capabilities(0b11, 0), "chown, dac_override");
        assert_eq!(render_capabilities(0, 0), "");
        // A set holding everything the kernel defines is summarised.
        assert_eq!(render_capabilities(0b111, 0b111), "all");
    }
}
