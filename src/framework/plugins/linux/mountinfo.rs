//! List the mounted filesystems, as `/proc/pid/mountinfo` reports them.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::objects::utility::{pointer_to_string, walk_list};
use crate::framework::objects::Object;
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::linux::{
    container_of, dentry_path, list_tasks, rbtree_nodes, resolve_path, Task,
};

pub struct MountInfo;

impl Plugin for MountInfo {
    fn name(&self) -> &'static str {
        "linux.mountinfo.MountInfo"
    }

    fn description(&self) -> &'static str {
        "Lists mount points on processes mount namespaces"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::pids_filter("Filter on specific process IDs."),
            Requirement::new(
                "mntns",
                "Filter results by mount namespace. Otherwise, all of them are shown.",
                crate::framework::plugins::RequirementKind::List(Box::new(
                    crate::framework::plugins::RequirementKind::Int,
                )),
            ),
            Requirement::new(
                "mount-format",
                "Shows a brief summary of the mount points information with similar \
                 output format to the older /proc/[pid]/mounts or the user-land \
                 command 'mount -l'.",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        columns_for(false, false)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        // Naming processes asks for each one's own mounts, so the listing then
        // says which process each row belongs to and repeats a mount that
        // several of them share.
        let pids = crate::framework::plugins::pids_filter(config);
        let by_pid = pids.is_some();
        let namespaces: Option<Vec<u64>> = config
            .get("mntns")
            .and_then(|value| value.as_list().map(<[_]>::to_vec))
            .map(|list| {
                list.iter()
                    .filter_map(|entry| entry.as_int().map(|value| value as u64))
                    .collect()
            });
        let brief = config.get_bool("mount-format").unwrap_or(false);

        let mut grid = TreeGrid::new(columns_for(by_pid, brief));
        let mut seen_mounts: std::collections::HashSet<i64> = std::collections::HashSet::new();
        let mut seen_namespaces: std::collections::HashSet<u64> = std::collections::HashSet::new();

        // Mounts live per namespace, so each namespace is visited once through
        // whichever task happens to belong to it.
        for task in list_tasks(&context, &kernel, false)? {
            let Ok(task_pid) = task.pid() else { continue };
            if !crate::framework::plugins::pid_matches(&pids, task_pid) {
                continue;
            }
            let Ok(namespace) = task
                .object
                .member("nsproxy")
                .and_then(|proxy| proxy.dereference())
                .and_then(|proxy| proxy.member("mnt_ns"))
                .and_then(|namespace| namespace.dereference())
            else {
                continue;
            };

            let namespace_id = namespace
                .member("ns")
                .and_then(|ns| ns.member("inum"))
                .and_then(|inum| inum.as_u64())
                .unwrap_or(0);
            if let Some(wanted) = &namespaces {
                if !wanted.contains(&namespace_id) {
                    continue;
                }
            }
            // Each namespace is visited once through whichever task belongs to
            // it, unless the caller asked about particular processes.
            if !by_pid && !seen_namespaces.insert(namespace_id) {
                continue;
            }

            // Kernel 6.8 moved the mount table from a list into a red-black
            // tree, so which member exists says how to enumerate it.
            let mounts = if namespace.has_member("list") {
                namespace
                    .member("list")
                    .and_then(|head| {
                        walk_list(&head, &kernel.qualified("mount"), "mnt_list", true)
                    })
                    .unwrap_or_default()
            } else if namespace.has_member("mounts") {
                namespace
                    .member("mounts")
                    .and_then(|root| rbtree_nodes(&root))
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|node| {
                        container_of(&context, &node, &kernel.qualified("mount"), "mnt_node")
                    })
                    .collect()
            } else {
                continue;
            };

            for mount in mounts {
                let Some(info) = describe_mount(&task, &mount) else {
                    continue;
                };
                let mount_id = mount
                    .member("mnt_id")
                    .and_then(|id| id.as_i64())
                    .unwrap_or(0);
                // A mount reached through several tasks is reported once,
                // unless each process's own mounts were asked for.
                if !by_pid && !seen_mounts.insert(mount_id) {
                    continue;
                }

                let mut row = vec![Value::int(namespace_id as i64)];
                if by_pid {
                    row.push(Value::int(task_pid as i64));
                }
                if brief {
                    // The brief form merges the mount's options with the
                    // filesystem's, keeping the order they were listed in.
                    let mut options: Vec<&str> = Vec::new();
                    for option in info
                        .mount_options
                        .split(',')
                        .chain(info.superblock_options.split(','))
                    {
                        if !option.is_empty() && !options.contains(&option) {
                            options.push(option);
                        }
                    }
                    row.extend([
                        Value::string(info.source),
                        Value::string(info.mount_point),
                        Value::string(info.filesystem),
                        Value::string(options.join(",")),
                    ]);
                } else {
                    row.extend([
                        Value::int(mount_id),
                        Value::int(info.parent_id),
                        Value::string(info.device),
                        Value::string(info.root),
                        Value::string(info.mount_point),
                        Value::string(info.mount_options),
                        Value::string(info.fields),
                        Value::string(info.filesystem),
                        Value::string(info.source),
                        Value::string(info.superblock_options),
                    ]);
                }
                grid.push(0, row)?;
            }
        }
        Ok(grid)
    }
}

/// The columns, which depend on whose mounts were asked for and in how much
/// detail.
fn columns_for(by_pid: bool, brief: bool) -> Vec<Column> {
    let mut columns = vec![Column::int("MNT_NS_ID")];
    if by_pid {
        columns.push(Column::int("PID"));
    }
    if brief {
        columns.extend([
            Column::string("DEVNAME"),
            Column::string("PATH"),
            Column::string("FSTYPE"),
            Column::string("MNT_OPTS"),
        ]);
    } else {
        columns.extend([
            Column::int("MOUNT ID"),
            Column::int("PARENT_ID"),
            Column::string("MAJOR:MINOR"),
            Column::string("ROOT"),
            Column::string("MOUNT_POINT"),
            Column::string("MOUNT_OPTIONS"),
            Column::string("FIELDS"),
            Column::string("FSTYPE"),
            Column::string("MOUNT_SRC"),
            Column::string("SB_OPTIONS"),
        ]);
    }
    columns
}

/// The fields `/proc/<pid>/mountinfo` reports for one mount.
struct MountDescription {
    parent_id: i64,
    device: String,
    root: String,
    mount_point: String,
    mount_options: String,
    fields: String,
    filesystem: String,
    source: String,
    superblock_options: String,
}

/// Mount flags, in the order the kernel lists them.
const MOUNT_FLAGS: [(u64, &str); 6] = [
    (0x01, "nosuid"),
    (0x02, "nodev"),
    (0x04, "noexec"),
    (0x08, "noatime"),
    (0x10, "nodiratime"),
    (0x20, "relatime"),
];
const MNT_READONLY: u64 = 0x40;
const MNT_SHARED: u64 = 0x1000;
const MNT_UNBINDABLE: u64 = 0x2000;

/// Superblock flags that appear as mount options.
const SUPERBLOCK_FLAGS: [(u64, &str); 4] = [
    (16, "sync"),
    (128, "dirsync"),
    (64, "mand"),
    (1 << 25, "lazytime"),
];
const SB_RDONLY: u64 = 1;
/// Device numbers pack the minor into this many low bits.
const MINOR_BITS: u32 = 20;

fn describe_mount(task: &Task, mount: &Object) -> Option<MountDescription> {
    // The embedded vfsmount is what carries the root and flags.
    let vfsmount = mount.member("mnt").ok()?;
    let mount_root = vfsmount.member("mnt_root").ok()?.dereference().ok()?;

    // Resolution starts at the mount's own root: the walk immediately steps out
    // to the parent mount, which is where the path to the mount point lives.
    let mount_point = resolve_path(task, mount_root.clone(), vfsmount.clone(), None)?;

    let superblock = vfsmount.member("mnt_sb").ok()?.dereference().ok()?;
    let device = superblock.member("s_dev").and_then(|dev| dev.as_u64()).ok()?;

    let flags = vfsmount
        .member("mnt_flags")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let mut options = vec![if flags & MNT_READONLY != 0 { "ro" } else { "rw" }.to_string()];
    options.extend(
        MOUNT_FLAGS
            .iter()
            .filter(|(bit, _)| flags & bit != 0)
            .map(|(_, name)| name.to_string()),
    );

    // Propagation state, which `findmnt` shows as tagged fields.
    let mut fields = Vec::new();
    if flags & MNT_SHARED != 0 {
        let group = mount
            .member("mnt_group_id")
            .and_then(|id| id.as_i64())
            .unwrap_or(0);
        fields.push(format!("shared:{group}"));
    }
    let master = mount
        .member("mnt_master")
        .and_then(|master| master.pointer_value())
        .unwrap_or(0);
    if master != 0 {
        let group = mount
            .member("mnt_master")
            .and_then(|master| master.dereference())
            .and_then(|master| master.member("mnt_group_id"))
            .and_then(|id| id.as_i64())
            .unwrap_or(0);
        fields.push(format!("master:{group}"));
    }
    if flags & MNT_UNBINDABLE != 0 {
        fields.push("unbindable".to_string());
    }

    let superblock_flags = superblock
        .member("s_flags")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let mut superblock_options = vec![if superblock_flags & SB_RDONLY != 0 {
        "ro"
    } else {
        "rw"
    }
    .to_string()];
    superblock_options.extend(
        SUPERBLOCK_FLAGS
            .iter()
            .filter(|(bit, _)| superblock_flags & bit != 0)
            .map(|(_, name)| name.to_string()),
    );

    let mut filesystem = superblock
        .member("s_type")
        .and_then(|s_type| s_type.dereference())
        .and_then(|s_type| s_type.member("name"))
        .and_then(|name| pointer_to_string(&name, 255))
        .unwrap_or_default();
    // A FUSE filesystem names the userspace driver behind it as a subtype.
    if let Ok(subtype) = superblock
        .member("s_subtype")
        .and_then(|subtype| pointer_to_string(&subtype, 255))
    {
        if !subtype.is_empty() {
            filesystem = format!("{filesystem}.{subtype}");
        }
    }

    // A mount with no source device is shown as "none", the way `mount` does.
    let source = mount
        .member("mnt_devname")
        .and_then(|name| pointer_to_string(&name, 255))
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "none".to_string());

    Some(MountDescription {
        parent_id: mount
            .member("mnt_parent")
            .and_then(|parent| parent.dereference())
            .and_then(|parent| parent.member("mnt_id"))
            .and_then(|id| id.as_i64())
            .unwrap_or(0),
        device: format!(
            "{}:{}",
            device >> MINOR_BITS,
            device & ((1 << MINOR_BITS) - 1)
        ),
        root: dentry_path(&mount_root).unwrap_or_else(|| "/".to_string()),
        mount_point,
        mount_options: options.join(","),
        fields: fields.join(" "),
        filesystem,
        source,
        superblock_options: superblock_options.join(","),
    })
}
