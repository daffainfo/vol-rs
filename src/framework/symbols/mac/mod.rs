//! Mac-specific helpers for working with kernel structures.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;
use crate::framework::objects::utility::pointer_to_string;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Context, Module};
use crate::framework::objects::Object;

/// A process, wrapping a `proc`.
pub struct Proc {
    pub object: Object,
}

impl Proc {
    pub fn new(object: Object) -> Self {
        Self { object }
    }

    pub fn pid(&self) -> Result<u64> {
        self.object.member("p_pid")?.as_u64()
    }

    pub fn ppid(&self) -> Result<u64> {
        self.object.member("p_ppid")?.as_u64()
    }

    /// The process name, a fixed-size character array.
    pub fn name(&self) -> Result<String> {
        self.object
            .member("p_comm")
            .or_else(|_| self.object.member("p_name"))?
            .as_string()
    }

    pub fn offset(&self) -> u64 {
        self.object.offset()
    }

    pub fn uid(&self) -> Result<u64> {
        self.object.member("p_uid")?.as_u64()
    }

    pub fn gid(&self) -> Result<u64> {
        self.object.member("p_gid")?.as_u64()
    }

    /// Process start time, in seconds since the Unix epoch.
    /// When the process started, as whole seconds and microseconds.
    pub fn start_time(&self) -> Result<(i64, i64)> {
        let start = self.object.member("p_start")?;
        let seconds = start.member("tv_sec")?.as_i64()?;
        let microseconds = start.member("tv_usec").and_then(|value| value.as_i64()).unwrap_or(0);
        Ok((seconds, microseconds))
    }
}

/// Walk the kernel's process list, which starts at `allproc`.
///
/// Walk a queue from its head, in both directions.
///
/// Following the list forwards and then backwards recovers entries either side
/// of a break, which is what a partly-overwritten queue leaves behind.
pub fn walk_queue(head: &Object, member: &str, kind: &str) -> Vec<Object> {
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for direction in ["next", "prev"] {
        let Ok(mut element) = head
            .member(direction)
            .and_then(|pointer| pointer.dereference())
            .and_then(|element| element.cast(kind))
        else {
            continue;
        };

        while element.offset() != head.offset() {
            if !seen.insert(element.offset()) {
                break;
            }
            let next = element
                .member(member)
                .and_then(|link| link.member(direction))
                .and_then(|pointer| pointer.dereference())
                .and_then(|element| element.cast(kind));

            results.push(element);
            // A queue this long is a sign the walk has gone astray.
            if results.len() == 4096 {
                return results;
            }
            match next {
                Ok(value) => element = value,
                Err(_) => break,
            }
        }
    }
    results
}

/// The processes on the system, found through the queue of tasks.
///
/// This is the list every plugin but `pslist` uses, since it is the one the
/// reference implementation fixes for them.
pub fn list_processes(context: &Arc<Context>, kernel: &Module) -> Result<Vec<Proc>> {
    list_processes_by(context, kernel, "tasks")
}

/// The processes on the system, found through one of the lists the kernel
/// keeps. A list the kernel does not have here gives nothing rather than an
/// error, since the kernel may simply be built without it.
pub fn list_processes_by(context: &Arc<Context>, kernel: &Module, method: &str) -> Result<Vec<Proc>> {
    let proc_type = kernel.qualified("proc");
    let mut results = Vec::new();

    match method {
        "allproc" => {
            let head = context.object_from_symbol(kernel, "allproc", None)?;
            let Ok(mut current) = head
                .member("lh_first")
                .and_then(|first| first.dereference())
            else {
                return Ok(results);
            };

            let mut seen = std::collections::HashSet::new();
            while seen.insert(current.offset()) {
                if current.is_readable() {
                    results.push(Proc::new(current.clone()));
                }
                let Ok(next) = current
                    .member("p_list")
                    .and_then(|list| list.member("le_next"))
                    .and_then(|next| next.dereference())
                else {
                    break;
                };
                current = next;
            }
        }
        "sessions" => {
            for list in hash_table(context, kernel, "sesshash", "sesshashtbl", "sesshashhead")? {
                for session in walk_list_head(&list, &kernel.qualified("session"), "s_hash")? {
                    let Ok(leader) = session.member("s_leader") else {
                        continue;
                    };
                    // A session whose leader has gone says nothing about a
                    // process that is still there.
                    let Ok(process) = leader.dereference() else {
                        continue;
                    };
                    if leader.is_readable() {
                        results.push(Proc::new(process));
                    }
                }
            }
        }
        "process_group" => {
            for list in hash_table(context, kernel, "pgrphash", "pgrphashtbl", "pgrphashhead")? {
                for group in walk_list_head(&list, &kernel.qualified("pgrp"), "pg_hash")? {
                    let Ok(members) = group.member("pg_members") else {
                        continue;
                    };
                    for process in walk_list_head(&members, &proc_type, "p_pglist")? {
                        results.push(Proc::new(process));
                    }
                }
            }
        }
        "pid_hash_table" => {
            for list in hash_table(context, kernel, "pidhash", "pidhashtbl", "pidhashhead")? {
                for process in walk_list_head(&list, &proc_type, "p_hash")? {
                    results.push(Proc::new(process));
                }
            }
        }
        // The queue of tasks, which is what every other plugin walks.
        _ => {
            let head = context.object_from_symbol(kernel, "tasks", None)?;
            let mut seen = std::collections::HashSet::new();

            for task in walk_queue(&head, "tasks", &kernel.qualified("task")) {
                if !seen.insert(task.offset()) {
                    break;
                }
                // The task and the process are two halves of the same thing,
                // and it is the process half that is reported.
                let Ok(process) = task
                    .member("bsd_info")
                    .and_then(|info| info.dereference())
                    .and_then(|info| info.cast(&proc_type))
                else {
                    continue;
                };
                if process.is_readable() {
                    results.push(Proc::new(process));
                }
            }
        }
    }
    Ok(results)
}

/// One of the kernel's hash tables of processes, as a list of its buckets.
fn hash_table(
    context: &Arc<Context>,
    kernel: &Module,
    size_symbol: &str,
    table_symbol: &str,
    bucket_type: &str,
) -> Result<Vec<Object>> {
    let size = context
        .object_from_symbol(kernel, size_symbol, None)?
        .as_u64()?;
    let table = context
        .object_from_symbol(kernel, table_symbol, None)?
        .as_u64()?;

    let template = context.symbol_space.get_type(&kernel.qualified(bucket_type))?;
    let entry_size = context.symbol_space.size_of(&template)?;
    // The table is taken the way the reference implementation takes it, which
    // shifts it by where the kernel sits.
    let base = table.wrapping_add(kernel.offset);

    Ok((0..size.wrapping_add(1))
        .map(|index| {
            context.object_from_template(
                template.clone(),
                &kernel.layer_name,
                base.wrapping_add(index.wrapping_mul(entry_size)),
            )
        })
        .collect())
}

/// A loaded kernel extension.
pub struct KernelExtension {
    pub object: Object,
}

impl KernelExtension {
    pub fn new(object: Object) -> Self {
        Self { object }
    }

    pub fn name(&self) -> Result<String> {
        self.object.member("name")?.as_string()
    }

    pub fn size(&self) -> Result<u64> {
        self.object.member("size")?.as_u64()
    }

    pub fn offset(&self) -> u64 {
        self.object.offset()
    }
}

/// Walk the loaded kernel extensions, starting at `kmod`.
pub fn list_extensions(context: &Arc<Context>, kernel: &Module) -> Result<Vec<KernelExtension>> {
    let head = context.object_from_symbol(kernel, "kmod", None)?;
    let kmod_type = kernel.qualified("kmod_info");

    // The first extension is taken as it is found, which is what the reference
    // implementation does before it starts checking.
    let Ok(first) = head
        .dereference()
        .and_then(|first| first.cast(&kmod_type))
    else {
        return Ok(Vec::new());
    };
    let mut results = vec![KernelExtension::new(first.clone())];

    let Ok(mut pointer) = first.member("next") else {
        return Ok(results);
    };
    let mut seen = std::collections::HashSet::new();

    // A list this long is a sign the walk has gone astray.
    while pointer.pointer_value().unwrap_or(0) != 0
        && !seen.contains(&pointer.pointer_value().unwrap_or(0))
        && seen.len() < 1024
    {
        let Ok(extension) = pointer.dereference() else {
            break;
        };
        if !extension.is_readable() {
            break;
        }
        seen.insert(pointer.pointer_value().unwrap_or(0));
        results.push(KernelExtension::new(extension.clone()));

        let Ok(next) = extension.member("next") else {
            break;
        };
        pointer = next;
    }
    Ok(results)
}

impl Proc {
    /// The task's command line arguments.
    ///
    /// Darwin records the argument count and the address of the block holding
    /// the strings. The block also carries the executable path ahead of them.
    pub fn arguments(&self) -> Result<(u64, Vec<String>)> {
        let argc = self.object.member("p_argc")?.as_u64()?;
        let start = self.object.member("user_stack")?.as_u64()?;
        if start == 0 || argc == 0 || argc > 1024 {
            return Ok((argc, Vec::new()));
        }

        // The arguments sit just below the top of the user stack. Read a bounded
        // window and split it rather than trusting a length from the image.
        const WINDOW: usize = 0x2000;
        let base = start.saturating_sub(WINDOW as u64);
        let data = self
            .object
            .context()
            .layers
            .read(self.object.layer_name(), base, WINDOW, true)?;

        let strings: Vec<String> = data
            .split(|&byte| byte == 0)
            .filter(|part| {
                !part.is_empty() && part.iter().all(|&b| b.is_ascii_graphic() || b == b' ')
            })
            .map(|part| String::from_utf8_lossy(part).to_string())
            .collect();

        // The last `argc` plausible strings are the arguments themselves.
        let taken = strings
            .iter()
            .rev()
            .take(argc as usize)
            .rev()
            .cloned()
            .collect();
        Ok((argc, taken))
    }

    /// The process's open file descriptors, as `(file, path, descriptor)`.
    ///
    /// The path names the file a descriptor refers to, and for everything that
    /// is not a file it is the kind of descriptor in angle brackets. A
    /// descriptor of a kind the kernel does not name keeps the path of the one
    /// before it, which is what the reference implementation reports.
    pub fn file_descriptors(&self) -> Vec<(Object, Option<String>, u64)> {
        let descriptors = self.object.member("p_fd").and_then(|fd| fd.dereference());

        let last = descriptors
            .as_ref()
            .ok()
            .and_then(|fd| fd.member("fd_lastfile").ok())
            .and_then(|last| last.as_i64().ok())
            .unwrap_or(1024);
        let total = descriptors
            .as_ref()
            .ok()
            .and_then(|fd| fd.member("fd_nfiles").ok())
            .and_then(|count| count.as_i64().ok())
            .unwrap_or(1024);

        let mut count = last.max(total);
        // A table this large is a sign the count is not to be trusted, so a
        // plausible number is used instead.
        if count > 4096 {
            count = 1024;
        }
        if count < 0 {
            count = 0;
        }

        let Ok(table) = descriptors
            .and_then(|fd| fd.member("fd_ofiles"))
            .and_then(|files| files.pointer_value())
        else {
            return Vec::new();
        };

        let context = self.object.context().clone();
        let Some(table_name) = self.symbol_table() else {
            return Vec::new();
        };
        let Ok(fileproc_template) = context
            .symbol_space
            .get_type(&crate::framework::symbols::join_name(&table_name, "fileproc"))
        else {
            return Vec::new();
        };

        let mut results = Vec::new();
        let mut path: Option<String> = None;

        for descriptor in 0..count as u64 {
            let Ok(raw) =
                context
                    .layers
                    .read(self.object.layer_name(), table + descriptor * 8, 8, false)
            else {
                continue;
            };
            let entry = u64::from_le_bytes(raw.try_into().unwrap());
            if entry == 0 {
                continue;
            }

            let file = context.object_from_template(
                fileproc_template.clone(),
                self.object.layer_name(),
                entry,
            );
            let Some(kind) = file
                .member("f_fglob")
                .and_then(|glob| glob.dereference())
                .ok()
                .map(|glob| descriptor_kind(&glob))
            else {
                continue;
            };

            match kind.as_deref() {
                Some("VNODE") => {
                    let vnode = file
                        .member("f_fglob")
                        .and_then(|glob| glob.dereference())
                        .and_then(|glob| glob.member("fg_data"))
                        .and_then(|data| data.pointer_value())
                        .ok()
                        .filter(|address| *address != 0)
                        .map(|address| self.object.at_offset(address));
                    if let Some(vnode) = vnode {
                        let Ok(vnode) = vnode
                            .cast(&crate::framework::symbols::join_name(&table_name, "vnode"))
                        else {
                            continue;
                        };
                        path = Some(vnode_full_path(&vnode));
                    }
                }
                Some(kind) => path = Some(format!("<{}>", kind.to_lowercase())),
                None => {}
            }

            results.push((file, path.clone(), descriptor));
        }
        results
    }

    /// The symbol table this process was read from.
    pub fn symbol_table(&self) -> Option<String> {
        let resolved = self.object.resolved_template().ok()?;
        Some(resolved.as_struct()?.table.clone())
    }
}

/// What kind of thing a file descriptor refers to, named the way the kernel
/// names it with its `DTYPE_` prefix removed.
pub fn descriptor_kind(glob: &Object) -> Option<String> {
    let kind = if glob.has_member("fg_type") {
        glob.member("fg_type").ok()
    } else if glob.member("fg_ops").and_then(|ops| ops.pointer_value()).unwrap_or(0) != 0 {
        glob.member("fg_ops")
            .and_then(|ops| ops.dereference())
            .and_then(|ops| ops.member("fo_type"))
            .ok()
    } else {
        None
    }?;

    // A descriptor of no kind is one the kernel has not filled in.
    if kind.as_u64().ok()? == 0 {
        return None;
    }
    Some(kind.enum_name().ok()?.replace("DTYPE_", ""))
}

/// The value the kernel writes over memory it has freed.
const ZP_POISON: u64 = 0xDEADBEEFDEADBEEF;

/// The vnode is the root of a mounted filesystem.
const VNODE_IS_MOUNT_ROOT: u64 = 0x000001;
/// The filesystem is mounted at the root of the tree.
const MNT_ROOTFS: u64 = 0x00004000;

/// The full path of a file, built by naming each vnode from the file up to the
/// root of the tree and crossing any mount points on the way.
pub fn vnode_full_path(vnode: &Object) -> String {
    let flag = vnode
        .member("v_flag")
        .and_then(|flag| flag.as_u64())
        .unwrap_or(0);
    let mount = vnode.member("v_mount").ok();
    let mount_address = mount
        .as_ref()
        .and_then(|mount| mount.pointer_value().ok())
        .unwrap_or(0);

    // A vnode that is the root of the filesystem mounted at the root of the
    // tree is the root itself.
    if flag & VNODE_IS_MOUNT_ROOT != 0 && mount_address != 0 {
        let mount_flag = mount
            .as_ref()
            .and_then(|mount| mount.dereference().ok())
            .and_then(|mount| mount.member("mnt_flag").ok())
            .and_then(|flag| flag.as_u64().ok())
            .unwrap_or(0);
        if mount_flag & MNT_ROOTFS != 0 {
            return "/".to_string();
        }
    }

    let mut elements: Vec<String> = Vec::new();
    let mut current = vnode.clone();
    let mut name = vnode.member("v_name").ok();

    // A path deeper than this is a sign the chain has gone astray.
    for _ in 0..1000 {
        // Not every vnode on the way is named, and an unnamed one still leads
        // onwards.
        if let Some(pointer) = &name {
            if pointer.pointer_value().unwrap_or(0) != 0 {
                match pointer_to_string(pointer, 255) {
                    Ok(element) => elements.push(element),
                    Err(_) => break,
                }
            }
        }

        let flag = current
            .member("v_flag")
            .and_then(|flag| flag.as_u64())
            .unwrap_or(0);
        let mount = current.member("v_mount").ok();
        let mount_address = mount
            .as_ref()
            .and_then(|mount| mount.pointer_value().ok())
            .unwrap_or(0);

        let next = if flag & VNODE_IS_MOUNT_ROOT != 0 && mount_address != 0 {
            // The path continues at the directory the filesystem was mounted
            // over, so a file inside a mount reads as one whole path.
            mount
                .and_then(|mount| mount.dereference().ok())
                .and_then(|mount| mount.member("mnt_vnodecovered").ok())
                .filter(|covered| covered.pointer_value().unwrap_or(0) != 0)
                .and_then(|covered| covered.dereference().ok())
        } else {
            current
                .member("v_parent")
                .and_then(|parent| parent.dereference())
                .ok()
                .filter(|parent| parent.member("v_name").is_ok())
        };

        let Some(next) = next else { break };
        name = next.member("v_name").ok();
        current = next;
    }

    elements.reverse();
    if elements.is_empty() {
        String::new()
    } else {
        format!("/{}", elements.join("/"))
    }
}

/// The path of a mapped file, built by naming each vnode from the file to the
/// root. Mappings are named without crossing mount points, and always read as
/// an absolute path even when nothing could be named.
///
/// Takes the pointer to the file's vnode rather than the vnode itself, since
/// the chain is followed pointer by pointer.
pub fn vnode_map_path(handle: &Object) -> String {
    let mut elements: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut node = handle.clone();

    while node.pointer_value().unwrap_or(0) != 0 && seen.insert(node.offset()) {
        let Ok(name) = node
            .dereference()
            .and_then(|vnode| vnode.member("v_name"))
            .and_then(|name| {
                if name.pointer_value()? == 0 {
                    return Err(VolatilityError::Other("No name".to_string()));
                }
                pointer_to_string(&name, 255)
            })
        else {
            break;
        };
        elements.push(name);
        // A chain this long is a sign it has gone astray.
        if elements.len() > 1024 {
            break;
        }
        let Ok(parent) = node
            .dereference()
            .and_then(|vnode| vnode.member("v_parent"))
        else {
            break;
        };
        node = parent;
    }

    elements.reverse();
    format!("/{}", elements.join("/"))
}


/// A mounted filesystem.
pub struct Mount {
    pub object: Object,
}

impl Mount {
    /// The device the filesystem was mounted from.
    pub fn device(&self) -> Option<String> {
        self.statfs_string("f_mntfromname")
    }

    /// Where the filesystem is mounted.
    pub fn mount_point(&self) -> Option<String> {
        self.statfs_string("f_mntonname")
    }

    /// The filesystem type.
    pub fn filesystem_type(&self) -> Option<String> {
        self.statfs_string("f_fstypename")
    }

    /// Read one of the fixed-size name arrays inside `mnt_vfsstat`.
    fn statfs_string(&self, member: &str) -> Option<String> {
        self.object
            .member("mnt_vfsstat")
            .ok()?
            .member(member)
            .ok()?
            .as_string()
            .ok()
    }
}

/// Walk the kernel's list of mounted filesystems.
pub fn list_mounts(context: &Arc<Context>, kernel: &Module) -> Result<Vec<Mount>> {
    let head = context.object_from_symbol(kernel, "mountlist", None)?;
    Ok(
        walk_tailq(&head, &kernel.qualified("mount"), "mnt_list")?
            .into_iter()
            .map(|object| Mount { object })
            .collect(),
    )
}

/// Walk a BSD `TAILQ`, whose links live in a named member of each element.
///
/// Walk a tail queue, giving each element in turn.
pub fn walk_tailq(head: &Object, element_type: &str, link_member: &str) -> Result<Vec<Object>> {
    walk_iterable(head, "tqh_first", "tqe_next", element_type, link_member)
}

/// Walk a list whose head names its first element, giving each in turn.
pub fn walk_list_head(head: &Object, element_type: &str, link_member: &str) -> Result<Vec<Object>> {
    walk_iterable(head, "lh_first", "le_next", element_type, link_member)
}

/// Walk a singly linked list, giving each element in turn.
pub fn walk_slist(head: &Object, element_type: &str, link_member: &str) -> Result<Vec<Object>> {
    walk_iterable(head, "slh_first", "sle_next", element_type, link_member)
}

/// Walk a list from its head, following the link each element carries.
///
/// The walk stops at an element it has already passed, and at a list longer
/// than any the kernel would really keep, so a damaged list cannot run away
/// with it.
fn walk_iterable(
    head: &Object,
    first_member: &str,
    next_member: &str,
    element_type: &str,
    link_member: &str,
) -> Result<Vec<Object>> {
    let context = head.context().clone();
    let template = context.symbol_space.get_type(element_type)?;

    let Ok(mut pointer) = head.member(first_member) else {
        return Ok(Vec::new());
    };
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    while pointer.pointer_value().unwrap_or(0) != 0 {
        if !seen.insert(pointer.offset()) {
            break;
        }
        // A list this long is a sign the walk has gone astray.
        if seen.len() == 4096 {
            break;
        }

        let address = pointer.pointer_value()?;
        let element = context.object_from_template(template.clone(), head.layer_name(), address);
        if pointer.is_readable() {
            results.push(element.clone());
        }

        let Ok(next) = element
            .member(link_member)
            .and_then(|link| link.member(next_member))
        else {
            break;
        };
        pointer = next;
    }
    Ok(results)
}

/// Render a `sockaddr` as text, for the address families that have one. An
/// address family with no text form gives an empty string rather than nothing,
/// which is what callers print.
pub fn format_sockaddr(sockaddr: &Object) -> String {
    let Ok(family) = sockaddr.member("sa_family").and_then(|family| family.as_u64()) else {
        return String::new();
    };
    let Ok(data_offset) = sockaddr.member("sa_data").map(|data| data.offset()) else {
        return String::new();
    };
    let context = sockaddr.context().clone();

    match family {
        // AF_INET: two bytes of port, then four of address.
        2 => context
            .layers
            .read(sockaddr.layer_name(), data_offset + 2, 4, false)
            .map(|raw| format!("{}.{}.{}.{}", raw[0], raw[1], raw[2], raw[3]))
            .unwrap_or_default(),
        // AF_INET6: the address begins eight bytes into the structure.
        30 => context
            .layers
            .read(sockaddr.layer_name(), data_offset + 6, 16, false)
            .map(|raw| crate::framework::renderers::conversion::convert_ipv6(&raw))
            .unwrap_or_default(),
        // AF_LINK: a link-level address, which is a hardware address.
        18 => format_sockaddr_dl(sockaddr),
        _ => String::new(),
    }
}

/// Render a `sockaddr_dl` as a hardware address. The address sits inside the
/// structure's data after the interface name, and both lengths are recorded in
/// the structure itself.
pub fn format_sockaddr_dl(sockaddr: &Object) -> String {
    let Ok(name_length) = sockaddr.member("sdl_nlen").and_then(|length| length.as_u64()) else {
        return String::new();
    };
    let Ok(address_length) = sockaddr.member("sdl_alen").and_then(|length| length.as_u64()) else {
        return String::new();
    };
    // Anything longer than this is not a hardware address, so nothing is
    // reported rather than a run of meaningless bytes.
    if address_length > 14 {
        return String::new();
    }
    let Ok(data) = sockaddr.member("sdl_data") else {
        return String::new();
    };

    let mut bytes = Vec::new();
    for step in 0..address_length {
        // The data holds the name first, so the address starts after it. The
        // recorded length can run past the end of the field, and then the
        // address is only as long as what is actually there.
        let Ok(byte) = data
            .index(name_length + step)
            .and_then(|element| element.as_u64())
        else {
            break;
        };
        bytes.push(format!("{:02X}", byte as u8));
    }
    bytes.join(":")
}


/// One mapped region of a process's address space, wrapping a `vm_map_entry`.
pub struct VmMapEntry {
    pub object: Object,
}

impl VmMapEntry {
    pub fn start(&self) -> Result<u64> {
        self.object.member("links")?.member("start")?.as_u64()
    }

    pub fn end(&self) -> Result<u64> {
        self.object.member("links")?.member("end")?.as_u64()
    }

    /// Page protection, in the `rwx` form.
    ///
    /// Write and execute are only reported alongside read, which is how the
    /// reference implementation reads the protection bits.
    pub fn protection(&self) -> String {
        let protection = self
            .object
            .member("protection")
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        let mut text = String::with_capacity(3);
        for (letter, bits) in [('r', 1), ('w', 3), ('x', 5)] {
            text.push(if protection & bits == bits { letter } else { '-' });
        }
        text
    }

    /// Which part of the address space this mapping belongs to, as the kernel
    /// tags it.
    pub fn range_alias(&self) -> u64 {
        if self.object.has_member("alias") {
            self.object
                .member("alias")
                .and_then(|alias| alias.as_u64())
                .unwrap_or(0)
        } else {
            self.object
                .member("vme_offset")
                .and_then(|offset| offset.as_u64())
                .unwrap_or(0)
                & 0xFFF
        }
    }

    /// The name of a mapping that is part of the process rather than a file.
    pub fn special_path(&self) -> String {
        match self.range_alias() {
            1..=9 => "[heap]".to_string(),
            30 => "[stack]".to_string(),
            _ => String::new(),
        }
    }

    /// The vnode backing this mapping, when a file backs it.
    ///
    /// The mapping names a memory object, which may be shadowed by others, and
    /// the last of those names the pager that reads it. Only a pager that
    /// reads from a file leads to a vnode.
    pub fn vnode_handle(&self, kernel: &Module) -> Option<Object> {
        if self
            .object
            .member("is_sub_map")
            .and_then(|value| value.as_u64())
            .unwrap_or(0)
            == 1
        {
            return None;
        }

        let object = if self.object.has_member("vme_object") {
            self.object.member("vme_object").ok()?
        } else {
            self.object.member("object").ok()?
        };
        let map_object = if object.has_member("vm_object") {
            object.member("vm_object").ok()?
        } else {
            object.member("vmo_object").ok()?
        };
        if map_object.pointer_value().ok()? == 0 {
            return None;
        }

        // A memory object may shadow another, and the one at the end of the
        // chain is the one that is backed.
        let mut current = map_object;
        loop {
            let Ok(shadow) = current
                .dereference()
                .and_then(|object| object.member("shadow"))
                .and_then(|shadow| shadow.dereference())
            else {
                break;
            };
            if shadow.offset() == 0 {
                break;
            }
            current = shadow;
        }
        if current.offset() == 0 {
            return None;
        }

        let pager = match current.member("pager") {
            Ok(pager) => pager,
            // Before the chain has been followed once the object is still a
            // pointer to the memory object rather than the object itself.
            Err(_) => current.dereference().ok()?.member("pager").ok()?,
        };
        let pager_address = pager.pointer_value().ok()?;
        if pager_address == 0 {
            return None;
        }
        let operations = pager
            .dereference()
            .and_then(|pager| pager.member("mo_pager_ops"))
            .and_then(|ops| ops.dereference())
            .ok()?;

        // Only a pager that reads from a file leads to a vnode, and the kernel
        // is asked which pager this is by name.
        let named = self
            .object
            .context()
            .symbol_space
            .symbols_at(operations.offset())
            .iter()
            .any(|name| name == "vnode_pager_ops" || name == "_vnode_pager_ops");
        if !named {
            return None;
        }

        let template = self
            .object
            .context()
            .symbol_space
            .get_type(&kernel.qualified("vnode_pager"))
            .ok()?;
        let vnode_pager = self.object.context().object_from_template(
            template,
            self.object.layer_name(),
            pager_address,
        );
        vnode_pager.member("vnode_handle").ok()
    }

    /// The name of whatever backs this mapping.
    pub fn path(&self, kernel: &Module) -> String {
        match self.vnode_handle(kernel) {
            Some(handle) if handle.pointer_value().unwrap_or(0) != 0 => vnode_map_path(&handle),
            _ => String::new(),
        }
    }
}

impl Proc {
    /// A layer that reads the process's own address space.
    ///
    /// The kernel keeps each task's page table root in its physical map, so a
    /// layer rooted there translates the user addresses the task's mappings
    /// describe. A process whose map cannot be read has none.
    pub fn process_layer(&self) -> Result<Option<String>> {
        use crate::framework::layers::intel::IntelLayer;

        let context = self.object.context().clone();
        let Ok(task) = self.task() else {
            return Ok(None);
        };
        let Ok(dtb) = task
            .member("map")
            .and_then(|map| map.dereference())
            .and_then(|map| map.member("pmap"))
            .and_then(|pmap| pmap.dereference())
            .and_then(|pmap| pmap.member("pm_cr3"))
            .and_then(|cr3| cr3.as_u64())
        else {
            return Ok(None);
        };
        let parent = context.layers.get(self.object.layer_name())?;
        let Some(intel) = parent.as_any().downcast_ref::<IntelLayer>() else {
            return Ok(None);
        };

        let name = context
            .layers
            .free_name(&format!("{}_Process", self.object.layer_name()));
        context.layers.add(std::sync::Arc::new(IntelLayer::new(
            name.clone(),
            intel.base_layer_name(),
            dtb,
            intel.config().clone(),
        )));
        Ok(Some(name))
    }

    /// The task structure behind the process.
    pub fn task(&self) -> Result<crate::framework::objects::Object> {
        let task = self.object.member("task")?;
        let task_address = task.pointer_value()?;
        if task_address == 0 {
            return Err(VolatilityError::Other(
                "Process has no task structure".to_string(),
            ));
        }

        let context = self.object.context().clone();
        let resolved = self.object.resolved_template()?;
        let table = resolved
            .as_struct()
            .map(|structure| structure.table.clone())
            .ok_or_else(|| {
                VolatilityError::Other("Cannot determine the symbol table".to_string())
            })?;
        let template = context
            .symbol_space
            .get_type(&crate::framework::symbols::join_name(&table, "task"))?;
        Ok(context.object_from_template(template, self.object.layer_name(), task_address))
    }

    /// The process's mapped regions, in address order.
    ///
    /// The map is a doubly-linked list of entries hanging off the task's
    /// `vm_map`. The header entry is the list anchor rather than a real region.
    pub fn vm_map_entries(&self) -> Result<Vec<VmMapEntry>> {
        let task = self.object.member("task")?;
        let task_address = task.pointer_value()?;
        if task_address == 0 {
            return Ok(Vec::new());
        }

        let context = self.object.context().clone();
        let resolved = self.object.resolved_template()?;
        let table = resolved
            .as_struct()
            .map(|structure| structure.table.clone())
            .ok_or_else(|| {
                VolatilityError::Other("Cannot determine the symbol table".to_string())
            })?;

        let task_template = context
            .symbol_space
            .get_type(&crate::framework::symbols::join_name(&table, "task"))?;
        let task = context.object_from_template(
            task_template,
            self.object.layer_name(),
            task_address,
        );

        let map = task.member("map")?.dereference()?;
        let header = map.member("hdr")?.member("links")?;
        let entry_count = map
            .member("hdr")
            .and_then(|hdr| hdr.member("nentries"))
            .and_then(|count| count.as_u64())
            .unwrap_or(0)
            .min(100_000);

        let entry_template = context
            .symbol_space
            .get_type(&crate::framework::symbols::join_name(&table, "vm_map_entry"))?;

        let mut results = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut address = header.member("next")?.pointer_value()?;
        let header_offset = header.offset();

        while address != 0 && address != header_offset && results.len() < entry_count as usize {
            if !seen.insert(address) {
                break;
            }
            let entry = context.object_from_template(
                entry_template.clone(),
                self.object.layer_name(),
                address,
            );
            if !entry.is_readable() {
                break;
            }
            // The kernel fills freed memory with this value to catch its own
            // mistakes, so an entry holding it is no longer a mapping.
            let poisoned = [entry.member("links").and_then(|links| links.member("start")),
                            entry.member("links").and_then(|links| links.member("end"))]
                .into_iter()
                .any(|value| value.and_then(|value| value.as_u64()).unwrap_or(0) == ZP_POISON);
            if poisoned {
                break;
            }

            let next = entry
                .member("links")
                .and_then(|links| links.member("next"))
                .and_then(|pointer| pointer.pointer_value());

            results.push(VmMapEntry { object: entry });
            match next {
                Ok(value) => address = value,
                Err(_) => break,
            }
        }
        Ok(results)
    }
}

/// Attributing a kernel address to the extension that owns it.
///
/// The Mac `check_*` plugins all read a table of function pointers and ask
/// which extension each entry belongs to. An entry owned by none has been
/// redirected.
pub struct ExtensionResolver {
    /// The kernel and every loaded extension, with the range each covers.
    handlers: Vec<(String, u64, u64)>,
    /// How far the kernel sits from where its symbol file describes it.
    kernel_offset: u64,
}

impl ExtensionResolver {
    pub fn new(context: &Arc<Context>, kernel: &Module) -> Result<Self> {
        let mask = context.layers.address_mask(&kernel.layer_name);

        // The kernel's own text comes first, so an address inside it is
        // attributed to the kernel rather than to an extension that happens to
        // overlap.
        let mut handlers = Vec::new();
        let start = ["vm_kernel_stext", "stext"]
            .iter()
            .find_map(|symbol| context.object_from_symbol(kernel, symbol, None).ok())
            .and_then(|value| value.as_u64().ok())
            .unwrap_or(0)
            & mask;
        let end = ["vm_kernel_etext", "etext"]
            .iter()
            .find_map(|symbol| context.object_from_symbol(kernel, symbol, None).ok())
            .and_then(|value| value.as_u64().ok())
            .unwrap_or(0)
            & mask;
        handlers.push(("__kernel__".to_string(), start, end));

        for extension in list_extensions(context, kernel)? {
            let Ok(name) = extension.name() else { continue };
            let base = extension
                .object
                .member("address")
                .and_then(|address| address.as_u64())
                .unwrap_or(0)
                & mask;
            let Ok(size) = extension.size() else { continue };
            handlers.push((name, base, base.wrapping_add(size)));
        }

        Ok(Self {
            handlers,
            kernel_offset: kernel.offset,
        })
    }

    /// Describe an address as the module holding it and the symbol naming it.
    ///
    /// An address no module claims is reported as unknown, and an address that
    /// no symbol names exactly has none to give.
    pub fn describe(&self, context: &Arc<Context>, address: u64) -> (String, String) {
        self.describe_shifted(context, address, self.kernel_offset)
    }

    /// The same, without taking off where the kernel sits, which is how the
    /// socket filters are looked up.
    pub fn describe_unshifted(&self, context: &Arc<Context>, address: u64) -> (String, String) {
        self.describe_shifted(context, address, 0)
    }

    fn describe_shifted(
        &self,
        context: &Arc<Context>,
        address: u64,
        shift: u64,
    ) -> (String, String) {
        let mut module = "UNKNOWN".to_string();
        let mut symbol = "N/A".to_string();

        for (name, start, end) in &self.handlers {
            if *start <= address && address <= *end {
                module = name.clone();
                if name == "__kernel__" {
                    // The symbol file records addresses before the kernel was
                    // placed in memory, so the shift comes off first.
                    if let Some(found) = context
                        .symbol_space
                        .symbols_at(address.wrapping_sub(shift))
                        .first()
                    {
                        symbol = found.clone();
                    }
                }
                break;
            }
        }
        (module, symbol)
    }

}
