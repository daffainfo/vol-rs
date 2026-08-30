//! Report the files the kernel currently holds in its page cache.
//!
//! Every filesystem the kernel has mounted keeps a list of the inodes it has
//! touched, and each inode records how much of its content is resident. That
//! makes the page cache a record of which files were recently read or written,
//! including ones since deleted from disk.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::utility::{pointer_to_string, walk_list};
use crate::framework::objects::Object;
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::conversion::timespec_to_datetime;
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::linux::{
    mount_points, read_qstr, resolve_path, walk_hlist, xarray_entries,
};

pub struct Files;

/// The page size every file in the cache is held in.
const PAGE_SIZE: u64 = 4096;

/// The file type a mode names, where it names one.
fn inode_type_name(inode: &Object) -> Option<&'static str> {
    let mode = inode.member("i_mode").and_then(|m| m.as_u64()).unwrap_or(0);
    match mode & 0xF000 {
        0x1000 => Some("FIFO"),
        0x2000 => Some("CHR"),
        0x4000 => Some("DIR"),
        0x6000 => Some("BLK"),
        0x8000 => Some("REG"),
        0xA000 => Some("LNK"),
        0xC000 => Some("SOCK"),
        _ => None,
    }
}

/// The file type, as an absent value when the mode names none.
fn inode_type(inode: &Object) -> Value {
    match inode_type_name(inode) {
        Some(name) => Value::string(name),
        None => Value::unparsable(),
    }
}

/// The mode, rendered the way `ls -l` shows it.
fn file_mode(inode: &Object) -> String {
    let mode = inode.member("i_mode").and_then(|m| m.as_u64()).unwrap_or(0);
    let mut text = String::with_capacity(10);
    text.push(match mode & 0xF000 {
        0x4000 => 'd',
        0x8000 => '-',
        0xA000 => 'l',
        0x1000 => 'p',
        0xC000 => 's',
        0x2000 => 'c',
        0x6000 => 'b',
        _ => '?',
    });
    for shift in [6, 3, 0] {
        let bits = (mode >> shift) & 0x7;
        text.push(if bits & 0x4 != 0 { 'r' } else { '-' });
        text.push(if bits & 0x2 != 0 { 'w' } else { '-' });
        text.push(if bits & 0x1 != 0 { 'x' } else { '-' });
    }
    // The set-user, set-group and sticky bits replace the execute characters.
    let mut bytes: Vec<char> = text.chars().collect();
    if mode & 0o4000 != 0 {
        bytes[3] = if bytes[3] == 'x' { 's' } else { 'S' };
    }
    if mode & 0o2000 != 0 {
        bytes[6] = if bytes[6] == 'x' { 's' } else { 'S' };
    }
    if mode & 0o1000 != 0 {
        bytes[9] = if bytes[9] == 'x' { 't' } else { 'T' };
    }
    bytes.into_iter().collect()
}

impl Plugin for Files {
    fn name(&self) -> &'static str {
        "linux.pagecache.Files"
    }

    fn description(&self) -> &'static str {
        "Lists files from memory"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "type",
                "List of space-separated file type filters i.e. --type REG DIR",
                crate::framework::plugins::RequirementKind::List(Box::new(
                    crate::framework::plugins::RequirementKind::String,
                )),
            ),
            Requirement::new(
                "find",
                "Filename (full path) to find",
                crate::framework::plugins::RequirementKind::String,
            ),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("SuperblockAddr", ColumnType::UInt),
            Column::string("MountPoint"),
            Column::string("Device"),
            Column::int("InodeNum"),
            Column::new("InodeAddr", ColumnType::UInt),
            Column::string("FileType"),
            Column::int("InodePages"),
            Column::int("CachedPages"),
            Column::string("FileMode"),
            Column::datetime("AccessTime"),
            Column::datetime("ModificationTime"),
            Column::datetime("ChangeTime"),
            Column::string("FilePath"),
            Column::int("InodeSize"),
        ]
    }

    fn timeline(
        &self,
        context: Arc<Context>,
        config: &Configuration,
    ) -> Option<crate::framework::plugins::Timeline> {
        use crate::framework::plugins::{TimeKind, Timeline};

        let kernel = kernel_module(&context, config).ok()?;
        let mut timeline = Timeline::new();
        for entry in cached_inodes(&context, &kernel, true).ok()? {
            let description = format!("Cached Inode for {}", entry.path);
            timeline.push(
                description.clone(),
                TimeKind::Accessed,
                inode_time(&entry.inode, "i_atime"),
            );
            timeline.push(
                description.clone(),
                TimeKind::Modified,
                inode_time(&entry.inode, "i_mtime"),
            );
            timeline.push(
                description,
                TimeKind::Changed,
                inode_time(&entry.inode, "i_ctime"),
            );
        }
        Some(timeline)
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let mut grid = TreeGrid::new(self.columns());

        let wanted_types: Option<Vec<String>> = config.get("type").and_then(|value| {
            value.as_list().map(|list| {
                list.iter()
                    .filter_map(|entry| entry.as_str().map(str::to_string))
                    .collect()
            })
        });
        let wanted_path = config.get_string("find");

        for entry in cached_inodes(&context, &kernel, true)? {
            if let Some(types) = &wanted_types {
                if !types.is_empty()
                    && !inode_type_name(&entry.inode)
                        .is_some_and(|kind| types.iter().any(|wanted| wanted == kind))
                {
                    continue;
                }
            }

            // Looking for one path stops at the first file that has it.
            if let Some(path) = &wanted_path {
                if &entry.path == path {
                    grid.push(0, inode_row(&entry))?;
                    break;
                }
            } else {
                grid.push(0, inode_row(&entry))?;
            }
        }
        Ok(grid)
    }
}

/// One inode found in the page cache, with where it was reached from.
pub struct CachedInode {
    pub superblock: Object,
    pub mount_point: String,
    pub inode: Object,
    pub path: String,
}

/// Every inode reachable from a mounted filesystem's dentry tree.
///
/// The kernel keeps a dentry for each name it has looked up, so walking them
/// from each mount's root recovers the paths of files still in the page cache.
pub fn cached_inodes(
    context: &Arc<Context>,
    kernel: &Module,
    follow_symlinks: bool,
) -> Result<Vec<CachedInode>> {
    let mut results = Vec::new();
    let mut seen_superblocks = std::collections::HashSet::new();
    let mut seen_inodes = std::collections::HashSet::new();
    let mut seen_dentries = std::collections::HashSet::new();

    for (task, mount) in mount_points(context, kernel)? {
        let Ok(vfsmount) = mount.member("mnt") else {
            continue;
        };
        let Ok(mount_root) = vfsmount.member("mnt_root").and_then(|r| r.dereference()) else {
            continue;
        };
        let Some(mount_point) = resolve_path(&task, mount_root, vfsmount.clone(), None) else {
            continue;
        };

        let Ok(superblock) = vfsmount.member("mnt_sb").and_then(|sb| sb.dereference()) else {
            continue;
        };
        if !superblock.is_readable() || !seen_superblocks.insert(superblock.offset()) {
            continue;
        }

        // The root of a filesystem is its own parent, which is what marks it.
        let Ok(root) = superblock.member("s_root").and_then(|root| root.dereference()) else {
            continue;
        };
        if root
            .member("d_parent")
            .and_then(|parent| parent.pointer_value())
            .map(|parent| parent != root.offset())
            .unwrap_or(true)
        {
            continue;
        }

        if let Some(inode) = cacheable_inode(&root) {
            if seen_inodes.insert(inode.offset()) {
                results.push(CachedInode {
                    superblock: superblock.clone(),
                    mount_point: mount_point.clone(),
                    inode,
                    path: mount_point.clone(),
                });
            }
        }

        // Paths below the root are built from the mount point downwards. The
        // root itself contributes nothing to avoid a doubled leading slash.
        let parent = if mount_point == "/" { "" } else { &mount_point };
        walk_dentries(
            context,
            kernel,
            &root,
            parent,
            &superblock,
            &mount_point,
            follow_symlinks,
            &mut seen_dentries,
            &mut seen_inodes,
            &mut results,
        );
    }
    Ok(results)
}

/// The inode behind a dentry, if it can hold cached pages.
fn cacheable_inode(dentry: &Object) -> Option<Object> {
    let inode = dentry.member("d_inode").ok()?.dereference().ok()?;
    if !inode.is_readable() {
        return None;
    }
    // The same liveness test the rest of the port uses for an inode.
    let number = inode.member("i_ino").ok()?.as_u64().ok()?;
    let references = inode
        .member("i_count")
        .and_then(|count| count.member("counter"))
        .and_then(|value| value.as_i64())
        .unwrap_or(-1);
    if number == 0 || references < 0 {
        return None;
    }
    // Reading cached pages needs an address space to read them from.
    let mapping = inode.member("i_mapping").ok()?;
    if mapping.pointer_value().ok()? == 0 || !mapping.dereference().ok()?.is_readable() {
        return None;
    }
    Some(inode)
}

#[allow(clippy::too_many_arguments)]
fn walk_dentries(
    context: &Arc<Context>,
    kernel: &Module,
    parent_dentry: &Object,
    parent_path: &str,
    superblock: &Object,
    mount_point: &str,
    follow_symlinks: bool,
    seen_dentries: &mut std::collections::HashSet<u64>,
    seen_inodes: &mut std::collections::HashSet<u64>,
    results: &mut Vec<CachedInode>,
) {
    // Kernel 6.8 moved the children from a doubly-linked list into an hlist,
    // renaming both the head and the link within each child.
    let entries = if parent_dentry.has_member("d_children") {
        let Ok(head) = parent_dentry.member("d_children") else {
            return;
        };
        walk_hlist(context, &head, &kernel.qualified("dentry"), "d_sib")
    } else {
        let Ok(head) = parent_dentry.member("d_subdirs") else {
            return;
        };
        walk_list(&head, &kernel.qualified("dentry"), "d_child", true)
    };
    let Ok(entries) = entries else {
        return;
    };

    for dentry in entries {
        if dentry.offset() == parent_dentry.offset() || !seen_dentries.insert(dentry.offset()) {
            continue;
        }
        let Some(inode) = cacheable_inode(&dentry) else {
            continue;
        };
        let Some(name) = dentry.member("d_name").ok().and_then(|qstr| read_qstr(&qstr)) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let path = format!("{parent_path}/{name}");

        if seen_inodes.insert(inode.offset()) {
            let mode = inode.member("i_mode").and_then(|m| m.as_u64()).unwrap_or(0);
            // A fast symlink stores its target inline, which is worth showing.
            let shown = if follow_symlinks && mode & 0xF000 == 0xA000 {
                inode
                    .member("i_link")
                    .ok()
                    .filter(|link| link.pointer_value().unwrap_or(0) != 0)
                    .and_then(|link| pointer_to_string(&link, 255).ok())
                    .map(|target| format!("{path} -> {target}"))
                    .unwrap_or_else(|| path.clone())
            } else {
                path.clone()
            };

            results.push(CachedInode {
                superblock: superblock.clone(),
                mount_point: mount_point.to_string(),
                inode: inode.clone(),
                path: shown,
            });
        }

        if mode_is_directory(&inode) {
            walk_dentries(
                context,
                kernel,
                &dentry,
                &path,
                superblock,
                mount_point,
                follow_symlinks,
                seen_dentries,
                seen_inodes,
                results,
            );
        }
    }
}

fn mode_is_directory(inode: &Object) -> bool {
    inode
        .member("i_mode")
        .and_then(|mode| mode.as_u64())
        .map(|mode| mode & 0xF000 == 0x4000)
        .unwrap_or(false)
}

/// Render one cached inode as a row.
pub fn inode_row(entry: &CachedInode) -> Vec<Value> {
    let inode = &entry.inode;
    let read = |name: &str| inode.member(name).and_then(|value| value.as_i64()).unwrap_or(0);

    let device = entry
        .superblock
        .member("s_dev")
        .and_then(|dev| dev.as_u64())
        .unwrap_or(0);
    let size = read("i_size");
    let cached = inode
        .member("i_mapping")
        .and_then(|mapping| mapping.dereference())
        .and_then(|mapping| mapping.member("nrpages"))
        .and_then(|pages| pages.as_i64())
        .unwrap_or(0);

    vec![
        Value::hex(entry.superblock.offset()),
        Value::string(entry.mount_point.clone()),
        Value::string(format!("{}:{}", device >> 20, device & ((1 << 20) - 1))),
        Value::int(read("i_ino")),
        Value::hex(inode.offset()),
        inode_type(inode),
        // The inode's size rounded up to whole pages.
        Value::int((size + 0xFFF) / 0x1000),
        Value::int(cached),
        Value::string(file_mode(inode)),
        inode_time(inode, "i_atime"),
        inode_time(inode, "i_mtime"),
        inode_time(inode, "i_ctime"),
        Value::string(entry.path.clone()),
        Value::int(size),
    ]
}


/// One of an inode's timestamps.
///
/// The kernel moved these from `timespec` structures to packed fields, so both
/// spellings are tried.
fn inode_time(inode: &Object, member: &str) -> Value {
    // Kernel 6.6 renamed these with a leading underscore, and 6.11 split them
    // into separate seconds and nanoseconds fields.
    let timespec = inode
        .member(&format!("__{member}"))
        .or_else(|_| inode.member(member))
        .ok()
        .and_then(|time| {
            Some((
                time.member("tv_sec").ok()?.as_i64().ok()?,
                time.member("tv_nsec").ok()?.as_i64().ok()?,
            ))
        })
        .or_else(|| {
            Some((
                inode.member(&format!("{member}_sec")).ok()?.as_i64().ok()?,
                inode.member(&format!("{member}_nsec")).ok()?.as_i64().ok()?,
            ))
        });

    match timespec.and_then(|(seconds, nanoseconds)| timespec_to_datetime(seconds, nanoseconds)) {
        Some(when) => Value::DateTime(when),
        None => Value::unreadable(),
    }
}


/// Reports the individual cached pages of one file.
pub struct InodePages;

impl Plugin for InodePages {
    fn name(&self) -> &'static str {
        "linux.pagecache.InodePages"
    }

    fn description(&self) -> &'static str {
        "Lists and recovers cached inode pages"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "find",
                "Filename (full path) to find",
                crate::framework::plugins::RequirementKind::String,
            ),
            Requirement::new(
                "inode",
                "Inode address",
                crate::framework::plugins::RequirementKind::Int,
            ),
            Requirement::new(
                "dump",
                "Extract inode content",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("PageVAddr", ColumnType::UInt),
            Column::new("PagePAddr", ColumnType::UInt),
            Column::new("MappingAddr", ColumnType::UInt),
            Column::int("Index"),
            Column::bool("DumpSafe"),
            Column::string("Flags"),
            Column::string("Output File"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let grid = TreeGrid::new(self.columns());

        // The plugin describes one file, named either by the address of its
        // inode or by its path, but not by both.
        let requested = config.get_int("inode").map(|value| value as u64);
        let wanted_path = config.get_string("find");
        if requested.is_some() && wanted_path.is_some() {
            log::error!("Cannot use --inode and --find simultaneously");
            return Ok(grid);
        }

        let inode = match (&wanted_path, requested) {
            (Some(path), _) => match find_inode(&context, &kernel, path) {
                Some(inode) => inode,
                None => {
                    log::error!("Unable to find inode with path {path}");
                    return Ok(grid);
                }
            },
            (None, Some(address)) => {
                context.module_object(&kernel, "inode", address)?
            }
            (None, None) => {
                log::error!("You must use either --inode or --find");
                return Ok(grid);
            }
        };

        if !inode_is_valid(&inode) {
            log::error!("Invalid inode at 0x{:x}", inode.offset());
            return Ok(grid);
        }
        let mode = inode
            .member("i_mode")
            .and_then(|mode| mode.as_u64())
            .unwrap_or(0);
        if mode & 0xF000 != 0x8000 {
            log::error!("The inode is not a regular file");
            return Ok(grid);
        }

        let size = inode
            .member("i_size")
            .and_then(|size| size.as_u64())
            .unwrap_or(0);
        let (pages, corrupt) = cached_pages(&context, &kernel, &inode);

        // Writing the file out happens before the pages are listed, so the name
        // the listing carries is the one the data went to.
        let mut file = Value::not_applicable();
        if config.get_bool("dump").unwrap_or(false) {
            let name = crate::framework::plugins::windows::pslist::sanitize_filename(&format!(
                "inode_0x{:x}.dmp",
                inode.offset()
            ));
            log::info!(
                "[*] Writing inode at 0x{:x} to '{name}'",
                inode.offset()
            );
            write_inode_contents(&context, &kernel, &inode, size, &pages, &name);
            file = Value::string(name);
        }

        let mut grid = grid;
        for page in &pages {
            // A page that belongs to a different file was reached through a
            // shared structure and is not part of this one.
            if page.mapping != inode.member("i_mapping").and_then(|m| m.pointer_value()).unwrap_or(0)
            {
                log::warn!(
                    "Cached page at {:#x} has a mismatched address space with the inode. \
                     Skipping page",
                    page.virtual_address
                );
                continue;
            }

            let offset = page.index * PAGE_SIZE;
            grid.push(
                0,
                vec![
                    Value::hex(page.virtual_address),
                    match page.physical_address {
                        Some(address) => Value::hex(address),
                        None => Value::not_available(),
                    },
                    Value::hex(page.mapping),
                    Value::int(page.index as i64),
                    // A page beyond the end of the file, or one whose address
                    // space cannot be read, would not be written out.
                    Value::Bool(
                        offset < size
                            && page.mapping != 0
                            && context
                                .layers
                                .is_valid(&kernel.layer_name, page.mapping, 1),
                    ),
                    Value::string(page.flags.clone()),
                    file.clone(),
                ],
            )?;
        }
        if corrupt {
            log::warn!("Page cache for inode at {:#x} is corrupt", inode.offset());
        }
        Ok(grid)
    }
}

/// Whether an inode looks like one the kernel is really using.
fn inode_is_valid(inode: &Object) -> bool {
    inode
        .member("i_ino")
        .and_then(|number| number.as_u64())
        .map(|number| number > 0)
        .unwrap_or(false)
}

/// Write a file's cached pages out, leaving holes where pages are missing.
///
/// The result is as long as the file was, so a page that was never cached
/// leaves a gap rather than shifting everything after it.
fn write_inode_contents(
    context: &Arc<Context>,
    kernel: &Module,
    inode: &Object,
    size: u64,
    pages: &[CachedPage],
    name: &str,
) {
    use std::io::{Seek, SeekFrom, Write};

    let mapping = inode
        .member("i_mapping")
        .and_then(|mapping| mapping.pointer_value())
        .unwrap_or(0);
    let physical = physical_layer(context, kernel);
    let chosen = crate::framework::plugins::free_extracted_name(name);
    let mut file: Option<std::fs::File> = None;

    for page in pages {
        if page.mapping != mapping {
            continue;
        }
        let Some(address) = page.physical_address else {
            continue;
        };
        let Ok(content) = context
            .layers
            .read(&physical, address, PAGE_SIZE as usize, false)
        else {
            continue;
        };

        let start = page.index * PAGE_SIZE;
        let length = (size.saturating_sub(start)).min(content.len() as u64);
        if start >= size || start + length > size {
            log::error!(
                "Page out of file bounds: inode 0x{:x}, inode size {size}, page index {}",
                inode.offset(),
                page.index
            );
            continue;
        }

        // The file is only created once there is something to put in it.
        if file.is_none() {
            match std::fs::File::create(&chosen) {
                Ok(handle) => {
                    let _ = handle.set_len(size);
                    file = Some(handle);
                }
                Err(error) => {
                    log::error!("Unable to write to file ({chosen}): {error}");
                    return;
                }
            }
        }
        if let Some(handle) = file.as_mut() {
            let _ = handle.seek(SeekFrom::Start(start));
            let _ = handle.write_all(&content[..length as usize]);
        }
    }
}

/// One cached page of a file.
struct CachedPage {
    /// Where the page structure sits, as the kernel layer reports it.
    virtual_address: u64,
    /// The frame the page describes, or nothing when the page structure sits
    /// below the start of the page array.
    physical_address: Option<u64>,
    mapping: u64,
    index: u64,
    flags: String,
}

/// The names of the flags set on a page.
///
/// The kernel names its own page flags in an enumeration, and several names can
/// share a value, so every matching name is reported. They are taken in the
/// order the symbol file lists them.
fn page_flag_names(context: &Arc<Context>, kernel: &Module, flags: u64) -> Vec<String> {
    let Ok(template) = context
        .symbol_space
        .get_type(&kernel.qualified("pageflags"))
    else {
        return Vec::new();
    };
    let Some(enumeration) = template.as_enum() else {
        return Vec::new();
    };

    let mut names: Vec<(&String, &i64)> = enumeration.choices.iter().collect();
    names.sort_by(|left, right| left.0.cmp(right.0));
    names
        .into_iter()
        .filter(|(_, bit)| **bit >= 0 && flags & (1u64 << **bit) != 0)
        .map(|(name, _)| name.clone())
        .collect()
}

/// The pages an inode currently has cached.
///
/// The second value says whether the walk was cut short by a page the capture
/// does not hold, which the reference implementation reports as a corrupt page
/// cache rather than as a shorter file.
fn cached_pages(
    context: &Arc<Context>,
    kernel: &Module,
    inode: &Object,
) -> (Vec<CachedPage>, bool) {
    let mut pages = Vec::new();

    // A file with no size or nothing resident has no cached pages at all.
    if inode
        .member("i_size")
        .and_then(|size| size.as_u64())
        .unwrap_or(0)
        == 0
    {
        return (pages, false);
    }
    let Ok(mapping) = inode.member("i_mapping") else {
        return (pages, false);
    };
    let Ok(space) = mapping.dereference() else {
        return (pages, false);
    };
    if !space.is_readable()
        || space
            .member("nrpages")
            .and_then(|count| count.as_u64())
            .unwrap_or(0)
            == 0
    {
        return (pages, false);
    }

    let (Ok(tree), Ok(page_type)) = (
        space.member("i_pages"),
        context.symbol_space.get_type(&kernel.qualified("page")),
    ) else {
        return (pages, false);
    };
    let (Ok(page_struct_size), Some(vmemmap)) = (
        context.symbol_space.size_of(&page_type),
        vmemmap_start(context, kernel),
    ) else {
        return (pages, false);
    };
    let Ok(entries) = xarray_entries(context, kernel, &tree) else {
        return (pages, false);
    };

    let mask = mask_for(context, kernel);
    let vmemmap = vmemmap & mask;
    for entry in entries {
        let address = entry & mask;
        // A page structure the capture does not hold, or one that cannot be a
        // page at all, means the cache cannot be walked any further.
        if !context.layers.is_valid(&kernel.layer_name, address, 1) {
            log::error!("Invalid cached page address at {address:#x}, aborting");
            return (pages, true);
        }
        let page = context.object_from_template(page_type.clone(), &kernel.layer_name, address);
        let owner = page
            .member("mapping")
            .and_then(|owner| owner.pointer_value())
            .unwrap_or(0);
        let physical_address = address
            .checked_sub(vmemmap)
            .map(|delta| (delta / page_struct_size) * PAGE_SIZE);
        if (owner != 0 && !context.layers.is_valid(&kernel.layer_name, owner, 1))
            || physical_address.is_none()
        {
            log::error!("Invalid cached page at {address:#x}, aborting");
            return (pages, true);
        }

        pages.push(CachedPage {
            virtual_address: address,
            physical_address,
            mapping: owner,
            index: page
                .member("index")
                .and_then(|index| index.as_u64())
                .unwrap_or(0),
            flags: page_flag_names(
                context,
                kernel,
                page.member("flags").and_then(|f| f.as_u64()).unwrap_or(0),
            )
            .into_iter()
            .map(|name| name.replace("PG_", ""))
            .collect::<Vec<String>>()
            .join(","),
        });
    }
    (pages, false)
}

/// Find a cached inode by its path.
fn find_inode(context: &Arc<Context>, kernel: &Module, wanted: &str) -> Option<Object> {
    cached_inodes(context, kernel, false)
        .ok()?
        .into_iter()
        .find(|entry| entry.path == wanted)
        .map(|entry| entry.inode)
}

/// Reports the cached files with the sizes a recovery would produce.
pub struct RecoverFs;

impl Plugin for RecoverFs {
    fn name(&self) -> &'static str {
        "linux.pagecache.RecoverFs"
    }

    fn description(&self) -> &'static str {
        "Recovers the cached filesystem (directories, files, symlinks) into a compressed tarball."
    }

    fn epilog(&self) -> Option<&'static str> {
        Some(
            "Details: level 0 directories are named after the UUID of the parent \
             superblock; metadata aren't replicated to extracted objects; objects \
             modification time is set to the plugin run time; absolute symlinks are \
             converted to relative symlinks to prevent referencing the analyst's \
             filesystem. Troubleshooting: to fix extraction errors related to long \
             paths, please consider using https://github.com/mxmlnkn/ratarmount.",
        )
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "tmpfs_only",
                "Extracts only files from tmpfs file systems",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
            Requirement::new(
                "compression_format",
                "Compression format (default: gz)",
                crate::framework::plugins::RequirementKind::Choice(vec![
                    "gz".to_string(),
                    "bz2".to_string(),
                    "xz".to_string(),
                ]),
            )
            .with_default(crate::framework::context::ConfigValue::Str("gz".to_string())),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        let mut columns = Files.columns();
        // The recovery view adds how much of each file could be reconstructed.
        columns.push(Column::int("Recovered FileSize"));
        columns
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let mut grid = TreeGrid::new(self.columns());
        let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut prefixes: std::collections::HashSet<String> = std::collections::HashSet::new();
        let tmpfs_only = config.get_bool("tmpfs_only").unwrap_or(false);
        let format = config
            .get_string("compression_format")
            .unwrap_or_else(|| "gz".to_string());

        // Everything recovered goes into one archive, with a single timestamp
        // so the tree carries the time of the run rather than of the capture.
        let mut archive = crate::framework::tar::Archive::new();
        let mtime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_secs_f64())
            .unwrap_or(0.0);

        for entry in cached_inodes(&context, &kernel, false)? {
            let mode = entry
                .inode
                .member("i_mode")
                .and_then(|mode| mode.as_u64())
                .unwrap_or(0)
                & 0xF000;
            // Only files, directories and symlinks can be written back out.
            if !matches!(mode, 0x8000 | 0x4000 | 0xA000) {
                continue;
            }
            // A path that is not absolute is the result of smear.
            if !entry.path.starts_with('/') {
                continue;
            }
            // A superblock whose type cannot be read describes no filesystem.
            let filesystem = entry
                .superblock
                .member("s_type")
                .and_then(|s_type| s_type.dereference())
                .and_then(|s_type| s_type.member("name"))
                .and_then(|name| pointer_to_string(&name, 255))
                .ok()
                .filter(|name| !name.is_empty());
            let Some(filesystem) = filesystem else {
                continue;
            };
            // Recovering only what was never on disk leaves out everything a
            // filesystem could be read back from.
            if tmpfs_only && filesystem != "tmpfs" {
                continue;
            }

            // Paths are prefixed with the filesystem's identity so that two
            // mounts cannot collide in the recovered tree.
            let prefix = superblock_prefix(&entry.superblock);
            let prefixed = format!("{prefix}{}", entry.path);
            if !visited.insert(prefixed.clone()) {
                continue;
            }
            if prefixes.insert(prefix.clone()) {
                archive.directory(&prefix, 0o755, mtime);
            }

            // A regular file contributes as much of itself as the cache still
            // holds. A directory or symlink has no contents for the question to
            // apply to.
            let mut target = None;
            let recovered = match mode {
                0x8000 => {
                    let contents = recovered_contents(&context, &kernel, &entry.inode);
                    archive.file(&prefixed, 0o444, mtime, &contents);
                    Value::int(contents.len() as i64)
                }
                0x4000 => {
                    archive.directory(&prefixed, 0o755, mtime);
                    Value::not_applicable()
                }
                // A symlink with no readable target cannot be written out at
                // all, so it is left out rather than listed with no
                // destination.
                _ => {
                    let Some(destination) = entry
                        .inode
                        .member("i_link")
                        .ok()
                        .filter(|link| link.pointer_value().unwrap_or(0) != 0)
                        .and_then(|link| pointer_to_string(&link, 255).ok())
                    else {
                        continue;
                    };
                    archive.symlink(
                        &prefixed,
                        &relative_target(&entry.path, &destination),
                        0o444,
                        mtime,
                    );
                    target = Some(destination);
                    Value::not_applicable()
                }
            };

            let mut values = inode_row(&entry);
            if let Some(target) = target {
                let index = values.len() - 2;
                values[index] = Value::string(format!("{} -> {target}", entry.path));
            }
            values.push(recovered);
            grid.push(0, values)?;
        }

        let name = format!("recovered_fs.tar.{format}");
        match compress(&archive.finish(), &format) {
            Some(data) => {
                if let Err(error) = crate::framework::plugins::write_extracted(&name, &data) {
                    log::error!("Unable to write to file ({name}): {error}");
                }
            }
            None => log::error!("Unknown compression format {format}"),
        }
        Ok(grid)
    }
}

/// A symlink's target, made relative so that it cannot reach out of the
/// recovered tree into the filesystem it is unpacked on.
fn relative_target(source: &str, destination: &str) -> String {
    let Some(absolute) = destination.strip_prefix('/') else {
        return destination.to_string();
    };
    // One step up for each directory between the link and the root.
    let depth = source
        .trim_start_matches('/')
        .split('/')
        .count()
        .saturating_sub(1);
    let mut path = String::new();
    for _ in 0..depth {
        path.push_str("../");
    }
    path.push_str(absolute);
    path
}

/// Compress the archive the way the chosen format asks for.
fn compress(data: &[u8], format: &str) -> Option<Vec<u8>> {
    use std::io::Write;
    match format {
        "gz" => {
            let mut encoder = flate2::write::GzEncoder::new(
                Vec::new(),
                flate2::Compression::new(9),
            );
            encoder.write_all(data).ok()?;
            encoder.finish().ok()
        }
        "bz2" => {
            let mut encoder =
                bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(9));
            encoder.write_all(data).ok()?;
            encoder.finish().ok()
        }
        "xz" => {
            let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
            encoder.write_all(data).ok()?;
            encoder.finish().ok()
        }
        _ => None,
    }
}

/// The contents of a file, as far as the page cache still holds them.
///
/// Pages that were evicted leave holes, which are written as zeros so that
/// everything after them stays at the offset it had in the original file.
fn recovered_contents(context: &Arc<Context>, kernel: &Module, inode: &Object) -> Vec<u8> {
    let size = inode
        .member("i_size")
        .and_then(|size| size.as_u64())
        .unwrap_or(0);
    let mapping = inode
        .member("i_mapping")
        .and_then(|mapping| mapping.pointer_value())
        .unwrap_or(0);
    let physical = physical_layer(context, kernel);
    let (pages, _) = cached_pages(context, kernel, inode);

    let mut contents: Vec<u8> = Vec::new();
    for page in pages {
        if page.mapping != mapping {
            continue;
        }
        let Some(address) = page.physical_address else {
            continue;
        };
        let Ok(data) = context
            .layers
            .read(&physical, address, PAGE_SIZE as usize, false)
        else {
            continue;
        };

        let start = page.index * PAGE_SIZE;
        let length = size.saturating_sub(start).min(data.len() as u64);
        if start >= size || start + length > size {
            continue;
        }
        let end = (start + length) as usize;
        if contents.len() < end {
            contents.resize(end, 0);
        }
        contents[start as usize..end].copy_from_slice(&data[..length as usize]);
    }
    contents
}

/// The identity a recovered filesystem's paths are prefixed with.
fn superblock_prefix(superblock: &Object) -> String {
    if let Ok(uuid) = superblock.member("s_uuid").and_then(|uuid| uuid.bytes()) {
        if uuid.len() == 16 {
            let hex: String = uuid.iter().map(|byte| format!("{byte:02x}")).collect();
            return format!(
                "/{}-{}-{}-{}-{}",
                &hex[0..8],
                &hex[8..12],
                &hex[12..16],
                &hex[16..20],
                &hex[20..32]
            );
        }
    }
    let device = superblock
        .member("s_dev")
        .and_then(|dev| dev.as_u64())
        .unwrap_or(0);
    format!("/{}:{}", device >> 20, device & ((1 << 20) - 1))
}

/// The virtual address the `struct page` array begins at.
fn vmemmap_start(context: &Arc<Context>, kernel: &Module) -> Option<u64> {
    // KASLR kernels record the base. Without it the layout is fixed.
    context
        .object_from_symbol(kernel, "vmemmap_base", None)
        .and_then(|value| value.as_u64())
        .ok()
        .or(Some(0xFFFF_EA00_0000_0000))
}

/// The layer holding the machine's physical memory.
fn physical_layer(context: &Arc<Context>, kernel: &Module) -> String {
    use crate::framework::layers::intel::IntelLayer;
    context
        .layers
        .get(&kernel.layer_name)
        .ok()
        .and_then(|layer| {
            layer
                .as_any()
                .downcast_ref::<IntelLayer>()
                .map(|intel| intel.base_layer_name().to_string())
        })
        .unwrap_or_else(|| kernel.layer_name.clone())
}

/// The mask the kernel layer applies to its addresses.
fn mask_for(context: &Arc<Context>, kernel: &Module) -> u64 {
    context.layers.address_mask(&kernel.layer_name)
}
