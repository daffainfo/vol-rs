//! List every file the kernel currently has a vnode for.
//!
//! The vnode cache holds an entry per file the system has touched recently, so
//! this recovers paths that no longer appear in any process's open files.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::mac::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::objects::utility::pointer_to_string;
use crate::framework::objects::Object;
use crate::framework::symbols::mac::{list_mounts, vnode_full_path, walk_tailq};

pub struct ListFiles;

impl Plugin for ListFiles {
    fn name(&self) -> &'static str {
        "mac.list_files.List_Files"
    }

    fn description(&self) -> &'static str {
        "Lists all open file descriptors for all processes."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Mac
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Address", ColumnType::UInt),
            Column::string("File Path"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let vnode_type = kernel.qualified("vnode");
        let mut found = Vnodes::default();

        // Every mounted filesystem holds several lists of the vnodes belonging
        // to it, and each of those is a place a file can be found.
        for mount in list_mounts(&context, &kernel)? {
            for list in ["mnt_vnodelist", "mnt_workerqueue", "mnt_newvnodes"] {
                let Ok(head) = mount.object.member(list) else {
                    continue;
                };
                for vnode in walk_tailq(&head, &vnode_type, "v_mntvnodes").unwrap_or_default() {
                    let address = vnode.offset();
                    found.walk(address, &vnode);
                }
            }
            // The filesystem itself names three vnodes of its own. These are
            // known by where the filesystem points at them rather than by
            // where they are, which is how the reference implementation
            // reports them.
            for member in ["mnt_vnodecovered", "mnt_realrootvp", "mnt_devvp"] {
                let Ok(pointer) = mount.object.member(member) else {
                    continue;
                };
                let address = pointer.offset();
                let Ok(vnode) = pointer.dereference() else {
                    continue;
                };
                found.walk(address, &vnode);
            }
        }

        let mut grid = TreeGrid::new(self.columns());
        for (address, entry) in &found.order {
            grid.push(
                0,
                vec![
                    Value::hex(*address),
                    Value::string(found.path(&entry.name, entry.parent)),
                ],
            )?;
        }
        Ok(grid)
    }
}

/// One vnode that has been found, along with what it is called and where it
/// sits.
struct Entry {
    name: String,
    parent: Option<u64>,
}

/// The vnodes found so far, in the order they were found.
#[derive(Default)]
struct Vnodes {
    order: Vec<(u64, Entry)>,
    index: HashMap<u64, usize>,
}

impl Vnodes {
    /// Follow a list of vnodes, taking in each one and its parents.
    fn walk(&mut self, address: u64, vnode: &Object) {
        let mut current = vnode.clone();
        let mut address = address;
        loop {
            if !self.add(address, &current) {
                break;
            }

            // A file is only worth having if the directories above it are
            // there too, so each parent is taken in as well.
            let mut parent = parent_of(&current);
            while let Some(node) = parent {
                if !self.walk_one(&node) {
                    break;
                }
                parent = parent_of(&node);
            }


            let Ok(next) = current
                .member("v_mntvnodes")
                .and_then(|link| link.member("tqe_next"))
                .and_then(|next| next.dereference())
            else {
                break;
            };
            address = next.offset();
            current = next;
        }
    }

    /// The same walk, reporting whether it took anything in.
    fn walk_one(&mut self, vnode: &Object) -> bool {
        let before = self.order.len();
        self.walk(vnode.offset(), vnode);
        self.order.len() > before
    }

    /// Take one vnode in, reporting whether it was worth having.
    fn add(&mut self, address: u64, vnode: &Object) -> bool {
        if !vnode.is_readable() {
            return false;
        }
        if self.index.contains_key(&address) {
            return false;
        }
        // A vnode with no name says nothing about any file.
        let Some(name) = vnode_name(vnode) else {
            return false;
        };
        let parent = parent_of(vnode).map(|parent| parent.offset());

        self.index.insert(address, self.order.len());
        self.order.push((address, Entry { name, parent }));
        true
    }

    /// Build a file's path by naming each directory above it.
    fn path(&self, name: &str, parent: Option<u64>) -> String {
        let mut elements = vec![name.to_string()];
        let mut seen = HashSet::new();
        let mut current = parent.unwrap_or(0);

        while let Some(position) = self.index.get(&current) {
            let (_, entry) = &self.order[*position];
            match entry.parent {
                None => current = 0,
                // A parent that has been seen before is a loop, and a looping
                // path says nothing.
                Some(parent) if !seen.insert(parent) => {
                    elements.clear();
                    break;
                }
                Some(parent) => current = parent,
            }
            elements.insert(0, entry.name.clone());
        }

        let path = if elements.len() > 1 {
            elements.join("/")
        } else {
            name.to_string()
        };
        // A mount root is named by its whole path, so joining it to a name
        // gives a doubled separator.
        match path.strip_prefix('/') {
            Some(rest) if rest.starts_with('/') => rest.to_string(),
            _ => path,
        }
    }
}

/// What a vnode is called. The root of a mounted filesystem is named by its
/// whole path, since it is the point the filesystem hangs from.
fn vnode_name(vnode: &Object) -> Option<String> {
    let flag = vnode
        .member("v_flag")
        .and_then(|flag| flag.as_u64())
        .unwrap_or(0);
    if flag & 1 == 1 {
        return Some(vnode_full_path(vnode));
    }
    vnode
        .member("v_name")
        .and_then(|name| pointer_to_string(&name, 255))
        .ok()
}

/// The directory a vnode sits in, where it is in memory.
///
/// A file at the root of the tree has none, and a parent that cannot be read
/// is treated the same way.
fn parent_of(vnode: &Object) -> Option<Object> {
    let parent = vnode
        .member("v_parent")
        .and_then(|parent| parent.dereference())
        .ok()?;
    parent.is_readable().then_some(parent)
}
