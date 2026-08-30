//! Find sockets by scanning memory rather than walking file descriptors.
//!
//! A socket whose owning process has exited, or whose descriptor table has been
//! tampered with, is invisible to `sockstat` but its structure may still be
//! resident. Two things give one away: the destructor pointer stored inside the
//! socket, and the file operations of a descriptor that owns one. Both are
//! addresses of known symbols, so searching physical memory for those values
//! finds the structures that hold them.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashSet;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::layers::intel::IntelLayer;
use crate::framework::layers::scanners::{scan_layer, MultiStringScanner};
use crate::framework::objects::Object;
use crate::framework::plugins::linux::kernel_module;
use crate::framework::plugins::linux::sockstat::{describe, text_or_absent};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

pub struct Sockscan;

/// Symbols a socket's own destructor pointer can hold.
const DESTRUCTORS: &[&str] = &[
    "sock_def_destruct",
    "packet_sock_destruct",
    "unix_sock_destructor",
    "netlink_sock_destruct",
    "inet_sock_destruct",
];

/// Symbols the file operations of a socket descriptor can hold.
const FILE_OPERATIONS: &[&str] = &["socket_file_ops", "sockfs_dentry_operations"];

/// What following a descriptor's file operations led to.
enum Walk {
    /// The socket the descriptor owns.
    Socket(Object),
    /// Nothing usable. The hit was a coincidence or has been paged out.
    Nothing,
    /// The inode's container address is not mapped.
    ///
    /// The reference implementation builds that container without checking
    /// whether it was produced, and dies on the `None` it gets back, so the
    /// listing simply ends here.
    Unmapped,
}

impl Plugin for Sockscan {
    fn name(&self) -> &'static str {
        "linux.sockscan.Sockscan"
    }

    fn description(&self) -> &'static str {
        "Scans for network connections found in memory layer."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Linux
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("Sock Offset", ColumnType::UInt),
            Column::string("Family"),
            Column::string("Type"),
            Column::string("Proto"),
            Column::string("Source Addr"),
            Column::string("Source Port"),
            Column::string("Destination Addr"),
            Column::string("Destination Port"),
            Column::string("State"),
            Column::string("Filter"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        // The structures are found in physical memory but the addresses they
        // hold are the kernel's, so every object built here reads its own bytes
        // from one layer and follows its pointers in the other.
        let physical = physical_layer(&context, &kernel);
        let virtual_layer = kernel.layer_name.clone();

        // A pointer is packed to the machine's own width, since that is how it
        // appears in memory.
        let pointer_size = context
            .symbol_space
            .table(&kernel.symbol_table_name)
            .map(|table| table.pointer_size())
            .unwrap_or(8);
        let needle_for = |name: &str| -> Option<Vec<u8>> {
            let address = context.symbol_offset(&kernel, name).ok()?;
            let packed = canonical(address).to_le_bytes();
            Some(packed[..pointer_size.min(8)].to_vec())
        };
        let destructor_needles: Vec<Vec<u8>> =
            DESTRUCTORS.iter().filter_map(|name| needle_for(name)).collect();
        let file_needles: Vec<Vec<u8>> = FILE_OPERATIONS
            .iter()
            .filter_map(|name| needle_for(name))
            .collect();

        let mut needles = destructor_needles.clone();
        needles.extend(file_needles.iter().cloned());
        let mut grid = TreeGrid::new(self.columns());
        if needles.is_empty() {
            return Ok(grid);
        }

        let sock_type = context.symbol_space.get_type(&kernel.qualified("sock"))?;
        let file_type = context.symbol_space.get_type(&kernel.qualified("file"))?;
        let destructor_offset = member_offset(&context, &sock_type, "sk_destruct");
        let operations_offset = member_offset(&context, &file_type, "f_op");

        let layer = context.layers.get(&physical)?;
        let scanner = MultiStringScanner::new(needles)?;
        let mut hits: Vec<u64> = Vec::new();
        scan_layer(layer.as_ref(), &context.layers, &scanner, None, |offset| {
            hits.push(offset)
        })?;

        // The reference implementation records the physical address of each
        // socket it has already reported, but only ever sets that address for
        // the sockets it found by their destructor. Every socket reached
        // through a descriptor therefore shares one entry, and only the first
        // of them is reported.
        let mut seen: HashSet<Option<u64>> = HashSet::new();

        for hit in hits {
            let Ok(matched) = context.layers.read(&physical, hit, pointer_size, false) else {
                continue;
            };

            let mut socket = None;
            let mut physical_address = None;

            if destructor_needles.iter().any(|needle| needle == &matched) {
                if let Some(address) = hit.checked_sub(destructor_offset) {
                    physical_address = Some(address);
                    socket = Some(
                        context
                            .object_from_template(sock_type.clone(), &physical, address)
                            .with_native_layer(&virtual_layer),
                    );
                }
            }

            if file_needles.iter().any(|needle| needle == &matched) {
                match walk_descriptor(
                    &context,
                    &kernel,
                    &physical,
                    &virtual_layer,
                    &file_type,
                    &sock_type,
                    hit.wrapping_sub(operations_offset),
                ) {
                    Walk::Socket(found) => socket = Some(found),
                    Walk::Nothing => socket = None,
                    Walk::Unmapped => {
                        grid.mark_truncated();
                        return Ok(grid);
                    }
                }
            }

            let Some(socket) = socket else { continue };
            if !seen.insert(physical_address) {
                continue;
            }
            if let Some(row) = row_for(&context, &kernel, &socket) {
                grid.push(0, row)?;
            }
        }
        Ok(grid)
    }
}

/// The offset of `member` within `template`, or zero if it has none.
fn member_offset(
    context: &Arc<Context>,
    template: &Arc<crate::framework::objects::template::Template>,
    member: &str,
) -> u64 {
    context
        .symbol_space
        .find_member(template, member)
        .ok()
        .flatten()
        .map(|(offset, _)| offset)
        .unwrap_or(0)
}

/// Sign-extend a kernel address the way the layer canonicalises it.
fn canonical(address: u64) -> u64 {
    if address & (1 << 47) != 0 {
        address | 0xFFFF_0000_0000_0000
    } else {
        address & 0x0000_FFFF_FFFF_FFFF
    }
}

/// The layer holding the machine's physical memory.
fn physical_layer(context: &Arc<Context>, kernel: &Module) -> String {
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

/// Follow a descriptor found in physical memory to the socket it owns.
fn walk_descriptor(
    context: &Arc<Context>,
    kernel: &Module,
    physical: &str,
    virtual_layer: &str,
    file_type: &Arc<crate::framework::objects::template::Template>,
    sock_type: &Arc<crate::framework::objects::template::Template>,
    address: u64,
) -> Walk {
    let file = context
        .object_from_template(file_type.clone(), physical, address)
        .with_native_layer(virtual_layer);

    let Ok(dentry) = file.member("f_path").and_then(|path| path.member("dentry")) else {
        return Walk::Nothing;
    };
    if dentry.pointer_value().unwrap_or(0) == 0 {
        return Walk::Nothing;
    }
    let Ok(dentry) = dentry.dereference() else {
        return Walk::Nothing;
    };

    let Ok(inode) = dentry.member("d_inode").and_then(|inode| inode.pointer_value()) else {
        return Walk::Nothing;
    };
    if inode == 0 {
        return Walk::Nothing;
    }

    let Ok(alloc_type) = context.symbol_space.get_type(&kernel.qualified("socket_alloc")) else {
        return Walk::Nothing;
    };
    let inode_offset = member_offset(context, &alloc_type, "vfs_inode");
    let Some(container) = inode.checked_sub(inode_offset) else {
        return Walk::Unmapped;
    };
    if !context.layers.is_valid(virtual_layer, container, 1) {
        return Walk::Unmapped;
    }

    let alloc = context
        .object_from_template(alloc_type, virtual_layer, container)
        .with_native_layer(virtual_layer);
    let Ok(inner) = alloc
        .member("socket")
        .and_then(|socket| socket.member("sk"))
        .and_then(|sk| sk.pointer_value())
    else {
        return Walk::Nothing;
    };
    if inner == 0 {
        return Walk::Nothing;
    }

    // The socket itself is reported by where it sits in physical memory, which
    // is what the scan would have found had its destructor been recognised.
    let Ok(layer) = context.layers.get(virtual_layer) else {
        return Walk::Nothing;
    };
    let Some(intel) = layer.as_any().downcast_ref::<IntelLayer>() else {
        return Walk::Nothing;
    };
    let Ok((sock_address, _)) = intel.translate_single(&context.layers, inner) else {
        return Walk::Nothing;
    };

    Walk::Socket(
        context
            .object_from_template(sock_type.clone(), physical, sock_address)
            .with_native_layer(virtual_layer),
    )
}

/// Describe a socket, or decide it says nothing worth reporting.
fn row_for(context: &Arc<Context>, kernel: &Module, socket: &Object) -> Option<Vec<Value>> {
    let details = describe(context, kernel, socket)?;

    // Memory holds plenty of sockets that were never connected to anything, and
    // structures that only look like sockets. A row with neither end named is
    // dropped, though the reference implementation tests the source twice and
    // never the destination, so a socket with only a destination is dropped
    // along with them.
    let source_missing = details.source_address.is_none();
    let source_unbound = details.source_address.as_deref() == Some("0.0.0.0");
    let destination_unbound = details.destination_address.as_deref() == Some("0.0.0.0");
    if (source_unbound || source_missing) && (destination_unbound || source_missing) {
        if details.state.as_deref() == Some("UNCONNECTED") {
            return None;
        }
        if details.source_port.as_deref() == Some("0")
            && details.destination_port.as_deref() == Some("0")
        {
            return None;
        }
    }

    Some(vec![
        Value::hex(socket.offset()),
        Value::string(details.family),
        Value::string(details.socket_type),
        text_or_absent(details.protocol),
        text_or_absent(details.source_address),
        text_or_absent(details.source_port),
        text_or_absent(details.destination_address),
        text_or_absent(details.destination_port),
        text_or_absent(details.state),
        text_or_absent(details.filter),
    ])
}
