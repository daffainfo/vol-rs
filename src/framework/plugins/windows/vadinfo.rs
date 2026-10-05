//! The VAD tree describes every reserved or committed region of a process's
//! address space. It is a balanced binary tree, so listing it means an in-order
//! traversal from the root held in the process.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashSet;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::utility::unicode_string;
use crate::framework::objects::template::Template;
use crate::framework::objects::Object;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{pid_filter, pid_matches, OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::{list_processes, Process};

/// Lists process memory ranges.
pub struct VadInfo;

/// Guard against a corrupt tree turning into an unbounded walk.
const MAX_VADS: usize = 100_000;

impl Plugin for VadInfo {
    fn name(&self) -> &'static str {
        "windows.vadinfo.VadInfo"
    }

    fn description(&self) -> &'static str {
        "Lists process memory ranges."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "address",
                "Process virtual memory address to include (all other address \
                 ranges are excluded).",
                crate::framework::plugins::RequirementKind::Int,
            ),
            Requirement::pid_filter("Filter on specific process IDs"),
            Requirement::new(
                "dump",
                "Extract listed memory ranges",
                crate::framework::plugins::RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
            Requirement::new(
                "maxsize",
                "Maximum size for dumped VAD sections (all the bigger sections \
                 will be ignored)",
                crate::framework::plugins::RequirementKind::Int,
            )
            .with_default(crate::framework::context::ConfigValue::Int(
                MAXSIZE_DEFAULT as i64,
            )),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::int("PID"),
            Column::string("Process"),
            Column::new("Offset", ColumnType::UInt),
            Column::new("Start VPN", ColumnType::UInt),
            Column::new("End VPN", ColumnType::UInt),
            Column::string("Tag"),
            Column::string("Protection"),
            Column::int("CommitCharge"),
            Column::int("PrivateMemory"),
            Column::new("Parent", ColumnType::UInt),
            Column::string("File"),
            Column::string("File output"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let filter = pid_filter(config);
        let dump = config.get_bool("dump").unwrap_or(false);
        let maxsize = config.get_int("maxsize").unwrap_or(MAXSIZE_DEFAULT as i64);
        let wanted_address = config.get_int("address").map(|value| value as u64);
        let physical = crate::framework::plugins::windows::physical_layer(config);
        let mut grid = TreeGrid::new(self.columns());
        // The kernel's own table of protection constants.
        let values = protect_values(&context, &kernel);

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }
            let name = process.image_file_name().unwrap_or_default();

            for vad in walk_vad_tree(&context, &kernel, &process).unwrap_or_default() {
                // A single address narrows the listing to the one range that
                // holds it.
                if let Some(address) = wanted_address {
                    let (Some(start), Some(end)) = (start_vpn(&vad), end_vpn(&vad)) else {
                        continue;
                    };
                    if !(start <= address && address <= end) {
                        continue;
                    }
                }

                let file_output = if dump {
                    match vad_dump(&context, &process, &vad, &physical, pid, maxsize) {
                        Some(name) => name,
                        None => "Error outputting file".to_string(),
                    }
                } else {
                    "Disabled".to_string()
                };
                grid.push(
                    0,
                    vec![
                        Value::int(pid as i64),
                        Value::string(name.clone()),
                        // Reported in the form the address is written in,
                        // sign-extended rather than masked.
                        Value::hex(canonical(&context, &kernel, vad.offset())),
                        start_vpn(&vad).map(Value::hex).unwrap_or_else(Value::unreadable),
                        end_vpn(&vad).map(Value::hex).unwrap_or_else(Value::unreadable),
                        tag(&context, &vad)
                            .map(Value::string)
                            .unwrap_or_else(Value::unreadable),
                        Value::string(protection_string(&vad, &values)),
                        commit_charge(&vad)
                            .map(Value::int)
                            .unwrap_or_else(Value::unreadable),
                        private_memory(&vad)
                            .map(Value::int)
                            .unwrap_or_else(Value::unreadable),
                        parent(&vad)
                            .map(|address| Value::hex(canonical(&context, &kernel, address)))
                            .unwrap_or_else(Value::unreadable),
                        match file_name(&vad) {
                            Some(name) => Value::string(name),
                            None => Value::not_applicable(),
                        },
                        Value::string(file_output),
                    ],
                )?;
            }
        }
        Ok(grid)
    }
}

/// The largest range written out unless a smaller limit is given.
const MAXSIZE_DEFAULT: u64 = 1024 * 1024 * 1024;

/// Extracts the complete data for Vad as a FileInterface.
///
/// # Args
///
/// * `context` - The context to retrieve required elements (layers, symbol
///   tables) from
/// * `vad` - The suspected VAD to extract (ObjectInterface)
/// * `maxsize` - Max size of VAD section (default MAXSIZE_DEFAULT)
///
/// Write one memory range out, named after the process and the range.
///
/// The range is read a piece at a time, and pages the image does not hold are
/// written as zeroes so that what was captured keeps its place in the file.
pub fn vad_dump(
    context: &Arc<Context>,
    process: &Process,
    vad: &Object,
    physical: &str,
    pid: u64,
    maxsize: i64,
) -> Option<String> {
    let (start, end) = (start_vpn(vad)?, end_vpn(vad)?);
    // A damaged entry can hold a range the wrong way round, which leaves the
    // size negative. Upstream carries that through: the limit does not catch
    // it, nothing is read, and the file is written empty and still named.
    let size = (end as i64) - (start as i64) + 1;
    if maxsize > 0 && size > maxsize {
        log::debug!("Skip VAD dump {start:#x}-{end:#x} due to maxsize limit");
        return None;
    }
    let layer = process.address_space(physical).ok()?;

    let name = format!("pid.{pid}.vad.{start:#x}-{end:#x}.dmp");
    // Upstream opens the file before it starts reading and commits it when the
    // handle is dropped, so a dump that gave up part way still leaves what it
    // had behind. It reads in ten megabyte pieces, and so does this, rather
    // than holding a whole mapping in memory.
    let (stored, mut handle) = crate::framework::plugins::open_extracted(&name).ok()?;
    const CHUNK: u64 = 1024 * 1024 * 10;
    let wanted = size.max(0) as u64;
    let mut offset = start;
    let mut complete = true;
    while offset < start.wrapping_add(wanted) {
        let take = CHUNK.min(start + wanted - offset);
        let Ok(data) = context.layers.read(&layer, offset, take as usize, true) else {
            complete = false;
            break;
        };
        if data.is_empty() {
            break;
        }
        if std::io::Write::write_all(&mut handle, &data).is_err() {
            complete = false;
            break;
        }
        offset += take;
    }

    if !complete {
        return None;
    }
    // The name reported is the one written, which is not the one asked for
    // when a file of that name was already there.
    Some(stored)
}

/// Walk the VAD tree of one process, in order.
pub fn walk_vad_tree(
    context: &Arc<Context>,
    kernel: &Module,
    process: &Process,
) -> Result<Vec<Object>> {
    let vad_root = process.object.member("VadRoot")?;

    // Newer kernels root the tree at an _RTL_AVL_TREE with a Root pointer.
    // Older ones put the root node inline.
    let root_address = match vad_root.member("Root") {
        Ok(root) => root.pointer_value()?,
        Err(_) => vad_root.pointer_value().unwrap_or(vad_root.offset()),
    };
    if root_address == 0 {
        return Ok(Vec::new());
    }

    let short = context
        .symbol_space
        .get_type(&kernel.qualified("_MMVAD_SHORT"))?;
    let full = context.symbol_space.get_type(&kernel.qualified("_MMVAD"))?;
    let layer = process.object.layer_name().to_string();

    let mut results = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();
    traverse(
        context,
        kernel,
        &layer,
        (&short, &full),
        root_address,
        0,
        &mut seen,
        &mut results,
    );
    Ok(results)
}

/// Walk one subtree, reporting each node before its children.
///
/// A node is reported as the type its pool tag names: the short structure for
/// the tags that have no file behind them, the full one otherwise. The root is
/// allowed to carry no tag, because it is a header rather than an allocation.
/// Any other untagged node is where the tree stops being real, and neither it
/// nor anything below it is reported.
#[allow(clippy::too_many_arguments)]
fn traverse(
    context: &Arc<Context>,
    kernel: &Module,
    layer: &str,
    types: (&Arc<Template>, &Arc<Template>),
    address: u64,
    depth: usize,
    seen: &mut HashSet<u64>,
    results: &mut Vec<Object>,
) {
    // A tree this deep is corrupt rather than large.
    if address == 0 || depth > 100 || !seen.insert(address) || results.len() >= MAX_VADS {
        return;
    }

    let (short, full) = types;
    let node = context.object_from_template(short.clone(), layer, address);
    let tag = tag(context, &node);

    let reported = match tag.as_deref() {
        Some("VadS") | Some("VadF") => Some(node.clone()),
        Some(name) if name.starts_with("Vad") => {
            Some(context.object_from_template(full.clone(), layer, address))
        }
        _ if depth == 0 => None,
        _ => return,
    };
    if let Some(node) = reported {
        results.push(node);
    }

    for right in [false, true] {
        if let Some(child) = child(&node, right) {
            traverse(
                context,
                kernel,
                layer,
                types,
                child,
                depth + 1,
                seen,
                results,
            );
        }
    }
}

/// A VAD node's left or right child, whichever naming variant it uses.
pub fn child(node: &Object, right: bool) -> Option<u64> {
    child_pointer(node, if right { "RightChild" } else { "LeftChild" })
}

/// Read one of a VAD node's child pointers, across the naming variants.
fn child_pointer(node: &Object, child: &str) -> Option<u64> {
    // Newer kernels keep the links in a Left/Right pair on a balanced-tree
    // node, which the longer structure holds one level down. Older ones name
    // the children outright.
    let modern = match child {
        "LeftChild" => "Left",
        _ => "Right",
    };
    for path in [
        vec!["VadNode"],
        vec!["Core", "VadNode"],
        vec!["Core"],
        vec![],
    ] {
        let mut base = node.clone();
        let mut reached = true;
        for step in &path {
            match base.member(step) {
                Ok(next) => base = next,
                Err(_) => {
                    reached = false;
                    break;
                }
            }
        }
        if !reached {
            continue;
        }
        for candidate in [child, modern] {
            if let Ok(value) = base
                .member(candidate)
                .and_then(|value| value.pointer_value())
            {
                return Some(value);
            }
        }
    }
    None
}

/// Read a member that may sit either directly on the node or inside `Core`.
fn field(node: &Object, name: &str) -> Option<Object> {
    node.member(name)
        .or_else(|_| node.member("Core").and_then(|core| core.member(name)))
        .ok()
}

/// The starting virtual page number, reassembled from its high and low halves.
///
/// This is the first accessible byte in the range.
pub fn start_vpn(node: &Object) -> Option<u64> {
    let low = field(node, "StartingVpn")?.as_u64().ok()?;
    // 64-bit kernels split the page number across two fields, with the high
    // part placed at bit 44 of the address rather than of the page number.
    let high = field(node, "StartingVpnHigh")
        .and_then(|value| value.as_u64().ok())
        .unwrap_or(0);
    Some((low << 12) | (high << 44))
}

/// The ending virtual page number, reassembled the same way.
///
/// This is the last accessible byte in the range.
pub fn end_vpn(node: &Object) -> Option<u64> {
    let low = field(node, "EndingVpn")?.as_u64().ok()?;
    let high = field(node, "EndingVpnHigh")
        .and_then(|value| value.as_u64().ok())
        .unwrap_or(0);
    // The end VPN names the last page, so the range covers it entirely. The
    // one is added to the low part before it is shifted, and the high part is
    // then or-ed in, so a carry out of the low part stays inside its own field
    // instead of reaching the high one.
    Some((((low + 1) << 12) | (high << 44)) - 1)
}

pub fn parent(node: &Object) -> Option<u64> {
    for base in [Some(node.clone()), node.member("Core").ok()].into_iter().flatten() {
        // Older kernels name the parent outright. Newer ones keep it in the
        // tree node, where its low bits carry the balance instead.
        if let Ok(parent) = base.member("Parent").and_then(|value| value.pointer_value()) {
            return Some(parent & !0x3);
        }
        let Ok(tree) = base.member("VadNode") else {
            continue;
        };
        for name in ["ParentValue", "u1"] {
            if let Ok(value) = tree.member(name).and_then(|value| value.as_u64()) {
                return Some(value & !0x3);
            }
        }
    }
    None
}

/// One of the flags packed into a range's header, wherever this kernel keeps
/// them.
fn flag_field(vad: &Object, name: &str) -> Option<u64> {
    for base in [Some(vad.clone()), vad.member("Core").ok()].into_iter().flatten() {
        for union in ["u", "u1"] {
            let Ok(union) = base.member(union) else {
                continue;
            };
            for flags in ["VadFlags", "VadFlags1"] {
                if let Ok(value) = union
                    .member(flags)
                    .and_then(|flags| flags.member(name))
                    .and_then(|value| value.as_u64())
                {
                    return Some(value);
                }
            }
        }
    }
    None
}

/// The four-character pool tag preceding the VAD allocation.
pub fn tag(context: &Arc<Context>, node: &Object) -> Option<String> {
    // The allocation header sits in front of the node, and how far in front
    // depends on the width of a pointer.
    let sixty_four_bit = node
        .table_name()
        .and_then(|table| context.symbol_space.table(&table).ok())
        .map(|table| table.pointer_size())
        .unwrap_or(8)
        == 8;
    let address = node.offset().checked_sub(if sixty_four_bit { 12 } else { 4 })?;
    let data = context
        .layers
        .read(node.layer_name(), address, 4, false)
        .ok()?;
    // The bytes are the name: a tag like `Vad ` is three letters and a space,
    // and standing in for that space would rename it. Bytes that are not text
    // are not a tag at all, which is how a node that only looked like one is
    // told apart.
    String::from_utf8(data).ok()
}

/// Page protection, rendered as the constant name Windows uses.
pub fn protection(node: &Object) -> Option<String> {
    let flags = field(node, "u")
        .or_else(|| field(node, "u1"))?
        .member("VadFlags")
        .ok()?;
    let value = flags.member("Protection").ok()?.as_u64().ok()?;

    // The values index a table the kernel builds at boot. These are the
    // conventional names for the standard entries.
    const NAMES: [&str; 8] = [
        "PAGE_NOACCESS",
        "PAGE_READONLY",
        "PAGE_EXECUTE",
        "PAGE_EXECUTE_READ",
        "PAGE_READWRITE",
        "PAGE_WRITECOPY",
        "PAGE_EXECUTE_READWRITE",
        "PAGE_EXECUTE_WRITECOPY",
    ];
    Some(
        NAMES
            .get(value as usize)
            .map(|name| name.to_string())
            .unwrap_or_else(|| format!("{value:#x}")),
    )
}

/// The mapped file backing this region, when there is one.
pub fn file_name_of(node: &Object) -> Option<String> {
    file_name(node)
}

fn file_name(node: &Object) -> Option<String> {
    // Windows XP and Server 2003 hang the control area off the range itself.
    // Vista and later reach it through a subsection, and there the pointer to
    // the file is a fast reference rather than a plain one.
    let name = match node.member("ControlArea") {
        Ok(area) => area
            .member("FilePointer")
            .and_then(|file| file.member("FileName"))
            .ok()?,
        Err(_) => {
            let file_pointer = node
                .member("Subsection")
                .and_then(|subsection| subsection.member("ControlArea"))
                .and_then(|area| area.member("FilePointer"))
                .ok()?;
            let address =
                crate::framework::symbols::windows::fast_reference(&file_pointer).ok()?;
            if address == 0 {
                return None;
            }
            let context = node.context().clone();
            let template = context
                .symbol_space
                .get_type(&crate::framework::symbols::join_name(
                    &node.table_name()?,
                    "_FILE_OBJECT",
                ))
                .ok()?;
            context
                .object_from_template(template, node.layer_name(), address)
                .with_native_layer(node.native_layer_name())
                .member("FileName")
                .ok()?
        }
    };

    // A name of no length is no name, which is reported as not applicable
    // rather than as an empty one.
    if name.member("Length").and_then(|f| f.as_u64()).unwrap_or(0) == 0 {
        return None;
    }
    unicode_string(&name).ok()
}

/// Look up the array of memory protection constants from the memory sample.
/// These don't change often, but if they do in the future, then finding them
/// dynamically versus hard-coding here will ensure we parse them properly.
///
/// # Args
///
/// * `context` - The context to retrieve required elements (layers, symbol
///   tables) from
///
/// The protection constants this kernel uses, read from its own table.
///
/// A range's protection is an index into `MmProtectToValue`, and the value
/// there is a mask of the Win32 page constants. Reading the table rather than
/// assuming it keeps the names right across kernel versions.
pub fn protect_values(context: &Arc<Context>, kernel: &Module) -> Vec<u32> {
    let Ok(address) = context.symbol_offset(kernel, "MmProtectToValue") else {
        return Vec::new();
    };
    let Ok(data) = context
        .layers
        .read(&kernel.layer_name, address, 32 * 4, false)
    else {
        return Vec::new();
    };
    data.chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4])))
        .collect()
}

/// The names Windows gives each protection bit, in the order it reports them.
///
/// These are from WinNT.h.
const WINNT_PROTECTIONS: &[(&str, u32)] = &[
    ("PAGE_NOACCESS", 0x01),
    ("PAGE_READONLY", 0x02),
    ("PAGE_READWRITE", 0x04),
    ("PAGE_WRITECOPY", 0x08),
    ("PAGE_EXECUTE", 0x10),
    ("PAGE_EXECUTE_READ", 0x20),
    ("PAGE_EXECUTE_READWRITE", 0x40),
    ("PAGE_EXECUTE_WRITECOPY", 0x80),
    ("PAGE_GUARD", 0x100),
    ("PAGE_NOCACHE", 0x200),
    ("PAGE_WRITECOMBINE", 0x400),
    ("PAGE_TARGETS_INVALID", 0x4000_0000),
];

/// A range's protection, as the kernel's own table names it.
pub fn protection_string(vad: &Object, values: &[u32]) -> String {
    let index = flag_field(vad, "Protection").unwrap_or(0) as usize;

    // An index past the end of the table names nothing.
    let value = values.get(index).copied().unwrap_or(0);
    WINNT_PROTECTIONS
        .iter()
        .filter(|(_, mask)| value & mask != 0)
        .map(|(name, _)| *name)
        .collect::<Vec<&str>>()
        .join("|")
}

/// An address in the form it is written, rather than masked.
fn canonical(context: &Arc<Context>, kernel: &Module, address: u64) -> u64 {
    use crate::framework::layers::intel::IntelLayer;
    context
        .layers
        .get(&kernel.layer_name)
        .ok()
        .and_then(|layer| {
            layer
                .as_any()
                .downcast_ref::<IntelLayer>()
                .map(|intel| intel.canonicalize(address))
        })
        .unwrap_or(address)
}

/// How many pages of a range are committed.
pub fn commit_charge(vad: &Object) -> Option<i64> {
    // Some kernels name it outright rather than packing it into the flags.
    for base in [Some(vad.clone()), vad.member("Core").ok()].into_iter().flatten() {
        if let Ok(value) = base.member("CommitCharge").and_then(|value| value.as_i64()) {
            return Some(value);
        }
    }
    flag_field(vad, "CommitCharge").map(|value| value as i64)
}

/// Whether a range is private to its process.
pub fn private_memory(vad: &Object) -> Option<i64> {
    flag_field(vad, "PrivateMemory").map(|value| value as i64)
}

/// Whether a range is private to its process, for callers outside this module.
pub fn private_memory_of(vad: &Object) -> Option<i64> {
    private_memory(vad)
}

/// The control area describing what a range is mapped from.
pub fn control_area(vad: &Object) -> Option<Object> {
    // Windows xp and 2003 name it directly.
    if let Ok(area) = vad
        .member("ControlArea")
        .and_then(|area| area.dereference())
    {
        return Some(area);
    }
    // Vista and beyond reach it through the subsection.
    vad.member("Subsection")
        .and_then(|subsection| subsection.dereference())
        .and_then(|subsection| subsection.member("ControlArea"))
        .and_then(|area| area.dereference())
        .ok()
}

/// The file object a control area refers to.
pub fn file_object(control_area: &Object) -> Option<Object> {
    let pointer = control_area.member("FilePointer").ok()?;
    // A fast reference keeps a small count in the bits below the alignment a
    // pointer is guaranteed to have, and how many of them there are follows
    // the architecture.
    let address = crate::framework::symbols::windows::fast_reference(&pointer).ok()?;
    if address == 0 {
        return None;
    }
    let context = control_area.context().clone();
    let table = control_area.resolved_template().ok()?.as_struct()?.table.clone();
    let template = context
        .symbol_space
        .get_type(&crate::framework::symbols::join_name(&table, "_FILE_OBJECT"))
        .ok()?;
    Some(context.object_from_template(template, control_area.layer_name(), address))
}
