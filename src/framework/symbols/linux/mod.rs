//! Linux-specific helpers for working with kernel structures.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

pub mod module_elf;
pub mod resolver;

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Context, Module};
use crate::framework::objects::utility::{pointer_to_string, walk_list, walk_list_both};
use crate::framework::renderers::conversion::{ns_to_timespec64, timespec_to_datetime};
use crate::framework::objects::Object;

/// A task, wrapping a `task_struct`.
///
/// Linux makes no structural distinction between a process and a thread: both
/// are tasks. `tgid` is what userspace calls the process ID, and `pid` is what
/// it calls the thread ID.
pub struct Task {
    pub object: Object,
}

impl Task {
    pub fn new(object: Object) -> Self {
        Self { object }
    }

    /// The thread ID, as userspace sees it.
    pub fn tid(&self) -> Result<u64> {
        self.object.member("pid")?.as_u64()
    }

    /// The process ID, as userspace sees it. Threads of one process share this.
    pub fn pid(&self) -> Result<u64> {
        self.object.member("tgid")?.as_u64()
    }

    /// The parent process ID, preferring the real parent over a tracing one.
    ///
    /// A task whose parent cannot be read reports zero, which is what the
    /// kernel's own getppid does for a reparented orphan.
    pub fn ppid(&self) -> Result<u64> {
        Ok(self
            .object
            .member("real_parent")
            .or_else(|_| self.object.member("parent"))
            .and_then(|parent| parent.dereference())
            .and_then(|parent| parent.member("tgid"))
            .and_then(|tgid| tgid.as_u64())
            .unwrap_or(0))
    }

    /// The short command name, a fixed-size character array in the task.
    pub fn comm(&self) -> Result<String> {
        self.object.member("comm")?.as_string()
    }

    pub fn offset(&self) -> u64 {
        self.object.offset()
    }

    /// Whether this task is a thread rather than a process leader.
    pub fn is_thread(&self) -> bool {
        match (self.pid(), self.tid()) {
            (Ok(pid), Ok(tid)) => pid != tid,
            _ => false,
        }
    }

    /// A credential field, read from the task's `cred`.
    fn credential(&self, name: &str) -> Result<u64> {
        let cred = self.object.member("cred")?.dereference()?;
        let field = cred.member(name)?;
        // Modern kernels wrap ids in a `kuid_t`/`kgid_t` struct with one member.
        field
            .member("val")
            .and_then(|value| value.as_u64())
            .or_else(|_| field.as_u64())
    }

    pub fn uid(&self) -> Result<u64> {
        self.credential("uid")
    }

    pub fn gid(&self) -> Result<u64> {
        self.credential("gid")
    }

    pub fn euid(&self) -> Result<u64> {
        self.credential("euid")
    }

    pub fn egid(&self) -> Result<u64> {
        self.credential("egid")
    }

    /// Process start time as `(seconds, nanoseconds)` since the Unix epoch.
    ///
    /// The kernel records this in nanoseconds since boot, so it needs the boot
    /// time to become a wall-clock timestamp. The fractional part is kept,
    /// since that is the precision the reference implementation reports.
    pub fn creation_time(&self, boot_time_seconds: Option<i64>) -> Result<(i64, u32)> {
        // Order matters: `start_boottime` (kernels >= 5.5) counts from
        // CLOCK_BOOTTIME while `start_time` counts from CLOCK_MONOTONIC. The
        // two differ by however long the machine spent suspended, often under a
        // microsecond, which is enough to shift a rendered timestamp.
        let raw = self
            .object
            .member("start_boottime")
            .or_else(|_| self.object.member("real_start_time"))
            .or_else(|_| self.object.member("start_time"))?;

        // Older kernels store a timespec. Newer ones a nanosecond counter.
        let since_boot: i64 = if let Ok(seconds) = raw.member("tv_sec") {
            let nanoseconds = raw
                .member("tv_nsec")
                .and_then(|value| value.as_i64())
                .unwrap_or(0);
            seconds.as_i64()? * 1_000_000_000 + nanoseconds
        } else {
            raw.as_u64()? as i64
        };

        // The reference implementation splits the counter into a timespec and
        // then turns that into a timedelta through a double, which decides the
        // microsecond the timestamp is rendered with. The boot time contributes
        // whole seconds only.
        let (seconds, nanoseconds) =
            crate::framework::renderers::conversion::ns_to_timespec64(since_boot);
        let total = seconds as f64 + nanoseconds as f64 / 1e9;
        let whole = total.trunc();
        let mut microseconds = ((total - whole) * 1e6).round_ties_even() as i64;
        let mut seconds = whole as i64 + boot_time_seconds.unwrap_or(0);
        if microseconds >= 1_000_000 {
            seconds += 1;
            microseconds -= 1_000_000;
        }
        Ok((seconds, (microseconds * 1000) as u32))
    }

    /// The task's memory descriptor, absent for kernel threads.
    pub fn mm(&self) -> Result<Option<Object>> {
        let mm = self.object.member("mm")?;
        if mm.pointer_value()? == 0 {
            return Ok(None);
        }
        Ok(Some(mm.dereference()?))
    }

    /// Whether this is a kernel thread, which has no user address space.
    pub fn is_kernel_thread(&self) -> bool {
        matches!(self.mm(), Ok(None))
    }

    /// The inode number identifying the task's time namespace.
    ///
    /// Kernels before 5.6 have no time namespaces, so this is `None` there.
    pub fn time_namespace_id(&self) -> Option<u64> {
        self.time_namespace()?.member("ns").ok()?.member("inum").ok()?.as_u64().ok()
    }

    fn time_namespace(&self) -> Option<Object> {
        self.object
            .member("nsproxy")
            .ok()?
            .dereference()
            .ok()?
            .member("time_ns")
            .ok()?
            .dereference()
            .ok()
    }

    /// The boot-time offset this task's time namespace applies, as a timespec.
    pub fn time_namespace_boottime_offset(&self) -> Option<(i64, i64)> {
        let offsets = self.time_namespace()?.member("offsets").ok()?;
        let boottime = offsets.member("boottime").ok()?;
        Some((
            boottime.member("tv_sec").ok()?.as_i64().ok()?,
            boottime.member("tv_nsec").ok()?.as_i64().ok()?,
        ))
    }

    /// Build a layer over this task's own address space, returning its name.
    ///
    /// User addresses such as the argument vector mean nothing in the kernel's
    /// address space: they have to be translated through the process's own page
    /// tables, rooted at the `pgd` its memory descriptor records. Kernel threads
    /// have no such descriptor and so return `None`.
    pub fn process_layer(&self) -> Result<Option<String>> {
        use crate::framework::layers::intel::IntelLayer;

        let Some(mm) = self.mm()? else {
            return Ok(None);
        };
        let pgd = mm.member("pgd")?.as_u64()?;

        let context = self.object.context();
        let parent = context.layers.get(self.object.layer_name())?;
        let Some(intel) = parent.as_any().downcast_ref::<IntelLayer>() else {
            return Ok(None);
        };

        // `pgd` is a kernel virtual address. The new layer needs the physical
        // one to use as the root of its own page table walk.
        let Ok((dtb, _)) = intel.translate_single(&context.layers, pgd) else {
            return Ok(None);
        };
        if dtb == 0 {
            return Ok(None);
        }

        let name = context
            .layers
            .free_name(&format!("{}_Process", self.object.layer_name()));
        context.layers.add(Arc::new(IntelLayer::new(
            name.clone(),
            intel.base_layer_name(),
            dtb,
            intel.config().clone(),
        )));
        Ok(Some(name))
    }

    /// Whether the task looks like a real task rather than a smeared one.
    ///
    /// A list walk over an image captured on a live system picks up structures
    /// that were being torn down as the memory was read. Requiring the pointers
    /// every task must have to be readable, and the two memory descriptors to
    /// agree, rejects those without discarding live tasks.
    pub fn is_valid(&self) -> bool {
        let context = self.object.context();
        let layer = self.object.layer_name();

        // The whole structure has to be present, not merely its first page.
        match self.object.size() {
            Ok(size) if context.layers.is_valid(layer, self.object.offset(), size) => {}
            _ => return false,
        }

        if self.object.member("pid").and_then(|v| v.as_i64()).unwrap_or(-1) < 0
            || self.object.member("tgid").and_then(|v| v.as_i64()).unwrap_or(-1) < 0
        {
            return false;
        }

        // These are never null in a live task, so an unreadable one is smear.
        for name in ["signal", "nsproxy", "real_parent"] {
            if self.object.has_member(name) && !self.pointer_is_readable(name) {
                return false;
            }
        }

        // active_mm may be null for a kernel thread. Only a set one must read.
        if self.object.has_member("active_mm")
            && self.pointer_target("active_mm") != Some(0)
            && !self.pointer_is_readable("active_mm")
        {
            return false;
        }

        match self.pointer_target("mm") {
            Some(0) | None => {}
            Some(_) => {
                if !self.pointer_is_readable("mm") {
                    return false;
                }
                // A running task borrows its own mm as active_mm. A mismatch
                // means the two fields were captured at different moments.
                if self.pointer_target("mm") != self.pointer_target("active_mm") {
                    return false;
                }
            }
        }

        true
    }

    /// The address a pointer member holds, or None if it cannot be read.
    fn pointer_target(&self, name: &str) -> Option<u64> {
        self.object.member(name).ok()?.pointer_value().ok()
    }

    /// Whether a pointer member is non-null and points somewhere readable.
    fn pointer_is_readable(&self, name: &str) -> bool {
        match self.pointer_target(name) {
            Some(0) | None => false,
            Some(_) => self
                .object
                .member(name)
                .and_then(|pointer| pointer.dereference())
                .map(|target| target.is_readable())
                .unwrap_or(false),
        }
    }

    /// The other threads sharing this task's thread group.
    ///
    /// Kernel 6.7 moved the thread list from the task's own `thread_group` into
    /// the shared `signal_struct`, so which member links the group depends on
    /// the kernel being analysed.
    pub fn threads(&self, kernel: &Module) -> Result<Vec<Task>> {
        let task_type = kernel.qualified("task_struct");

        let (head, member) = if self.object.has_member("signal")
            && self
                .object
                .member("signal")
                .and_then(|signal| signal.dereference())
                .map(|signal| signal.has_member("thread_head"))
                .unwrap_or(false)
        {
            // kernels >= 6.7
            let signal = self.object.member("signal")?.dereference()?;
            (signal.member("thread_head")?, "thread_node")
        } else if self.object.has_member("thread_group") {
            // kernels < 6.7
            (self.object.member("thread_group")?, "thread_group")
        } else {
            return Ok(Vec::new());
        };

        let mut seen = std::collections::HashSet::new();
        seen.insert(self.offset());
        let mut threads = Vec::new();
        for object in walk_list(&head, &task_type, member, true)? {
            let task = Task::new(object);
            if !task.is_valid() || !seen.insert(task.offset()) {
                continue;
            }
            threads.push(task);
        }
        Ok(threads)
    }
}

/// Walk the kernel's task list, starting from `init_task`.
///
/// When `include_threads` is set every task is returned. Otherwise only the
/// thread group leaders, which is what userspace calls processes.
pub fn list_tasks(
    context: &Arc<Context>,
    kernel: &Module,
    include_threads: bool,
) -> Result<Vec<Task>> {
    list_tasks_filtered(context, kernel, include_threads, &|_| true)
}

/// Walk the task list, keeping only the processes `keep` accepts.
///
/// The filter is applied to thread group leaders alone: selecting a process
/// selects all of its threads, whose own ids are never compared against it.
pub fn list_tasks_filtered(
    context: &Arc<Context>,
    kernel: &Module,
    include_threads: bool,
    keep: &dyn Fn(&Task) -> bool,
) -> Result<Vec<Task>> {
    let init_task = context.object_from_symbol(kernel, "init_task", Some("task_struct"))?;
    let task_type = kernel.qualified("task_struct");

    // `init_task` is the sentinel head of the list, not a task the tools report:
    // `ps` never shows swapper/0 either. Walking both directions from it reaches
    // the tasks stranded beyond any unreadable node in a smeared image.
    let head = init_task.member("tasks")?;

    let mut tasks = Vec::new();
    for object in walk_list_both(&head, &task_type, "tasks")? {
        let task = Task::new(object);
        if !task.is_valid() || !keep(&task) {
            continue;
        }
        if include_threads {
            let threads = task.threads(kernel).unwrap_or_default();
            tasks.push(task);
            tasks.extend(threads);
        } else {
            tasks.push(task);
        }
    }

    Ok(tasks)
}

/// Addresses of the kernel's parameter accessor functions.
///
/// Which function a parameter's operations table points at is what says how to
/// read its value, so the addresses are resolved once and compared against.
struct ParameterHandlers {
    /// Accessor address to the integer type it reads.
    integers: std::collections::HashMap<u64, &'static str>,
    array_get: Option<u64>,
    string_get: Option<u64>,
    charp_get: Option<u64>,
    bool_get: Option<u64>,
    invbool_get: Option<u64>,
}

impl ParameterHandlers {
    fn new(context: &Arc<Context>, kernel: &Module) -> Self {
        let mask = context.layers.address_mask(&kernel.layer_name);
        let address_of = |name: &str| -> Option<u64> {
            context
                .symbol_offset(kernel, name)
                .ok()
                .map(|address| address & mask)
        };

        let mut integers = std::collections::HashMap::new();
        for (symbol, type_name) in [
            ("param_get_invbool", "int"),
            ("param_get_bool", "int"),
            ("param_get_int", "int"),
            ("param_get_ulong", "long unsigned int"),
            ("param_get_ullong", "long long unsigned int"),
            ("param_get_long", "long int"),
            ("param_get_uint", "unsigned int"),
            ("param_get_ushort", "short unsigned int"),
            ("param_get_short", "short int"),
            ("param_get_byte", "char"),
        ] {
            if let Some(address) = address_of(symbol) {
                integers.insert(address, type_name);
            }
        }

        Self {
            integers,
            array_get: address_of("param_array_get"),
            string_get: address_of("param_get_string"),
            charp_get: address_of("param_get_charp"),
            bool_get: address_of("param_get_bool"),
            invbool_get: address_of("param_get_invbool"),
        }
    }

    /// Decode one parameter's value, recursing once into array elements.
    fn value_of(
        &self,
        context: &Arc<Context>,
        kernel: &Module,
        param: &Object,
        depth: usize,
    ) -> Option<String> {
        // Older kernels put the accessor directly in the parameter.
        let accessor = if param.has_member("get") {
            param.member("get").and_then(|get| get.pointer_value()).ok()?
        } else {
            param
                .member("ops")
                .and_then(|ops| ops.dereference())
                .and_then(|ops| ops.member("get"))
                .and_then(|get| get.pointer_value())
                .ok()?
        };
        if accessor == 0 {
            return None;
        }

        if Some(accessor) == self.array_get {
            // An array's elements may each have their own type.
            if depth > 0 {
                return None;
            }
            let array = param.member("arr").and_then(|arr| arr.dereference()).ok()?;
            let max = array
                .member("num")
                .and_then(|num| num.dereference())
                .and_then(|num| num.as_u64())
                .or_else(|_| array.member("max").and_then(|max| max.as_u64()))
                .ok()?;
            if max > 32 {
                return None;
            }
            let element_base = array.member("elem").and_then(|elem| elem.pointer_value()).ok()?;
            let element_size = array
                .member("elemsize")
                .and_then(|size| size.as_u64())
                .ok()?;
            let template = context
                .symbol_space
                .get_type(&kernel.qualified("kernel_param"))
                .ok()?;

            let mut elements = Vec::new();
            for index in 0..max {
                let element = context.object_from_template(
                    template.clone(),
                    &kernel.layer_name,
                    element_base + element_size * index,
                );
                elements.push(
                    self.value_of(context, kernel, &element, depth + 1)
                        .unwrap_or_else(|| "None".to_string()),
                );
            }
            if elements.is_empty() {
                return None;
            }
            return Some(elements.join(","));
        }

        if Some(accessor) == self.string_get || Some(accessor) == self.charp_get {
            let text = param.member("str").ok()?;
            let count = if Some(accessor) == self.string_get {
                text.dereference()
                    .and_then(|inner| inner.member("maxlen"))
                    .and_then(|len| len.as_u64())
                    .unwrap_or(256) as usize
            } else {
                256
            };
            return pointer_to_string(&text, count).ok();
        }

        if let Some(type_name) = self.integers.get(&accessor) {
            let address = param.member("arg").and_then(|arg| arg.pointer_value()).ok()?;
            let template = context.symbol_space.get_type(&kernel.qualified(type_name)).ok()?;
            // The reference implementation builds this object through the
            // kernel module without marking the offset absolute, so the module's
            // load offset is added to an address that already is absolute. The
            // read then almost always lands on an unmapped page and the value is
            // reported as unavailable. Matching its output means matching that.
            let shifted = context.symbol_address(kernel, &address);
            let value = context
                .object_from_template(template, &kernel.layer_name, shifted)
                .as_i64()
                .ok()?;

            if Some(accessor) == self.bool_get {
                return Some(if value == 0 { "N" } else { "Y" }.to_string());
            }
            if Some(accessor) == self.invbool_get {
                return Some(if value == 0 { "Y" } else { "N" }.to_string());
            }
            return Some(value.to_string());
        }

        None
    }
}

/// The outcome of looking for the inode behind a file-backed mapping.
enum InodeLookup {
    /// The inode was found and looks live.
    Found(Object),
    /// Something needed to find it could not be read.
    Unreadable,
    /// Everything was readable, but there is no usable inode.
    Missing,
}

/// A task's memory areas, and whether enumeration ended early.
///
/// `truncated` marks the point where the reference implementation stops
/// producing output, so callers can stop where it does.
#[derive(Default)]
pub struct VmaList {
    pub areas: Vec<Vma>,
    pub truncated: bool,
}

/// Upper bound on the number of memory areas a task is believed to have.
const MAX_VMA_COUNT: usize = 100_000;

// Maple tree layout constants, from include/linux/maple_tree.h.
const MT_FLAGS_HEIGHT_MASK: u64 = 0x7C;
const MT_FLAGS_HEIGHT_OFFSET: u32 = 0x02;
const MAPLE_NODE_TYPE_SHIFT: u32 = 0x03;
const MAPLE_NODE_TYPE_MASK: u64 = 0x0F;
const MAPLE_NODE_POINTER_MASK: u64 = 0xFF;
const MAPLE_DENSE: u64 = 0;
const MAPLE_LEAF_64: u64 = 1;
const MAPLE_RANGE_64: u64 = 2;
const MAPLE_ARANGE_64: u64 = 3;

/// Every non-empty slot in a maple tree.
///
/// Kernel 6.1 replaced the linked list of memory areas with a maple tree, a
/// B-tree whose child pointers carry the node's type in their low bits. Walking
/// it means masking those bits off to get the address and reading them back to
/// know how to interpret the node.
pub fn maple_tree_slots(tree: &Object) -> Result<(Vec<u64>, bool)> {
    let root = tree.member("ma_root")?.pointer_value()?;
    let flags = tree.member("ma_flags")?.as_u64()?;
    let expected_depth = (flags & MT_FLAGS_HEIGHT_MASK) >> MT_FLAGS_HEIGHT_OFFSET;
    // The tree's own address, with the flag bits masked off, is what the root
    // node records as its parent.
    let parent = tree.offset() & !MAPLE_NODE_POINTER_MASK;

    let mut slots = Vec::new();
    let mut seen = std::collections::HashSet::new();
    // A node in a page that was not captured ends the walk. What was reached
    // before it is still real, so it is kept and the caller told it is partial.
    let complete = parse_maple_node(tree, root, parent, expected_depth, 1, &mut seen, &mut slots)?;
    Ok((slots, !complete))
}

#[allow(clippy::too_many_arguments)]
fn parse_maple_node(
    tree: &Object,
    entry: u64,
    parent: u64,
    expected_depth: u64,
    depth: u64,
    seen: &mut std::collections::HashSet<u64>,
    slots: &mut Vec<u64>,
) -> Result<bool> {
    if !seen.insert(entry) {
        log::warn!("Maple tree entry {entry:#x} already seen; not descending again");
        return Ok(true);
    }
    if expected_depth < depth {
        log::warn!(
            "Maple tree at {:#x} declares depth {expected_depth} but reached {depth}",
            tree.offset()
        );
    }

    let pointer = entry & !MAPLE_NODE_POINTER_MASK;
    let node_type = (entry >> MAPLE_NODE_TYPE_SHIFT) & MAPLE_NODE_TYPE_MASK;

    let context = tree.context().clone();
    let table = vma_table(tree)?;

    // Each node records its parent, which is what confirms the pointer really
    // is a node rather than a value that happened to look like one.
    let parent_template = context
        .symbol_space
        .get_type(&crate::framework::symbols::join_name(&table, "pointer"))?;
    // The ISF describes `pointer` as a plain integer, so the address bits the
    // layer does not use have to be masked off here rather than by the reader.
    let mask = context.layers.address_mask(tree.layer_name());
    let Ok(node_parent) = context
        .object_from_template(parent_template, tree.layer_name(), pointer)
        .as_u64()
        .map(|value| value & mask)
    else {
        return Ok(false);
    };
    if node_parent & !MAPLE_NODE_POINTER_MASK != parent {
        return Ok(true);
    }

    let node_template = context
        .symbol_space
        .get_type(&crate::framework::symbols::join_name(&table, "maple_node"))?;
    let node = context.object_from_template(node_template, tree.layer_name(), pointer);

    // Which union member holds the slots depends on the node type.
    let container = match node_type {
        MAPLE_DENSE => "alloc",
        MAPLE_LEAF_64 | MAPLE_RANGE_64 => "mr64",
        MAPLE_ARANGE_64 => "ma64",
        other => {
            log::debug!("Unknown maple tree node type {other} at {pointer:#x}");
            return Ok(false);
        }
    };

    let Ok(entries) = node
        .member(container)
        .and_then(|union| union.member("slot"))
        .and_then(|array| array.iter_array())
    else {
        return Ok(false);
    };

    for element in entries {
        let Ok(slot) = element.as_u64().map(|value| value & mask) else {
            return Ok(false);
        };
        if slot & !MAPLE_NODE_TYPE_MASK == 0 {
            continue;
        }
        match node_type {
            // A leaf's slots are the values the tree stores.
            MAPLE_DENSE | MAPLE_LEAF_64 => slots.push(slot),
            // An internal node's slots are further nodes.
            _ => {
                if !parse_maple_node(tree, slot, pointer, expected_depth, depth + 1, seen, slots)? {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

/// A loaded kernel module.
pub struct KernelModule {
    pub object: Object,
}

impl KernelModule {
    pub fn new(object: Object) -> Self {
        Self { object }
    }

    pub fn name(&self) -> Result<String> {
        self.object.member("name")?.as_string()
    }

    pub fn offset(&self) -> u64 {
        self.object.offset()
    }

    /// Size of the module's executable text.
    ///
    /// The layout changed in kernel 4.5, which moved the sizes into a
    /// `module_layout` sub-structure, and again later into `mem`.
    /// Size of a memory region the module owns, by its `mod_mem_type` name.
    ///
    /// Kernel 6.4 replaced the pair of layout structures with one array indexed
    /// by region type, so the region has to be looked up through that enum.
    fn memory_region_size(&self, region: &str) -> Option<u64> {
        let table = vma_table(&self.object).ok()?;
        let index = self
            .object
            .context()
            .symbol_space
            .get_type(&crate::framework::symbols::join_name(&table, "mod_mem_type"))
            .ok()
            .and_then(|template| template.as_enum().cloned())?
            .choices
            .get(region)
            .copied()?;
        self.object
            .member("mem")
            .and_then(|regions| regions.index(index as u64))
            .and_then(|region| region.member("size"))
            .and_then(|size| size.as_u64())
            .ok()
    }

    /// Size of the module's permanently resident sections.
    pub fn core_size(&self) -> Result<u64> {
        if self.object.has_member("mem") {
            // kernels 6.4+
            let total: u64 = ["MOD_TEXT", "MOD_DATA", "MOD_RODATA", "MOD_RO_AFTER_INIT"]
                .iter()
                .filter_map(|region| self.memory_region_size(region))
                .sum();
            return Ok(total);
        }
        self.object
            .member("core_layout")
            .and_then(|layout| layout.member("size"))
            .or_else(|_| self.object.member("core_size"))
            .and_then(|size| size.as_u64())
    }

    /// Size of the sections discarded once the module has initialised.
    pub fn init_size(&self) -> Result<u64> {
        if self.object.has_member("mem") {
            // kernels 6.4+
            let total: u64 = ["MOD_INIT_TEXT", "MOD_INIT_DATA", "MOD_INIT_RODATA"]
                .iter()
                .filter_map(|region| self.memory_region_size(region))
                .sum();
            return Ok(total);
        }
        self.object
            .member("init_layout")
            .and_then(|layout| layout.member("size"))
            .or_else(|_| self.object.member("init_size"))
            .and_then(|size| size.as_u64())
    }

    /// The parameters the module was loaded with, as `(name, value)` pairs.
    ///
    /// A parameter's type is not recorded directly: it is implied by which
    /// accessor the kernel installed in its operations table, so each `get`
    /// pointer is compared against the handlers the kernel exports.
    pub fn load_parameters(&self, context: &Arc<Context>, kernel: &Module) -> Vec<(String, Option<String>)> {
        let mut results = Vec::new();
        if !self.object.has_member("kp") {
            return results;
        }
        let count = self
            .object
            .member("num_kp")
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        // More than this many means the field was misread.
        if count > 128 {
            return results;
        }
        let Ok(base) = self.object.member("kp").and_then(|kp| kp.pointer_value()) else {
            return results;
        };
        let Ok(template) = context.symbol_space.get_type(&kernel.qualified("kernel_param")) else {
            return results;
        };
        let Ok(size) = context.symbol_space.size_of(&template) else {
            return results;
        };

        let handlers = ParameterHandlers::new(context, kernel);
        for index in 0..count {
            let param = context.object_from_template(
                template.clone(),
                &kernel.layer_name,
                base + index * size,
            );
            let Ok(name) = param
                .member("name")
                .and_then(|name| pointer_to_string(&name, 32))
            else {
                continue;
            };
            let value = handlers.value_of(context, kernel, &param, 0);
            results.push((name, value));
        }
        results
    }

    /// Size of just the module's executable text.
    pub fn core_text_size(&self) -> Result<u64> {
        if self.object.has_member("mem") {
            return self
                .memory_region_size("MOD_TEXT")
                .ok_or_else(|| VolatilityError::Other("no MOD_TEXT region".to_string()));
        }
        self.object
            .member("core_layout")
            .and_then(|layout| layout.member("text_size"))
            .or_else(|_| self.object.member("core_text_size"))
            .and_then(|size| size.as_u64())
    }

    /// Whether this really is an allocated module rather than freed memory.
    ///
    /// The check that matters is the self-reference: a module's embedded
    /// kobject points back at the module, which stray memory will not.
    pub fn is_valid(&self) -> bool {
        const MAXIMUM_SECTION: u64 = 20_000_000;
        const MINIMUM_TOTAL: u64 = 4096;

        let context = self.object.context();
        match self.object.size() {
            Ok(size) if context.layers.is_valid(self.object.layer_name(), self.offset(), size) => {}
            _ => return false,
        }

        let (Ok(core), Ok(text), Ok(init)) =
            (self.core_size(), self.core_text_size(), self.init_size())
        else {
            return false;
        };
        if !(text > 0 && text <= MAXIMUM_SECTION)
            || !(core > 0 && core <= MAXIMUM_SECTION)
            || core + init < MINIMUM_TOTAL
        {
            return false;
        }

        self.object
            .member("mkobj")
            .and_then(|mkobj| mkobj.member("mod"))
            .and_then(|pointer| pointer.pointer_value())
            .map(|address| address == self.offset())
            .unwrap_or(false)
    }

    /// Size of the module's executable text, as the resolver bounds it.
    pub fn code_size(&self) -> Result<u64> {
        self.core_size()
    }

    /// The taint flags the module set on the kernel, rendered as letters.
    /// The letters the kernel would print for this module's taints.
    ///
    /// A kernel from 4.10 carries the table of flags itself, and it says both
    /// which letter marks a flag and which marks its absence. Older ones are
    /// read from the fixed table below.
    pub fn taints(&self, context: &Arc<Context>, kernel: &Module) -> Result<String> {
        let taints = self.object.member("taints")?.as_u64()?;
        Ok(taint_letters(context, kernel, taints, true))
    }

    /// The same taints, spelled out.
    pub fn taints_described(&self, context: &Arc<Context>, kernel: &Module) -> Result<String> {
        let taints = self.object.member("taints")?.as_u64()?;
        let letters = taint_letters(context, kernel, taints, true);
        Ok(letters
            .chars()
            .filter_map(describe_taint)
            .collect::<Vec<&str>>()
            .join(","))
    }

    /// The arguments the module was loaded with.
    pub fn arguments(&self) -> Result<String> {
        let args = self.object.member("args")?;
        crate::framework::objects::utility::pointer_to_string(&args, 512)
    }
}

/// Walk an `hlist`, which links its members singly rather than in a ring.
///
/// The head holds only a `first` pointer and each node only a `next`, so the
/// walk ends at a null rather than by returning to the head.
pub fn walk_hlist(
    context: &Arc<Context>,
    head: &Object,
    type_name: &str,
    member: &str,
) -> Result<Vec<Object>> {
    let template = context.symbol_space.get_type(type_name)?;
    let offset = context
        .symbol_space
        .find_member(&template, member)?
        .map(|(offset, _)| offset)
        .ok_or_else(|| VolatilityError::Other(format!("'{type_name}' has no member '{member}'")))?;

    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current = head.member("first")?.pointer_value()?;

    while current != 0 && results.len() < MAX_VMA_COUNT {
        if !seen.insert(current) {
            break;
        }
        let containing = current.wrapping_sub(offset);
        let object = context.object_from_template(template.clone(), head.layer_name(), containing);
        let next = object
            .member(member)
            .and_then(|node| node.member("next"))
            .and_then(|next| next.pointer_value());
        results.push(object);
        match next {
            Ok(value) => current = value,
            Err(_) => break,
        }
    }
    Ok(results)
}

/// Every value stored in an XArray, which is what an IDR is built on.
///
/// Entries are reached through a radix tree of slot arrays. A slot holding an
/// internal node has its low bits tagged, which is what distinguishes a branch
/// from a stored value.
pub fn xarray_entries(context: &Arc<Context>, kernel: &Module, array: &Object) -> Result<Vec<u64>> {
    /// The low bits a slot uses to mark what it holds.
    const TAG_MASK: u64 = 3;
    const TAG_INTERNAL: u64 = 2;

    let node_type = context.symbol_space.get_type(&kernel.qualified("xa_node"))?;
    let slots = context
        .symbol_space
        .find_member(&node_type, "slots")?
        .map(|(offset, template)| (offset, template))
        .ok_or_else(|| VolatilityError::Other("xa_node has no slots".to_string()))?;
    // The slot count is a power of two, and its exponent is the shift between
    // one level of the tree and the next.
    let chunk_size = context
        .object_from_template(slots.1.clone(), &kernel.layer_name, 0)
        .count()
        .unwrap_or(64);
    let chunk_shift = chunk_size.trailing_zeros();

    let head = array.member("xa_head")?.pointer_value()?;
    if head == 0 {
        return Ok(Vec::new());
    }

    let internal = head & TAG_MASK == TAG_INTERNAL;
    let node_pointer = if head & TAG_MASK != 0 {
        head & !TAG_MASK
    } else {
        head
    };

    let mut results = Vec::new();
    if !internal {
        results.push(node_pointer);
        return Ok(results);
    }

    // A node records its own depth through the shift it applies.
    let height = context
        .object_from_template(node_type.clone(), &kernel.layer_name, node_pointer)
        .member("shift")?
        .as_u64()?
        / chunk_shift as u64
        + 1;

    walk_xarray_node(
        context,
        kernel,
        &node_type,
        slots.0,
        chunk_size,
        node_pointer,
        height,
        &mut results,
    )?;
    Ok(results)
}

#[allow(clippy::too_many_arguments)]
fn walk_xarray_node(
    context: &Arc<Context>,
    kernel: &Module,
    node_type: &Arc<crate::framework::objects::template::Template>,
    slots_offset: u64,
    chunk_size: u64,
    node_pointer: u64,
    height: u64,
    results: &mut Vec<u64>,
) -> Result<()> {
    const TAG_MASK: u64 = 3;
    const TAG_INTERNAL: u64 = 2;

    for index in 0..chunk_size {
        let raw = context.layers.read(
            &kernel.layer_name,
            node_pointer + slots_offset + index * 8,
            8,
            false,
        )?;
        let slot = u64::from_le_bytes(raw.try_into().unwrap());
        if slot == 0 {
            continue;
        }
        let pointer = if slot & TAG_MASK == TAG_INTERNAL {
            slot & !TAG_INTERNAL
        } else {
            slot
        };

        if height <= 1 {
            results.push(pointer);
        } else {
            walk_xarray_node(
                context,
                kernel,
                node_type,
                slots_offset,
                chunk_size,
                pointer,
                height - 1,
                results,
            )?;
        }
    }
    Ok(())
}

/// Every node in a red-black tree, in pre-order.
///
/// The kernel uses these where a list would once have served. The mount table
/// from 6.8 onwards, for instance. Order follows the reference implementation's
/// traversal: the node, then its left subtree, then its right.
pub fn rbtree_nodes(root: &Object) -> Result<Vec<Object>> {
    /// A tree deeper or larger than this is corrupt rather than genuinely big.
    const MAX_NODES: usize = 100_000;

    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let Ok(first) = root.member("rb_node").and_then(|node| node.dereference()) else {
        return Ok(results);
    };

    // An explicit stack keeps a deep tree from exhausting the real one.
    let mut pending = vec![first];
    while let Some(node) = pending.pop() {
        if node.offset() == 0 || !node.is_readable() || !seen.insert(node.offset()) {
            continue;
        }
        if results.len() >= MAX_NODES {
            break;
        }

        // Pushed right-then-left so the left subtree is visited first.
        if let Ok(right) = node.member("rb_right").and_then(|child| child.dereference()) {
            pending.push(right);
        }
        if let Ok(left) = node.member("rb_left").and_then(|child| child.dereference()) {
            pending.push(left);
        }
        results.push(node);
    }
    Ok(results)
}

/// The structure a member of it is embedded in, the `container_of` idiom.
pub fn container_of(
    context: &Arc<Context>,
    member: &Object,
    type_name: &str,
    member_name: &str,
) -> Option<Object> {
    let template = context.symbol_space.get_type(type_name).ok()?;
    let offset = context
        .symbol_space
        .find_member(&template, member_name)
        .ok()?
        .map(|(offset, _)| offset)?;
    Some(context.object_from_template(
        template,
        member.layer_name(),
        member.offset().wrapping_sub(offset),
    ))
}

/// Every module found by scanning the module allocation range.
///
/// A module unlinked from the list to hide it still occupies its allocation, so
/// walking that range finds it. Candidates are cheap to reject: a real module's
/// embedded kobject points back at the module itself.
pub fn scan_modules(
    context: &Arc<Context>,
    kernel: &Module,
    known: &std::collections::HashSet<u64>,
) -> Result<Vec<KernelModule>> {
    let mask = context.layers.address_mask(&kernel.layer_name);
    let template = context.symbol_space.get_type(&kernel.qualified("module"))?;
    let module_kobject = context
        .symbol_space
        .get_type(&kernel.qualified("module_kobject"))?;
    let self_reference = context
        .symbol_space
        .find_member(&template, "mkobj")?
        .map(|(offset, _)| offset)
        .unwrap_or(0)
        + context
            .symbol_space
            .find_member(&module_kobject, "mod")?
            .map(|(offset, _)| offset)
            .unwrap_or(0);

    let (start, end) = module_allocation_range(context, kernel)?;
    // Allocations are pointer-aligned, so whole bytes can be skipped.
    let alignment = context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .map(|table| table.pointer_size() as u64)
        .unwrap_or(8);

    let mut results = Vec::new();
    let mut address = start & mask;
    let end = end & mask;
    while address < end {
        let candidate = address;
        address += alignment;
        if known.contains(&candidate) {
            continue;
        }

        let Ok(raw) = context
            .layers
            .read(&kernel.layer_name, candidate + self_reference, 8, false)
        else {
            continue;
        };
        if u64::from_le_bytes(raw.try_into().unwrap()) & mask != candidate {
            continue;
        }

        let module = KernelModule::new(context.object_from_template(
            template.clone(),
            &kernel.layer_name,
            candidate,
        ));
        if module.is_valid() {
            results.push(module);
        }
    }
    Ok(results)
}

/// The virtual range modules are allocated from.
pub fn module_allocation_range(context: &Arc<Context>, kernel: &Module) -> Result<(u64, u64)> {
    // Kernel 5.19 moved the bounds into `mod_tree`. Before that they were two
    // separate symbols.
    let from_tree = |name: &str| {
        context
            .object_from_symbol(kernel, "mod_tree", None)
            .and_then(|tree| tree.member(name))
            .and_then(|value| value.as_u64())
    };
    let low = from_tree("addr_min").or_else(|_| {
        context
            .object_from_symbol(kernel, "module_addr_min", Some("unsigned long"))
            .and_then(|value| value.as_u64())
    });
    let high = from_tree("addr_max").or_else(|_| {
        context
            .object_from_symbol(kernel, "module_addr_max", Some("unsigned long"))
            .and_then(|value| value.as_u64())
    });
    match (low, high) {
        (Ok(low), Ok(high)) if high > low => Ok((low, high)),
        _ => Err(VolatilityError::Other(
            "Could not determine the module allocation range".to_string(),
        )),
    }
}

/// One module as sysfs records it.
pub struct KsetModule {
    pub name: String,
    /// Address the reference implementation prints for this module.
    pub reported_offset: u64,
    pub module: KernelModule,
}

/// Modules as sysfs knows them, keyed by name.
///
/// Every module registers a kobject under `/sys/module`, which is a different
/// record from the module list `lsmod` reads. A module present in one and not
/// the other has been unlinked from that list. The classic way of hiding.
pub fn kset_modules(
    context: &Arc<Context>,
    kernel: &Module,
) -> Result<Vec<KsetModule>> {
    let kset = context.object_from_symbol(kernel, "module_kset", Some("kset"))?;
    let kobject_type = kernel.qualified("kobject");

    let module_kobject = context
        .symbol_space
        .get_type(&kernel.qualified("module_kobject"))?;
    // The kobject is embedded at the start of its module_kobject.
    let kobject_offset = context
        .symbol_space
        .find_member(&module_kobject, "kobj")?
        .map(|(offset, _)| offset)
        .unwrap_or(0);

    let mut results = Vec::new();
    let head = kset.member("list")?;
    for kobject in walk_list(&head, &kobject_type, "entry", true)? {
        let container = context.object_from_template(
            module_kobject.clone(),
            &kernel.layer_name,
            kobject.offset().wrapping_sub(kobject_offset),
        );
        let Ok(name) = kobject
            .member("name")
            .and_then(|name| pointer_to_string(&name, 32))
        else {
            continue;
        };
        if name.is_empty() {
            continue;
        }

        // A kobject still being set up, or already torn down, holds fewer
        // references than a live module's does.
        let references = kobject
            .member("kref")
            .and_then(|kref| kref.member("refcount"))
            .and_then(|count| {
                count
                    .member("counter")
                    .or_else(|_| count.member("refs").and_then(|refs| refs.member("counter")))
            })
            .and_then(|value| value.as_i64())
            .unwrap_or(0);
        if references <= 2 {
            continue;
        }

        let Ok(pointer) = container.member("mod") else {
            continue;
        };
        let Ok(module) = pointer.dereference() else {
            continue;
        };
        results.push(KsetModule {
            name,
            // The reference implementation reports the address of the pointer
            // field rather than of the module it points at.
            reported_offset: pointer.offset(),
            module: KernelModule::new(module),
        });
    }
    Ok(results)
}

/// Walk the kernel's loaded module list.
pub fn list_modules(context: &Arc<Context>, kernel: &Module) -> Result<Vec<KernelModule>> {
    let head = context.object_from_symbol(kernel, "modules", Some("list_head"))?;
    Ok(walk_list(&head, &kernel.qualified("module"), "list", true)?
        .into_iter()
        .map(KernelModule::new)
        .collect())
}


/// One mapped region of a task's address space, wrapping a `vm_area_struct`.
pub struct Vma {
    pub object: Object,
}

impl Vma {
    /// Resolve the inode behind a file-backed mapping.
    ///
    /// The three outcomes are kept apart deliberately: a read that fails and an
    /// inode that is simply absent lead the reference implementation to
    /// different places. The first skips the mapping, the second ends the
    /// plugin's output.
    fn backing_inode(&self) -> InodeLookup {
        let Some(file) = self.file() else {
            return InodeLookup::Unreadable;
        };

        // Reads the numbers the kernel keeps consistent for a live inode.
        let looks_live = |inode: &Object| -> Option<bool> {
            let number = inode.member("i_ino").ok()?.as_u64().ok()?;
            let count = inode
                .member("i_count")
                .ok()?
                .member("counter")
                .ok()?
                .as_i64()
                .ok()?;
            Some(number > 0 && count >= 0)
        };
        let resolved = |address: u64| -> Option<Object> {
            let inode = file
                .member("f_inode")
                .ok()?
                .dereference()
                .ok()?
                .at_offset(address);
            inode.is_readable().then_some(inode)
        };

        // The cached inode pointer, where the kernel is new enough to have one.
        let mut candidate = None;
        if file.has_member("f_inode") {
            let Ok(address) = file.member("f_inode").and_then(|p| p.pointer_value()) else {
                return InodeLookup::Unreadable;
            };
            if address != 0 {
                candidate = resolved(address);
            }
        }

        let usable = match &candidate {
            Some(inode) => match looks_live(inode) {
                Some(live) => live,
                // The inode's own fields could not be read.
                None => return InodeLookup::Unreadable,
            },
            None => false,
        };

        if !usable {
            // Fall back to the dentry's inode.
            let Ok(dentry_address) = file
                .member("f_path")
                .and_then(|path| path.member("dentry"))
                .and_then(|d| d.pointer_value())
            else {
                return InodeLookup::Unreadable;
            };
            let Ok(dentry) = file
                .member("f_path")
                .and_then(|path| path.member("dentry"))
                .and_then(|d| d.dereference())
            else {
                return InodeLookup::Unreadable;
            };
            if dentry_address == 0 || !dentry.is_readable() {
                return InodeLookup::Missing;
            }
            let Ok(address) = dentry.member("d_inode").and_then(|i| i.pointer_value()) else {
                return InodeLookup::Unreadable;
            };
            candidate = (address != 0).then(|| resolved(address)).flatten();
        }

        match candidate {
            Some(inode) => match looks_live(&inode) {
                Some(true) => InodeLookup::Found(inode),
                Some(false) => InodeLookup::Missing,
                None => InodeLookup::Unreadable,
            },
            None => InodeLookup::Missing,
        }
    }

    /// Whether the area is valid, reporting the point at which the reference
    /// implementation stops producing output.
    ///
    /// Upstream reads `inode.i_size` without checking that the inode was
    /// resolved, so a file-backed mapping whose inode is absent raises there
    /// and ends the plugin's output. `Err` marks that point so callers can
    /// truncate where it does.
    pub fn validity(&self) -> Result<bool> {
        if !self.is_valid() {
            return Ok(false);
        }
        if self.file().is_some() {
            match self.backing_inode() {
                InodeLookup::Found(inode) => {
                    let size = inode.member("i_size").and_then(|v| v.as_i64()).unwrap_or(0);
                    if size > 0 && self.page_offset().unwrap_or(0) > size as u64 {
                        return Ok(false);
                    }
                }
                // A read failure is caught upstream and skips the mapping.
                InodeLookup::Unreadable => return Ok(false),
                InodeLookup::Missing => {
                    return Err(VolatilityError::Other(
                        "vm_area_struct.is_valid: backing inode is absent".to_string(),
                    ))
                }
            }
        }
        Ok(true)
    }

    /// Whether the area looks like a real mapping rather than a smeared one.
    ///
    /// A mapping always spans a whole number of pages and starts before it
    /// ends. A file-backed one cannot begin past the end of the file it maps.
    pub fn is_valid(&self) -> bool {
        let (Ok(start), Ok(end)) = (self.start(), self.end()) else {
            return false;
        };
        if self.flags().is_err() {
            return false;
        }

        let page_size = 0x1000;
        let length = end.wrapping_sub(start);
        if start > end || (start == 0 && length == 0) || length % page_size != 0 {
            return false;
        }

        true
    }

    pub fn new(object: Object) -> Self {
        Self { object }
    }

    pub fn start(&self) -> Result<u64> {
        self.object.member("vm_start")?.as_u64()
    }

    pub fn end(&self) -> Result<u64> {
        self.object.member("vm_end")?.as_u64()
    }

    pub fn flags(&self) -> Result<u64> {
        self.object.member("vm_flags")?.as_u64()
    }

    /// Offset into the backing file, in pages.
    /// The mapping's offset into the file it maps, in bytes.
    ///
    /// The kernel records it in pages, so it is shifted back up. An anonymous
    /// mapping has no file and so no offset.
    pub fn page_offset(&self) -> Result<u64> {
        if self.file().is_none() {
            return Ok(0);
        }
        let page_shift = self
            .object
            .context()
            .layers
            .get(self.object.layer_name())
            .map(|layer| (layer.address_mask(), 12))
            .map(|(_, shift)| shift)
            .unwrap_or(12);
        Ok(self.object.member("vm_pgoff")?.as_u64()? << page_shift)
    }

    /// Protection rendered the way `/proc/pid/maps` shows it.
    pub fn protection(&self) -> String {
        // Only read/write/execute are reported. The shared/private bit is not
        // part of what upstream prints.
        let flags = self.flags().unwrap_or(0);
        let mut text = String::with_capacity(3);
        text.push(if flags & 0x1 != 0 { 'r' } else { '-' });
        text.push(if flags & 0x2 != 0 { 'w' } else { '-' });
        text.push(if flags & 0x4 != 0 { 'x' } else { '-' });
        text
    }

    /// The file backing this mapping, if it has one.
    pub fn file(&self) -> Option<Object> {
        let file = self.object.member("vm_file").ok()?;
        (file.pointer_value().ok()? != 0).then(|| file.dereference().ok())?
    }

    /// The path of the backing file.
    pub fn file_path(&self) -> Option<String> {
        let file = self.file()?;
        path_from_file(&file)
    }

    /// The device and inode numbers of the backing file.
    /// The name a mapping is listed under, as `/proc/<pid>/maps` shows it.
    ///
    /// A file-backed area is named by its path. The anonymous ones are
    /// recognised by where they sit relative to the task's heap, stack and
    /// vDSO, and anything else is simply anonymous.
    pub fn name(&self, task: &Task) -> Option<String> {
        if let Some(file) = self.file() {
            // A file's path only means anything relative to the task's root,
            // which is what supplies any mount prefixes.
            return path_for_file(task, &file);
        }

        let (start, end) = (self.start().ok()?, self.end().ok()?);
        let mm = task.mm().ok().flatten()?;
        let field = |name: &str| mm.member(name).and_then(|value| value.as_u64()).ok();

        if let (Some(start_brk), Some(brk)) = (field("start_brk"), field("brk")) {
            if start <= start_brk && end >= brk {
                return Some("[heap]".to_string());
            }
        }
        if let Some(start_stack) = field("start_stack") {
            if start <= start_stack && start_stack <= end {
                return Some("[stack]".to_string());
            }
        }
        if let Some(vdso) = mm
            .member("context")
            .and_then(|context| context.member("vdso"))
            .and_then(|value| value.as_u64())
            .ok()
        {
            if start == vdso {
                return Some("[vdso]".to_string());
            }
        }
        Some("Anonymous Mapping".to_string())
    }

    pub fn device_and_inode(&self) -> Option<(u64, u64, u64)> {
        let file = self.file()?;
        let inode = file
            .member("f_inode")
            .or_else(|_| {
                file.member("f_path")
                    .and_then(|path| path.member("dentry"))
                    .and_then(|dentry| dentry.dereference())
                    .and_then(|dentry| dentry.member("d_inode"))
            })
            .ok()?
            .dereference()
            .ok()?;

        let number = inode.member("i_ino").ok()?.as_u64().ok()?;
        // The device number packs major and minor into one value.
        let device = inode
            .member("i_sb")
            .and_then(|sb| sb.dereference())
            .and_then(|sb| sb.member("s_dev"))
            .and_then(|dev| dev.as_u64())
            .unwrap_or(0);
        Some((device >> 20, device & 0xFFFFF, number))
    }
}

/// Resolve a `file`'s path by walking its dentry up to the mount root.
pub fn path_from_file(file: &Object) -> Option<String> {
    let path = file.member("f_path").ok()?;
    let dentry = path.member("dentry").ok()?.dereference().ok()?;
    dentry_path(&dentry)
}

/// Marker upstream appends to a path whose file has been unlinked.
const DELETED_MARKER: &str = "(deleted)";
/// Marker upstream prefixes to a path with a missing component.
const SMEAR_MARKER: &str = "<potentially smeared>";

/// A file's path as seen from a task's root, crossing mount points.
///
/// This mirrors the kernel's `prepend_path`: components are collected from the
/// dentry towards the root, and when the walk reaches the root of a mounted
/// filesystem it continues from the mount point in the parent mount. Without
/// that hop a file on a sub-mount loses the prefix the mount is attached at --
/// `/run/systemd/...` would come out as `/systemd/...`.
pub fn path_for_file(task: &Task, file: &Object) -> Option<String> {
    path_for_file_of_kind(task, file, false)
}

/// As [`path_for_file`], but a caller interested only in real files can ask for
/// the name a socket or pipe has in the filesystem rather than the description
/// the kernel would print for it.
pub fn path_for_file_of_kind(task: &Task, file: &Object, files_only: bool) -> Option<String> {
    // A pseudo-file names itself through its dentry operations rather than by
    // its position in a directory tree.
    if !files_only {
        if let Some(name) = special_dentry_name(task, file) {
            return Some(name);
        }
    }

    let path = file.member("f_path").ok()?;
    // A dentry that is absent, or whose parent link cannot be read, gives no
    // path at all rather than a partial one.
    if path.member("dentry").ok()?.pointer_value().ok()? == 0 {
        return None;
    }
    let dentry = path.member("dentry").ok()?.dereference().ok()?;
    dentry.member("d_parent").ok()?.pointer_value().ok()?;

    let vfsmount = path.member("mnt").ok()?.dereference().ok()?;
    let inode = file.member("f_inode").ok().and_then(|i| i.dereference().ok());

    resolve_path(task, dentry, vfsmount, inode)
}

/// Every mount point on the system, paired with the task that reaches it.
///
/// Mounts live per namespace, so each namespace is visited once through
/// whichever task belongs to it, and a mount reached twice is reported once.
pub fn mount_points(context: &Arc<Context>, kernel: &Module) -> Result<Vec<(Task, Object)>> {
    let mut results = Vec::new();
    let mut seen_namespaces = std::collections::HashSet::new();
    let mut seen_mounts = std::collections::HashSet::new();

    for task in list_tasks(context, kernel, false)? {
        let Ok(namespace) = task
            .object
            .member("nsproxy")
            .and_then(|proxy| proxy.dereference())
            .and_then(|proxy| proxy.member("mnt_ns"))
            .and_then(|namespace| namespace.dereference())
        else {
            continue;
        };
        if !seen_namespaces.insert(namespace.offset()) {
            continue;
        }

        // Kernel 6.8 moved the mount table from a list into a red-black tree.
        let mounts = if namespace.has_member("list") {
            namespace
                .member("list")
                .and_then(|head| walk_list(&head, &kernel.qualified("mount"), "mnt_list", true))
                .unwrap_or_default()
        } else if namespace.has_member("mounts") {
            namespace
                .member("mounts")
                .and_then(|root| rbtree_nodes(&root))
                .unwrap_or_default()
                .into_iter()
                .filter_map(|node| {
                    container_of(context, &node, &kernel.qualified("mount"), "mnt_node")
                })
                .collect()
        } else {
            continue;
        };

        for mount in mounts {
            let id = mount
                .member("mnt_id")
                .and_then(|id| id.as_i64())
                .unwrap_or(0);
            if !seen_mounts.insert(id) {
                continue;
            }
            results.push((Task::new(task.object.clone()), mount));
        }
    }
    Ok(results)
}

/// Whether the task's root directory can be read.
///
/// Every path is resolved relative to it, so when it cannot be read no path can
/// be produced, and the reference implementation stops there rather than
/// carrying on with the next file.
pub fn task_root_readable(task: &Task) -> bool {
    task.object
        .member("fs")
        .and_then(|fs| fs.dereference())
        .and_then(|fs| fs.member("root"))
        .and_then(|root| root.member("dentry"))
        .and_then(|dentry| dentry.pointer_value())
        .is_ok()
}

/// A path relative to a task's root, crossing mount points.
///
/// Shared by files and by mount points, which differ only in which dentry and
/// which mount they start from.
pub fn resolve_path(
    task: &Task,
    mut dentry: Object,
    mut vfsmount: Object,
    inode: Option<Object>,
) -> Option<String> {
    let fs = task.object.member("fs").ok()?.dereference().ok()?;
    let root = fs.member("root").ok()?;
    let root_dentry = root.member("dentry").ok()?.pointer_value().ok()?;
    let root_mount = root.member("mnt").ok()?.pointer_value().ok()?;

    let mut components: Vec<String> = Vec::new();
    let mut smeared = false;

    for _ in 0..256 {
        if dentry.offset() == root_dentry && vfsmount.offset() == root_mount {
            break;
        }

        let mount_root = vfsmount
            .member("mnt_root")
            .and_then(|value| value.pointer_value())
            .unwrap_or(0);
        let parent_address = dentry
            .member("d_parent")
            .and_then(|value| value.pointer_value())
            .unwrap_or(0);
        let is_root = parent_address == dentry.offset();

        if dentry.offset() == mount_root || is_root {
            // Reached the top of this tree. If it is not the mount's own root
            // the walk has escaped the tree it started in.
            if dentry.offset() != mount_root {
                break;
            }
            let Some(mount) = containing_mount(&vfsmount) else {
                break;
            };
            let parent_mount = mount
                .member("mnt_parent")
                .and_then(|value| value.pointer_value())
                .unwrap_or(0);
            // A mount that is its own parent is a global root.
            if parent_mount == 0 || parent_mount == mount.offset() {
                break;
            }
            let Ok(mountpoint) = mount
                .member("mnt_mountpoint")
                .and_then(|value| value.dereference())
            else {
                break;
            };
            dentry = mountpoint;
            vfsmount = mount.at_offset(parent_mount).member("mnt").ok()?;
            continue;
        }

        let name = dentry
            .member("d_name")
            .ok()
            .and_then(|name| read_qstr(&name))
            .unwrap_or_default();
        // An empty component is what a smeared dentry looks like. Upstream
        // keeps the gap visible rather than silently closing it.
        if name.is_empty() {
            smeared = true;
        }
        components.push(name.trim_matches('/').to_string());

        if parent_address == 0 {
            break;
        }
        dentry = dentry.at_offset(parent_address);
    }

    components.reverse();
    let path = format!("/{}", components.join("/"));

    if smeared {
        return Some(format!("{SMEAR_MARKER} {path}"));
    }
    if let Some(inode) = inode {
        if inode.is_readable() && inode.member("i_nlink").and_then(|n| n.as_u64()).unwrap_or(1) == 0
        {
            return Some(format!(" {path} {DELETED_MARKER}"));
        }
    }
    Some(path)
}

/// The name a pseudo-file is listed under.
///
/// Sockets, pipes, anonymous inodes and the shared mappings behind `/dev/zero`
/// have no path in any directory tree. The kernel gives their dentries a
/// `d_dname` callback instead, and which callback it is says what kind of
/// object it is, so the function's address is resolved back to its symbol.
fn special_dentry_name(task: &Task, file: &Object) -> Option<String> {
    let dentry = file.member("f_path").ok()?.member("dentry").ok()?.dereference().ok()?;
    let operations = dentry.member("d_op").ok()?;
    if operations.pointer_value().ok()? == 0 {
        return None;
    }
    let dname = operations
        .dereference()
        .ok()?
        .member("d_dname")
        .ok()?
        .pointer_value()
        .ok()?;
    if dname == 0 {
        return None;
    }

    // From here the file is known to name itself, so a failure to read the rest
    // is reported rather than falling back to a directory path.
    let inode_pointer = dentry
        .member("d_inode")
        .and_then(|inode| inode.pointer_value())
        .unwrap_or(0);
    let inode = match dentry.member("d_inode").and_then(|inode| inode.dereference()) {
        Ok(inode) if inode_pointer != 0 && inode.is_readable() => inode,
        _ => return Some(format!("<invalid dentry inode> {inode_pointer:x}")),
    };
    let inode_number = inode.member("i_ino").and_then(|n| n.as_u64()).unwrap_or(0);
    let references = inode
        .member("i_count")
        .and_then(|count| count.member("counter"))
        .and_then(|value| value.as_i64())
        .unwrap_or(-1);
    if inode_number == 0 || references < 0 {
        return Some(format!("<invalid dentry inode> {inode_pointer:x}"));
    }

    // Comparing against the handful of callbacks the kernel uses is cheaper
    // than resolving an arbitrary address back to a symbol.
    let context = task.object.context();
    let table = vma_table(&task.object).ok()?;
    let module = context
        .module_names()
        .into_iter()
        .filter_map(|name| context.module(&name).ok())
        .find(|module| module.symbol_table_name == table)?;
    let mask = context.layers.address_mask(&module.layer_name);
    let address_of = |name: &str| -> Option<u64> {
        context
            .symbol_offset(&module, name)
            .ok()
            .map(|address| address & mask)
    };

    let kind = if Some(dname) == address_of("sockfs_dname") {
        "socket"
    } else if Some(dname) == address_of("anon_inodefs_dname") {
        "anon_inode"
    } else if Some(dname) == address_of("pipefs_dname") {
        "pipe"
    } else if Some(dname) == address_of("simple_dname") {
        // A simple name is the whole path already, and such a file only ever
        // appears here once it has been unlinked.
        let name = dentry
            .member("d_name")
            .ok()
            .and_then(|qstr| read_qstr(&qstr))
            .unwrap_or_default();
        return Some(if name.is_empty() {
            format!(":[{inode_number}]")
        } else {
            format!("/{name} {DELETED_MARKER}")
        });
    } else if Some(dname) == address_of("ns_dname") {
        // A namespace file names itself after the kind of namespace, which is
        // recorded in the operations table the dentry carries.
        let operations = if dentry
            .member("d_inode")
            .and_then(|inode| inode.dereference())
            .map(|inode| inode.has_member("i_private"))
            .unwrap_or(false)
            && !stashed_is_counter(&dentry)
        {
            // kernels >= 6.9 keep the namespace behind the inode
            inode
                .member("i_private")
                .and_then(|private| private.pointer_value())
                .ok()
                .and_then(|address| {
                    let template = context
                        .symbol_space
                        .get_type(&crate::framework::symbols::join_name(&table, "ns_common"))
                        .ok()?;
                    context
                        .object_from_template(template, dentry.layer_name(), address)
                        .member("ops")
                        .and_then(|ops| ops.dereference())
                        .ok()
                })
        } else {
            // 3.19 <= kernels < 6.9 keep it in the dentry's private data
            dentry
                .member("d_fsdata")
                .and_then(|data| data.pointer_value())
                .ok()
                .and_then(|address| {
                    let template = context
                        .symbol_space
                        .get_type(&crate::framework::symbols::join_name(
                            &table,
                            "proc_ns_operations",
                        ))
                        .ok()?;
                    Some(context.object_from_template(template, dentry.layer_name(), address))
                })
        };

        let name = operations
            .and_then(|operations| operations.member("name").ok())
            .and_then(|name| pointer_to_string(&name, 255).ok())
            .unwrap_or_else(|| "<unsupported ns_dname implementation>".to_string());
        return Some(format!("{name}:[{inode_number}]"));
    } else {
        return Some(format!("<unsupported d_op symbol> {dname:x}"));
    };

    Some(format!("{kind}:[{inode_number}]"))
}

/// Whether a namespace's `stashed` member is still a counter.
///
/// Kernel 6.9 changed it from an atomic counter to a dentry pointer, which is
/// what says where the namespace's operations table can be found.
fn stashed_is_counter(dentry: &Object) -> bool {
    let Ok(table) = vma_table(dentry) else {
        return true;
    };
    dentry
        .context()
        .symbol_space
        .get_type(&crate::framework::symbols::join_name(&table, "ns_common"))
        .ok()
        .and_then(|template| {
            let space = &dentry.context().symbol_space;
            space
                .find_member(&template, "stashed")
                .ok()?
                .map(|(_, member)| member.type_name().contains("atomic64_t"))
        })
        .unwrap_or(true)
}

/// The `mount` structure a `vfsmount` is embedded in.
///
/// Kernel 3.3 split the private parts of a mount into `struct mount`, leaving
/// `vfsmount` as a member of it, so stepping out is the `container_of` idiom.
fn containing_mount(vfsmount: &Object) -> Option<Object> {
    let table = vma_table(vfsmount).ok()?;
    let context = vfsmount.context();
    let mount_type = crate::framework::symbols::join_name(&table, "mount");
    let template = context.symbol_space.get_type(&mount_type).ok()?;
    let offset = context
        .symbol_space
        .find_member(&template, "mnt")
        .ok()?
        .map(|(offset, _)| offset)?;
    Some(context.object_from_template(
        template,
        vfsmount.layer_name(),
        vfsmount.offset().wrapping_sub(offset),
    ))
}

/// Build a path by walking a dentry chain towards the root.
///
/// Each dentry names one component. The chain ends when a dentry is its own
/// parent, which is how the kernel marks a mount root.
pub fn dentry_path(dentry: &Object) -> Option<String> {
    let mut components: Vec<String> = Vec::new();
    let mut current = dentry.clone();
    let mut seen = std::collections::HashSet::new();

    // A path deeper than this, or one that revisits a dentry, means the chain
    // is corrupt rather than genuinely deep.
    for _ in 0..128 {
        if !seen.insert(current.offset()) {
            break;
        }
        let name = current
            .member("d_name")
            .ok()
            .and_then(|name| read_qstr(&name))
            .unwrap_or_default();

        let parent_address = current
            .member("d_parent")
            .ok()
            .and_then(|parent| parent.pointer_value().ok())?;

        // A dentry that is its own parent is the root of its mount.
        if parent_address == current.offset() || parent_address == 0 {
            break;
        }
        if !name.is_empty() && name != "/" {
            components.push(name);
        }
        current = current.at_offset(parent_address);
    }

    components.reverse();
    Some(format!("/{}", components.join("/")))
}

/// Read a kernel `qstr`, which pairs a length with a pointer to the characters.
pub fn read_qstr(qstr: &Object) -> Option<String> {
    let length = qstr
        .member("len")
        .ok()
        .and_then(|len| len.as_u64().ok())
        // Older kernels pack the length and hash into one field.
        .or_else(|| {
            qstr.member("hash_len")
                .ok()
                .and_then(|value| value.as_u64().ok())
                .map(|value| value >> 32)
        })?;
    if length == 0 || length > 4096 {
        return None;
    }

    let address = qstr.member("name").ok()?.pointer_value().ok()?;
    if address == 0 {
        return None;
    }
    let data = qstr
        .context()
        .layers
        .read(qstr.layer_name(), address, length as usize, true)
        .ok()?;
    Some(String::from_utf8_lossy(&data).to_string())
}

impl Task {
    /// The task's mapped regions, in address order.
    ///
    /// Walks the `vm_next` chain, which is how kernels before 6.1 link the
    /// regions. Newer kernels use a maple tree, which this does not yet read.
    /// The task's heap mappings, as `(start, length)` pairs.
    ///
    /// The heap is the region the program break moves through, so a mapping
    /// counts when it spans any part of `start_brk..brk`.
    pub fn heap_sections(&self) -> Result<Vec<(u64, u64)>> {
        let Some(mm) = self.mm()? else {
            return Ok(Vec::new());
        };
        let brk = mm.member("brk")?.as_u64()?;
        let start_brk = mm.member("start_brk")?.as_u64()?;

        let mut sections = Vec::new();
        for vma in self.vmas()?.areas {
            let (Ok(start), Ok(end)) = (vma.start(), vma.end()) else {
                continue;
            };
            if start <= brk && end >= start_brk && end > start {
                sections.push((start, end - start));
            }
        }
        Ok(sections)
    }

    pub fn vmas(&self) -> Result<VmaList> {
        let Some(mm) = self.mm()? else {
            // A kernel thread has no user address space.
            return Ok(VmaList::default());
        };

        let context = self.object.context().clone();
        let vma_template = context.symbol_space.get_type(
            &crate::framework::symbols::join_name(
                vma_table(&self.object)?.as_str(),
                "vm_area_struct",
            ),
        )?;
        let layer = self.object.layer_name().to_string();

        let mut partial = false;
        let addresses = if mm.has_member("mmap") {
            // kernels < 6.1 chain the areas through `vm_next`.
            let mut addresses = Vec::new();
            let mut seen = std::collections::HashSet::new();
            let mut address = mm.member("mmap")?.pointer_value()?;
            while address != 0 && addresses.len() < MAX_VMA_COUNT {
                if !seen.insert(address) {
                    break;
                }
                let vma = context.object_from_template(vma_template.clone(), &layer, address);
                let next = vma.member("vm_next").and_then(|next| next.pointer_value());
                addresses.push(address);
                match next {
                    Ok(value) => address = value,
                    Err(_) => break,
                }
            }
            addresses
        } else if mm.has_member("mm_mt") {
            // kernels >= 6.1 keep them in a maple tree.
            let (slots, truncated) = maple_tree_slots(&mm.member("mm_mt")?)?;
            partial = truncated;
            slots
        } else {
            return Err(VolatilityError::Other(
                "Unable to find mmap or mm_mt in mm_struct".to_string(),
            ));
        };

        let mut results = VmaList {
            truncated: partial,
            ..Default::default()
        };
        for address in addresses {
            // A slot that was never filled holds a value describing the slot
            // rather than a pointer, which lands in the first page.
            if address < 0x1000 {
                continue;
            }
            let vma = Vma::new(context.object_from_template(
                vma_template.clone(),
                &layer,
                address,
            ));
            match vma.validity() {
                Ok(true) => results.areas.push(vma),
                Ok(false) => {}
                Err(_) => {
                    results.truncated = true;
                    break;
                }
            }
        }
        Ok(results)
    }

    /// The task's command line arguments.
    pub fn arguments(&self) -> Result<Vec<String>> {
        let Some(mm) = self.mm()? else {
            return Ok(Vec::new());
        };
        let start = mm.member("arg_start")?.as_u64()?;
        let end = mm.member("arg_end")?.as_u64()?;
        read_string_block(&self.object, start, end)
    }

    /// The task's environment variables, as `KEY=VALUE` strings.
    /// The task's environment block, split on its NUL separators.
    ///
    /// The block lives in the task's own address space and is read whole: a
    /// partial read would silently truncate the listing, so a block that is not
    /// fully mapped yields nothing at all.
    pub fn environment(&self) -> Result<Vec<String>> {
        // A block bigger than this means the pointers were misread.
        const MAX_ENVIRONMENT: u64 = 8192;

        let Some(mm) = self.mm()? else {
            return Ok(Vec::new());
        };
        let start = mm.member("env_start")?.as_u64()?;
        let end = mm.member("env_end")?.as_u64()?;
        let Some(size) = end.checked_sub(start) else {
            return Ok(Vec::new());
        };
        if size == 0 || size > MAX_ENVIRONMENT {
            return Ok(Vec::new());
        }

        let Some(layer) = self.process_layer()? else {
            return Ok(Vec::new());
        };
        let context = self.object.context();
        if !context.layers.is_valid(&layer, start, size) {
            return Ok(Vec::new());
        }

        let data = context.layers.read(&layer, start, size as usize, false)?;
        // Only the trailing terminators are dropped. An empty entry in the
        // middle is a real, if odd, part of the block.
        let trimmed = data.iter().rposition(|byte| *byte != 0).map_or(&data[..0], |last| &data[..=last]);

        Ok(trimmed
            .split(|byte| *byte == 0)
            .map(|part| String::from_utf8_lossy(part).to_string())
            .collect())
    }
}

/// Read a run of NUL-separated strings from a task's address space.
fn read_string_block(task: &Object, start: u64, end: u64) -> Result<Vec<String>> {
    // A block larger than this means the pointers were misread.
    const MAX_BLOCK: u64 = 0x20000;
    if end <= start || end - start > MAX_BLOCK {
        return Ok(Vec::new());
    }
    let data = task
        .context()
        .layers
        .read(task.layer_name(), start, (end - start) as usize, true)?;

    Ok(data
        .split(|&byte| byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).to_string())
        .collect())
}

/// The symbol table an object came from, needed to qualify sibling type names.
fn vma_table(object: &Object) -> Result<String> {
    let resolved = object.resolved_template()?;
    resolved
        .as_struct()
        .map(|structure| structure.table.clone())
        .ok_or_else(|| {
            VolatilityError::Other("Cannot determine the symbol table for this task".to_string())
        })
}


/// An open file descriptor of a task.
pub struct OpenFile {
    pub descriptor: u64,
    pub file: Object,
}

impl OpenFile {
    /// The path the descriptor refers to.
    pub fn path(&self) -> Option<String> {
        path_from_file(&self.file)
    }

    /// The inode backing the descriptor, if it has one.
    pub fn inode(&self) -> Option<Object> {
        self.file
            .member("f_inode")
            .or_else(|_| {
                self.file
                    .member("f_path")
                    .and_then(|path| path.member("dentry"))
                    .and_then(|dentry| dentry.dereference())
                    .and_then(|dentry| dentry.member("d_inode"))
            })
            .ok()?
            .dereference()
            .ok()
    }
}

impl Task {
    /// The task's open file descriptors.
    ///
    /// The descriptor table is an array of `file` pointers whose length the
    /// kernel records alongside it. Sparse entries are null and are skipped.
    pub fn open_files(&self) -> Result<Vec<OpenFile>> {
        let files = self.object.member("files")?;
        if files.pointer_value()? == 0 {
            // A kernel thread has no descriptor table.
            return Ok(Vec::new());
        }
        let files = files.dereference()?;

        // `fdt` points at the current table. `fdtab` is the embedded fallback
        // used before the table has been expanded.
        let table = files
            .member("fdt")
            .and_then(|fdt| fdt.dereference())
            .or_else(|_| files.member("fdtab"))?;

        let max = table.member("max_fds")?.as_u64()?;
        // A table larger than this means the structure was misread.
        if max == 0 || max > 0x100000 {
            return Ok(Vec::new());
        }

        let array = table.member("fd")?.pointer_value()?;
        if array == 0 {
            return Ok(Vec::new());
        }

        let context = self.object.context().clone();
        let file_template = context.symbol_space.get_type(
            &crate::framework::symbols::join_name(vma_table(&self.object)?.as_str(), "file"),
        )?;
        let pointer_size = 8u64;

        let mut results = Vec::new();
        for descriptor in 0..max {
            let Ok(data) = context.layers.read(
                self.object.layer_name(),
                array + descriptor * pointer_size,
                pointer_size as usize,
                false,
            ) else {
                continue;
            };
            let address = u64::from_le_bytes(data.try_into().unwrap());
            if address == 0 {
                continue;
            }
            let file = context.object_from_template(
                file_template.clone(),
                self.object.layer_name(),
                address,
            );
            // A descriptor whose file structure is not present tells us nothing,
            // so it is left out rather than reported as a row of blanks.
            if !file.is_readable() {
                continue;
            }
            results.push(OpenFile { descriptor, file });
        }
        Ok(results)
    }

    /// The capability sets held by the task, as raw bit masks.
    ///
    /// Returns `(inheritable, permitted, effective, bounding, ambient)`. A
    /// kernel too old to have a given set reports zero for it.
    pub fn capabilities(&self) -> Result<(u64, u64, u64, u64, u64)> {
        // The effective credentials are what a task acts with. `real_cred` is
        // what it may return to, and is the set upstream reports.
        let cred = self.object.member("real_cred")?.dereference()?;
        let read = |name: &str| -> u64 {
            cred.member(name)
                .and_then(|set| {
                    // Kernel 6.3 replaced the array of 32-bit words with a
                    // single 64-bit `val`. Older kernels keep two words, whose
                    // second holds the high bits.
                    if let Ok(value) = set.member("val").and_then(|value| value.as_u64()) {
                        return Ok(value);
                    }
                    let words = set.member("cap")?;
                    let low = words.index(0)?.as_u64()?;
                    let high = words.index(1).and_then(|word| word.as_u64()).unwrap_or(0);
                    Ok(low | (high << 32))
                })
                .unwrap_or(0)
        };
        Ok((
            read("cap_inheritable"),
            read("cap_permitted"),
            read("cap_effective"),
            read("cap_bset"),
            read("cap_ambient"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::layers::physical::BufferLayer;
    use crate::framework::symbols::isf::IsfFile;
    use crate::framework::symbols::native::x64_native_table;
    use crate::framework::symbols::SymbolTable;

    /// A cut-down kernel with just enough of `task_struct` to walk the list.
    const ISF: &str = r#"{
        "metadata": {"format": "6.2.0"},
        "base_types": {
            "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
            "int": {"size": 4, "signed": true, "kind": "int", "endian": "little"},
            "char": {"size": 1, "signed": true, "kind": "char", "endian": "little"}
        },
        "user_types": {
            "list_head": {"kind": "struct", "size": 16, "fields": {
                "next": {"offset": 0, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "list_head"}}},
                "prev": {"offset": 8, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "list_head"}}}
            }},
            "task_struct": {"kind": "struct", "size": 64, "fields": {
                "tasks": {"offset": 0, "type": {"kind": "struct", "name": "list_head"}},
                "pid": {"offset": 16, "type": {"kind": "base", "name": "int"}},
                "tgid": {"offset": 20, "type": {"kind": "base", "name": "int"}},
                "comm": {"offset": 24, "type": {"kind": "array", "count": 16, "subtype": {"kind": "base", "name": "char"}}}
            }}
        },
        "enums": {},
        "symbols": {"init_task": {"address": 512}}
    }"#;

    /// Build the fixture, optionally severing the forward link out of the
    /// first task so that the one after it is reachable only going backwards.
    fn build_with(forward_hole: bool) -> (Arc<Context>, Arc<Module>) {
        let mut memory = vec![0u8; 0x1000];
        // `init_task` is the list head, and is the swapper task rather than a
        // process any tool reports.
        let tasks: [(u64, u32, &[u8]); 3] = [
            (0x200, 0, b"swapper/0"),
            (0x300, 2, b"kthreadd"),
            (0x400, 900, b"bash"),
        ];

        for (index, (offset, pid, name)) in tasks.iter().enumerate() {
            let next = tasks[(index + 1) % tasks.len()].0;
            let previous = tasks[(index + tasks.len() - 1) % tasks.len()].0;
            let at = *offset as usize;
            memory[at..at + 8].copy_from_slice(&next.to_le_bytes());
            memory[at + 8..at + 16].copy_from_slice(&previous.to_le_bytes());
            memory[at + 16..at + 20].copy_from_slice(&pid.to_le_bytes());
            memory[at + 20..at + 24].copy_from_slice(&pid.to_le_bytes());
            memory[at + 24..at + 24 + name.len()].copy_from_slice(name);
        }

        if forward_hole {
            // kthreadd's `next` now points outside the layer, which is what a
            // page that was not captured looks like to the walk.
            memory[0x300..0x308].copy_from_slice(&0x9000u64.to_le_bytes());
        }

        let context = Arc::new(Context::new());
        context.layers.add(Arc::new(BufferLayer::new("kernel", memory)));
        let isf = IsfFile::from_slice(ISF.as_bytes()).unwrap();
        context.add_symbol_table(Arc::new(SymbolTable::new(
            "vmlinux",
            isf,
            x64_native_table(),
        )));
        let module = context.add_module(
            Module::new("kernel", "vmlinux", "kernel", 0).with_absolute_addresses(true),
        );
        (context, module)
    }

    fn build() -> (Arc<Context>, Arc<Module>) {
        build_with(false)
    }

    #[test]
    fn walks_the_task_list_from_init_task() {
        let (context, kernel) = build();
        let tasks = list_tasks(&context, &kernel, false).unwrap();

        // `init_task` heads the list but is not one of its entries, so the
        // swapper task is absent. As it is from `ps` and from Volatility.
        let names: Vec<String> = tasks.iter().map(|t| t.comm().unwrap()).collect();
        assert_eq!(names, vec!["kthreadd", "bash"]);
        assert_eq!(tasks[1].pid().unwrap(), 900);
    }

    #[test]
    fn reaches_tasks_stranded_past_an_unreadable_link() {
        let (context, kernel) = build_with(true);
        let tasks = list_tasks(&context, &kernel, false).unwrap();

        // Going forward the walk reaches kthreadd and then falls into the hole.
        // bash is only reachable from the other end, so a one-way walk drops it.
        let names: Vec<String> = tasks.iter().map(|t| t.comm().unwrap()).collect();
        assert_eq!(names, vec!["kthreadd", "bash"]);
    }

    #[test]
    fn a_leader_is_not_reported_as_a_thread() {
        let (context, kernel) = build();
        let tasks = list_tasks(&context, &kernel, false).unwrap();
        // pid == tgid for every task here, so none is a thread.
        assert!(tasks.iter().all(|task| !task.is_thread()));
    }
}

/// Enumerate tasks by walking the parent/child tree rather than the task list.
///
/// This reaches tasks through a different set of pointers than [`list_tasks`],
/// so a task unlinked from the task list to hide it may still be found here.
/// Comparing the two enumerations is what makes hidden processes visible.
pub fn list_tasks_by_children(context: &Arc<Context>, kernel: &Module) -> Result<Vec<Task>> {
    let init_task = context.object_from_symbol(kernel, "init_task", Some("task_struct"))?;
    let task_type = kernel.qualified("task_struct");

    let mut results = Vec::new();
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    let mut pending = vec![init_task];

    while let Some(task) = pending.pop() {
        if !seen.insert(task.offset()) || results.len() >= 100_000 {
            continue;
        }

        // Each task heads a list of its children, linked through `sibling`.
        if let Ok(children_head) = task.member("children") {
            for child in
                walk_list(&children_head, &task_type, "sibling", true).unwrap_or_default()
            {
                if !seen.contains(&child.offset()) {
                    pending.push(child);
                }
            }
        }
        results.push(Task::new(task));
    }

    results.sort_by_key(|task| task.offset());
    Ok(results)
}

/// A network interface, wrapping a `net_device`.
pub struct NetDevice {
    pub object: Object,
}

impl NetDevice {
    /// The interface name, a fixed-size character array.
    pub fn name(&self) -> Result<String> {
        self.object.member("name")?.as_string()
    }

    /// The interface's index within its namespace.
    pub fn index(&self) -> Result<i64> {
        self.object.member("ifindex")?.as_i64()
    }

    /// The hardware address, formatted the way `ip` shows it.
    pub fn mac_address(&self) -> Option<String> {
        // The address length varies by link type. Ethernet is six bytes.
        let length = self
            .object
            .member("addr_len")
            .and_then(|len| len.as_u64())
            .unwrap_or(6)
            .min(32) as usize;
        if length == 0 {
            return None;
        }

        let field = self.object.member("perm_addr").ok()?;
        let data = self
            .object
            .context()
            .layers
            .read(self.object.layer_name(), field.offset(), length, false)
            .ok()?;
        Some(
            data.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<String>>()
                .join(":"),
        )
    }

    pub fn flags(&self) -> u64 {
        self.object
            .member("flags")
            .and_then(|flags| flags.as_u64())
            .unwrap_or(0)
    }

    /// Whether the interface is capturing traffic not addressed to it.
    pub fn is_promiscuous(&self) -> bool {
        // IFF_PROMISC is bit eight of the interface flags.
        self.flags() & 0x100 != 0
    }

    /// The operational state, as the kernel records it.
    pub fn state(&self) -> String {
        // The operstate values come from RFC 2863.
        match self
            .object
            .member("operstate")
            .and_then(|state| state.as_u64())
            .unwrap_or(0)
        {
            0 => "UNKNOWN",
            1 => "NOTPRESENT",
            2 => "DOWN",
            3 => "LOWERLAYERDOWN",
            4 => "TESTING",
            5 => "DORMANT",
            6 => "UP",
            _ => "UNKNOWN",
        }
        .to_string()
    }

    /// The interface flags, rendered as their names.
    /// The interface flags as userspace sees them, named and sorted.
    ///
    /// This follows the kernel's `dev_get_flags`: the flags describing link
    /// state are not kept in `flags` at all but derived from `state`, so they
    /// are cleared and then recomputed.
    pub fn flag_names(&self) -> Vec<String> {
        let Ok(table) = vma_table(&self.object) else {
            return Vec::new();
        };
        let space = &self.object.context().symbol_space;

        let enumeration = |name: &str| {
            space
                .get_type(&crate::framework::symbols::join_name(&table, name))
                .ok()
                .and_then(|template| template.as_enum().cloned())
        };
        let Some(device_flags) = enumeration("net_device_flags") else {
            return Vec::new();
        };
        let choice = |name: &str| device_flags.choices.get(name).copied().unwrap_or(0) as u64;

        let clear_flags = choice("IFF_PROMISC")
            | choice("IFF_ALLMULTI")
            | choice("IFF_RUNNING")
            | choice("IFF_LOWER_UP")
            | choice("IFF_DORMANT");
        // The reference implementation spells IFF_ALLMULTI with a stray bracket
        // in the second mask, so that mask only ever clears IFF_PROMISC.
        let clear_gflags = choice("IFF_PROMISC");

        let gflags = self
            .object
            .member("gflags")
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        let mut flags = (self.flags() & !clear_flags) | (gflags & !clear_gflags);

        let state = self
            .object
            .member("state")
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        let link_state = enumeration("netdev_state_t");
        let is_set = |name: &str| {
            link_state
                .as_ref()
                .and_then(|template| template.choices.get(name).copied())
                .is_some_and(|bit| state & (1 << bit) != 0)
        };

        if is_set("__LINK_STATE_START") {
            if matches!(self.state().as_str(), "UP" | "UNKNOWN") {
                flags |= choice("IFF_RUNNING");
            }
            if !is_set("__LINK_STATE_NOCARRIER") {
                flags |= choice("IFF_LOWER_UP");
            }
            if is_set("__LINK_STATE_DORMANT") {
                flags |= choice("IFF_DORMANT");
            }
        }

        let mut names: Vec<String> = device_flags
            .choices
            .iter()
            .filter(|(_, value)| **value != 0 && flags & (**value as u64) == **value as u64)
            .map(|(name, _)| name.clone())
            .collect();
        // Sorted so the output does not depend on the enumeration's order.
        names.sort_unstable();
        names
    }

    /// The IPv4 addresses configured on the interface, with prefix lengths.
    /// The IPv4 addresses configured on the interface.
    ///
    /// Each entry is `(address, prefix length, scope)`.
    pub fn ipv4_addresses(&self) -> Vec<(String, u64, String)> {
        let mut results = Vec::new();
        let Ok(table) = vma_table(&self.object) else {
            return results;
        };
        let context = self.object.context().clone();
        let Ok(in_device) = self
            .object
            .member("ip_ptr")
            .and_then(|pointer| pointer.pointer_value())
            .and_then(|address| {
                let template = context
                    .symbol_space
                    .get_type(&crate::framework::symbols::join_name(&table, "in_device"))?;
                Ok(context.object_from_template(template, self.object.layer_name(), address))
            })
        else {
            return results;
        };
        let Ok(ifaddr_template) = context
            .symbol_space
            .get_type(&crate::framework::symbols::join_name(&table, "in_ifaddr"))
        else {
            return results;
        };
        let scopes = context
            .symbol_space
            .get_type(&crate::framework::symbols::join_name(&table, "rt_scope_t"))
            .ok()
            .and_then(|template| template.as_enum().cloned());

        // The addresses form a singly-linked list on the device.
        let mut current = in_device
            .member("ifa_list")
            .and_then(|list| list.pointer_value())
            .unwrap_or(0);
        let mut seen = std::collections::HashSet::new();

        while current != 0 && seen.len() <= 128 {
            if !seen.insert(current) {
                break;
            }
            let address = context.object_from_template(
                ifaddr_template.clone(),
                self.object.layer_name(),
                current,
            );

            if let (Ok(raw), Ok(prefix)) = (
                address.member("ifa_address").and_then(|value| value.as_u64()),
                address
                    .member("ifa_prefixlen")
                    .and_then(|value| value.as_u64()),
            ) {
                let scope = address
                    .member("ifa_scope")
                    .and_then(|value| value.as_u64())
                    .ok()
                    .and_then(|value| {
                        scopes
                            .as_ref()?
                            .inverse
                            .get(&(value as i64))
                            .map(String::as_str)
                    })
                    .map(scope_name)
                    .unwrap_or("unknown")
                    .to_string();
                results.push((
                    crate::framework::renderers::conversion::convert_ipv4(raw as u32),
                    prefix,
                    scope,
                ));
            }

            current = address
                .member("ifa_next")
                .and_then(|next| next.pointer_value())
                .unwrap_or(0);
        }
        results
    }

    /// The IPv6 addresses configured on the interface.
    ///
    /// Each entry is `(address, prefix length, scope)`.
    pub fn ipv6_addresses(&self) -> Vec<(String, u64, String)> {
        let mut results = Vec::new();
        let Ok(table) = vma_table(&self.object) else {
            return results;
        };
        let context = self.object.context().clone();
        let ifaddr_type = crate::framework::symbols::join_name(&table, "inet6_ifaddr");

        let Ok(inet6_dev) = self
            .object
            .member("ip6_ptr")
            .and_then(|pointer| pointer.pointer_value())
            .and_then(|address| {
                let template = context
                    .symbol_space
                    .get_type(&crate::framework::symbols::join_name(&table, "inet6_dev"))?;
                Ok(context.object_from_template(template, self.object.layer_name(), address))
            })
        else {
            return results;
        };

        // Kernels from 3.0 chain the addresses through a list_head.
        let Ok(head) = inet6_dev.member("addr_list") else {
            return results;
        };
        let Ok(entries) = walk_list(&head, &ifaddr_type, "if_list", true) else {
            return results;
        };

        for entry in entries {
            let Ok(prefix) = entry.member("prefix_len").and_then(|value| value.as_u64()) else {
                continue;
            };
            let Some(address) = entry
                .member("addr")
                .and_then(|addr| addr.member("in6_u"))
                .and_then(|union| union.member("u6_addr8"))
                .and_then(|bytes| bytes.bytes())
                .ok()
            else {
                continue;
            };

            // The scope lives in a bitmask rather than an enumeration.
            let scope = match entry.member("scope").and_then(|value| value.as_u64()) {
                Ok(value) if value & IFA_HOST != 0 => "host",
                Ok(value) if value & IFA_LINK != 0 => "link",
                Ok(value) if value & IFA_SITE != 0 => "site",
                _ => "global",
            };

            results.push((
                crate::framework::renderers::conversion::convert_ipv6(&address),
                prefix,
                scope.to_string(),
            ));
        }
        results
    }
}

/// IPv6 address scope bits, from the kernel's `ipv6.h`.
const IFA_HOST: u64 = 0x0010;
const IFA_LINK: u64 = 0x0020;
const IFA_SITE: u64 = 0x0040;

/// Translate a kernel route scope into the name `ip` prints for it.
fn scope_name(scope: &str) -> &'static str {
    match scope {
        "RT_SCOPE_UNIVERSE" => "global",
        "RT_SCOPE_NOWHERE" => "nowhere",
        "RT_SCOPE_HOST" => "host",
        "RT_SCOPE_LINK" => "link",
        "RT_SCOPE_SITE" => "site",
        _ => "unknown",
    }
}

/// The network namespaces on the system.
pub fn list_net_namespaces(context: &Arc<Context>, kernel: &Module) -> Result<Vec<Object>> {
    let head = context.object_from_symbol(kernel, "net_namespace_list", Some("list_head"))?;
    walk_list(&head, &kernel.qualified("net"), "list", true)
}

/// The interfaces belonging to a network namespace.
pub fn list_net_devices(
    kernel: &Module,
    namespace: &Object,
) -> Result<Vec<NetDevice>> {
    let head = namespace.member("dev_base_head")?;
    Ok(
        walk_list(&head, &kernel.qualified("net_device"), "dev_list", true)?
            .into_iter()
            .map(|object| NetDevice { object })
            .collect(),
    )
}

/// The moment the system booted, as a `timespec64`.
///
/// The kernel keeps two offsets that convert monotonic time to real and to boot
/// time. Their difference is the boot instant. Returns `None` when the
/// timekeeper cannot be read, which leaves callers to report the time as
/// unavailable rather than as 1970.
pub fn boot_time_timespec(context: &Arc<Context>, kernel: &Module) -> Option<(i64, i64)> {
    // Kernels from 3.17 wrap the timekeeper in `tk_core`. The symbol carries
    // its own type, so no type name is supplied here.
    let timekeeper = context
        .object_from_symbol(kernel, "tk_core", None)
        .ok()
        .and_then(|core| core.member("timekeeper").ok())
        .or_else(|| context.object_from_symbol(kernel, "timekeeper", None).ok())?;

    let read_ktime = |name: &str| -> Option<i64> {
        let field = timekeeper.member(name).ok()?;
        // Older kernels wrap ktime_t in a union with a `tv64` member.
        field
            .member("tv64")
            .and_then(|inner| inner.as_i64())
            .or_else(|_| field.as_i64())
            .ok()
    };

    let offs_real = read_ktime("offs_real")?;
    let offs_boot = read_ktime("offs_boot").unwrap_or(0);
    let (seconds, nanoseconds) = ns_to_timespec64(offs_real - offs_boot);

    // A boot time outside the plausible range means the structure was misread.
    (1_000_000_000..=4_000_000_000)
        .contains(&seconds)
        .then_some((seconds, nanoseconds))
}

/// The whole-second part of the boot time, as task timestamps are built on.
///
/// A task's creation time is the boot instant with its sub-second part dropped,
/// plus the task's own offset since boot, so the fraction in a reported
/// timestamp belongs entirely to the task. The seconds are taken after the
/// timestamp has been rounded to microseconds, since a boot time within half a
/// microsecond of the next second carries into it.
pub fn boot_time_seconds(context: &Arc<Context>, kernel: &Module) -> Option<i64> {
    let (seconds, nanoseconds) = boot_time_timespec(context, kernel)?;
    timespec_to_datetime(seconds, nanoseconds).map(|when| when.timestamp())
}

/// Mask an address the way the reference implementation reports Linux offsets.
///
/// Linux symbol tables carry an address mask matching the architecture's
/// virtual address width, and offsets are reported through it, so the
/// sign-extension bits of a kernel address do not appear.
pub fn masked_address(address: u64, pointer_size: usize) -> u64 {
    if pointer_size == 8 {
        // x86-64 uses 48 significant virtual address bits.
        address & 0x0000_FFFF_FFFF_FFFF
    } else {
        address
    }
}

/// The letters standing for a set of taint flags.
///
/// The kernel's own table is used where it exists, since it knows which flags
/// this build has and what to print when one is absent.
pub fn taint_letters(
    context: &Arc<Context>,
    kernel: &Module,
    taints: u64,
    is_module: bool,
) -> String {
    if let Ok(flags) = context.object_from_symbol(kernel, "taint_flags", Some("taint_flag")) {
        if let Ok(size) = context.symbol_space.size_of(&flags.template()) {
            let mut letters = String::new();
            for bit in 0..64u32 {
                let Ok(flag) = context.object(
                    &kernel.qualified("taint_flag"),
                    &kernel.layer_name,
                    flags.offset() + bit as u64 * size,
                ) else {
                    break;
                };
                let (Ok(true_char), Ok(false_char), Ok(module)) = (
                    flag.member("c_true").and_then(|value| value.as_u64()),
                    flag.member("c_false").and_then(|value| value.as_u64()),
                    flag.member("module").and_then(|value| value.as_u64()),
                ) else {
                    break;
                };
                // The table ends where it stops describing anything.
                if true_char == 0 && false_char == 0 {
                    break;
                }
                if is_module && module == 0 {
                    continue;
                }
                let (Some(marked), Some(unmarked)) = (
                    char::from_u32(true_char as u32),
                    char::from_u32(false_char as u32),
                ) else {
                    continue;
                };
                if taints & (1 << bit) != 0 {
                    letters.push(marked);
                } else if unmarked != ' ' {
                    letters.push(unmarked);
                }
            }
            return letters;
        }
    }

    // Older kernels do not carry the table, so the flags this framework knows
    // about stand in.
    TAINT_FLAGS
        .iter()
        .filter(|(_, _, module, _)| !is_module || *module)
        .filter(|(shift, _, _, _)| taints & shift != 0)
        .map(|(_, letter, _, _)| *letter)
        .collect()
}

/// What each taint letter means: its bit, its letter, whether a module can
/// carry it, and whether it is reported when present.
const TAINT_FLAGS: &[(u64, char, bool, &str)] = &[
    (1, 'P', true, "PROPRIETARY_MODULE"),
    (2, 'F', false, "FORCED_MODULE"),
    (4, 'S', false, "CPU_OUT_OF_SPEC"),
    (8, 'R', false, "FORCED_RMMOD"),
    (16, 'M', false, "MACHINE_CHECK"),
    (32, 'B', false, "BAD_PAGE"),
    (64, 'U', false, "USER"),
    (128, 'D', false, "DIE"),
    (256, 'A', false, "OVERRIDDEN_ACPI_TABLE"),
    (512, 'W', false, "WARN"),
    (1024, 'C', true, "CRAP"),
    (2048, 'I', false, "FIRMWARE_WORKAROUND"),
    (4096, 'O', true, "OOT_MODULE"),
    (8192, 'E', true, "UNSIGNED_MODULE"),
    (16384, 'L', false, "SOFTLOCKUP"),
    (32768, 'K', true, "LIVEPATCH"),
    (65536, 'X', true, "AUX"),
    (131072, 'T', true, "RANDSTRUCT"),
    (262144, 'N', true, "TEST"),
];

/// What a taint letter stands for, where it stands for anything.
fn describe_taint(letter: char) -> Option<&'static str> {
    TAINT_FLAGS
        .iter()
        .find(|(_, candidate, _, _)| *candidate == letter)
        .map(|(_, _, _, description)| *description)
}
