//! Recover the parts of files that are still cached in memory.
//!
//! Windows keeps three caches of a file: the pages mapped as data, the pages
//! mapped as an image, and the views the cache manager holds. Each is walked
//! separately, and what is still resident is written out.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::utility::unicode_string;
use crate::framework::objects::Object;
use crate::framework::plugins::windows::handles::{handles, object_type_of_header};
use crate::framework::plugins::windows::{kernel_module, physical_layer, vadinfo};
use crate::framework::plugins::{
    pid_filter, pid_matches, OperatingSystem, Plugin, Requirement, RequirementKind,
};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};
use crate::framework::symbols::windows::poolscanner::{header_cookie, object_type_map};
use crate::framework::symbols::windows::{list_processes, object_name};

pub struct DumpFiles;

/// The devices whose files are worth recovering. The object type is also used
/// for pipes and sockets, which are not files on a disk.
const FILE_DEVICE_DISK: u64 = 0x7;
const FILE_DEVICE_NETWORK_FILE_SYSTEM: u64 = 0x14;

/// A page is this large, and a view of the cache holds this many bytes.
const PAGE_SIZE: u64 = 0x1000;
const VIEW_SIZE: u64 = 0x40000;
/// The bottom bits of a view's offset count references rather than bytes.
const VIEW_OFFSET_MASK: u64 = 0xFFFF_FFFF_FFFF_0000;
/// A view index array holds this many entries.
const VIEW_ARRAY: u64 = 0x80;
/// A file smaller than this is described by a single level of index array.
const FIRST_LEVEL_SIZE: u64 = 1 << (18 + 7);

impl Plugin for DumpFiles {
    fn name(&self) -> &'static str {
        "windows.dumpfiles.DumpFiles"
    }

    fn description(&self) -> &'static str {
        "Dumps cached file contents from Windows memory samples."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::kernel(),
            Requirement::new(
                "pid",
                "Process ID to include (all other processes are excluded)",
                RequirementKind::Int,
            ),
            Requirement::new(
                "virtaddr",
                "Dump the _FILE_OBJECTs at the given virtual address(es)",
                RequirementKind::List(Box::new(RequirementKind::Int)),
            ),
            Requirement::new(
                "physaddr",
                "Dump a single _FILE_OBJECTs at the given physical address(es)",
                RequirementKind::List(Box::new(RequirementKind::Int)),
            ),
            Requirement::new(
                "filter",
                "Dump files matching regular expression FILTER",
                RequirementKind::String,
            ),
            Requirement::new(
                "ignore-case",
                "Ignore case in filter match",
                RequirementKind::Bool,
            )
            .with_default(crate::framework::context::ConfigValue::Bool(false)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Cache"),
            Column::new("FileObject", ColumnType::UInt),
            Column::string("FileName"),
            Column::string("Result"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let physical = physical_layer(config);
        let filter = pid_filter(config);
        // A name pattern and an explicit address ask different questions, and
        // asking both at once has no answer.
        let addresses = |name: &str| -> Vec<u64> {
            config
                .get(name)
                .and_then(|value| value.as_list().map(<[_]>::to_vec))
                .unwrap_or_default()
                .iter()
                .filter_map(|entry| entry.as_int().map(|value| value as u64))
                .collect()
        };
        let virtual_addresses = addresses("virtaddr");
        let physical_addresses = addresses("physaddr");
        let pattern = match config.get_string("filter") {
            Some(text) => {
                if !virtual_addresses.is_empty() || !physical_addresses.is_empty() {
                    return Err(crate::error::VolatilityError::Other(
                        "Cannot use filter flag with an address flag".to_string(),
                    ));
                }
                let text = if config.get_bool("ignore-case").unwrap_or(false) {
                    format!("(?i){text}")
                } else {
                    text
                };
                Some(regex::Regex::new(&text).map_err(|error| {
                    crate::error::VolatilityError::Other(format!(
                        "Could not compile the filter: {error}"
                    ))
                })?)
            }
            None => None,
        };
        let type_map = object_type_map(&context, &kernel);
        let cookie = header_cookie(&context, &kernel);

        let mut grid = TreeGrid::new(self.columns());
        // A file open in several processes is only recovered once.
        let mut dumped: Vec<u64> = Vec::new();

        // Naming addresses asks about those file objects alone, and the
        // processes are not walked at all.
        if !virtual_addresses.is_empty() || !physical_addresses.is_empty() {
            for (address, is_virtual) in virtual_addresses
                .iter()
                .map(|address| (*address, true))
                .chain(physical_addresses.iter().map(|address| (*address, false)))
            {
                let layer = if is_virtual {
                    kernel.layer_name.clone()
                } else {
                    physical.clone()
                };
                let Ok(file) = context.object(&kernel.qualified("_FILE_OBJECT"), &layer, address)
                else {
                    continue;
                };
                for row in dump_file(&context, &kernel, &physical, &file) {
                    grid.push(0, row)?;
                }
            }
            return Ok(grid);
        }

        for process in list_processes(&context, &kernel)? {
            let Ok(pid) = process.pid() else { continue };
            if !pid_matches(&filter, pid) {
                continue;
            }

            // The files a process holds open, and then the ones it has mapped:
            // a mapped image usually has no handle left open on it.
            let mut files: Vec<Object> = Vec::new();
            if let Ok(object_table) = process.object.member("ObjectTable") {
                for handle in handles(&context, &kernel, &object_table) {
                    if object_type_of_header(&handle.header, &type_map, cookie).as_deref()
                        != Some("File")
                    {
                        continue;
                    }
                    if let Some(file) = body_of(&context, &kernel, &handle.header) {
                        files.push(file);
                    }
                }
            }
            for vad in vadinfo::walk_vad_tree(&context, &kernel, &process).unwrap_or_default() {
                if let Some(control_area) = vadinfo::control_area(&vad) {
                    if let Some(file) = vadinfo::file_object(&control_area) {
                        // A mapping whose file has no name of its own names
                        // nothing worth recovering.
                        if file_is_named(&context, &file) {
                            files.push(file);
                        }
                    }
                }
            }

            for file in files {
                if let Some(pattern) = &pattern {
                    match file_name_with_device(&context, &kernel, &file) {
                        Some(name) if pattern.is_match(&name) => {}
                        _ => continue,
                    }
                }
                if dumped.contains(&file.offset()) {
                    continue;
                }
                dumped.push(file.offset());

                for row in dump_file(&context, &kernel, &physical, &file) {
                    grid.push(0, row)?;
                }
            }
        }
        Ok(grid)
    }
}

/// Recover each cache of one file.
fn dump_file(
    context: &Arc<Context>,
    kernel: &Module,
    physical: &str,
    file: &Object,
) -> Vec<Vec<Value>> {
    // The object type is shared with pipes and sockets, which have no cached
    // contents to recover.
    let device_type = file
        .member("DeviceObject")
        .and_then(|device| device.dereference())
        .and_then(|device| device.member("DeviceType"))
        .and_then(|kind| kind.as_u64());
    if !matches!(
        device_type,
        Ok(FILE_DEVICE_DISK) | Ok(FILE_DEVICE_NETWORK_FILE_SYSTEM)
    ) {
        return Vec::new();
    }

    let name = file_name_with_device(context, kernel, file).unwrap_or_default();
    let base = name
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or_default()
        .to_string();

    let Ok(pointers) = file
        .member("SectionObjectPointer")
        .and_then(|pointers| pointers.dereference())
    else {
        return Vec::new();
    };

    let mut rows = Vec::new();
    // The two section caches hold pages of physical memory. The cache
    // manager's views are pages of the kernel's own space.
    for (member, extension, cache) in [
        ("DataSectionObject", "dat", "DataSectionObject"),
        ("ImageSectionObject", "img", "ImageSectionObject"),
    ] {
        let Ok(control_area) = pointers
            .member(member)
            .and_then(|section| section.dereference_as(&kernel.qualified("_CONTROL_AREA")))
        else {
            continue;
        };
        if !control_area_is_valid(&control_area) {
            continue;
        }
        let written = control_area_pages(context, kernel, &control_area).and_then(|pages| {
            write_pages(
                context,
                physical,
                &pages,
                file,
                &control_area,
                cache,
                extension,
                &base,
            )
        });
        rows.push(row(file, &control_area, cache, extension, &base, written));
    }

    if let Ok(cache_map) = pointers
        .member("SharedCacheMap")
        .and_then(|map| map.dereference_as(&kernel.qualified("_SHARED_CACHE_MAP")))
    {
        if cache_map_is_valid(&cache_map) {
            let written = cache_map_views(context, kernel, &cache_map).and_then(|pages| {
                write_pages(
                    context,
                    &kernel.layer_name,
                    &pages,
                    file,
                    &cache_map,
                    "SharedCacheMap",
                    "vacb",
                    &base,
                )
            });
            rows.push(row(file, &cache_map, "SharedCacheMap", "vacb", &base, written));
        }
    }
    rows
}

/// One row of the listing.
fn row(
    file: &Object,
    memory_object: &Object,
    cache: &str,
    extension: &str,
    base: &str,
    result: Option<String>,
) -> Vec<Value> {
    vec![
        Value::string(cache),
        Value::hex(file.offset()),
        Value::string(base),
        match result {
            Some(name) => Value::string(name),
            // Nothing of the file is still in memory.
            None => Value::string("Error dumping file"),
        },
    ]
    .into_iter()
    .collect::<Vec<_>>()
    .tap(|row| {
        let _ = (memory_object, extension, row);
    })
}

/// A small helper so a row can be built and inspected in one expression.
trait Tap: Sized {
    fn tap(self, apply: impl FnOnce(&Self)) -> Self {
        apply(&self);
        self
    }
}

impl<T> Tap for T {}

/// Write out what is still resident, returning the name of the file written.
#[allow(clippy::too_many_arguments)]
fn write_pages(
    context: &Arc<Context>,
    layer: &str,
    pages: &[(u64, u64, u64)],
    file: &Object,
    memory_object: &Object,
    cache: &str,
    extension: &str,
    base: &str,
) -> Option<String> {
    let name = format!(
        "file.{:#x}.{:#x}.{cache}.{base}.{extension}",
        file.offset(),
        memory_object.offset()
    );

    let mut contents: Vec<u8> = Vec::new();
    let mut written = 0usize;
    for (memory_offset, file_offset, size) in pages {
        let Ok(data) = context
            .layers
            .read(layer, *memory_offset, *size as usize, true)
        else {
            // A page that cannot be read at all abandons the whole file.
            return None;
        };
        written += data.len();
        let end = (*file_offset as usize) + data.len();
        if contents.len() < end {
            contents.resize(end, 0);
        }
        contents[*file_offset as usize..end].copy_from_slice(&data);
    }
    if written == 0 {
        return None;
    }

    // The name reported is the one written, which is not the one asked for
    // when a file of that name was already there.
    crate::framework::plugins::write_extracted(&name, &contents).ok()
}

/// Whether a section's control area describes something recoverable.
fn control_area_is_valid(control_area: &Object) -> bool {
    let Ok(segment) = control_area
        .member("Segment")
        .and_then(|segment| segment.dereference())
    else {
        return false;
    };
    // The segment points back at the area that owns it.
    let Ok(owner) = segment
        .member("ControlArea")
        .and_then(|owner| owner.pointer_value())
    else {
        return false;
    };
    if owner != control_area.offset() {
        return false;
    }
    let Ok(total) = segment
        .member("TotalNumberOfPtes")
        .and_then(|total| total.as_u64())
    else {
        return false;
    };
    let Ok(size) = segment
        .member("SizeOfSegment")
        .and_then(|size| size.as_u64())
    else {
        return false;
    };
    size == total * PAGE_SIZE
}

/// The pages of a section that are still in memory.
///
/// Each subsection describes a run of the file, and each of its page table
/// entries says whether that page is resident and where. A field that cannot
/// be read abandons the file: half a file is not worth writing out.
fn control_area_pages(
    context: &Arc<Context>,
    kernel: &Module,
    control_area: &Object,
) -> Option<Vec<(u64, u64, u64)>> {
    let area_size = control_area.size().ok()?;
    let entry_size = context
        .symbol_space
        .get_type(&kernel.qualified("_MMPTE"))
        .and_then(|template| context.symbol_space.size_of(&template))
        .unwrap_or(8);

    // A section holding an image is described in disk sectors. One holding
    // data is described in pages.
    let image = control_area
        .member("u")
        .and_then(|union| union.member("Flags"))
        .and_then(|flags| flags.member("Image"))
        .and_then(|image| image.as_u64())
        .ok()?;
    let sector_size = if image == 1 { 0x200 } else { 0x1000 };

    let mut subsection = context
        .object(
            &kernel.qualified("_SUBSECTION"),
            control_area.layer_name(),
            control_area.offset() + area_size,
        )
        .ok()?;

    let mut pages = Vec::new();
    loop {
        // A subsection belonging to another area, or one that cannot be read
        // at all, ends the chain.
        let Ok(owner) = subsection
            .member("ControlArea")
            .and_then(|owner| owner.pointer_value())
        else {
            break;
        };
        if owner != control_area.offset() {
            break;
        }

        let start = subsection
            .member("StartingSector")
            .and_then(|sector| sector.as_u64())
            .ok()?
            * sector_size;
        let base = subsection
            .member("SubsectionBase")
            .and_then(|base| base.pointer_value())
            .ok()?;
        let count = subsection
            .member("PtesInSubsection")
            .and_then(|count| count.as_u64())
            .ok()?;

        for index in 0..count {
            let at = base + entry_size * index;
            let file_offset = start + index * PAGE_SIZE;
            // An entry that cannot be built is skipped. One that can be built
            // but not read abandons the file.
            let Ok(entry) =
                context.object(&kernel.qualified("_MMPTE"), control_area.layer_name(), at)
            else {
                continue;
            };
            let union = entry.member("u").ok()?;

            // A page is either mapped, or on its way out and still in memory.
            let valid = union
                .member("Hard")
                .and_then(|hard| hard.member("Valid"))
                .and_then(|valid| valid.as_u64())
                .ok()?;
            if valid == 1 {
                let frame = union
                    .member("Hard")
                    .and_then(|hard| hard.member("PageFrameNumber"))
                    .and_then(|frame| frame.as_u64())
                    .ok()?;
                pages.push((frame << 12, file_offset, PAGE_SIZE));
                continue;
            }

            let transition = union
                .member("Trans")
                .and_then(|transition| transition.member("Transition"))
                .and_then(|transition| transition.as_u64())
                .ok()?;
            if transition == 1 {
                let frame = union
                    .member("Trans")
                    .and_then(|transition| transition.member("PageFrameNumber"))
                    .and_then(|frame| frame.as_u64())
                    .ok()?;
                // A page on its way out keeps a flag in the top bits of its
                // frame number.
                pages.push(((frame & ((1u64 << 33) - 1)) << 12, file_offset, PAGE_SIZE));
            }
        }

        let next = subsection
            .member("NextSubsection")
            .and_then(|next| next.pointer_value())
            .ok()?;
        if next == 0 {
            break;
        }
        subsection = context
            .object(
                &kernel.qualified("_SUBSECTION"),
                control_area.layer_name(),
                next,
            )
            .ok()?;
    }
    Some(pages)
}

/// Whether the cache manager's record of a file is coherent.
fn cache_map_is_valid(map: &Object) -> bool {
    let quad = |name: &str| -> Option<i64> {
        map.member(name)
            .and_then(|value| value.member("QuadPart"))
            .and_then(|value| value.as_i64())
            .ok()
    };
    let (Some(file_size), Some(valid_length), Some(section_size)) = (
        quad("FileSize"),
        quad("ValidDataLength"),
        quad("SectionSize"),
    ) else {
        return false;
    };
    if file_size <= 0 || valid_length <= 0 {
        return false;
    }
    if section_size < 0
        || (file_size < valid_length && valid_length != 0x7FFF_FFFF_FFFF_FFFF)
    {
        return false;
    }
    true
}

/// The views of a file the cache manager is holding.
fn cache_map_views(
    context: &Arc<Context>,
    kernel: &Module,
    map: &Object,
) -> Option<Vec<(u64, u64, u64)>> {
    let section_size = map
        .member("SectionSize")
        .and_then(|size| size.member("QuadPart"))
        .and_then(|size| size.as_u64())
        .ok()?;
    let full_blocks = section_size / VIEW_SIZE;
    let left_over = section_size % VIEW_SIZE;

    let mut views = Vec::new();
    let save = |view: &Object, views: &mut Vec<(u64, u64, u64)>| {
        let (Ok(address), Ok(offset)) = (
            view.member("BaseAddress")
                .and_then(|address| address.pointer_value()),
            view.member("Overlay")
                .and_then(|overlay| overlay.member("FileOffset"))
                .and_then(|offset| offset.member("QuadPart"))
                .and_then(|offset| offset.as_u64()),
        ) else {
            return;
        };
        views.push((address, offset & VIEW_OFFSET_MASK, VIEW_SIZE));
    };

    // A small file is described by the four views the record itself holds.
    let mut index = 0;
    while index < full_blocks && full_blocks <= 4 {
        if let Ok(view) = map
            .member("InitialVacbs")
            .and_then(|views| views.index(index))
            .and_then(|view| view.dereference())
        {
            if belongs_to(&view, map) {
                save(&view, &mut views);
            }
        }
        index += 1;
    }
    if left_over > 0 && full_blocks < 4 {
        if let Ok(view) = map
            .member("InitialVacbs")
            .and_then(|views| views.index(index))
            .and_then(|view| view.dereference())
        {
            if belongs_to(&view, map) {
                save(&view, &mut views);
            }
        }
    }

    // A larger file needs an array of its own.
    let array = map
        .member("Vacbs")
        .and_then(|array| array.pointer_value())
        .ok()?;
    if array == 0 {
        return Some(views);
    }
    // The array often begins with the same view the record already holds.
    if let Ok(first) = map
        .member("InitialVacbs")
        .and_then(|views| views.index(0))
        .map(|view| view.offset())
    {
        if first == array {
            return Some(views);
        }
    }

    let view_type = kernel.qualified("_VACB");
    let read_view = |address: u64| -> Option<Object> {
        let pointer = context
            .layers
            .read(map.layer_name(), address, 8, false)
            .ok()?;
        let target = u64::from_le_bytes(pointer.try_into().ok()?)
            & context.layers.address_mask(map.layer_name());
        if target == 0 {
            return None;
        }
        context.object(&view_type, map.layer_name(), target).ok()
    };

    if section_size <= FIRST_LEVEL_SIZE {
        for counter in 0..full_blocks {
            if let Some(view) = read_view(array + counter * 8) {
                if belongs_to(&view, map) {
                    save(&view, &mut views);
                }
            }
        }
        if left_over > 0 {
            if let Some(view) = read_view(array + full_blocks * 8) {
                if belongs_to(&view, map) {
                    save(&view, &mut views);
                }
            }
        }
        return Some(views);
    }

    // A file larger than the first level can describe is held in a tree of
    // index arrays.
    let depth = (section_size as f64).log2().ceil();
    let depth = (((depth - 18.0) / 7.0).ceil()) as u64;
    walk_index(context, kernel, map, array, 0, depth, &save, &mut views);
    Some(views)
}

/// Whether a view belongs to the record being read.
fn belongs_to(view: &Object, map: &Object) -> bool {
    view.member("SharedCacheMap")
        .and_then(|owner| owner.pointer_value())
        .map(|owner| owner == map.offset())
        .unwrap_or(false)
}

/// Walk one level of the tree of view index arrays.
#[allow(clippy::too_many_arguments)]
fn walk_index(
    context: &Arc<Context>,
    kernel: &Module,
    map: &Object,
    array: u64,
    level: u64,
    limit: u64,
    save: &impl Fn(&Object, &mut Vec<(u64, u64, u64)>),
    views: &mut Vec<(u64, u64, u64)>,
) {
    if level > limit {
        return;
    }
    let view_type = kernel.qualified("_VACB");
    for index in 0..VIEW_ARRAY {
        let Ok(pointer) = context
            .layers
            .read(map.layer_name(), array + index * 8, 8, false)
        else {
            continue;
        };
        let target = u64::from_le_bytes(pointer.try_into().unwrap())
            & context.layers.address_mask(map.layer_name());
        if target == 0 {
            continue;
        }
        let Ok(view) = context.object(&view_type, map.layer_name(), target) else {
            continue;
        };
        if belongs_to(&view, map) {
            save(&view, views);
        } else {
            walk_index(context, kernel, map, target, level + 1, limit, save, views);
        }
    }
}

/// A file's name, prefixed by the device it lives on.
fn file_name_with_device(context: &Arc<Context>, kernel: &Module, file: &Object) -> Option<String> {
    let mut name = String::new();
    if let Ok(device) = file
        .member("DeviceObject")
        .and_then(|device| device.pointer_value())
    {
        if context.layers.is_valid(file.native_layer_name(), device, 1) {
            if let Ok(device) = file
                .member("DeviceObject")
                .and_then(|device| device.dereference())
            {
                if let Some(device_name) = object_name(&device, kernel) {
                    name = format!("\\Device\\{device_name}");
                }
            }
        }
    }
    if let Ok(path) = file.member("FileName").and_then(|path| unicode_string(&path)) {
        name.push_str(&path);
    }
    Some(name)
}

/// The object an object header precedes, as a file.
fn body_of(context: &Arc<Context>, kernel: &Module, header: &Object) -> Option<Object> {
    let header_type = context
        .symbol_space
        .get_type(&kernel.qualified("_OBJECT_HEADER"))
        .ok()?;
    let body = context
        .symbol_space
        .find_member(&header_type, "Body")
        .ok()??
        .0;
    let template = context
        .symbol_space
        .get_type(&kernel.qualified("_FILE_OBJECT"))
        .ok()?;
    Some(context.object_from_template(
        template,
        header.layer_name(),
        header.offset() + body,
    ))
}

/// Unused: kept so the map of caches reads in one place.
#[allow(dead_code)]
fn caches() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("dat", "DataSectionObject"),
        ("img", "ImageSectionObject"),
        ("vacb", "SharedCacheMap"),
    ])
}

/// Whether a file object still names a file.
fn file_is_named(context: &Arc<Context>, file: &Object) -> bool {
    let Ok(name) = file.member("FileName") else {
        return false;
    };
    let Ok(length) = name.member("Length").and_then(|length| length.as_u64()) else {
        return false;
    };
    if length == 0 {
        return false;
    }
    name.member("Buffer")
        .and_then(|buffer| buffer.pointer_value())
        .map(|buffer| context.layers.is_valid(file.native_layer_name(), buffer, 1))
        .unwrap_or(false)
}
