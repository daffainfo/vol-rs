//! Finding kernel objects by the pool allocations that hold them.
//!
//! Every kernel pool allocation is prefixed by a header carrying a
//! four-character tag naming what was allocated, so searching memory for a tag
//! finds objects that are no longer on any list (freed, or deliberately
//! unlinked), which is what the `*scan` plugins are for.
//!
//! A tag match alone is weak evidence: the same four bytes occur constantly in
//! ordinary data. Each tag therefore comes with a constraint on the
//! allocation's size, pool type and index, and the object carved out of it is
//! checked against the kernel's own table of object types.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Context, Module};
use crate::framework::layers::scanners::{scan_layer, MultiStringScanner};
use crate::framework::objects::Object;

/// Which pools an allocation may live in.
pub const PAGED: u8 = 1;
pub const NONPAGED: u8 = 2;
pub const FREE: u8 = 4;

/// What a pool tag has to be attached to for it to count.
#[derive(Debug, Clone)]
pub struct PoolConstraint {
    /// The four bytes to search for.
    pub tag: Vec<u8>,
    /// The type of the object the allocation holds.
    pub type_name: String,
    /// The table that type is described in, when it is not the kernel's own.
    pub table: Option<String>,
    /// The name the kernel's own type table gives it, when it is an executive
    /// object. A structure that is not one has none.
    pub object_type: Option<&'static str>,
    /// Which pools the allocation may be in.
    pub page_type: u8,
    /// Bounds on the allocation's size, in bytes.
    pub size: (Option<u64>, Option<u64>),
    /// Bounds on the pool index.
    pub index: (Option<u64>, Option<u64>),
    /// Whether to trust the tag rather than the kernel's type table.
    pub skip_type_test: bool,
    /// Structures allocated alongside the object, which count towards its size.
    pub additional_structures: Vec<&'static str>,
    /// What makes a carved object of this kind believable, when the kind is
    /// one this module does not know how to check for itself.
    pub validator: Option<fn(&Object) -> bool>,
}

impl PoolConstraint {
    /// A constraint for a tag whose object is not one of the built-in kinds.
    pub fn custom(tag: &[u8], type_name: &str, page_type: u8, minimum_size: u64) -> Self {
        Self::new(tag, type_name, page_type).sized(minimum_size)
    }

    pub fn new(tag: &[u8], type_name: &str, page_type: u8) -> Self {
        Self {
            tag: tag.to_vec(),
            type_name: type_name.to_string(),
            table: None,
            object_type: None,
            page_type,
            size: (None, None),
            index: (None, None),
            skip_type_test: false,
            additional_structures: Vec::new(),
            validator: None,
        }
    }

    pub fn of_type(mut self, object_type: &'static str) -> Self {
        self.object_type = Some(object_type);
        self
    }

    /// Look the type up in another table than the kernel's.
    pub fn in_table(mut self, table: &str) -> Self {
        self.table = Some(table.to_string());
        self
    }

    /// Bound the allocation's size at both ends.
    pub fn with_size(mut self, minimum: u64, maximum: Option<u64>) -> Self {
        self.size = (Some(minimum), maximum);
        self
    }

    /// Say what makes an object of this kind believable.
    pub fn validated_by(mut self, validator: fn(&Object) -> bool) -> Self {
        self.validator = Some(validator);
        self
    }

    /// Bound which pool the allocation came from.
    pub fn with_index(mut self, minimum: u64, maximum: u64) -> Self {
        self.index = (Some(minimum), Some(maximum));
        self
    }

    /// The type's fully qualified name.
    pub fn qualified_type(&self, kernel: &Module) -> String {
        match &self.table {
            Some(table) => crate::framework::symbols::join_name(table, &self.type_name),
            None => kernel.qualified(&self.type_name),
        }
    }

    fn sized(mut self, minimum: u64) -> Self {
        self.size = (Some(minimum), None);
        self
    }

    pub fn trusting_the_tag(mut self) -> Self {
        self.skip_type_test = true;
        self
    }

    fn with(mut self, structure: &'static str) -> Self {
        self.additional_structures.push(structure);
        self
    }
}

/// The constraints the reference implementation ships with.
///
/// A tag whose last byte has its high bit set is the same allocation in a
/// protected pool, which is why several objects appear twice.
pub fn builtin_constraints(tags: &[&[u8]]) -> Vec<PoolConstraint> {
    let all = vec![
        PoolConstraint::new(b"AtmT", "_RTL_ATOM_TABLE", PAGED | NONPAGED | FREE).sized(200),
        PoolConstraint::new(b"Pro\xe3", "_EPROCESS", NONPAGED | FREE)
            .of_type("Process")
            .sized(600)
            .trusting_the_tag(),
        PoolConstraint::new(b"Proc", "_EPROCESS", NONPAGED | FREE)
            .of_type("Process")
            .sized(600)
            .trusting_the_tag(),
        PoolConstraint::new(b"Thr\xe5", "_ETHREAD", NONPAGED | FREE)
            .of_type("Thread")
            .sized(600)
            .trusting_the_tag(),
        PoolConstraint::new(b"Thre", "_ETHREAD", NONPAGED | FREE)
            .of_type("Thread")
            .sized(600),
        PoolConstraint::new(b"Fil\xe5", "_FILE_OBJECT", NONPAGED | FREE)
            .of_type("File")
            .sized(150),
        PoolConstraint::new(b"File", "_FILE_OBJECT", NONPAGED | FREE)
            .of_type("File")
            .sized(150),
        PoolConstraint::new(b"Mut\xe1", "_KMUTANT", NONPAGED | FREE)
            .of_type("Mutant")
            .sized(64),
        PoolConstraint::new(b"Muta", "_KMUTANT", NONPAGED | FREE)
            .of_type("Mutant")
            .sized(64),
        PoolConstraint::new(b"Dri\xf6", "_DRIVER_OBJECT", NONPAGED | FREE)
            .of_type("Driver")
            .sized(248)
            .with("_DRIVER_EXTENSION"),
        PoolConstraint::new(b"Driv", "_DRIVER_OBJECT", NONPAGED | FREE)
            .of_type("Driver")
            .sized(248),
        PoolConstraint::new(b"MmLd", "_LDR_DATA_TABLE_ENTRY", NONPAGED | FREE).sized(76),
        PoolConstraint::new(b"Sym\xe2", "_OBJECT_SYMBOLIC_LINK", PAGED | FREE)
            .of_type("SymbolicLink")
            .sized(72),
        PoolConstraint::new(b"Symb", "_OBJECT_SYMBOLIC_LINK", PAGED | FREE)
            .of_type("SymbolicLink")
            .sized(72),
        PoolConstraint::new(b"CM10", "_CMHIVE", PAGED | FREE)
            .sized(800)
            .trusting_the_tag(),
    ];

    if tags.is_empty() {
        return all;
    }
    all.into_iter()
        .filter(|constraint| tags.contains(&constraint.tag.as_slice()))
        .collect()
}

/// An object found in a pool allocation.
pub struct PoolHit {
    /// Which constraint matched.
    pub constraint: PoolConstraint,
    /// The object itself.
    pub object: Object,
    /// The allocation header it was carved out of.
    pub header: Object,
}

/// The objects a single pool tag names.
///
/// Most scanning plugins want exactly this: one tag, and the objects the
/// kernel's own constraints say may be found under it.
pub fn scan_for_tag(
    context: &Arc<Context>,
    kernel: &Module,
    tag: &[u8],
) -> Result<Vec<Object>> {
    scan_for_tags(context, kernel, &[tag])
}

/// Scan for the objects allocated under any of several tags.
///
/// A structure whose tag changed between releases is looked for under every
/// spelling it has had.
pub fn scan_for_tags(
    context: &Arc<Context>,
    kernel: &Module,
    tags: &[&[u8]],
) -> Result<Vec<Object>> {
    let constraints = builtin_constraints(tags);
    Ok(generate_pool_scan(context, kernel, &constraints)?
        .into_iter()
        .map(|hit| hit.object)
        .collect())
}

/// Scan for every object matching any of `constraints`.
pub fn generate_pool_scan(
    context: &Arc<Context>,
    kernel: &Module,
    constraints: &[PoolConstraint],
) -> Result<Vec<PoolHit>> {
    let type_map = object_type_map(context, kernel);
    let cookie = header_cookie(context, kernel);
    let top_down = is_windows_8_or_later(context, kernel);

    // Windows 10 keeps its pools in the kernel's own address space. Earlier
    // versions are searched in physical memory, where the pools are contiguous.
    let scan_layer = if is_windows_10(context, kernel) {
        kernel.layer_name.clone()
    } else {
        physical_beneath(context, &kernel.layer_name)
    };
    let alignment = if pointer_size(context, kernel) == 8 { 16 } else { 8 };

    let mut results = Vec::new();
    for (constraint, header) in pool_scan(context, kernel, &scan_layer, constraints, alignment)? {
        for object in carve(context, kernel, &header, &constraint, top_down, alignment) {
            if constraint.object_type.is_some() && !constraint.skip_type_test {
                match object_type_of(context, kernel, &object, &type_map, cookie) {
                    Some(found) if Some(found.as_str()) == constraint.object_type => {}
                    _ => continue,
                }
            }
            results.push(PoolHit {
                constraint: constraint.clone(),
                object,
                header: header.clone(),
            });
        }
    }
    Ok(results)
}

/// Find pool headers carrying any of the constraints' tags.
fn pool_scan(
    context: &Arc<Context>,
    kernel: &Module,
    layer_name: &str,
    constraints: &[PoolConstraint],
    alignment: u64,
) -> Result<Vec<(PoolConstraint, Object)>> {
    let header_type = context
        .symbol_space
        .get_type(&kernel.qualified("_POOL_HEADER"))?;
    let tag_offset = context
        .symbol_space
        .find_member(&header_type, "PoolTag")?
        .map(|(offset, _)| offset)
        .unwrap_or(4);

    let mut by_tag: HashMap<Vec<u8>, &PoolConstraint> = HashMap::new();
    for constraint in constraints {
        by_tag.insert(constraint.tag.clone(), constraint);
    }

    let layer = context.layers.get(layer_name)?;
    let scanner = MultiStringScanner::new(by_tag.keys().cloned().collect())?;
    let mut hits: Vec<u64> = Vec::new();
    scan_layer(layer.as_ref(), &context.layers, &scanner, None, |offset| {
        hits.push(offset)
    })?;

    let mut found = Vec::new();
    for hit in hits {
        let Ok(tag) = context.layers.read(layer_name, hit, 4, false) else {
            continue;
        };
        let Some(constraint) = by_tag.get(&tag) else {
            continue;
        };
        let Some(address) = hit.checked_sub(tag_offset) else {
            continue;
        };
        let header = context.object_from_template(header_type.clone(), layer_name, address);

        if !matches_constraint(&header, constraint, alignment) {
            continue;
        }
        found.push(((*constraint).clone(), header));
    }
    Ok(found)
}

/// Whether an allocation is the shape the constraint calls for.
fn matches_constraint(header: &Object, constraint: &PoolConstraint, alignment: u64) -> bool {
    let Ok(block_size) = header.member("BlockSize").and_then(|value| value.as_u64()) else {
        return false;
    };
    let size = alignment * block_size;
    // A bound of zero is no bound: upstream tests each one for truth before
    // comparing, so a zero never rejects anything.
    if let Some(minimum) = constraint.size.0.filter(|bound| *bound != 0) {
        if size < minimum {
            return false;
        }
    }
    if let Some(maximum) = constraint.size.1.filter(|bound| *bound != 0) {
        if size > maximum {
            return false;
        }
    }

    let Ok(pool_type) = header.member("PoolType").and_then(|value| value.as_u64()) else {
        return false;
    };
    // Vista and later swapped the sense of the low bit. Every kernel this runs
    // against is later than that.
    let free = pool_type == 0;
    let nonpaged = pool_type % 2 == 0 && pool_type > 0;
    let paged = pool_type % 2 == 1;
    let allowed = (constraint.page_type & FREE != 0 && free)
        || (constraint.page_type & NONPAGED != 0 && nonpaged)
        || (constraint.page_type & PAGED != 0 && paged);
    if !allowed {
        return false;
    }

    let lower = constraint.index.0.filter(|bound| *bound != 0);
    let upper = constraint.index.1.filter(|bound| *bound != 0);
    if lower.is_some() || upper.is_some() {
        let Ok(index) = header.member("PoolIndex").and_then(|value| value.as_u64()) else {
            return false;
        };
        if let Some(minimum) = lower {
            if index < minimum {
                return false;
            }
        }
        if let Some(maximum) = upper {
            if index > maximum {
                return false;
            }
        }
    }
    true
}

/// Carve the object out of an allocation.
///
/// Windows 8 and later put the object header at the end of the allocation,
/// behind a variable run of optional headers, so the body is found by trying
/// each aligned position and asking whether what lands there is coherent.
fn carve(
    context: &Arc<Context>,
    kernel: &Module,
    header: &Object,
    constraint: &PoolConstraint,
    top_down: bool,
    alignment: u64,
) -> Vec<Object> {
    let Ok(body_type) = context
        .symbol_space
        .get_type(&constraint.qualified_type(kernel))
    else {
        return Vec::new();
    };
    let layer = header.layer_name().to_string();
    let Ok(header_size) = context.symbol_space.size_of(header.template()) else {
        return Vec::new();
    };
    let start = header.offset() + header_size;

    // A structure that is not an executive object simply follows the header.
    if constraint.object_type.is_none() {
        return vec![context.object_from_template(body_type, &layer, start)];
    }

    let Ok(object_header_type) = context
        .symbol_space
        .get_type(&kernel.qualified("_OBJECT_HEADER"))
    else {
        return Vec::new();
    };
    let member = |name: &str| -> Option<(u64, u64)> {
        let (offset, template) = context
            .symbol_space
            .find_member(&object_header_type, name)
            .ok()??;
        let size = context.symbol_space.size_of(&template).ok()?;
        Some((offset, size))
    };
    let Some((body_offset, _)) = member("Body") else {
        return Vec::new();
    };

    if !top_down {
        // Earlier kernels place the object at the end of the allocation, so its
        // size is what says where it starts.
        let Ok(block_size) = header.member("BlockSize").and_then(|value| value.as_u64()) else {
            return Vec::new();
        };
        let mut size = context.symbol_space.size_of(&body_type).unwrap_or(0);
        for extra in &constraint.additional_structures {
            if let Ok(template) = context.symbol_space.get_type(&kernel.qualified(extra)) {
                size += context.symbol_space.size_of(&template).unwrap_or(0);
            }
        }
        let rounded = size.div_ceil(alignment) * alignment;
        let Some(address) = (header.offset() + block_size * alignment).checked_sub(rounded) else {
            return Vec::new();
        };
        return vec![context.object_from_template(body_type, &layer, address)];
    }

    let (Some((infomask_offset, _)), Some((pointercount_offset, pointercount_size))) =
        (member("InfoMask"), member("PointerCount"))
    else {
        return Vec::new();
    };
    let (optional_headers, lengths) = optional_header_lengths(context, kernel);
    let padding_index = optional_headers.iter().position(|name| *name == "PADDING_INFO");
    let longest: u64 = lengths.iter().sum();

    let Ok(block_size) = header.member("BlockSize").and_then(|value| value.as_u64()) else {
        return Vec::new();
    };
    let limit = longest.min(block_size * alignment);
    // One read rather than many: the bytes examined are the same either way.
    let Ok(data) = context
        .layers
        .read(&layer, start, (limit + infomask_offset) as usize, true)
    else {
        return Vec::new();
    };

    let mut found = Vec::new();
    let mut address = 0u64;
    while address < limit {
        let at = |offset: u64| -> Option<usize> { usize::try_from(address + offset).ok() };
        let (Some(mask_at), Some(count_at)) = (at(infomask_offset), at(pointercount_offset)) else {
            break;
        };
        if count_at + pointercount_size as usize > data.len() || mask_at >= data.len() {
            break;
        }

        let infomask = data[mask_at];
        let mut raw = [0u8; 8];
        let take = (pointercount_size as usize).min(8);
        raw[..take].copy_from_slice(&data[count_at..count_at + take]);
        let pointer_count = i64::from_le_bytes(raw);
        if !(0..0x100_0000).contains(&pointer_count) {
            address += alignment;
            continue;
        }

        // The mask says which optional headers are present, and so how far
        // back from here the object header actually starts.
        let mut headers_length = 0u64;
        let mut padding_present = false;
        for (index, length) in lengths.iter().enumerate() {
            if infomask & (1 << index) != 0 {
                headers_length += length;
                if Some(index) == padding_index {
                    padding_present = true;
                }
            }
        }

        let mut padding_length = 0u64;
        if padding_present {
            let Some(padding_at) = address.checked_sub(headers_length) else {
                address += alignment;
                continue;
            };
            let Ok(padding_at) = usize::try_from(padding_at) else {
                break;
            };
            if padding_at + 4 > data.len() {
                address += alignment;
                continue;
            }
            padding_length = u32::from_le_bytes(
                data[padding_at..padding_at + 4].try_into().unwrap_or([0; 4]),
            ) as u64;
            padding_length = padding_length
                .saturating_sub(lengths.get(padding_index.unwrap_or(0)).copied().unwrap_or(0));
        }

        // Some kernels record a padding length that runs past the allocation.
        if address.saturating_sub(headers_length) >= padding_length && padding_length > address {
            address += alignment;
            continue;
        }

        let object = context.object_from_template(
            body_type.clone(),
            &layer,
            address + body_offset + start,
        );
        let valid = match constraint.validator {
            Some(validator) => validator(&object),
            None => is_valid_object(context, kernel, &object, &constraint.type_name),
        };
        if valid {
            found.push(object);
        }
        address += alignment;
    }
    found
}

/// The optional object headers this kernel defines, and their sizes.
fn optional_header_lengths(context: &Arc<Context>, kernel: &Module) -> (Vec<&'static str>, Vec<u64>) {
    let mut names = Vec::new();
    let mut sizes = Vec::new();
    for header in [
        "CREATOR_INFO",
        "NAME_INFO",
        "HANDLE_INFO",
        "QUOTA_INFO",
        "PROCESS_INFO",
        "AUDIT_INFO",
        "EXTENDED_INFO",
        "HANDLE_REVOCATION_INFO",
        "PADDING_INFO",
    ] {
        let name = kernel.qualified(&format!("_OBJECT_HEADER_{header}"));
        // Which of these exist varies by build, and the ones that do are in
        // this order, which is what the mask's bits refer to.
        if let Ok(template) = context.symbol_space.get_type(&name) {
            if let Ok(size) = context.symbol_space.size_of(&template) {
                names.push(header);
                sizes.push(size);
            }
        }
    }
    (names, sizes)
}

/// The kernel's own table of object type names, indexed as object headers
/// index it.
pub fn object_type_map(context: &Arc<Context>, kernel: &Module) -> HashMap<u64, String> {
    let mut map = HashMap::new();
    let address = context
        .symbol_offset(kernel, "ObTypeIndexTable")
        .or_else(|_| context.symbol_offset(kernel, "ObpObjectTypes"));
    let Ok(address) = address else {
        return map;
    };
    let Ok(type_template) = context.symbol_space.get_type(&kernel.qualified("_OBJECT_TYPE")) else {
        return map;
    };

    for index in 0..100u64 {
        let Ok(data) = context
            .layers
            .read(&kernel.layer_name, address + index * 8, 8, false)
        else {
            break;
        };
        let pointer = u64::from_le_bytes(data.try_into().unwrap_or([0; 8]))
            & context.layers.address_mask(&kernel.layer_name);
        // The first entry is always null. The next one that is ends the table.
        if pointer == 0 {
            if index > 0 {
                break;
            }
            continue;
        }
        let object_type =
            context.object_from_template(type_template.clone(), &kernel.layer_name, pointer);
        if let Ok(name) = object_type
            .member("Name")
            .and_then(|name| crate::framework::symbols::windows::unicode_string(&name))
        {
            map.insert(index, name);
        }
    }
    map
}

/// The value Windows 10 mixes into an object header's type index.
pub fn header_cookie(context: &Arc<Context>, kernel: &Module) -> Option<u64> {
    let address = context.symbol_offset(kernel, "ObHeaderCookie").ok()?;
    let data = context
        .layers
        .read(&kernel.layer_name, address, 1, false)
        .ok()?;
    Some(data[0] as u64)
}

/// What the kernel says an object is.
pub fn object_type_of(
    context: &Arc<Context>,
    kernel: &Module,
    object: &Object,
    type_map: &HashMap<u64, String>,
    cookie: Option<u64>,
) -> Option<String> {
    let object_header_type = context
        .symbol_space
        .get_type(&kernel.qualified("_OBJECT_HEADER"))
        .ok()?;
    let (body_offset, _) = context
        .symbol_space
        .find_member(&object_header_type, "Body")
        .ok()??;
    let address = object.offset().checked_sub(body_offset)?;
    let header = context.object_from_template(object_header_type, object.layer_name(), address);

    let type_index = header.member("TypeIndex").ok()?.as_u64().ok()?;
    // Windows 10 obfuscates the index with the header's own address and a
    // per-boot cookie.
    let index = match cookie {
        Some(cookie) => ((address >> 8) ^ cookie ^ type_index) & 0xFF,
        None => type_index,
    };
    type_map.get(&index).cloned()
}

/// Whether a carved object is coherent enough to report.
fn is_valid_object(
    context: &Arc<Context>,
    kernel: &Module,
    object: &Object,
    type_name: &str,
) -> bool {
    match type_name {
        "_EPROCESS" => super::process_is_valid(context, kernel, object),
        "_ETHREAD" => super::thread_is_valid(object),
        "_FILE_OBJECT" => super::file_is_valid(context, object),
        // The remaining types accept anything that reads, as upstream does.
        _ => true,
    }
}

/// The width of a pointer in the kernel's symbol table.
fn pointer_size(context: &Arc<Context>, kernel: &Module) -> usize {
    context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .map(|table| table.pointer_size())
        .unwrap_or(8)
}

/// Whether this kernel is Windows 10 or later.
pub fn is_windows_10(context: &Arc<Context>, kernel: &Module) -> bool {
    context
        .symbol_space
        .has_symbol(&kernel.qualified("ObHeaderCookie"))
}

/// Whether this kernel is Windows 8 or later.
pub fn is_windows_8_or_later(context: &Arc<Context>, kernel: &Module) -> bool {
    // The handle table lost its count member in Windows 8.
    match context
        .symbol_space
        .get_type(&kernel.qualified("_HANDLE_TABLE"))
    {
        Ok(template) => !context
            .symbol_space
            .find_member(&template, "HandleCount")
            .map(|found| found.is_some())
            .unwrap_or(false),
        Err(_) => true,
    }
}

/// Whether this kernel is Windows 8.1 or later.
pub fn is_windows_8_1_or_later(context: &Arc<Context>, kernel: &Module) -> bool {
    // The processor control block gained a pending-tick field in Windows 8.1.
    match context.symbol_space.get_type(&kernel.qualified("_KPRCB")) {
        Ok(template) => context
            .symbol_space
            .find_member(&template, "PendingTickFlags")
            .map(|found| found.is_some())
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// The layer holding physical memory beneath a virtual one.
pub fn physical_beneath(context: &Arc<Context>, layer_name: &str) -> String {
    use crate::framework::layers::intel::IntelLayer;
    context
        .layers
        .get(layer_name)
        .ok()
        .and_then(|layer| {
            layer
                .as_any()
                .downcast_ref::<IntelLayer>()
                .map(|intel| intel.base_layer_name().to_string())
        })
        .unwrap_or_else(|| layer_name.to_string())
}
