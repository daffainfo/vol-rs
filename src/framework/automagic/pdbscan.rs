//! Finding the Windows kernel, and the symbol file that describes it.
//!
//! A Windows kernel carries a record naming the PDB file it was built with: the
//! bytes `RSDS`, a GUID, an age, and a file name. Finding that record identifies
//! the exact build, which is what selects a symbol file. The record also has to
//! be turned into the address the kernel is loaded at, and there are several
//! ways to arrive at that. They are tried cheapest first, as the reference
//! implementation does.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::Context;
use crate::framework::layers::intel::IntelLayer;
use crate::framework::layers::scanners::{scan_layer, BytesScanner, RegExScanner};
use crate::framework::layers::DataLayer;

/// The names a Windows kernel's PDB may go by.
const KERNEL_MODULE_NAMES: &[&str] = &["ntkrnlmp", "ntkrnlpa", "ntkrpamp", "ntoskrnl"];

/// How far past a candidate kernel base to look for its PDB record.
const MAX_PDB_SIZE: u64 = 0x40_0000;

/// Pages of unreadable memory to tolerate while walking back to the image header.
const MAXIMUM_INVALID_COUNT: u32 = 100;

const PAGE_SIZE: u64 = 0x1000;

/// The first instructions of the processor start block, which is what makes it
/// recognisable in low physical memory.
const JMP_AND_COMPLETION_SIGNATURE: u64 = 0x0001_0006_00E9;
const PROCESSOR_START_BLOCK_CR3_OFFSET: u64 = 0xA0;
const PROCESSOR_START_BLOCK_LM_TARGET_OFFSET: u64 = 0x70;

/// A kernel's identity, as its PDB record gives it.
#[derive(Debug, Clone)]
pub struct KernelCandidate {
    /// The PDB's GUID, upper-case hex, which names the exact build.
    pub guid: String,
    pub age: u32,
    /// The PDB file name, such as `ntkrnlmp.pdb`.
    pub pdb_name: String,
    /// Where the record was found.
    pub signature_offset: u64,
    /// Where the image containing it starts, if its header could be found.
    pub mz_offset: Option<u64>,
}

impl KernelCandidate {
    /// The name of the symbol file describing this kernel.
    pub fn symbol_file_name(&self) -> String {
        format!("{}-{}", self.guid, self.age)
    }

    /// The directory that file sits in, which is named after the PDB.
    pub fn symbol_directory(&self) -> String {
        format!("windows/{}", self.pdb_name.trim_end_matches('\0'))
    }
}

/// A kernel that was found, and where it is loaded.
#[derive(Debug, Clone)]
pub struct ValidKernel {
    pub virtual_offset: u64,
    pub candidate: KernelCandidate,
}

/// Scan `layer` between `start` and `end` for kernel PDB records.
///
/// Each record found is paired with the start of the image holding it, by
/// walking back a page at a time to the `MZ` header.
pub fn pdbname_scan(
    context: &Arc<Context>,
    layer_name: &str,
    start: u64,
    end: Option<u64>,
) -> Result<Vec<KernelCandidate>> {
    let layer = context.layers.get(layer_name)?;
    let end = end.unwrap_or_else(|| layer.maximum_address());
    if end <= start {
        return Ok(Vec::new());
    }

    // `RSDS`, then the GUID and age, then the name of the PDB itself.
    let names = KERNEL_MODULE_NAMES
        .iter()
        .map(|name| format!("{name}\\.pdb"))
        .collect::<Vec<_>>()
        .join("|");
    let scanner = RegExScanner::new(&format!("(?s-u)RSDS.{{20}}({names})\x00"))?;

    let sections = [(start, end - start)];
    let mut hits: Vec<u64> = Vec::new();
    scan_layer(
        layer.as_ref(),
        &context.layers,
        &scanner,
        Some(&sections),
        |offset| hits.push(offset),
    )?;

    // A search for the image header never goes below the previous record, as
    // the reference implementation does: two kernels cannot share a header.
    let mut lowest_page = 0u64;
    let mut candidates = Vec::new();
    for hit in hits {
        let Ok(data) = layer.read(&context.layers, hit, 64, true) else {
            continue;
        };
        let Some(candidate) = decode_record(&data, hit) else {
            continue;
        };

        let signature_page = hit / PAGE_SIZE;
        let mut mz_offset = None;
        let mut invalid = 0u32;
        let mut page = signature_page;
        while page > lowest_page {
            if invalid > MAXIMUM_INVALID_COUNT {
                break;
            }
            let address = page * PAGE_SIZE;
            if !layer.is_valid(&context.layers, address, 2) {
                invalid += 1;
                page -= 1;
                continue;
            }
            if layer
                .read(&context.layers, address, 2, false)
                .map(|header| header == b"MZ")
                .unwrap_or(false)
            {
                mz_offset = Some(address);
                break;
            }
            page -= 1;
        }
        lowest_page = signature_page;

        candidates.push(KernelCandidate {
            mz_offset,
            ..candidate
        });
    }
    Ok(candidates)
}

/// Read a PDB record out of the bytes at a hit.
///
/// The GUID is stored as a little-endian word, two little-endian halves and
/// eight plain bytes, so it is reassembled rather than printed as it lies.
fn decode_record(data: &[u8], offset: u64) -> Option<KernelCandidate> {
    if data.len() < 24 || &data[..4] != b"RSDS" {
        return None;
    }
    let raw = &data[4..20];
    let order = [3usize, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15];
    let guid: String = order
        .iter()
        .map(|index| format!("{:02X}", raw[*index]))
        .collect();
    let age = u32::from_le_bytes(data[20..24].try_into().ok()?);

    let name_bytes = &data[24..];
    let end = name_bytes.iter().position(|byte| *byte == 0)?;
    let pdb_name = std::str::from_utf8(&name_bytes[..end]).ok()?.to_string();

    Some(KernelCandidate {
        guid,
        age,
        pdb_name,
        signature_offset: offset,
        mz_offset: None,
    })
}

/// Find the debug record naming one of `names` inside a range of a layer.
///
/// A module names the database describing it in a record somewhere inside its
/// own image, which is how a module's symbols are found without the module's
/// own headers being readable.
pub fn scan_for_record(
    context: &Arc<Context>,
    layer_name: &str,
    start: u64,
    end: u64,
    names: &[String],
) -> Option<KernelCandidate> {
    if end <= start || names.is_empty() {
        return None;
    }
    let layer = context.layers.get(layer_name).ok()?;
    let pattern = names
        .iter()
        .map(|name| name.replace('.', "\\."))
        .collect::<Vec<_>>()
        .join("|");
    let scanner = RegExScanner::new(&format!("(?s-u)RSDS.{{20}}({pattern})\x00")).ok()?;

    let sections = [(start, end - start)];
    let mut hits: Vec<u64> = Vec::new();
    scan_layer(
        layer.as_ref(),
        &context.layers,
        &scanner,
        Some(&sections),
        |offset| hits.push(offset),
    )
    .ok()?;

    hits.into_iter().find_map(|hit| {
        let data = layer.read(&context.layers, hit, 128, true).ok()?;
        decode_record(&data, hit)
    })
}

/// Find the kernel and where it is loaded.
///
/// The methods are tried in the order the reference implementation uses, which
/// runs from the cheapest and most reliable to a full scan of the address
/// space.
pub fn find_kernel(
    context: &Arc<Context>,
    virtual_layer: &str,
    physical_layer: &str,
) -> Option<ValidKernel> {
    let methods: [(&str, fn(&Arc<Context>, &str, &str) -> Option<ValidKernel>); 5] = [
        ("the processor start block", method_low_stub),
        ("the debugger data block", method_kdbg_offset),
        ("the loaded module list", method_module_offset),
        ("a fixed mapping", method_fixed_mapping),
        ("a scan of the address space", method_slow_scan),
    ];

    for (description, method) in methods {
        if let Some(found) = method(context, virtual_layer, physical_layer) {
            log::debug!(
                "Kernel base {:#x} found through {description}",
                found.virtual_offset
            );
            return Some(found);
        }
    }
    log::debug!("No Windows kernel was found by any method");
    None
}

/// Whether a candidate address really holds a kernel, and which one.
pub fn kernel_at(
    context: &Arc<Context>,
    virtual_layer: &str,
    address: u64,
) -> Option<ValidKernel> {
    check_kernel_offset(context, virtual_layer, address)
}

/// Re-read a kernel that a previous run already located.
///
/// Both the image's header and the record naming its database are read where
/// they were found rather than searched for again, so confirming a kernel
/// costs two small reads instead of a scan of the whole image. A file that no
/// longer says the same thing at those places simply fails, and the search
/// runs as it did the first time.
pub fn kernel_at_known_record(
    context: &Arc<Context>,
    virtual_layer: &str,
    kernel_offset: u64,
    record_offset: u64,
) -> Option<ValidKernel> {
    let layer = context.layers.get(virtual_layer).ok()?;
    if layer.read(&context.layers, kernel_offset, 2, false).ok()? != b"MZ" {
        return None;
    }
    let data = layer.read(&context.layers, record_offset, 64, true).ok()?;
    let mut candidate = decode_record(&data, record_offset)?;
    candidate.mz_offset = Some(kernel_offset);
    Some(ValidKernel {
        virtual_offset: kernel_offset,
        candidate,
    })
}

/// Whether a candidate address really holds a kernel, and which one.
fn check_kernel_offset(
    context: &Arc<Context>,
    virtual_layer: &str,
    address: u64,
) -> Option<ValidKernel> {
    let layer = context.layers.get(virtual_layer).ok()?;
    if layer
        .read(&context.layers, address, 2, false)
        .ok()
        .as_deref()
        != Some(b"MZ".as_slice())
    {
        return None;
    }
    let found = pdbname_scan(
        context,
        virtual_layer,
        address,
        Some(address + MAX_PDB_SIZE),
    )
    .ok()?;
    found.into_iter().next().map(|candidate| ValidKernel {
        virtual_offset: address,
        candidate,
    })
}

/// The kernel address recorded in the processor start block.
///
/// A 64-bit kernel leaves its own load address in low physical memory, along
/// with the page table base that identifies which block belongs to this image.
fn method_low_stub(
    context: &Arc<Context>,
    virtual_layer: &str,
    physical_layer: &str,
) -> Option<ValidKernel> {
    let intel = context.layers.get(virtual_layer).ok()?;
    let intel = intel.as_any().downcast_ref::<IntelLayer>()?;
    if intel.config().bits_per_register != 64 {
        return None;
    }
    let expected = (intel.page_map_offset() & ((1u64 << 47) - 1)) | 1;

    let physical = context.layers.get(physical_layer).ok()?;
    let read = |offset: u64| -> Option<u64> {
        let data = physical.read(&context.layers, offset, 8, false).ok()?;
        Some(u64::from_le_bytes(data.try_into().ok()?))
    };

    let mut kernel_hint = 0u64;
    let mut kernel_base = 0u64;
    for offset in (0x1000..0x10_0000).step_by(PAGE_SIZE as usize) {
        let Some(instructions) = read(offset) else {
            continue;
        };
        if 0xFFFF_FFFF_FFFF_00FF & instructions != JMP_AND_COMPLETION_SIGNATURE {
            continue;
        }
        // The block states the page table base it was started with. Only the
        // one matching this image's is ours.
        let Some(cr3) = read(offset + PROCESSOR_START_BLOCK_CR3_OFFSET) else {
            continue;
        };
        if cr3.wrapping_add(1) != expected {
            continue;
        }
        let Some(target) = read(offset + PROCESSOR_START_BLOCK_LM_TARGET_OFFSET) else {
            continue;
        };
        if target & 0x3 != 0 {
            continue;
        }
        kernel_hint = target & 0xFFFF_FFFF_FFFF;
        kernel_base = kernel_hint & !0x1F_FFFF & 0xFFFF_FFFF_FFFF;
        break;
    }

    if kernel_base == 0 {
        return None;
    }
    // The hint lands inside the kernel rather than at its start, so the search
    // walks back through the surrounding region a page at a time.
    while kernel_base + 0x200_0000 > kernel_hint {
        for step in (0..0x20_0000).step_by(PAGE_SIZE as usize) {
            if let Some(found) = check_kernel_offset(context, virtual_layer, kernel_base + step) {
                return Some(found);
            }
        }
        kernel_base = kernel_base.checked_sub(0x20_0000)?;
    }
    None
}

/// A kernel address held near a known marker in physical memory.
fn method_offset(
    context: &Arc<Context>,
    virtual_layer: &str,
    physical_layer: &str,
    pattern: &[u8],
    result_offset: i64,
) -> Option<ValidKernel> {
    let layer = context.layers.get(physical_layer).ok()?;
    let scanner = BytesScanner::new(pattern.to_vec());
    let mut hits = Vec::new();
    scan_layer(layer.as_ref(), &context.layers, &scanner, None, |offset| {
        hits.push(offset)
    })
    .ok()?;

    let mask = context.layers.address_mask(virtual_layer);
    let mut seen = std::collections::HashSet::new();
    for hit in hits {
        let Some(at) = hit.checked_add_signed(result_offset) else {
            continue;
        };
        let Ok(data) = layer.read(&context.layers, at, 8, false) else {
            continue;
        };
        let Ok(bytes) = <[u8; 8]>::try_from(data.as_slice()) else {
            continue;
        };
        let address = u64::from_le_bytes(bytes) & mask;
        if !seen.insert(address) {
            continue;
        }
        if let Some(found) = check_kernel_offset(context, virtual_layer, address) {
            return Some(found);
        }
    }
    None
}

fn method_kdbg_offset(
    context: &Arc<Context>,
    virtual_layer: &str,
    physical_layer: &str,
) -> Option<ValidKernel> {
    method_offset(context, virtual_layer, physical_layer, b"KDBG", 8)
}

fn method_module_offset(
    context: &Arc<Context>,
    virtual_layer: &str,
    physical_layer: &str,
) -> Option<ValidKernel> {
    // The loaded module list names the kernel's own image, and the entry holds
    // its address a fixed distance before that name.
    method_offset(
        context,
        virtual_layer,
        physical_layer,
        br"\SystemRoot\system32\nt",
        -16 - 8,
    )
}

/// The mapping older kernels are loaded at, which is fixed relative to where
/// they sit in physical memory.
fn method_fixed_mapping(
    context: &Arc<Context>,
    virtual_layer: &str,
    physical_layer: &str,
) -> Option<ValidKernel> {
    let intel = context.layers.get(virtual_layer).ok()?;
    let intel = intel.as_any().downcast_ref::<IntelLayer>()?;

    for candidate in pdbname_scan(context, physical_layer, 0, None).ok()? {
        let Some(mz_offset) = candidate.mz_offset else {
            continue;
        };
        let bits = intel.config().bits_per_register;
        let virtual_offset = if bits == 64 {
            let span = 64 - (intel.maximum_address() + 1).leading_zeros();
            mz_offset + (31u64 << (span - 5))
        } else {
            mz_offset + (1u64 << (bits - 1))
        };

        // Only if that address really does lead back to the image found.
        match intel.translate_single(&context.layers, virtual_offset) {
            Ok((physical, layer)) if physical == mz_offset && layer == physical_layer => {
                return Some(ValidKernel {
                    virtual_offset,
                    candidate,
                });
            }
            _ => log::debug!(
                "A kernel at {mz_offset:#x} does not map to {virtual_offset:#x} as expected"
            ),
        }
    }
    None
}

/// The last resort: look through the address space itself.
fn method_slow_scan(
    context: &Arc<Context>,
    virtual_layer: &str,
    _physical_layer: &str,
) -> Option<ValidKernel> {
    let intel = context.layers.get(virtual_layer).ok()?;
    let architecture = intel
        .as_any()
        .downcast_ref::<IntelLayer>()
        .map(|layer| layer.config().architecture);

    // A 64-bit kernel is always mapped high, so the search starts there before
    // falling back to the whole space.
    let starts: &[u64] = if architecture == Some("Intel64") {
        &[0x1F0 << 39, 0]
    } else {
        &[0]
    };

    for start in starts {
        let Ok(candidates) = pdbname_scan(context, virtual_layer, *start, None) else {
            continue;
        };
        for candidate in candidates {
            if let Some(mz_offset) = candidate.mz_offset {
                return Some(ValidKernel {
                    virtual_offset: mz_offset,
                    candidate,
                });
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_gives_the_guid_the_symbol_file_is_named_for() {
        let mut data = b"RSDS".to_vec();
        // The GUID as it lies in memory: a little-endian word, two little-endian
        // halves, then eight bytes in order.
        data.extend_from_slice(&[
            0x0C, 0x4D, 0x28, 0x89, 0xAC, 0xA6, 0x27, 0xC8, 0x4B, 0x9A, 0x44, 0xBD, 0x5A, 0xF9,
            0x29, 0x0B,
        ]);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(b"ntkrnlmp.pdb\0");

        let record = decode_record(&data, 0x1000).unwrap();
        assert_eq!(record.guid, "89284D0CA6ACC8274B9A44BD5AF9290B");
        assert_eq!(record.age, 1);
        assert_eq!(record.pdb_name, "ntkrnlmp.pdb");
        assert_eq!(record.symbol_file_name(), "89284D0CA6ACC8274B9A44BD5AF9290B-1");
        assert_eq!(record.symbol_directory(), "windows/ntkrnlmp.pdb");
    }
}
