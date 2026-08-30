//! Find virtual machines running under the captured host.
//!
//! Intel's hardware virtualisation keeps a control structure per guest, one
//! page long, holding the guest's page-table root and the nested paging root.
//! Finding those makes the guest's own memory addressable, which is how a
//! hypervisor's guests are recovered from a host capture.
//!
//! The structure's layout is not architectural: each processor generation
//! arranges the fields differently, and each arrangement ships as its own
//! description naming the revision it belongs to. A page opens with that
//! revision, so the description to read it with is chosen by the page itself.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement, RequirementKind};
use crate::framework::renderers::{Column, ColumnType, TreeGrid, Value};

pub struct Vmscan;

/// The control structure occupies one page.
const PAGE_SIZE: usize = 0x1000;

/// The bit in the host's fourth control register that says virtualisation is
/// on. A host running a guest has it set.
const CR4_VMXE: u64 = 1 << 13;

/// Bits the fourth control register reserves. A guest with any of them set is
/// not a guest.
const CR4_RESERVED: u64 = 0xFFFF_FFFF_FF88_9000;

impl Plugin for Vmscan {
    fn name(&self) -> &'static str {
        "vmscan.Vmscan"
    }

    fn description(&self) -> &'static str {
        "Scans for Intel VT-d structures and generates VM volatility configs for them"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![
            Requirement::new(
                "primary",
                "Physical base memory layer",
                RequirementKind::TranslationLayer,
            ),
            Requirement::new(
                "log-threshold",
                "Number of criteria failed to log to debug output",
                RequirementKind::Int,
            )
            .with_default(crate::framework::context::ConfigValue::Int(2)),
        ]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Any
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Architecture"),
            Column::new("VMCS Physical offset", ColumnType::UInt),
            Column::new("EPT", ColumnType::UInt),
            Column::new("Guest CR3", ColumnType::UInt),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        // The structures live in physical memory, so the search runs on the
        // layer the image itself provides rather than on any address space
        // built over it.
        let layer_name = config
            .get_string("physical_layer")
            .or_else(|| config.get_string("primary"))
            .unwrap_or_else(|| "base".to_string());
        let layer = context.layers.get(&layer_name)?;

        let layouts = layouts(&context);
        let mut grid = TreeGrid::new(self.columns());
        if layouts.is_empty() {
            log::warn!("No VMCS layout descriptions are installed; nothing to look for");
            return Ok(grid);
        }

        // Only the first bytes of each page are looked at, since the revision
        // is the first thing a control structure holds.
        let mut address = layer.minimum_address() & !(PAGE_SIZE as u64 - 1);
        let end = layer.maximum_address();
        const BATCH: usize = 0x100 * PAGE_SIZE;

        while address < end {
            let want = BATCH.min((end - address + 1) as usize);
            let Ok(data) = layer.read(&context.layers, address, want, true) else {
                address += BATCH as u64;
                continue;
            };

            for (index, page) in data.chunks(PAGE_SIZE).enumerate() {
                if page.len() < PAGE_SIZE {
                    break;
                }
                let revision = u32::from_le_bytes(page[0..4].try_into().unwrap());
                let Some(layout) = layouts.iter().find(|layout| layout.revision == revision)
                else {
                    continue;
                };
                let Some(failed) = verify(page, layout) else {
                    continue;
                };
                if !failed.is_empty() {
                    log::debug!(
                        "Potential {} VMCS found at {:x} with failed criteria: {failed:?}",
                        layout.name,
                        address + (index * PAGE_SIZE) as u64
                    );
                    continue;
                }

                grid.push(
                    0,
                    vec![
                        Value::string(layout.name.clone()),
                        Value::hex(address + (index * PAGE_SIZE) as u64),
                        Value::hex(layout.read(page, layout.ept)),
                        Value::hex(layout.read(page, layout.guest_cr3)),
                    ],
                )?;
            }
            address += BATCH as u64;
        }
        Ok(grid)
    }
}

/// One processor generation's arrangement of the control structure.
struct Layout {
    /// The description's own name, which is what a match is reported as.
    name: String,
    /// The revision a page of this shape opens with.
    revision: u32,
    vmcs_link_ptr: usize,
    host_cr3: usize,
    host_cr4: usize,
    guest_cr3: usize,
    guest_cr4: usize,
    ept: usize,
}

impl Layout {
    /// One of the structure's words.
    fn read(&self, page: &[u8], at: usize) -> u64 {
        let _ = self;
        page.get(at..at + 8)
            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
            .unwrap_or(0)
    }
}

/// The arrangements that are installed, in the order the descriptions are
/// found.
fn layouts(context: &Arc<Context>) -> Vec<Layout> {
    let finder = context.symbol_finder();
    let mut found = Vec::new();

    for (name, location) in finder.list("generic/vmcs") {
        let Ok(isf) = location.load() else { continue };
        let table = crate::framework::symbols::intermed::create_table(name.clone(), isf);

        // The revision is written down as the text of its own number.
        let Some(revision) = table
            .get_symbol("revision_id")
            .ok()
            .and_then(|symbol| symbol.constant_data)
            .and_then(|data| String::from_utf8(data).ok())
            .and_then(|text| text.trim().parse::<u32>().ok())
        else {
            continue;
        };

        let Ok(structure) = table.get_type("_VMCS") else {
            continue;
        };
        let field = |member: &str| -> Option<usize> {
            structure
                .as_struct()?
                .member(member)
                .map(|found| found.offset as usize)
        };
        let (
            Some(vmcs_link_ptr),
            Some(host_cr3),
            Some(host_cr4),
            Some(guest_cr3),
            Some(guest_cr4),
            Some(ept),
        ) = (
            field("vmcs_link_ptr"),
            field("host_cr3"),
            field("host_cr4"),
            field("guest_cr3"),
            field("guest_cr4"),
            field("ept"),
        )
        else {
            continue;
        };

        found.push(Layout {
            name,
            revision,
            vmcs_link_ptr,
            host_cr3,
            host_cr4,
            guest_cr3,
            guest_cr4,
            ept,
        });
    }
    found
}

/// Which of the tests a page fails, or `None` if it is not worth testing.
///
/// The tests are the ones described in *Hypervisor Memory Forensics*: a real
/// control structure has a clean abort field, a link pointer left at all ones,
/// virtualisation enabled in the host's control register, page-table roots
/// that are not zero, and no reserved bit set in the guest's.
fn verify(page: &[u8], layout: &Layout) -> Option<Vec<&'static str>> {
    let mut failed = Vec::new();

    if page.get(4..8)? != [0, 0, 0, 0] {
        failed.push("VMCS_ABORT_INVALID");
    }
    if layout.read(page, layout.vmcs_link_ptr) != u64::MAX {
        failed.push("VMCS_LINK_PTR_IS_NOT_FS");
    }
    if layout.read(page, layout.host_cr4) & CR4_VMXE == 0 {
        failed.push("VMCS_HOST_CR4_NO_VTX");
    }
    if layout.read(page, layout.guest_cr3) == 0 || layout.read(page, layout.host_cr3) == 0 {
        failed.push("VMCS_CR3_IS_ZERO");
    }
    if layout.read(page, layout.guest_cr4) & CR4_RESERVED != 0 {
        failed.push("VMCS_GUEST_CR4_RESERVED");
    }
    Some(failed)
}
