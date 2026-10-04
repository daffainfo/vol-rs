//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::Result;
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::objects::Object;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::layers::intel::IntelLayer;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, TreeGrid, Value};

/// Show OS & kernel details of the memory sample being analyzed.
pub struct Info;

impl Plugin for Info {
    fn name(&self) -> &'static str {
        "windows.info.Info"
    }

    fn description(&self) -> &'static str {
        "Show OS & kernel details of the memory sample being analyzed."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![Column::string("Variable"), Column::string("Value")]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let mut grid = TreeGrid::new(self.columns());
        let mut row = |name: &str, value: Value| -> Result<()> {
            grid.push(0, vec![Value::string(name), value])
        };

        let layer = context.layers.get(&kernel.layer_name)?;
        let intel = layer.as_any().downcast_ref::<IntelLayer>();

        row("Kernel Base", Value::hex(kernel.offset))?;
        if let Some(intel) = intel {
            row("DTB", Value::hex(intel.page_map_offset()))?;
        }

        let table = context.symbol_space.table(&kernel.symbol_table_name)?;
        row("Symbols", Value::string(table.source().unwrap_or_default()))?;
        row(
            "Is64Bit",
            Value::string(capitalised(table.pointer_size() == 8)),
        )?;
        row(
            "IsPAE",
            Value::string(capitalised(
                layer.metadata().get("pae").map(|value| value == "true") == Some(true),
            )),
        )?;

        // List the dependencies of a given layer, and how far down each one is.
        for (depth, name) in layer_depths(&context, &kernel.layer_name) {
            let layer = context.layers.get(&name)?;
            row(&name, Value::string(format!("{depth} {}", layer.kind())))?;
        }

        // The debugger data block, when this kernel still carries a readable one.
        if let Some(kdbg) = debugger_data_block(&context, &kernel) {
            row("KdDebuggerDataBlock", Value::hex(kdbg.offset()))?;
            // Returns the NT build lab string from the KDBG. The block points
            // at the string, of which the reference implementation reads at
            // most thirty two bytes.
            if let Some(build) = read_string(&kdbg, "NtBuildLab", 32) {
                row("NTBuildLab", Value::string(build))?;
            }
            // Returns the CSDVersion as an integer (i.e. Service Pack
            // number). The block points at it rather than holding it, and the
            // number sits in all but the lowest byte.
            if let Some(version) = kdbg
                .member("CmNtCSDVersion")
                .and_then(|pointer| pointer.as_u64())
                .ok()
                .filter(|address| *address != 0)
                .and_then(|address| {
                    context
                        .layers
                        .read(&kernel.layer_name, address, 4, false)
                        .ok()
                })
                .map(|raw| {
                    u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) >> 8
                })
            {
                row("CSDVersion", Value::string(version.to_string()))?;
            }
        }

        // The KdVersionBlock information from a kernel.
        let version = context.object_from_symbol(&kernel, "KdVersionBlock", Some("_DBGKD_GET_VERSION64"))?;
        row("KdVersionBlock", Value::hex(version.offset()))?;
        let field = |name: &str| version.member(name).and_then(|value| value.as_u64());
        row(
            "Major/Minor",
            Value::string(format!("{}.{}", field("MajorVersion")?, field("MinorVersion")?)),
        )?;
        row("MachineType", Value::string(field("MachineType")?.to_string()))?;

        let processors = context.object_from_symbol(&kernel, "KeNumberProcessors", Some("unsigned int"))?;
        row(
            "KeNumberProcessors",
            Value::string(processors.as_u64()?.to_string()),
        )?;

        // The _KUSER_SHARED_DATA structure for a kernel.
        let shared = shared_user_data(&context, &kernel)?;
        row(
            "SystemTime",
            match shared_system_time(&shared) {
                Some(when) => Value::string(when),
                None => Value::not_available(),
            },
        )?;
        row(
            "NtSystemRoot",
            Value::string(system_root(&shared).unwrap_or_default()),
        )?;
        row(
            "NtProductType",
            Value::string(product_type(&shared).unwrap_or_default()),
        )?;
        for name in ["NtMajorVersion", "NtMinorVersion"] {
            row(
                name,
                match shared.member(name).and_then(|value| value.as_u64()) {
                    Ok(value) => Value::string(value.to_string()),
                    Err(_) => Value::not_available(),
                },
            )?;
        }

        // The kernel's own PE headers describe what it was built for.
        if let Some(headers) = pe_headers(&context, &kernel) {
            for (name, value) in headers {
                row(&name, Value::string(value))?;
            }
        }
        Ok(grid)
    }
}

/// The major and minor release the shared user data records.
///
/// Several plugins decide what a structure holds by the release rather than by
/// what the symbols describe, and this is where they read it from.
pub fn windows_version(context: &Arc<Context>, kernel: &Module) -> Option<(u64, u64)> {
    let shared = shared_user_data(context, kernel).ok()?;
    let part = |name: &str| {
        shared
            .member(name)
            .and_then(|value| value.as_u64())
            .ok()
    };
    Some((part("NtMajorVersion")?, part("NtMinorVersion")?))
}

/// How the reference implementation spells a boolean.
fn capitalised(value: bool) -> &'static str {
    if value {
        "True"
    } else {
        "False"
    }
}

/// List the dependencies of a given layer.
///
/// Returns an iterable containing the levels and layer objects for all
/// dependent layers. The kernel's own layer comes first, then whatever it rests
/// on, which is how an image's description lists them.
fn layer_depths(context: &Arc<Context>, name: &str) -> Vec<(usize, String)> {
    fn walk(context: &Arc<Context>, name: &str, depth: usize, found: &mut Vec<(usize, String)>) {
        found.push((depth, name.to_string()));
        let Ok(layer) = context.layers.get(name) else {
            // FileLayer won't have dependencies
            return;
        };
        // In the order the layer names them, so an image is described the way
        // it was assembled.
        for below in layer.dependencies() {
            walk(context, &below, depth + 1, found);
        }
    }

    let mut found = Vec::new();
    walk(context, name, 0, &mut found);
    found
}

/// Returns the KDDEBUGGER_DATA64 structure for a kernel, if this kernel
/// carries one that reads.
fn debugger_data_block(context: &Arc<Context>, kernel: &Module) -> Option<Object> {
    // The kernel names where the block sits but does not always describe its
    // shape, so the description that ships with the tool is used instead.
    context.ensure_table("kdbg", "windows", "kdbg").ok()?;
    let address = context.symbol_offset(kernel, "KdDebuggerDataBlock").ok()?;
    let template = context
        .symbol_space
        .get_type("kdbg!_KDDEBUGGER_DATA64")
        .ok()?;
    let block = context.object_from_template(template, &kernel.layer_name, address);
    // The block names itself. Anything else means it was not really there.
    let tag = block
        .member("Header")
        .and_then(|header| header.member("OwnerTag"))
        .and_then(|tag| tag.as_u64())
        .ok()?;
    (tag == 0x4742_444B).then_some(block)
}

/// A NUL-terminated string a structure points at.
fn read_string(object: &Object, member: &str, length: usize) -> Option<String> {
    let address = object.member(member).ok()?.pointer_value().ok()?;
    if address == 0 {
        return None;
    }
    let data = object
        .context()
        .layers
        .read(object.native_layer_name(), address, length, true)
        .ok()?;
    let end = data.iter().position(|byte| *byte == 0).unwrap_or(data.len());
    Some(String::from_utf8_lossy(&data[..end]).to_string())
}

/// Returns the _KUSER_SHARED_DATA structure for a kernel.
fn shared_user_data(context: &Arc<Context>, kernel: &Module) -> Result<Object> {
    let pointer_size = context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .map(|table| table.pointer_size())
        .unwrap_or(8);
    // this is a hard-coded address in the Windows OS
    let address: u64 = if pointer_size == 4 {
        0xFFDF_0000
    } else {
        0xFFFF_F780_0000_0000
    };
    let template = context
        .symbol_space
        .get_type(&kernel.qualified("_KUSER_SHARED_DATA"))?;
    Ok(context.object_from_template(template, &kernel.layer_name, address))
}

/// The system time the shared page records.
fn shared_system_time(shared: &Object) -> Option<String> {
    let time = shared.member("SystemTime").ok()?;
    // The value is written in two halves and read back the same way.
    let low = time.member("LowPart").and_then(|part| part.as_u64()).ok()?;
    let high = time.member("High1Time").and_then(|part| part.as_u64()).ok()?;
    let when = crate::framework::renderers::conversion::wintime_to_datetime((high << 32) | low)?;
    Some(when.format("%Y-%m-%d %H:%M:%S%:z").to_string())
}

/// The Windows directory, as the shared page records it.
fn system_root(shared: &Object) -> Option<String> {
    let field = shared.member("NtSystemRoot").ok()?;
    let data = shared
        .context()
        .layers
        // Two hundred and sixty bytes, which is how many the reference
        // implementation reads, not how many characters the name may have.
        .read(shared.layer_name(), field.offset(), 260, true)
        .ok()?;
    let decoded = crate::framework::objects::utility::decode_utf16_le(&data);
    let end = decoded.find('\0').unwrap_or(decoded.len());
    Some(decoded[..end].to_string())
}

/// Which edition of Windows this is.
fn product_type(shared: &Object) -> Option<String> {
    let value = shared
        .member("NtProductType")
        .and_then(|field| field.enum_name())
        .ok()?;
    Some(value)
}

/// Gets the ntheader structure for the kernel of the specified layer.
fn pe_headers(context: &Arc<Context>, kernel: &Module) -> Option<Vec<(String, String)>> {
    let data = context
        .layers
        .read(&kernel.layer_name, kernel.offset, 0x1000, true)
        .ok()?;
    let header = crate::framework::symbols::windows::pe::parse(&data).ok()?;
    let built = chrono::DateTime::from_timestamp(header.time_date_stamp as i64, 0)?;

    Some(vec![
        (
            "PE MajorOperatingSystemVersion".to_string(),
            header.major_operating_system_version.to_string(),
        ),
        (
            "PE MinorOperatingSystemVersion".to_string(),
            header.minor_operating_system_version.to_string(),
        ),
        ("PE Machine".to_string(), header.machine_value.to_string()),
        (
            "PE TimeDateStamp".to_string(),
            // Spelled the way C's asctime does, which is what upstream prints.
            built.format("%a %b %e %H:%M:%S %Y").to_string(),
        ),
    ])
}
