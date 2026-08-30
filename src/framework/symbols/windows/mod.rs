//! Windows-specific helpers for working with kernel structures.
//!
//! These wrap the awkward parts of the Windows object model (processes and
//! their address spaces, the VAD tree, object headers), so plugins can ask for
//! what they want rather than reproducing the same pointer arithmetic.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

pub mod pe;
pub mod poolscanner;
pub mod sid_data;
pub mod sid;
pub mod registry;
pub mod resolver;
pub mod sam;
pub mod versions;
pub mod pdb;

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Context, Module};
use crate::framework::layers::intel::{IntelLayer, WINDOWS_INTEL, WINDOWS_INTEL_32E};
use crate::framework::objects::utility::{unicode_string, walk_list};
use crate::framework::objects::Object;

/// A process, wrapping an `_EPROCESS`.
#[derive(Clone)]
pub struct Process {
    pub object: Object,
}

impl Process {
    pub fn new(object: Object) -> Self {
        Self { object }
    }

    pub fn pid(&self) -> Result<u64> {
        self.object.member("UniqueProcessId")?.as_u64()
    }

    pub fn parent_pid(&self) -> Result<u64> {
        self.object.member("InheritedFromUniqueProcessId")?.as_u64()
    }

    /// The short image name, held in a fixed-size character array.
    pub fn image_file_name(&self) -> Result<String> {
        self.object.member("ImageFileName")?.as_string()
    }

    pub fn offset(&self) -> u64 {
        self.object.offset()
    }

    /// Number of threads, which distinguishes a live process from a shell of one.
    pub fn thread_count(&self) -> Result<u64> {
        self.object.member("ActiveThreads")?.as_u64()
    }

    /// Number of open handles, read from the process's object table.
    ///
    /// Returns an error rather than zero when the table cannot be read, so the
    /// caller can render the cell as unreadable instead of as a real count.
    pub fn handle_count(&self) -> Result<u64> {
        self.object
            .member("ObjectTable")?
            .dereference()?
            .member("HandleCount")?
            .as_u64()
    }

    /// The session this process belongs to.
    ///
    /// `Ok(None)` means the process is not attached to a session, which is
    /// normal for the system process and is reported as not applicable rather
    /// than as a failure.
    pub fn session_id(&self) -> Result<Option<u64>> {
        let session = self.object.member("Session")?;
        let address = session.pointer_value()?;
        if address == 0 {
            return Ok(None);
        }
        let context = self.object.context().clone();
        let template = context
            .symbol_space
            .get_type(&qualify(&self.object, "_MM_SESSION_SPACE")?)?;
        let space = context.object_from_template(template, self.object.layer_name(), address);
        Ok(Some(space.member("SessionId")?.as_u64()?))
    }

    pub fn create_time(&self) -> Result<u64> {
        // The field is a union. The time is its whole 64-bit value.
        self.object.member("CreateTime")?.member("QuadPart")?.as_u64()
    }

    pub fn exit_time(&self) -> Result<u64> {
        self.object.member("ExitTime")?.member("QuadPart")?.as_u64()
    }

    /// Whether this is a 32-bit process running under WoW64.
    pub fn is_wow64(&self) -> bool {
        for name in ["WoW64Process", "Wow64Process"] {
            if let Ok(member) = self.object.member(name) {
                if let Ok(value) = member.pointer_value() {
                    return value != 0;
                }
            }
        }
        false
    }

    /// The page directory base for this process's address space.
    pub fn directory_table_base(&self) -> Result<u64> {
        self.object
            .member("Pcb")?
            .member("DirectoryTableBase")
            .or_else(|_| self.object.member("Pcb")?.member("DirectoryTableBase"))?
            .as_u64()
    }

    /// The image path recorded by the audit subsystem at process creation.
    ///
    /// Unlike the PEB's copy this lives in kernel space, so it is readable
    /// without building the process's own address space, and a process cannot
    /// have rewritten it after the fact.
    pub fn audit_image_file_name(&self) -> Result<String> {
        let name = self
            .object
            .member("SeAuditProcessCreationInfo")?
            .member("ImageFileName")?
            .dereference()?
            .member("Name")?;
        unicode_string(&name)
    }

    /// Build a virtual layer for this process's own address space.
    ///
    /// Plugins that read a process's memory need this: the kernel layer maps
    /// kernel space, but user-space addresses only make sense through the
    /// process's own page tables.
    pub fn address_space(&self, physical_layer: &str) -> Result<String> {
        let context = self.object.context().clone();
        let dtb = self.directory_table_base()?;
        if dtb == 0 {
            return Err(VolatilityError::Other(
                "Process has no directory table base; it may be terminated".to_string(),
            ));
        }

        // Match the kernel layer's addressing mode so a 32-bit image does not
        // get a 64-bit layer.
        let kernel_layer = context.layers.get(self.object.layer_name())?;
        let config = kernel_layer
            .as_any()
            .downcast_ref::<IntelLayer>()
            .map(|layer| layer.config().clone())
            .unwrap_or(WINDOWS_INTEL_32E);
        let config = if config.bits_per_register == 32 {
            WINDOWS_INTEL
        } else {
            config
        };

        let pid = self.pid().unwrap_or(0);
        let layer_name = context.layers.free_name(&format!("process_{pid}"));
        context.layers.add(Arc::new(IntelLayer::new(
            &layer_name,
            physical_layer,
            dtb,
            config,
        )));
        Ok(layer_name)
    }

    /// The PEB, which holds the command line and loaded module list.
    ///
    /// Only reachable through the process's own address space, so `layer_name`
    /// must be the layer returned by [`Process::address_space`].
    pub fn peb(&self, layer_name: &str) -> Result<Object> {
        let peb_pointer = self.object.member("Peb")?;
        let address = peb_pointer.pointer_value()?;
        if address == 0 {
            return Err(VolatilityError::Other("Process has no PEB".to_string()));
        }
        let context = self.object.context().clone();
        let template = context
            .symbol_space
            .get_type(&qualify(&self.object, "_PEB")?)?;
        Ok(context.object_from_template(template, layer_name, address))
    }

    /// The command line, read out of the PEB's process parameters.
    pub fn command_line(&self, layer_name: &str) -> Result<String> {
        let peb = self.peb(layer_name)?;
        let parameters = peb.member("ProcessParameters")?.dereference()?;
        unicode_string(&parameters.member("CommandLine")?)
    }

    /// The full path of the executable image.
    pub fn image_path(&self, layer_name: &str) -> Result<String> {
        let peb = self.peb(layer_name)?;
        let parameters = peb.member("ProcessParameters")?.dereference()?;
        unicode_string(&parameters.member("ImagePathName")?)
    }
}

/// Qualify a bare type name with the symbol table the object came from.
fn qualify(object: &Object, type_name: &str) -> Result<String> {
    let resolved = object.resolved_template()?;
    let table = resolved
        .as_struct()
        .map(|structure| structure.table.clone())
        .ok_or_else(|| {
            VolatilityError::Other("Cannot determine the symbol table for this object".to_string())
        })?;
    Ok(crate::framework::symbols::join_name(&table, type_name))
}

/// Walk the kernel's active process list.
///
/// `PsActiveProcessHead` is a `_LIST_ENTRY` linking every `_EPROCESS` through
/// its `ActiveProcessLinks` member.
pub fn list_processes(context: &Arc<Context>, kernel: &Module) -> Result<Vec<Process>> {
    let head = context.object_from_symbol(kernel, "PsActiveProcessHead", Some("_LIST_ENTRY"))?;
    let type_name = kernel.qualified("_EPROCESS");

    Ok(walk_list(&head, &type_name, "ActiveProcessLinks", true)?
        .into_iter()
        .map(Process::new)
        .collect())
}

/// The kernel object header that precedes a named kernel object.
///
/// Kernel objects are preceded by an `_OBJECT_HEADER` whose `Body` member is
/// the object itself, so the header is found by stepping back from the object.
pub fn object_header(object: &Object, kernel: &Module) -> Result<Object> {
    let context = object.context().clone();
    let header_type = context
        .symbol_space
        .get_type(&kernel.qualified("_OBJECT_HEADER"))?;
    let body_offset = context
        .symbol_space
        .find_member(&header_type, "Body")?
        .map(|(offset, _)| offset)
        .ok_or_else(|| {
            VolatilityError::Other("_OBJECT_HEADER has no Body member".to_string())
        })?;

    Ok(context.object_from_template(
        header_type,
        object.layer_name(),
        object.offset().wrapping_sub(body_offset),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framework::layers::physical::BufferLayer;
    use crate::framework::symbols::isf::IsfFile;
    use crate::framework::symbols::native::x64_native_table;
    use crate::framework::symbols::SymbolTable;

    /// A cut-down kernel with just enough of `_EPROCESS` to walk a list.
    const ISF: &str = r#"{
        "metadata": {"format": "6.2.0"},
        "base_types": {
            "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
            "unsigned long long": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
            "unsigned char": {"size": 1, "signed": false, "kind": "char", "endian": "little"}
        },
        "user_types": {
            "_LIST_ENTRY": {"kind": "struct", "size": 16, "fields": {
                "Flink": {"offset": 0, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}},
                "Blink": {"offset": 8, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}}
            }},
            "_EPROCESS": {"kind": "struct", "size": 64, "fields": {
                "UniqueProcessId": {"offset": 0, "type": {"kind": "base", "name": "unsigned long long"}},
                "ActiveProcessLinks": {"offset": 8, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
                "InheritedFromUniqueProcessId": {"offset": 24, "type": {"kind": "base", "name": "unsigned long long"}},
                "ImageFileName": {"offset": 32, "type": {"kind": "array", "count": 15, "subtype": {"kind": "base", "name": "unsigned char"}}}
            }}
        },
        "enums": {},
        "symbols": {"PsActiveProcessHead": {"address": 256}}
    }"#;

    fn build() -> (Arc<Context>, Arc<Module>) {
        let mut memory = vec![0u8; 0x1000];
        let head = 0x100u64;
        let processes: [(u64, u64, &[u8]); 2] = [
            (0x200, 4, b"System"),
            (0x300, 400, b"smss.exe"),
        ];

        let mut write = |at: u64, value: u64| {
            let at = at as usize;
            memory[at..at + 8].copy_from_slice(&value.to_le_bytes());
        };

        for (index, (offset, pid, _)) in processes.iter().enumerate() {
            write(*offset, *pid);
            let links = offset + 8;
            let next = if index + 1 < processes.len() {
                processes[index + 1].0 + 8
            } else {
                head
            };
            let previous = if index == 0 {
                head
            } else {
                processes[index - 1].0 + 8
            };
            write(links, next);
            write(links + 8, previous);
        }
        write(head, processes[0].0 + 8);
        write(head + 8, processes[1].0 + 8);

        for (offset, _, name) in &processes {
            let at = (*offset + 32) as usize;
            memory[at..at + name.len()].copy_from_slice(name);
        }

        let context = Arc::new(Context::new());
        context.layers.add(Arc::new(BufferLayer::new("kernel", memory)));
        let isf = IsfFile::from_slice(ISF.as_bytes()).unwrap();
        context.add_symbol_table(Arc::new(SymbolTable::new("nt", isf, x64_native_table())));
        let module = context.add_module(
            Module::new("kernel", "nt", "kernel", 0).with_absolute_addresses(true),
        );
        (context, module)
    }

    #[test]
    fn walks_the_active_process_list() {
        let (context, kernel) = build();
        let processes = list_processes(&context, &kernel).unwrap();
        assert_eq!(processes.len(), 2);

        assert_eq!(processes[0].pid().unwrap(), 4);
        assert_eq!(processes[0].image_file_name().unwrap(), "System");
        assert_eq!(processes[1].pid().unwrap(), 400);
        assert_eq!(processes[1].image_file_name().unwrap(), "smss.exe");
    }
}

/// Read a kernel object's name from the name-info header preceding it.
///
/// Named kernel objects carry optional headers before the `_OBJECT_HEADER`,
/// whose presence is recorded in `InfoMask`. Returns `None` when the object has
/// no name, which is normal rather than an error.
pub fn object_name(object: &Object, kernel: &Module) -> Option<String> {
    let header = object_header(object, kernel).ok()?;
    header_name(&header, kernel)
}

/// Read the name recorded in front of an object header.
///
/// Named kernel objects carry optional headers before the `_OBJECT_HEADER`,
/// whose presence is recorded in `InfoMask`. Returns `None` when the object has
/// no name, which is normal rather than an error.
pub fn header_name(header: &Object, kernel: &Module) -> Option<String> {
    let context = header.context().clone();
    let info_mask = header.member("InfoMask").and_then(|f| f.as_u64()).ok()?;

    // How far the name sits ahead of the object header depends on which other
    // optional headers are present, and the kernel keeps a table of exactly
    // that: indexed by the mask's low bits, it gives the distance back.
    const NAME_INFO_BIT: u64 = 0x2;
    let table = context.symbol_offset(kernel, "ObpInfoMaskToOffset").ok()?;
    let index = info_mask & (NAME_INFO_BIT | (NAME_INFO_BIT - 1));
    let distance = context
        .layers
        .read(header.native_layer_name(), table + index, 1, false)
        .ok()?[0] as u64;
    // A distance of zero means this object carries no name at all.
    if distance == 0 {
        return None;
    }

    let template = context
        .symbol_space
        .get_type(&kernel.qualified("_OBJECT_HEADER_NAME_INFO"))
        .ok()?;
    let address = header.offset().checked_sub(distance)?;
    let info = context
        .object_from_template(template, header.layer_name(), address)
        .with_native_layer(header.native_layer_name());
    unicode_string(&info.member("Name").ok()?).ok()
}

impl Process {
    /// The process's access token.
    ///
    /// `Token` is an `_EX_FAST_REF`: the low bits are a reference count that
    /// must be masked off before the value is a usable pointer.
    pub fn token(&self) -> Result<Object> {
        let field = self.object.member("Token")?;
        let raw = field
            .member("Object")
            .and_then(|object| object.pointer_value())
            .or_else(|_| field.pointer_value())?;
        // The bottom four bits hold the count on both architectures.
        let address = raw & !0xF;
        if address == 0 {
            return Err(VolatilityError::Other("Process has no token".to_string()));
        }

        let context = self.object.context().clone();
        let template = context
            .symbol_space
            .get_type(&qualify(&self.object, "_TOKEN")?)?;
        Ok(context.object_from_template(template, self.object.layer_name(), address))
    }

    /// The SIDs in the process's token, rendered as strings.
    pub fn sids(&self) -> Result<Vec<String>> {
        let token = self.token()?;
        let count = token.member("UserAndGroupCount")?.as_u64()?;
        // A count beyond this means the token was misread.
        if count > 0x400 {
            return Err(VolatilityError::Other(
                "Implausible SID count in token".to_string(),
            ));
        }

        let array = token.member("UserAndGroups")?;
        let base = array.pointer_value()?;
        if base == 0 {
            return Ok(Vec::new());
        }

        let context = self.object.context().clone();
        let entry_template = context
            .symbol_space
            .get_type(&qualify(&self.object, "_SID_AND_ATTRIBUTES")?)?;
        let entry_size = context.symbol_space.size_of(&entry_template)?;
        let sid_template = context
            .symbol_space
            .get_type(&qualify(&self.object, "_SID")?)?;

        let mut sids = Vec::new();
        for index in 0..count {
            let entry = context.object_from_template(
                entry_template.clone(),
                self.object.layer_name(),
                base + index * entry_size,
            );
            // An entry whose SID cannot be read is skipped rather than
            // aborting the whole token.
            let Ok(address) = entry.member("Sid").and_then(|sid| sid.pointer_value()) else {
                continue;
            };
            if address == 0 {
                continue;
            }
            let sid = context.object_from_template(
                sid_template.clone(),
                self.object.layer_name(),
                address,
            );
            if let Ok(text) = sid::format_sid(&sid) {
                sids.push(text);
            }
        }
        Ok(sids)
    }

    /// The privileges present in the token, with whether each is enabled.
    ///
    /// Returns `(luid, present, enabled, enabled by default)`.
    pub fn privileges(&self) -> Result<Vec<(u64, bool, bool, bool)>> {
        let token = self.token()?;
        let privileges = token.member("Privileges")?;

        let present = privileges.member("Present")?.as_u64()?;
        let enabled = privileges.member("Enabled")?.as_u64()?;
        let default = privileges.member("EnabledByDefault")?.as_u64()?;

        // Each bit position is a privilege LUID.
        Ok((0..64)
            .map(|bit| {
                (
                    bit,
                    present & (1 << bit) != 0,
                    enabled & (1 << bit) != 0,
                    default & (1 << bit) != 0,
                )
            })
            .collect())
    }
}

/// Render a process's session as a cell, the way the process plugins do.
///
/// A process with no session reports not-applicable, which is normal for the
/// system process rather than a failed read.
pub fn pslist_session_id(process: &Process) -> crate::framework::renderers::Value {
    use crate::framework::renderers::Value;
    match process.session_id() {
        Ok(Some(id)) => Value::int(id as i64),
        Ok(None) => Value::not_applicable(),
        Err(_) => Value::unreadable(),
    }
}

/// Whether a process carved out of a pool allocation is coherent.
///
/// A tag match lands on anything. These are the checks the reference
/// implementation makes before believing what it found is really a process.
pub fn process_is_valid(context: &Arc<Context>, kernel: &Module, object: &Object) -> bool {
    let _ = (context, kernel);
    let Ok(name) = object
        .member("ImageFileName")
        .and_then(|field| field.as_string())
    else {
        return false;
    };
    if name.is_empty() {
        return false;
    }

    let Ok(pid) = object
        .member("UniqueProcessId")
        .and_then(|field| field.as_u64())
    else {
        return false;
    };

    // The system process is the one process with no creation time.
    if !(name == "System" && pid == 4) {
        let Ok(created) = object
            .member("CreateTime")
            .and_then(|field| field.member("QuadPart"))
            .and_then(|field| field.as_u64())
        else {
            return false;
        };
        if created == 0 {
            return false;
        }
        let Some(created) = crate::framework::renderers::conversion::wintime_to_datetime(created)
        else {
            return false;
        };
        if !plausible_year(created.format("%Y").to_string().parse().unwrap_or(0)) {
            return false;
        }

        // An exit time, where there is one, must be plausible and must not
        // precede the creation.
        if let Ok(exited) = object
            .member("ExitTime")
            .and_then(|field| field.member("QuadPart"))
            .and_then(|field| field.as_u64())
        {
            if let Some(exited) =
                crate::framework::renderers::conversion::wintime_to_datetime(exited)
            {
                if !plausible_year(exited.format("%Y").to_string().parse().unwrap_or(0))
                    || created > exited
                {
                    return false;
                }
            }
        }
    }

    // Process ids are multiples of four.
    if pid % 4 != 0 || pid == 0 || pid > MAX_PID {
        return false;
    }

    let Ok(directory_table_base) = object
        .member("Pcb")
        .and_then(|pcb| pcb.member("DirectoryTableBase"))
        .and_then(|field| field.as_u64())
    else {
        return false;
    };
    // The low bits hold process-context identifiers rather than an address, so
    // a base with nothing above them is not one.
    if directory_table_base == 0 || directory_table_base & !0xFFF == 0 {
        return false;
    }

    // The thread list must point into kernel space.
    let Ok((flink, blink)) = object.member("ThreadListHead").and_then(|list| {
        Ok((
            list.member("Flink")?.pointer_value()?,
            list.member("Blink")?.pointer_value()?,
        ))
    }) else {
        return false;
    };
    flink >= KERNEL_SPACE && blink >= KERNEL_SPACE
}

/// Whether a thread carved out of a pool allocation is coherent.
pub fn thread_is_valid(object: &Object) -> bool {
    let Ok(cid) = object.member("Cid") else {
        return false;
    };
    let (Ok(thread), Ok(process)) = (
        cid.member("UniqueThread").and_then(|field| field.as_u64()),
        cid.member("UniqueProcess").and_then(|field| field.as_u64()),
    ) else {
        return false;
    };
    // Thread and process ids are both multiples of four.
    if thread % 4 != 0 || process % 4 != 0 {
        return false;
    }

    // Every thread but the system process's has a creation time.
    if process != 4 {
        let Ok(created) = object
            .member("CreateTime")
            .and_then(|field| field.member("QuadPart"))
            .and_then(|field| field.as_u64())
        else {
            return false;
        };
        let Some(created) = crate::framework::renderers::conversion::wintime_to_datetime(created)
        else {
            return false;
        };
        if !plausible_year(created.format("%Y").to_string().parse().unwrap_or(0)) {
            return false;
        }
    }
    true
}

/// Whether a file object carved out of a pool allocation is coherent.
pub fn file_is_valid(context: &Arc<Context>, object: &Object) -> bool {
    let Ok(name) = object.member("FileName") else {
        return false;
    };
    let Ok(length) = name.member("Length").and_then(|field| field.as_u64()) else {
        return false;
    };
    if length == 0 {
        return false;
    }
    let Ok(buffer) = name.member("Buffer").and_then(|field| field.pointer_value()) else {
        return false;
    };
    context
        .layers
        .is_valid(name.native_layer_name(), buffer, 1)
}

/// A year a real timestamp could carry.
///
/// The upper bound moves with the clock, as the reference implementation's
/// does, so an image from the future is rejected the same way.
fn plausible_year(year: i32) -> bool {
    let now = chrono::Utc::now().format("%Y").to_string().parse::<i32>().unwrap_or(2000);
    year > 1998 && year < now + 10
}

/// The largest process id Windows will issue.
const MAX_PID: u64 = 4_194_304;

/// Where kernel space starts, for the rough test that a pointer is one.
const KERNEL_SPACE: u64 = 0x8000_0000;

impl Process {
    /// The process's 32-bit environment block, when it has one.
    ///
    /// A process running under WoW64 keeps a second, 32-bit view of itself,
    /// described by types the kernel's own symbols do not carry.
    pub fn peb32(&self, layer_name: &str) -> Result<Option<Object>> {
        let wow64 = self
            .object
            .member("WoW64Process")
            .or_else(|_| self.object.member("Wow64Process"))?
            .pointer_value()?;
        if wow64 == 0 {
            return Ok(None);
        }

        let context = self.object.context().clone();
        // Windows 10 puts the block behind another structure. Earlier versions
        // point straight at it.
        let address = if context
            .symbol_space
            .has_type(&qualify(&self.object, "_EWOW64PROCESS")?)
        {
            let template = context
                .symbol_space
                .get_type(&qualify(&self.object, "_EWOW64PROCESS")?)?;
            context
                .object_from_template(template, layer_name, wow64)
                .member("Peb")?
                .pointer_value()?
        } else {
            wow64
        };
        if address == 0 {
            return Ok(None);
        }

        let Ok(template) = context.symbol_space.get_type("wow64!_PEB32") else {
            return Ok(None);
        };
        Ok(Some(context.object_from_template(
            template,
            layer_name,
            address,
        )))
    }
}

/// The name of the table holding the 32-bit types a WoW64 process needs.
pub const WOW64_TABLE: &str = "wow64";

/// Whether a process is one an anomaly hunt should look at.
///
/// A terminated process that is still on the list, through smear or a leaked
/// handle, and the kernel's own processes produce false positives for the
/// plugins that look for tampering, so they are left out.
pub fn is_active_userland_process(context: &Arc<Context>, kernel: &Module, process: &Process) -> bool {
    if !process_is_valid(context, kernel, &process.object) {
        return false;
    }
    let threads = process
        .object
        .member("ActiveThreads")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    let pid = process.pid().unwrap_or(0);
    let parent = process.parent_pid().unwrap_or(0);
    let exited = process
        .object
        .member("ExitTime")
        .and_then(|time| time.member("QuadPart"))
        .and_then(|value| value.as_u64())
        .unwrap_or(1);

    // Upstream also asks whether the handle count could be read, but compares
    // two freshly built "unreadable" markers, which are never equal to each
    // other, so the question is always answered yes. A process whose handle
    // count is smeared is therefore still an active one.
    threads > 0 && pid != 4 && parent != 4 && exited == 0
}

/// Where kernel space begins, as the kernel itself records it.
///
/// A pointer below this cannot name kernel memory, which is what tells a
/// smeared or hostile value from a real one. The architectural value stands in
/// when the kernel's own word is paged out.
pub fn kernel_space_start(context: &Arc<Context>, kernel: &Module) -> u64 {
    let sixty_four_bit = context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .map(|table| table.pointer_size())
        .unwrap_or(8)
        == 8;
    let (type_name, default) = if sixty_four_bit {
        ("unsigned long long", 0xFFFF_8000_0000_0000u64)
    } else {
        ("unsigned long", 0x8000_0000)
    };
    let value = context
        .object_from_symbol(kernel, "MmSystemRangeStart", Some(type_name))
        .and_then(|value| value.as_u64())
        .unwrap_or(default);
    value & context.layers.address_mask(&kernel.layer_name)
}
