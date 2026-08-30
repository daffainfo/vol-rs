//! Linux plugins.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

pub mod pslist;
pub mod pstree;
pub mod lsmod;
pub mod psaux;
pub mod envars;
pub mod proc;
pub mod elfs;
pub mod lsof;
pub mod capabilities;
pub mod bash;
pub mod library_list;
pub mod pidhashtable;
pub mod kthreads;
pub mod mountinfo;
pub mod boottime;
pub mod iomem;
pub mod ptrace;
pub mod psscan;
pub mod kmsg;
pub mod graphics;
pub mod tracing;
pub mod vmaregexscan;
pub mod ebpf;
pub mod ip;
pub mod sockstat;
pub mod sockscan;
pub mod kallsyms;
pub mod pscallstack;
pub mod vmcoreinfo;
pub mod vmayarascan;
pub mod pagecache;
pub mod module_extract;
pub mod malware;

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::plugins::PluginRegistry;

pub fn register(registry: &mut PluginRegistry) {
    registry.add(Arc::new(pslist::PsList));
    registry.add(Arc::new(pstree::PsTree));
    registry.add(Arc::new(lsmod::Lsmod));
    registry.add(Arc::new(psaux::PsAux));
    registry.add(Arc::new(envars::Envars));
    registry.add(Arc::new(proc::Maps));
    registry.add(Arc::new(elfs::Elfs));
    registry.add(Arc::new(lsof::Lsof));
    registry.add(Arc::new(capabilities::Capabilities));
    registry.add(Arc::new(bash::Bash));
    registry.add(Arc::new(library_list::LibraryList));
    registry.add(Arc::new(pidhashtable::PidHashTable));
    registry.add(Arc::new(kthreads::Kthreads));
    registry.add(Arc::new(mountinfo::MountInfo));
    registry.add(Arc::new(boottime::BootTime));
    registry.add(Arc::new(iomem::IoMem));
    registry.add(Arc::new(ptrace::Ptrace));
    registry.add(Arc::new(psscan::PsScan));
    registry.add(Arc::new(kmsg::Kmsg));
    graphics::register(registry);
    tracing::register(registry);
    registry.add(Arc::new(vmaregexscan::VmaRegExScan));
    registry.add(Arc::new(ebpf::Ebpf));
    registry.add(Arc::new(ip::Addr));
    registry.add(Arc::new(ip::Link));
    registry.add(Arc::new(sockstat::Sockstat));
    registry.add(Arc::new(sockscan::Sockscan));
    registry.add(Arc::new(kallsyms::Kallsyms));
    registry.add(Arc::new(pscallstack::PsCallStack));
    registry.add(Arc::new(vmcoreinfo::VmCoreInfo));
    registry.add(Arc::new(vmayarascan::VmaYaraScan));
    registry.add(Arc::new(pagecache::Files));
    registry.add(Arc::new(pagecache::InodePages));
    registry.add(Arc::new(pagecache::RecoverFs));
    registry.add(Arc::new(module_extract::ModuleExtract));
    malware::register(registry);
}

/// Resolve the kernel module a Linux plugin was configured with.
pub fn kernel_module(context: &Arc<Context>, config: &Configuration) -> Result<Arc<Module>> {
    let name = config
        .get_string("kernel")
        .unwrap_or_else(|| "kernel".to_string());
    context.module(&name).map_err(|_| {
        VolatilityError::Other(
            "No kernel symbols are loaded for this image. Linux analysis needs an ISF file \
             built from the exact kernel; install one and point at it with --symbol-dirs."
                .to_string(),
        )
    })
}

/// The columns every module listing plugin shares.
pub fn module_columns() -> Vec<crate::framework::renderers::Column> {
    use crate::framework::renderers::{Column, ColumnType};
    vec![
        Column::new("Offset", ColumnType::UInt),
        Column::string("Module Name"),
        Column::new("Code Size", ColumnType::UInt),
        Column::string("Taints"),
        Column::string("Load Arguments"),
        Column::string("File Output"),
    ]
}

/// One row per module, written the way every module listing plugin writes it.
///
/// With `dump` set the module's sections are rebuilt into an ELF file and the
/// last column names it. Otherwise the column does not apply.
/// Each module is given with the offset its plugin reports for it, which is not
/// always the module structure's own address: a plugin that finds modules
/// through sysfs reports the pointer it followed.
pub fn module_rows(
    context: &Arc<Context>,
    kernel: &Module,
    modules: impl IntoIterator<Item = (u64, crate::framework::symbols::linux::KernelModule)>,
    dump: bool,
) -> Vec<Vec<crate::framework::renderers::Value>> {
    use crate::framework::renderers::Value;
    use crate::framework::symbols::linux::module_elf::extract_module;

    let mut rows = Vec::new();
    for (offset, module) in modules {
        // A module whose name cannot be read is left out entirely.
        let Ok(name) = module.name() else { continue };

        let file = if dump {
            match extract_module(context, kernel, &module) {
                Some(data) => {
                    let chosen = crate::framework::plugins::windows::pslist::sanitize_filename(
                        &format!("kernel_module.{name}.{offset:#x}.elf"),
                    );
                    // The name reported is the one asked for, even where a
                    // file of that name already existed and the data went to a
                    // numbered variant of it.
                    match crate::framework::plugins::write_extracted(&chosen, &data) {
                        Ok(_) => Value::string(chosen),
                        Err(_) => Value::not_available(),
                    }
                }
                // A module that is partly paged out cannot be rebuilt.
                None => Value::not_available(),
            }
        } else {
            Value::not_applicable()
        };

        rows.push(vec![
            Value::hex(offset),
            Value::string(name),
            // Both the resident and the discarded-after-init sections count
            // towards the size a module occupies.
            match (module.init_size(), module.core_size()) {
                (Ok(init), Ok(core)) => Value::hex(init + core),
                _ => Value::unreadable(),
            },
            // A module that taints nothing yields an empty string, which is the
            // correct answer rather than a failed read.
            module
                .taints_described(context, kernel)
                .map(Value::string)
                .unwrap_or_else(|_| Value::unreadable()),
            // The values a module was loaded with, in the order the kernel
            // records its parameters.
            Value::string(
                module
                    .load_parameters(context, kernel)
                    .into_iter()
                    .map(|(name, value)| {
                        format!("{name}={}", value.unwrap_or_else(|| "None".to_string()))
                    })
                    .collect::<Vec<String>>()
                    .join(", "),
            ),
            file,
        ]);
    }
    rows
}
