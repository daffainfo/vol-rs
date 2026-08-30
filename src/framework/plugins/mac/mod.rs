//! Mac plugins.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

pub mod pslist;
pub mod pstree;
pub mod lsmod;
pub mod psaux;
pub mod lsof;
pub mod mount;
pub mod ifconfig;
pub mod proc_maps;
pub mod malfind;
pub mod check_syscall;
pub mod check_trap_table;
pub mod trustedbsd;
pub mod kauth_scopes;
pub mod timers;
pub mod kauth_listeners;
pub mod vfsevents;
pub mod check_sysctl;
pub mod list_files;
pub mod netstat;
pub mod socket_filters;
pub mod dmesg;
pub mod bash;
pub mod kevents;

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context, Module};
use crate::framework::plugins::PluginRegistry;

pub fn register(registry: &mut PluginRegistry) {
    registry.add(Arc::new(pslist::PsList));
    registry.add(Arc::new(pstree::PsTree));
    registry.add(Arc::new(lsmod::Lsmod));
    registry.add(Arc::new(psaux::PsAux));
    registry.add(Arc::new(lsof::Lsof));
    registry.add(Arc::new(mount::Mount));
    registry.add(Arc::new(ifconfig::IfConfig));
    registry.add(Arc::new(proc_maps::Maps));
    registry.add(Arc::new(malfind::Malfind));
    registry.add(Arc::new(check_syscall::CheckSyscall));
    registry.add(Arc::new(check_trap_table::CheckTrapTable));
    registry.add(Arc::new(trustedbsd::TrustedBsd));
    registry.add(Arc::new(kauth_scopes::KauthScopes));
    registry.add(Arc::new(timers::Timers));
    registry.add(Arc::new(kauth_listeners::KauthListeners));
    registry.add(Arc::new(vfsevents::VfsEvents));
    registry.add(Arc::new(check_sysctl::CheckSysctl));
    registry.add(Arc::new(list_files::ListFiles));
    registry.add(Arc::new(netstat::NetStat));
    registry.add(Arc::new(socket_filters::SocketFilters));
    registry.add(Arc::new(dmesg::Dmesg));
    registry.add(Arc::new(bash::Bash));
    registry.add(Arc::new(kevents::Kevents));
}

/// Resolve the kernel module a Mac plugin was configured with.
pub fn kernel_module(context: &Arc<Context>, config: &Configuration) -> Result<Arc<Module>> {
    let name = config
        .get_string("kernel")
        .unwrap_or_else(|| "kernel".to_string());
    context.module(&name).map_err(|_| {
        VolatilityError::Other(
            "No kernel symbols are loaded for this image. Mac analysis needs an ISF file \
             built from the exact kernel; install one and point at it with --symbol-dirs."
                .to_string(),
        )
    })
}
