//! Telling one release of Windows from another by what its symbols describe.
//!
//! A symbol file produced from a kernel's own debug data rarely records the
//! version it came from, so a release is recognised instead by the types and
//! symbols that release introduced or removed. Each check below is the same
//! set of tests upstream applies, in the same order.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::framework::context::{Context, Module};

/// One test: a symbol or type name, an optional member of that type, and
/// whether it has to be there.
pub type Check = (&'static str, Option<&'static str>, bool);

/// Whether every check holds for the kernel's symbols.
pub fn matches(context: &Arc<Context>, kernel: &Module, checks: &[Check]) -> bool {
    for (name, member, wanted) in checks {
        let qualified = kernel.qualified(name);
        match member {
            None => {
                let present = context.symbol_space.has_symbol(&qualified)
                    || context.symbol_space.has_type(&qualified);
                if present != *wanted {
                    return false;
                }
            }
            Some(member) => match context.symbol_space.get_type(&qualified) {
                Ok(template) => {
                    let present = context
                        .symbol_space
                        .find_member(&template, member)
                        .map(|found| found.is_some())
                        .unwrap_or(false);
                    if present != *wanted {
                        return false;
                    }
                }
                // A type that is not described at all cannot have the member,
                // which is only a failure when the member was wanted.
                Err(_) => {
                    if *wanted {
                        return false;
                    }
                }
            },
        }
    }
    true
}

pub const IS_VISTA_OR_LATER: &[Check] = &[("KdCopyDataBlock", None, true)];

pub const IS_WINDOWS_8_OR_LATER: &[Check] = &[("_HANDLE_TABLE", Some("HandleCount"), false)];

pub const IS_WINDOWS_8_1_OR_LATER: &[Check] = &[("_KPRCB", Some("PendingTickFlags"), true)];

pub const IS_WINDOWS_10: &[Check] = &[("ObHeaderCookie", None, true)];

pub const IS_WIN10_UP_TO_15063: &[Check] = &[
    ("ObHeaderCookie", None, true),
    ("_HANDLE_TABLE", Some("HandleCount"), false),
    ("_EPROCESS", Some("KeepAliveCounter"), true),
];

pub const IS_WIN10_15063: &[Check] = &[
    ("ObHeaderCookie", None, true),
    ("_HANDLE_TABLE", Some("HandleCount"), false),
    ("_EPROCESS", Some("KeepAliveCounter"), false),
    ("_EPROCESS", Some("ControlFlowGuardEnabled"), true),
];

pub const IS_WIN10_15063_OR_LATER: &[Check] = &[
    ("ObHeaderCookie", None, true),
    ("_HANDLE_TABLE", Some("HandleCount"), false),
    ("_EPROCESS", Some("KeepAliveCounter"), false),
];

pub const IS_WIN10_16299_OR_LATER: &[Check] = &[
    ("ObHeaderCookie", None, true),
    ("_HANDLE_TABLE", Some("HandleCount"), false),
    ("_EPROCESS", Some("KeepAliveCounter"), false),
    ("_EPROCESS", Some("ControlFlowGuardEnabled"), false),
];

pub const IS_WIN10_17134_OR_LATER: &[Check] = &[
    ("_EPROCESS", Some("ProcessFirstResume"), true),
    ("_EPROCESS", Some("HighMemoryPriority"), true),
];

pub const IS_WIN10_17763_OR_LATER: &[Check] = &[
    ("_EPROCESS", Some("TrustletIdentity"), false),
    ("ParentSecurityDomain", None, true),
];

pub const IS_WIN10_18362_OR_LATER: &[Check] = &[
    ("ObHeaderCookie", None, true),
    ("_CM_CACHED_VALUE_INDEX", None, false),
    ("_WNF_PROCESS_CONTEXT", None, true),
];

pub const IS_WIN10_18363_OR_LATER: &[Check] = &[("_KQOS_GROUPING_SETS", None, true)];

pub const IS_WIN10_19041_OR_LATER: &[Check] = &[
    ("_EPROCESS", Some("TimerResolutionIgnore"), true),
    ("_EPROCESS", Some("VmProcessorHostTransition"), true),
    ("_KQOS_GROUPING_SETS", None, true),
];

pub const IS_WIN10_19577_OR_LATER: &[Check] = &[
    ("_EPROCESS", Some("PaeTop"), false),
    ("_EPROCESS", Some("IdealProcessorAssignmentBlock"), true),
];

pub const IS_WIN10_25398_OR_LATER: &[Check] = &[
    ("_EPROCESS", Some("MmSlabIdentity"), true),
    ("_EPROCESS", Some("EnableProcessImpersonationLogging"), true),
];

pub const IS_WIN10_10586_OR_LATER: &[Check] = &[
    ("_UNLOADED_DRIVERS", None, false),
    ("ObHeaderCookie", None, true),
];

pub const IS_WINDOWS_7_SP0: &[Check] = &[
    ("_EPROCESS", Some("VdmObjects"), true),
    ("_EPROCESS", Some("UmsScheduledThreads"), false),
    ("_EPROCESS", Some("QuotaUsage"), false),
    ("_EPROCESS", Some("WnfContext"), false),
];

pub const IS_WINDOWS_7_SP1: &[Check] = &[
    ("_EPROCESS", Some("VdmObjects"), false),
    ("_EPROCESS", Some("UmsScheduledThreads"), true),
    ("_EPROCESS", Some("QuotaUsage"), false),
    ("_EPROCESS", Some("WnfContext"), false),
];
