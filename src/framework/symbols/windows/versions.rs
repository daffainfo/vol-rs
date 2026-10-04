//! Telling one release of Windows from another.
//!
//! A symbol file sometimes records the version of the binary it was built
//! from, and when it does that is what decides the release. When it does not,
//! the release is recognised instead by the types and symbols that release
//! introduced or removed. Each test below is the same test upstream applies,
//! in the same order.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::cmp::Ordering;
use std::sync::Arc;

use crate::framework::context::{Context, Module};

/// One test: a symbol or type name, an optional member of that type, and
/// whether it has to be there.
pub type Check = (&'static str, Option<&'static str>, bool);

/// How to tell whether a kernel is at or past some point in the release
/// history.
pub struct Distinguisher {
    /// Whether the recorded version is at or past the point. The version is
    /// the four parts of the binary's own version, which is only consulted
    /// when the symbol file records all four.
    pub version: fn([u64; 4]) -> bool,
    /// What the symbols have to look like when there is no recorded version.
    pub fallbacks: &'static [Check],
}

/// The ordering between a four part version and a shorter bound.
///
/// The bounds come from upstream, where they are tuples of two, three or four
/// parts compared against a tuple of four. A tuple comparison runs out of
/// parts before it runs out of ordering, so the longer tuple is the greater
/// one when every shared part is equal. That is why a bound of two parts is
/// never equal to a version of four, and so why upstream's tests for an exact
/// release never hold for a symbol file that records its version.
fn order(version: [u64; 4], bound: &[u64]) -> Ordering {
    for (left, right) in version.iter().zip(bound) {
        match left.cmp(right) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    version.len().cmp(&bound.len())
}

fn at_least(version: [u64; 4], bound: &[u64]) -> bool {
    order(version, bound) != Ordering::Less
}

fn below(version: [u64; 4], bound: &[u64]) -> bool {
    order(version, bound) == Ordering::Less
}

fn exactly(version: [u64; 4], bound: &[u64]) -> bool {
    order(version, bound) == Ordering::Equal
}

/// The version of the binary the symbol file was built from.
///
/// All four parts have to be there. Upstream unpacks the version into four
/// names and falls back to the structural tests when that fails, so a file
/// recording only three parts is treated as recording none.
pub fn pe_version(context: &Arc<Context>, kernel: &Module) -> Option<[u64; 4]> {
    let table = context
        .symbol_space
        .table(&kernel.symbol_table_name)
        .ok()?;
    let pe = table
        .metadata()
        .raw
        .get("windows")
        .and_then(|windows| windows.get("pe"))?;
    let part = |name: &str| pe.get(name).and_then(serde_json::Value::as_u64);
    Some([
        part("major")?,
        part("minor")?,
        part("revision")?,
        part("build")?,
    ])
}

/// Whether the kernel is at or past the point this distinguisher names.
pub fn matches(context: &Arc<Context>, kernel: &Module, point: &Distinguisher) -> bool {
    // Try the primary method based on the pe version in the ISF.
    if let Some(version) = pe_version(context, kernel) {
        return (point.version)(version);
    }
    // Fall back to the backup method, if necessary.
    matches_checks(context, kernel, point.fallbacks)
}

/// Whether every structural check holds for the kernel's symbols.
pub fn matches_checks(context: &Arc<Context>, kernel: &Module, checks: &[Check]) -> bool {
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

pub const IS_WINDOWS_XP: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[5, 1]) && below(v, &[5, 2]),
    fallbacks: &[
        ("KdCopyDataBlock", None, false),
        ("_HANDLE_TABLE", Some("HandleCount"), true),
    ],
};

pub const IS_WINDOWS_XP_SP2: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[5, 1]) && below(v, &[5, 2]),
    fallbacks: &[
        ("KdCopyDataBlock", None, false),
        ("_MMFREE_POOL_ENTRY", None, false),
        ("_HANDLE_TABLE", Some("HandleCount"), true),
    ],
};

pub const IS_WINDOWS_XP_SP3: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[5, 1]) && below(v, &[5, 2]),
    fallbacks: &[
        ("KdCopyDataBlock", None, false),
        ("_MMFREE_POOL_ENTRY", None, true),
        ("_HANDLE_TABLE", Some("HandleCount"), true),
    ],
};

pub const IS_XP_OR_2003: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[5, 1]) && below(v, &[6, 0]),
    fallbacks: &[
        ("KdCopyDataBlock", None, false),
        ("_HANDLE_TABLE", Some("HandleCount"), true),
    ],
};

pub const IS_2003: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[5, 2]) && below(v, &[5, 3]),
    fallbacks: &[
        ("KdCopyDataBlock", None, false),
        ("_HANDLE_TABLE", Some("HandleCount"), true),
        ("_MM_AVL_TABLE", None, true),
    ],
};

pub const IS_VISTA_OR_LATER: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[6, 0]),
    fallbacks: &[("KdCopyDataBlock", None, true)],
};

pub const IS_WINDOWS_8_OR_LATER: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[6, 2]),
    fallbacks: &[("_HANDLE_TABLE", Some("HandleCount"), false)],
};

pub const IS_WINDOWS_8_1_OR_LATER: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[6, 3]),
    fallbacks: &[("_KPRCB", Some("PendingTickFlags"), true)],
};

pub const IS_WINDOWS_10: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[10, 0]),
    fallbacks: &[("ObHeaderCookie", None, true)],
};

pub const IS_WIN10: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[10, 0]),
    fallbacks: &[
        ("ObHeaderCookie", None, true),
        ("_HANDLE_TABLE", Some("HandleCount"), false),
    ],
};

pub const IS_WIN10_10586_OR_LATER: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[10, 0, 10586]),
    fallbacks: &[
        ("_UNLOADED_DRIVERS", None, false),
        ("ObHeaderCookie", None, true),
    ],
};

pub const IS_WIN10_UP_TO_15063: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[10, 0]) && below(v, &[10, 0, 15063]),
    fallbacks: &[
        ("ObHeaderCookie", None, true),
        ("_HANDLE_TABLE", Some("HandleCount"), false),
        ("_EPROCESS", Some("KeepAliveCounter"), true),
    ],
};

pub const IS_WIN10_15063: Distinguisher = Distinguisher {
    version: |v| exactly(v, &[10, 0, 15063]),
    fallbacks: &[
        ("ObHeaderCookie", None, true),
        ("_HANDLE_TABLE", Some("HandleCount"), false),
        ("_EPROCESS", Some("KeepAliveCounter"), false),
        ("_EPROCESS", Some("ControlFlowGuardEnabled"), true),
    ],
};

pub const IS_WIN10_15063_OR_LATER: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[10, 0, 15063]),
    fallbacks: &[
        ("ObHeaderCookie", None, true),
        ("_HANDLE_TABLE", Some("HandleCount"), false),
        ("_EPROCESS", Some("KeepAliveCounter"), false),
    ],
};

pub const IS_WIN10_16299_OR_LATER: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[10, 0, 16299]),
    fallbacks: &[
        ("ObHeaderCookie", None, true),
        ("_HANDLE_TABLE", Some("HandleCount"), false),
        ("_EPROCESS", Some("KeepAliveCounter"), false),
        ("_EPROCESS", Some("ControlFlowGuardEnabled"), false),
    ],
};

pub const IS_WIN10_17134_OR_LATER: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[10, 0, 17134]),
    fallbacks: &[
        ("_EPROCESS", Some("ProcessFirstResume"), true),
        ("_EPROCESS", Some("HighMemoryPriority"), true),
    ],
};

pub const IS_WIN10_17735_OR_LATER: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[10, 0, 17735]),
    fallbacks: &[
        ("_EPROCESS", Some("VmProcessorHost"), true),
        ("_EPROCESS", Some("VdmObjects"), false),
    ],
};

pub const IS_WIN10_17763_OR_LATER: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[10, 0, 17763]),
    fallbacks: &[
        ("_EPROCESS", Some("TrustletIdentity"), false),
        ("ParentSecurityDomain", None, true),
    ],
};

pub const IS_WIN10_18362_OR_LATER: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[10, 0, 18362]),
    fallbacks: &[
        ("ObHeaderCookie", None, true),
        ("_CM_CACHED_VALUE_INDEX", None, false),
        ("_WNF_PROCESS_CONTEXT", None, true),
    ],
};

pub const IS_WIN10_18363_OR_LATER: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[10, 0, 18363]),
    fallbacks: &[("_KQOS_GROUPING_SETS", None, true)],
};

pub const IS_WIN10_19041_OR_LATER: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[10, 0, 19041]),
    fallbacks: &[
        ("_EPROCESS", Some("TimerResolutionIgnore"), true),
        ("_EPROCESS", Some("VmProcessorHostTransition"), true),
        ("_KQOS_GROUPING_SETS", None, true),
    ],
};

pub const IS_WIN10_19577_OR_LATER: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[10, 0, 19577]),
    fallbacks: &[
        ("_EPROCESS", Some("PaeTop"), false),
        ("_EPROCESS", Some("IdealProcessorAssignmentBlock"), true),
    ],
};

pub const IS_WIN10_25398_OR_LATER: Distinguisher = Distinguisher {
    version: |v| at_least(v, &[10, 0, 25398]),
    fallbacks: &[
        ("_EPROCESS", Some("MmSlabIdentity"), true),
        ("_EPROCESS", Some("EnableProcessImpersonationLogging"), true),
    ],
};

pub const IS_WINDOWS_7_SP0: Distinguisher = Distinguisher {
    version: |v| exactly(v, &[6, 1, 7600]),
    fallbacks: &[
        ("_EPROCESS", Some("VdmObjects"), true),
        ("_EPROCESS", Some("UmsScheduledThreads"), false),
        ("_EPROCESS", Some("QuotaUsage"), false),
        ("_EPROCESS", Some("WnfContext"), false),
    ],
};

pub const IS_WINDOWS_7_SP1: Distinguisher = Distinguisher {
    version: |v| exactly(v, &[6, 1, 7601]),
    fallbacks: &[
        ("_EPROCESS", Some("VdmObjects"), false),
        ("_EPROCESS", Some("UmsScheduledThreads"), true),
        ("_EPROCESS", Some("QuotaUsage"), false),
        ("_EPROCESS", Some("WnfContext"), false),
    ],
};

/// Windows 7, which upstream notes is really Windows 7 or earlier.
pub const IS_WINDOWS_7: Distinguisher = Distinguisher {
    version: |v| exactly(v, &[6, 1]),
    fallbacks: &[
        ("_OBJECT_HEADER", Some("TypeIndex"), true),
        ("_HANDLE_TABLE", Some("HandleCount"), true),
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shorter_bound_is_the_smaller_tuple_when_its_parts_agree() {
        // Upstream compares a four part version against bounds of two and
        // three parts, so a two part bound never names an exact release.
        assert!(at_least([6, 1, 7600, 21417], &[6, 0]));
        assert!(!exactly([6, 1, 7600, 21417], &[6, 1]));
        assert!(!exactly([10, 0, 15063, 0], &[10, 0, 15063]));
        assert!(exactly([10, 0, 15063, 0], &[10, 0, 15063, 0]));
    }

    #[test]
    fn a_version_inside_a_half_open_range_is_recognised() {
        let xp = [5, 1, 2600, 2180];
        assert!(at_least(xp, &[5, 1]) && below(xp, &[5, 2]));
        let server = [5, 2, 3790, 1830];
        assert!(!(at_least(server, &[5, 1]) && below(server, &[5, 2])));
        assert!(at_least(server, &[5, 1]) && below(server, &[6, 0]));
    }

    #[test]
    fn windows_10_builds_compare_part_by_part() {
        assert!((IS_WIN10_19041_OR_LATER.version)([10, 0, 19041, 1288]));
        assert!(!(IS_WIN10_19041_OR_LATER.version)([10, 0, 18363, 1049]));
        assert!((IS_WINDOWS_8_OR_LATER.version)([10, 0, 14393, 1770]));
        assert!(!(IS_WINDOWS_8_OR_LATER.version)([6, 1, 7601, 24000]));
    }
}
