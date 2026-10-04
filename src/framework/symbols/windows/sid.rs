//! Security identifier formatting and the well-known name table.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use crate::error::{Result, VolatilityError};
use crate::framework::objects::Object;

/// Render a `_SID` in the conventional `S-1-5-21-...` string form.
///
/// The identifier authority is a six-byte big-endian value. The sub-authorities
/// are 32-bit little-endian and their count is stored in the header.
pub fn format_sid(sid: &Object) -> Result<String> {
    let revision = sid.member("Revision")?.as_u64()?;
    let count = sid.member("SubAuthorityCount")?.as_u64()?;

    // The same two checks the Windows API makes before calling a structure a
    // security identifier. Failing either means this is not one, and the
    // reference implementation stops reading the token rather than skipping
    // the entry.
    if revision & 0xF != 1 || count > 15 {
        return Err(VolatilityError::Other(
            "Not a security identifier".to_string(),
        ));
    }

    // The authority is six bytes, of which the reference implementation keeps
    // the last. Every authority Windows defines fits in that byte.
    let authority_bytes = sid.member("IdentifierAuthority")?.member("Value")?;
    let authority = authority_bytes.index(5)?.as_u64()?;

    let mut text = format!("S-{revision}-{authority}");

    // The sub-authorities are declared as an array of one and continue past
    // its end, so they are read by position rather than by index.
    let sub_authorities = sid.member("SubAuthority")?;
    let data = sid.context().layers.read(
        sub_authorities.native_layer_name(),
        sub_authorities.offset(),
        count as usize * 4,
        false,
    )?;
    for chunk in data.chunks_exact(4) {
        let value = u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4]));
        text.push_str(&format!("-{value}"));
    }
    Ok(text)
}

/// The conventional name for a well-known SID, if it has one.
///
/// Only the fixed SIDs are listed. Domain-relative SIDs carry a machine or
/// domain identifier and so cannot be named without the registry.
pub fn well_known_name(sid: &str) -> Option<&'static str> {
    Some(match sid {
        "S-1-0" => "Null Authority",
        "S-1-0-0" => "Nobody",
        "S-1-1" => "World Authority",
        "S-1-1-0" => "Everyone",
        "S-1-2" => "Local Authority",
        "S-1-2-0" => "Local",
        "S-1-3" => "Creator Authority",
        "S-1-3-0" => "Creator Owner",
        "S-1-3-1" => "Creator Group",
        "S-1-3-4" => "Owner Rights",
        "S-1-5" => "NT Authority",
        "S-1-5-1" => "Dialup",
        "S-1-5-2" => "Network",
        "S-1-5-3" => "Batch",
        "S-1-5-4" => "Interactive",
        "S-1-5-6" => "Service",
        "S-1-5-7" => "Anonymous",
        "S-1-5-9" => "Enterprise Domain Controllers",
        "S-1-5-10" => "Principal Self",
        "S-1-5-11" => "Authenticated Users",
        "S-1-5-12" => "Restricted Code",
        "S-1-5-13" => "Terminal Server Users",
        "S-1-5-14" => "Remote Interactive Logon",
        "S-1-5-18" => "Local System",
        "S-1-5-19" => "NT Authority",
        "S-1-5-20" => "NT Authority",
        "S-1-5-32-544" => "Administrators",
        "S-1-5-32-545" => "Users",
        "S-1-5-32-546" => "Guests",
        "S-1-5-32-547" => "Power Users",
        "S-1-5-32-548" => "Account Operators",
        "S-1-5-32-549" => "Server Operators",
        "S-1-5-32-550" => "Print Operators",
        "S-1-5-32-551" => "Backup Operators",
        "S-1-5-32-552" => "Replicator",
        "S-1-5-32-554" => "Pre-Windows 2000 Compatible Access",
        "S-1-5-32-555" => "Remote Desktop Users",
        "S-1-5-32-556" => "Network Configuration Operators",
        "S-1-5-32-558" => "Performance Monitor Users",
        "S-1-5-32-559" => "Performance Log Users",
        "S-1-5-32-562" => "Distributed COM Users",
        "S-1-5-32-568" => "IIS_IUSRS",
        "S-1-5-32-569" => "Cryptographic Operators",
        "S-1-5-32-573" => "Event Log Readers",
        "S-1-5-32-574" => "Certificate Service DCOM Access",
        "S-1-16-0" => "Untrusted Mandatory Level",
        "S-1-16-4096" => "Low Mandatory Level",
        "S-1-16-8192" => "Medium Mandatory Level",
        "S-1-16-8448" => "Medium Plus Mandatory Level",
        "S-1-16-12288" => "High Mandatory Level",
        "S-1-16-16384" => "System Mandatory Level",
        "S-1-16-20480" => "Protected Process Mandatory Level",
        _ => return None,
    })
}

/// The privileges a token can hold, indexed by their `_LUID` low part.
///
/// The values are fixed by Windows, and the descriptions are the ones the


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_sids_resolve_to_their_names() {
        assert_eq!(well_known_name("S-1-5-18"), Some("Local System"));
        assert_eq!(well_known_name("S-1-5-32-544"), Some("Administrators"));
        // A domain-relative SID cannot be named without the registry.
        assert_eq!(well_known_name("S-1-5-21-1004336348-1177238915-682003330-512"), None);
    }

}
