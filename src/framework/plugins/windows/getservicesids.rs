//! Derive the SID of each installed service from its name.
//!
//! Windows gives every service an account SID computed from its name rather
//! than assigned: the name is upper-cased, hashed with SHA-1, and the digest's
//! five words become the SID's sub-authorities under `S-1-5-80`. Recovering the
//! names from the registry therefore yields the SIDs without needing to find
//! them stored anywhere.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use sha1::{Digest, Sha1};

use crate::error::Result;
use crate::framework::context::{Configuration, Context};
use crate::framework::plugins::windows::kernel_module;
use crate::framework::symbols::windows::sid_data::is_known_service;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::windows::registry::{read_key, subkeys};

pub struct GetServiceSids;

/// Compute the service SID for a service name.
pub fn service_sid(name: &str) -> String {
    // The name is hashed upper-cased and as UTF-16, which is how Windows
    // canonicalises it before hashing.
    let upper: Vec<u16> = name.to_uppercase().encode_utf16().collect();
    let bytes: Vec<u8> = upper.iter().flat_map(|unit| unit.to_le_bytes()).collect();

    let digest = Sha1::digest(&bytes);

    // The twenty-byte digest becomes five little-endian 32-bit sub-authorities.
    let parts: Vec<String> = digest
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()).to_string())
        .collect();

    format!("S-1-5-80-{}", parts.join("-"))
}

impl Plugin for GetServiceSids {
    fn name(&self) -> &'static str {
        "windows.getservicesids.GetServiceSIDs"
    }

    fn description(&self) -> &'static str {
        "Lists process token sids."
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![Column::string("SID"), Column::string("Service")]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let table = kernel.symbol_table_name.clone();
        let mut grid = TreeGrid::new(self.columns());

        // Services are named in the machine's own hive, under whichever
        // control set the machine last booted from.
        for hive_object in super::registry::list_hives(&context, &kernel)? {
            let Ok(hive) = super::registry::open_hive(&context, &kernel, hive_object) else {
                continue;
            };
            if !hive
                .hive_name()
                .unwrap_or_default()
                .to_ascii_lowercase()
                .contains("machine\\system")
            {
                continue;
            }

            let Ok(root) = read_key(
                &context,
                &hive,
                &table,
                hive.root_cell_offset(),
                String::new(),
            ) else {
                continue;
            };

            let Some(services) = descend(
                &context,
                &hive,
                &table,
                root.clone(),
                &["CurrentControlSet", "Services"],
            )
            .or_else(|| descend(&context, &hive, &table, root, &["ControlSet001", "Services"]))
            else {
                continue;
            };

            for service in subkeys(&context, &hive, &table, &services).unwrap_or_default() {
                let Ok(name) = service.name() else { continue };
                // A service the well-known table already names is left to it.
                if is_known_service(&name) {
                    continue;
                }
                grid.push(
                    0,
                    vec![Value::string(service_sid(&name)), Value::string(name)],
                )?;
            }
        }
        Ok(grid)
    }
}

/// Follow a path of subkey names from a starting key.
fn descend(
    context: &Arc<Context>,
    hive: &crate::framework::layers::registry::RegistryHive,
    table: &str,
    start: crate::framework::symbols::windows::registry::RegistryKey,
    path: &[&str],
) -> Option<crate::framework::symbols::windows::registry::RegistryKey> {
    let mut current = start;
    for component in path {
        let children = subkeys(context, hive, table, &current).ok()?;
        current = children.into_iter().find(|child| {
            child
                .name()
                .map(|name| name.eq_ignore_ascii_case(component))
                .unwrap_or(false)
        })?;
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_sids_are_derived_from_the_name() {
        let sid = service_sid("TrustedInstaller");
        // The well-known SID for TrustedInstaller, which Windows documents.
        assert_eq!(
            sid,
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        );
    }

    #[test]
    fn the_name_is_hashed_case_insensitively() {
        assert_eq!(service_sid("trustedinstaller"), service_sid("TrustedInstaller"));
    }
}
