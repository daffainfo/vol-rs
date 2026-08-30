//! Recover cached domain credentials.
//!
//! Windows caches a verifier for each domain account that has logged in, so the
//! machine can authenticate them while disconnected. The cache entries are
//! encrypted under the `NL$KM` LSA secret.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context};
use crate::framework::layers::registry::RegistryHive;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::windows::registry::{read_key, subkeys, values, RegistryKey};
use crate::framework::symbols::windows::sam::{
    assemble_bootkey, decrypt_lsa_aes, decrypt_secret, lsa_key, BOOTKEY_SUBKEYS,
};

pub struct CacheDump;

/// The header preceding each cache entry's variable-length fields.
const ENTRY_HEADER_SIZE: usize = 0x60;

impl Plugin for CacheDump {
    fn name(&self) -> &'static str {
        "windows.registry.cachedump.Cachedump"
    }

    fn description(&self) -> &'static str {
        "Dumps lsa secrets from memory"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("Username"),
            Column::string("Domain"),
            Column::string("Domain name"),
            Column::string("Hash"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        // A hive that cannot be read leaves nothing to report rather than
        // failing the run: the secrets are simply not recoverable from this
        // image, which is what an empty table says.
        match self.gather(context, config) {
            Ok(grid) => Ok(grid),
            Err(error) => {
                log::warn!("Unable to recover secrets from this image: {error}");
                Ok(TreeGrid::new(self.columns()))
            }
        }
    }
}

impl CacheDump {
    fn gather(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let table = kernel.symbol_table_name.clone();

        let mut system_hive = None;
        let mut security_hive = None;
        for hive_object in super::list_hives(&context, &kernel)? {
            let Ok(hive) = super::open_hive(&context, &kernel, hive_object) else {
                continue;
            };
            let name = hive.hive_name().unwrap_or_default().to_ascii_uppercase();
            if name.ends_with("SYSTEM") {
                system_hive = Some(hive);
            } else if name.ends_with("SECURITY") {
                security_hive = Some(hive);
            }
        }

        let system_hive =
            system_hive.ok_or_else(|| VolatilityError::Other("No SYSTEM hive".to_string()))?;
        let security_hive =
            security_hive.ok_or_else(|| VolatilityError::Other("No SECURITY hive".to_string()))?;

        let bootkey = read_bootkey(&context, &system_hive, &table)?;
        let root = read_key(
            &context,
            &security_hive,
            &table,
            security_hive.root_cell_offset(),
            String::new(),
        )?;

        let policy = descend(&context, &security_hive, &table, root.clone(), &["Policy"])
            .ok_or_else(|| VolatilityError::Other("No Policy key".to_string()))?;
        let policy_children = subkeys(&context, &security_hive, &table, &policy)?;
        let modern = policy_children.iter().any(|key| {
            key.name()
                .map(|name| name.eq_ignore_ascii_case("PolEKList"))
                .unwrap_or(false)
        });
        if !modern {
            return Err(VolatilityError::Other(
                "Only Vista-and-later credential caches are supported".to_string(),
            ));
        }

        // The LSA key unwraps the NL$KM secret, which in turn unwraps the cache.
        let policy_value = policy_children
            .iter()
            .find(|key| {
                key.name()
                    .map(|name| name.eq_ignore_ascii_case("PolEKList"))
                    .unwrap_or(false)
            })
            .and_then(|key| values(&context, &security_hive, &table, key).ok())
            .and_then(|list| {
                list.into_iter()
                    .find(|value| value.name().map(|name| name.is_empty()).unwrap_or(false))
            })
            .ok_or_else(|| VolatilityError::Other("No PolEKList value".to_string()))?
            .data(&security_hive)?;

        let lsa = lsa_key(&policy_value, &bootkey, true)?;
        let nlkm = read_nlkm(&context, &security_hive, &table, &root, &lsa)?;

        // Each cached account is one value under the Cache key.
        let cache = descend(&context, &security_hive, &table, root, &["Cache"])
            .ok_or_else(|| VolatilityError::Other("No Cache key".to_string()))?;

        let mut grid = TreeGrid::new(self.columns());
        for value in values(&context, &security_hive, &table, &cache)? {
            let Ok(name) = value.name() else { continue };
            // NL$Control is bookkeeping rather than a cached credential.
            if !name.starts_with("NL$") || name == "NL$Control" {
                continue;
            }

            let data = value.data(&security_hive).unwrap_or_default();
            let Some(entry) = decode_entry(&data, &nlkm) else {
                continue;
            };

            grid.push(
                0,
                vec![
                    Value::string(entry.username),
                    Value::string(entry.domain),
                    Value::string(entry.domain_name),
                    Value::string(hex::encode(entry.hash)),
                ],
            )?;
        }
        Ok(grid)
    }
}

/// One decoded cache entry.
struct CacheEntry {
    username: String,
    domain: String,
    domain_name: String,
    hash: Vec<u8>,
}

/// Decode and decrypt one cache entry.
fn decode_entry(data: &[u8], nlkm: &[u8]) -> Option<CacheEntry> {
    if data.len() < ENTRY_HEADER_SIZE {
        return None;
    }

    let user_length = u16::from_le_bytes(data[0..2].try_into().ok()?) as usize;
    let domain_length = u16::from_le_bytes(data[2..4].try_into().ok()?) as usize;
    let domain_name_length = u16::from_le_bytes(data[0x3C..0x3E].try_into().ok()?) as usize;

    // An empty slot has no user name.
    if user_length == 0 || user_length > 512 {
        return None;
    }

    // The encrypted portion follows the header and is salted with its own IV,
    // which the header carries at offset 0x40.
    let encrypted = data.get(ENTRY_HEADER_SIZE..)?;
    let mut salted = data.get(0x40..0x50)?.to_vec();
    salted.resize(32, 0);
    salted.extend_from_slice(encrypted);

    let decrypted = decrypt_lsa_aes(&salted, nlkm).ok()?;

    // The plaintext opens with the hash, then the names, each padded to a
    // four-byte boundary.
    let hash = decrypted.get(..16)?.to_vec();
    let mut position = 72;

    let read_utf16 = |data: &[u8], at: usize, length: usize| -> String {
        let units: Vec<u16> = data
            .get(at..at + length)
            .unwrap_or_default()
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    };

    let username = read_utf16(&decrypted, position, user_length);
    position += (user_length + 3) & !3;
    let domain = read_utf16(&decrypted, position, domain_length);
    position += (domain_length + 3) & !3;
    let domain_name = read_utf16(&decrypted, position, domain_name_length);

    Some(CacheEntry {
        username,
        domain,
        domain_name,
        hash,
    })
}

/// Unwrap the NL$KM secret, which protects the credential cache.
fn read_nlkm(
    context: &Arc<Context>,
    hive: &RegistryHive,
    table: &str,
    root: &RegistryKey,
    lsa: &[u8],
) -> Result<Vec<u8>> {
    let secrets = descend(context, hive, table, root.clone(), &["Policy", "Secrets"])
        .ok_or_else(|| VolatilityError::Other("No Secrets key".to_string()))?;

    let nlkm_key = subkeys(context, hive, table, &secrets)?
        .into_iter()
        .find(|key| {
            key.name()
                .map(|name| name.eq_ignore_ascii_case("NL$KM"))
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            VolatilityError::Other("The NL$KM secret is not present".to_string())
        })?;

    let current = subkeys(context, hive, table, &nlkm_key)?
        .into_iter()
        .find(|child| {
            child
                .name()
                .map(|name| name.eq_ignore_ascii_case("CurrVal"))
                .unwrap_or(false)
        })
        .ok_or_else(|| VolatilityError::Other("NL$KM has no current value".to_string()))?;

    let encrypted = values(context, hive, table, &current)?
        .into_iter()
        .find(|value| value.name().map(|name| name.is_empty()).unwrap_or(false))
        .ok_or_else(|| VolatilityError::Other("NL$KM CurrVal is empty".to_string()))?
        .data(hive)?;

    decrypt_secret(&encrypted, lsa, true)
}

/// Reassemble the boot key from the SYSTEM hive.
fn read_bootkey(context: &Arc<Context>, hive: &RegistryHive, table: &str) -> Result<[u8; 16]> {
    let root = read_key(context, hive, table, hive.root_cell_offset(), String::new())?;
    let lsa = descend(context, hive, table, root, &["ControlSet001", "Control", "Lsa"])
        .ok_or_else(|| VolatilityError::Other("Could not find the Lsa key".to_string()))?;

    let children = subkeys(context, hive, table, &lsa)?;
    let mut fragments: [String; 4] = Default::default();

    for (position, wanted) in BOOTKEY_SUBKEYS.iter().enumerate() {
        let found = children
            .iter()
            .find(|child| {
                child
                    .name()
                    .map(|name| name.eq_ignore_ascii_case(wanted))
                    .unwrap_or(false)
            })
            .ok_or_else(|| {
                VolatilityError::Other(format!("Boot key subkey '{wanted}' is missing"))
            })?;
        fragments[position] = found.class_name(hive).ok_or_else(|| {
            VolatilityError::Other(format!("Boot key subkey '{wanted}' has no class name"))
        })?;
    }
    assemble_bootkey(&fragments)
}

/// Follow a path of subkey names from a starting key.
fn descend(
    context: &Arc<Context>,
    hive: &RegistryHive,
    table: &str,
    start: RegistryKey,
    path: &[&str],
) -> Option<RegistryKey> {
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
