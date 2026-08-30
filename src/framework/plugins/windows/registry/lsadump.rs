//! Recover the secrets the LSA stores in the registry.
//!
//! LSA secrets hold service account passwords, cached domain credentials and
//! machine account keys, material that is otherwise never written to disk in
//! recoverable form.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::sync::Arc;

use crate::error::{Result, VolatilityError};
use crate::framework::context::{Configuration, Context};
use crate::framework::layers::registry::RegistryHive;
use crate::framework::plugins::windows::kernel_module;
use crate::framework::plugins::{OperatingSystem, Plugin, Requirement};
use crate::framework::renderers::format_hints::multi_type_data;
use crate::framework::renderers::{Column, TreeGrid, Value};
use crate::framework::symbols::windows::registry::{read_key, subkeys, values, RegistryKey};
use crate::framework::symbols::windows::sam::{
    assemble_bootkey, decrypt_secret, lsa_key, BOOTKEY_SUBKEYS,
};

pub struct LsaDump;

impl Plugin for LsaDump {
    fn name(&self) -> &'static str {
        "windows.registry.lsadump.Lsadump"
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
            Column::string("Key"),
            Column::string("Secret"),
            Column::bytes("Hex"),
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

impl LsaDump {
    fn gather(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let table = kernel.symbol_table_name.clone();

        // Both the boot key and the secrets live in the SYSTEM and SECURITY
        // hives respectively.
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

        let system_hive = system_hive.ok_or_else(|| {
            VolatilityError::Other("Could not find the SYSTEM hive".to_string())
        })?;
        let security_hive = security_hive.ok_or_else(|| {
            VolatilityError::Other("Could not find the SECURITY hive".to_string())
        })?;

        let bootkey = read_bootkey(&context, &system_hive, &table)?;
        let security_root = read_key(
            &context,
            &security_hive,
            &table,
            security_hive.root_cell_offset(),
            String::new(),
        )?;

        // PolEKList marks a Vista-or-later system. The older key is only
        // present on systems predating it.
        let policy = descend(&context, &security_hive, &table, security_root.clone(), &["Policy"])
            .ok_or_else(|| {
                VolatilityError::Other("Could not find the Policy key".to_string())
            })?;

        let policy_children = subkeys(&context, &security_hive, &table, &policy)?;
        let modern = policy_children.iter().any(|key| {
            key.name()
                .map(|name| name.eq_ignore_ascii_case("PolEKList"))
                .unwrap_or(false)
        });

        let key_name = if modern { "PolEKList" } else { "PolSecretEncryptionKey" };
        let policy_key = policy_children
            .iter()
            .find(|key| {
                key.name()
                    .map(|name| name.eq_ignore_ascii_case(key_name))
                    .unwrap_or(false)
            })
            .ok_or_else(|| {
                VolatilityError::Other(format!("Could not find the {key_name} key"))
            })?;

        // The key material is the key's default (unnamed) value.
        let policy_value = values(&context, &security_hive, &table, policy_key)?
            .into_iter()
            .find(|value| value.name().map(|name| name.is_empty()).unwrap_or(false))
            .ok_or_else(|| {
                VolatilityError::Other(format!("The {key_name} key has no value"))
            })?
            .data(&security_hive)?;

        let lsa = lsa_key(&policy_value, &bootkey, modern)?;

        // Each secret is a subkey with a CurrVal holding the encrypted value.
        let secrets = descend(&context, &security_hive, &table, security_root, &["Policy", "Secrets"]);
        let mut grid = TreeGrid::new(self.columns());

        let Some(secrets) = secrets else {
            return Ok(grid);
        };

        for secret_key in subkeys(&context, &security_hive, &table, &secrets)? {
            let Ok(name) = secret_key.name() else { continue };

            let Some(current) = subkeys(&context, &security_hive, &table, &secret_key)?
                .into_iter()
                .find(|child| {
                    child
                        .name()
                        .map(|name| name.eq_ignore_ascii_case("CurrVal"))
                        .unwrap_or(false)
                })
            else {
                continue;
            };

            let Some(encrypted) = values(&context, &security_hive, &table, &current)?
                .into_iter()
                .find(|value| value.name().map(|name| name.is_empty()).unwrap_or(false))
            else {
                continue;
            };

            let data = encrypted.data(&security_hive).unwrap_or_default();
            // A secret that cannot be decrypted is still reported, with its
            // ciphertext, rather than being dropped silently.
            match decrypt_secret(&data, &lsa, modern) {
                Ok(plaintext) => grid.push(
                    0,
                    vec![
                        Value::string(name),
                        multi_type_data(&plaintext),
                        Value::Bytes(plaintext),
                    ],
                )?,
                Err(_) => grid.push(
                    0,
                    vec![Value::string(name), Value::unreadable(), Value::Bytes(data)],
                )?,
            }
        }
        Ok(grid)
    }
}

/// Reassemble the boot key from the SYSTEM hive.
fn read_bootkey(
    context: &Arc<Context>,
    hive: &RegistryHive,
    table: &str,
) -> Result<[u8; 16]> {
    let root = read_key(context, hive, table, hive.root_cell_offset(), String::new())?;
    let lsa = descend(
        context,
        hive,
        table,
        root,
        &["ControlSet001", "Control", "Lsa"],
    )
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
