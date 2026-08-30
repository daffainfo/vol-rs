//! Recover the password hashes stored in the SAM.
//!
//! This needs both hives: the SYSTEM hive holds the boot key, split across four
//! subkeys' class names, and the SAM hive holds the accounts encrypted under a
//! key derived from it.
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
    assemble_bootkey, decrypt_single_hash, decrypt_single_salted_hash, hashed_bootkey,
    SamEncryption,
    BOOTKEY_SUBKEYS, EMPTY_LM_HASH, EMPTY_NT_HASH, LM_SALT, NT_SALT,
};

pub struct HashDump;

impl Plugin for HashDump {
    fn name(&self) -> &'static str {
        "windows.registry.hashdump.Hashdump"
    }

    fn description(&self) -> &'static str {
        "Dumps user hashes from memory"
    }

    fn requirements(&self) -> Vec<Requirement> {
        vec![Requirement::kernel()]
    }

    fn operating_system(&self) -> OperatingSystem {
        OperatingSystem::Windows
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::string("User"),
            Column::int("rid"),
            Column::string("lmhash"),
            Column::string("nthash"),
        ]
    }

    fn run(&self, context: Arc<Context>, config: &Configuration) -> Result<TreeGrid> {
        let kernel = kernel_module(&context, config)?;
        let table = kernel.symbol_table_name.clone();

        // Open every hive once, then pick out the two that matter.
        let mut system_hive = None;
        let mut sam_hive = None;

        for hive_object in super::list_hives(&context, &kernel)? {
            let Ok(hive) = super::open_hive(&context, &kernel, hive_object) else {
                continue;
            };
            let name = hive.hive_name().unwrap_or_default().to_ascii_uppercase();
            if name.ends_with("SYSTEM") {
                system_hive = Some(hive);
            } else if name.ends_with("SAM") {
                sam_hive = Some(hive);
            }
        }

        let system_hive = system_hive.ok_or_else(|| {
            VolatilityError::Other(
                "Could not find the SYSTEM hive, which holds the boot key".to_string(),
            )
        })?;
        let sam_hive = sam_hive.ok_or_else(|| {
            VolatilityError::Other(
                "Could not find the SAM hive, which holds the account hashes".to_string(),
            )
        })?;

        let bootkey = read_bootkey(&context, &system_hive, &table)?;
        let (hashed, _encryption) = read_domain_key(&context, &sam_hive, &table, &bootkey)?;

        let mut grid = TreeGrid::new(self.columns());
        for (name, rid, v_value) in read_users(&context, &sam_hive, &table)? {
            let (lm, nt) = decrypt_user(&v_value, rid, &hashed);
            grid.push(
                0,
                vec![
                    Value::string(name),
                    Value::int(rid as i64),
                    // An account with no stored hash is reported with the
                    // documented empty-password value.
                    Value::string(hex::encode(lm.unwrap_or(EMPTY_LM_HASH))),
                    Value::string(hex::encode(nt.unwrap_or(EMPTY_NT_HASH))),
                ],
            )?;
        }
        Ok(grid)
    }
}

/// Reassemble the boot key from the four `Lsa` subkeys' class names.
fn read_bootkey(
    context: &Arc<Context>,
    hive: &RegistryHive,
    table: &str,
) -> Result<[u8; 16]> {
    let root = read_key(context, hive, table, hive.root_cell_offset(), String::new())?;

    // The control set the system actually booted from is what matters, but
    // ControlSet001 is the right answer on virtually every system.
    let lsa = descend(
        context,
        hive,
        table,
        root,
        &["ControlSet001", "Control", "Lsa"],
    )
    .ok_or_else(|| {
        VolatilityError::Other("Could not find the Lsa key in the SYSTEM hive".to_string())
    })?;

    let children = subkeys(context, hive, table, &lsa)?;
    let mut fragments: [String; 4] = Default::default();

    for (position, wanted) in BOOTKEY_SUBKEYS.iter().enumerate() {
        let found = children.iter().find(|child| {
            child
                .name()
                .map(|name| name.eq_ignore_ascii_case(wanted))
                .unwrap_or(false)
        });
        let Some(found) = found else {
            return Err(VolatilityError::Other(format!(
                "Boot key subkey '{wanted}' is missing"
            )));
        };
        fragments[position] = found.class_name(hive).ok_or_else(|| {
            VolatilityError::Other(format!("Boot key subkey '{wanted}' has no class name"))
        })?;
    }

    assemble_bootkey(&fragments)
}

/// Derive the hashed boot key from the SAM's domain record.
fn read_domain_key(
    context: &Arc<Context>,
    hive: &RegistryHive,
    table: &str,
    bootkey: &[u8; 16],
) -> Result<([u8; 16], SamEncryption)> {
    let root = read_key(context, hive, table, hive.root_cell_offset(), String::new())?;
    let account = descend(context, hive, table, root, &["SAM", "Domains", "Account"])
        .ok_or_else(|| {
            VolatilityError::Other("Could not find the Account key in the SAM hive".to_string())
        })?;

    let f_value = values(context, hive, table, &account)?
        .into_iter()
        .find(|value| value.name().map(|name| name == "F").unwrap_or(false))
        .ok_or_else(|| VolatilityError::Other("The Account key has no F value".to_string()))?;

    hashed_bootkey(&f_value.data(hive)?, bootkey)
}

/// Read every account's name, RID and `V` value.
fn read_users(
    context: &Arc<Context>,
    hive: &RegistryHive,
    table: &str,
) -> Result<Vec<(String, u32, Vec<u8>)>> {
    let root = read_key(context, hive, table, hive.root_cell_offset(), String::new())?;
    let users = descend(
        context,
        hive,
        table,
        root,
        &["SAM", "Domains", "Account", "Users"],
    )
    .ok_or_else(|| VolatilityError::Other("Could not find the Users key".to_string()))?;

    let mut accounts = Vec::new();
    for user_key in subkeys(context, hive, table, &users)? {
        let Ok(name) = user_key.name() else { continue };
        // Each account's key is named by its RID in hexadecimal. The Names
        // subkey is an index rather than an account.
        let Ok(rid) = u32::from_str_radix(&name, 16) else {
            continue;
        };

        let Some(v_value) = values(context, hive, table, &user_key)?
            .into_iter()
            .find(|value| value.name().map(|name| name == "V").unwrap_or(false))
        else {
            continue;
        };
        let data = v_value.data(hive)?;
        let username = read_username(&data).unwrap_or_else(|| format!("{rid}"));
        accounts.push((username, rid, data));
    }

    accounts.sort_by_key(|(_, rid, _)| *rid);
    Ok(accounts)
}

/// The account name, stored in the `V` value's variable-length section.
///
/// The value opens with a table of `(offset, length)` pairs. The second entry
/// describes the username, and its offsets are relative to the table's end.
fn read_username(v_value: &[u8]) -> Option<String> {
    const TABLE_END: usize = 0xCC;

    let offset = u32::from_le_bytes(v_value.get(0x0C..0x10)?.try_into().ok()?) as usize;
    let length = u32::from_le_bytes(v_value.get(0x10..0x14)?.try_into().ok()?) as usize;
    if length == 0 || length > 512 {
        return None;
    }

    let start = TABLE_END.checked_add(offset)?;
    let bytes = v_value.get(start..start + length)?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Some(String::from_utf16_lossy(&units))
}

/// Extract and decrypt one account's two hashes.
///
/// Each hash records its own layout: the older one is 20 bytes and keyed from
/// the account's identifier, the newer 56 and carries its own salt. An account
/// whose hash is stored in neither shape has none to report, and the caller
/// stands in the documented empty-password value.
fn decrypt_user(
    v_value: &[u8],
    rid: u32,
    hashed_bootkey: &[u8; 16],
) -> (Option<[u8; 16]>, Option<[u8; 16]>) {
    const TABLE_END: usize = 0xCC;

    let word = |at: usize| -> Option<usize> {
        Some(u32::from_le_bytes(v_value.get(at..at + 4)?.try_into().ok()?) as usize)
    };
    let slice = |from: usize, to: usize| -> Option<&[u8]> { v_value.get(from..to) };

    let lm = (|| {
        let offset = TABLE_END.checked_add(word(0x9C)?)?;
        let length = word(0xA0)?;
        match v_value.get(offset + 2)? {
            1 if length == 20 => decrypt_single_hash(
                rid,
                hashed_bootkey,
                slice(offset + 4, offset + 0x14)?,
                LM_SALT,
            ),
            2 if length == 56 => decrypt_single_salted_hash(
                rid,
                hashed_bootkey,
                slice(offset + 20, offset + 52)?,
                slice(offset + 4, offset + 20)?,
            ),
            _ => None,
        }
    })();

    let nt = (|| {
        let offset = TABLE_END.checked_add(word(0xA8)?)?;
        let length = word(0xAC)?;
        match v_value.get(offset + 2)? {
            1 if length == 20 => decrypt_single_hash(
                rid,
                hashed_bootkey,
                slice(offset + 4, offset + 20)?,
                NT_SALT,
            ),
            // The newer layout places the salt eight bytes in for this hash
            // and four for the other, so the two are not read alike.
            2 if length == 56 => decrypt_single_salted_hash(
                rid,
                hashed_bootkey,
                slice(offset + 24, offset + 56)?,
                slice(offset + 8, offset + 24)?,
            ),
            _ => None,
        }
    })();

    (lm, nt)
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
