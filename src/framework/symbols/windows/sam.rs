//! Decrypting the password hashes stored in the SAM.
//!
//! Windows protects the SAM with a key split across four registry keys, and
//! then encrypts each account's hashes with a key derived from that plus the
//! account's RID. Recovering a hash therefore means three steps:
//!
//! 1. reassemble the boot key from the `Lsa` subkeys' class names,
//! 2. derive the hashed boot key from the domain's `F` value,
//! 3. decrypt each account's `V` value and undo the RID-keyed DES layer.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use aes::cipher::{BlockCipherDecrypt, KeyInit};
use md5::{Digest, Md5};

use crate::error::{Result, VolatilityError};

/// The four `Lsa` subkeys whose class names carry the boot key, in the order
/// their characters appear in the scrambled key.
pub const BOOTKEY_SUBKEYS: [&str; 4] = ["JD", "Skew1", "GBG", "Data"];

/// The permutation Windows applies to the assembled key bytes.
const BOOTKEY_PERMUTATION: [usize; 16] =
    [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7];

/// Salts mixed into the hashed boot key derivation. These are fixed strings
/// compiled into Windows, including their trailing NUL.
const AQWERTY: &[u8] = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0";
const ANUM: &[u8] = b"0123456789012345678901234567890123456789\0";

/// The DES-encrypted form of an empty password, used to recognise accounts with
/// no password set.
pub const EMPTY_LM_HASH: [u8; 16] = [
    0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE, 0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE,
];
pub const EMPTY_NT_HASH: [u8; 16] = [
    0x31, 0xD6, 0xCF, 0xE0, 0xD1, 0x6A, 0xE9, 0x31, 0xB7, 0x3C, 0x59, 0xD7, 0xE0, 0xC0, 0x89, 0xC0,
];

/// RC4, implemented directly.
///
/// The algorithm is a few lines and has published test vectors, which makes it
/// cheaper to implement and verify here than to track a crate's API changes.
fn rc4(key: &[u8], data: &mut [u8]) {
    let mut state: [u8; 256] = [0; 256];
    for (index, byte) in state.iter_mut().enumerate() {
        *byte = index as u8;
    }

    // Key scheduling: permute the state according to the key.
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j
            .wrapping_add(state[i])
            .wrapping_add(key[i % key.len()]);
        state.swap(i, j as usize);
    }

    // Generation: emit a keystream byte per input byte and XOR it in.
    let (mut i, mut j) = (0u8, 0u8);
    for byte in data.iter_mut() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(state[i as usize]);
        state.swap(i as usize, j as usize);
        let k = state[(state[i as usize].wrapping_add(state[j as usize])) as usize];
        *byte ^= k;
    }
}

/// AES-128 in CBC mode, decrypt only.
///
/// Each block is decrypted and then XORed with the preceding ciphertext block,
/// which is all CBC decryption is.
fn aes_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = aes::Aes128::new(key.into());
    let mut previous = *iv;
    let mut output = Vec::with_capacity(data.len());

    for chunk in data.chunks_exact(16) {
        let ciphertext: [u8; 16] = chunk.try_into().expect("chunks_exact yields 16 bytes");
        let mut block = ciphertext.into();
        cipher.decrypt_block(&mut block);

        for (index, byte) in block.iter().enumerate() {
            output.push(byte ^ previous[index]);
        }
        previous = ciphertext;
    }
    output
}

/// Reassemble the boot key from the four class-name fragments.
///
/// Each fragment is eight hex characters. Together they form sixteen bytes that
/// are then permuted into the real key.
pub fn assemble_bootkey(fragments: &[String; 4]) -> Result<[u8; 16]> {
    let joined: String = fragments.concat();
    if joined.len() != 32 {
        return Err(VolatilityError::Other(format!(
            "Boot key fragments are {} characters, expected 32",
            joined.len()
        )));
    }

    let scrambled = hex::decode(&joined)
        .map_err(|_| VolatilityError::Other("Boot key fragments are not hexadecimal".to_string()))?;

    let mut bootkey = [0u8; 16];
    for (position, source) in BOOTKEY_PERMUTATION.iter().enumerate() {
        bootkey[position] = scrambled[*source];
    }
    Ok(bootkey)
}

/// Which encryption the SAM uses, taken from the `F` value's revision field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamEncryption {
    /// Windows 2000 through 8.1.
    Rc4,
    /// Windows 10 and later.
    Aes,
}

/// Derive the hashed boot key from the domain's `F` value.
pub fn hashed_bootkey(f_value: &[u8], bootkey: &[u8; 16]) -> Result<([u8; 16], SamEncryption)> {
    if f_value.len() < 0xA0 {
        return Err(VolatilityError::Other(
            "Domain F value is too short to contain a key".to_string(),
        ));
    }

    // The revision at offset 0x68 distinguishes the two schemes.
    let revision = f_value[0x68];
    match revision {
        1 => {
            // Windows salts the key with the domain's own random bytes and two
            // fixed strings before running RC4 over the stored key material.
            let mut hasher = Md5::new();
            hasher.update(&f_value[0x70..0x80]);
            hasher.update(AQWERTY);
            hasher.update(bootkey);
            hasher.update(ANUM);
            let key = hasher.finalize();

            let mut buffer = f_value[0x80..0xA0].to_vec();
            rc4(&key, &mut buffer);

            let mut hashed = [0u8; 16];
            hashed.copy_from_slice(&buffer[..16]);
            Ok((hashed, SamEncryption::Rc4))
        }
        2 | 3 => {
            // The newer scheme stores an IV alongside the ciphertext and uses
            // AES in CBC mode with the boot key directly.
            if f_value.len() < 0xD0 {
                return Err(VolatilityError::Other(
                    "Domain F value is too short for the AES layout".to_string(),
                ));
            }
            let iv: [u8; 16] = f_value[0x78..0x88].try_into().unwrap();
            let ciphertext = &f_value[0x88..0xA8];

            let decrypted = aes_cbc_decrypt(bootkey, &iv, ciphertext);
            if decrypted.len() < 16 {
                return Err(VolatilityError::Other(
                    "Domain key decrypted to too few bytes".to_string(),
                ));
            }

            let mut hashed = [0u8; 16];
            hashed.copy_from_slice(&decrypted[..16]);
            Ok((hashed, SamEncryption::Aes))
        }
        other => Err(VolatilityError::Other(format!(
            "Unknown SAM revision {other}"
        ))),
    }
}

/// Expand a seven-byte key into the eight-byte form DES expects.
///
/// DES keys carry a parity bit in each byte, so 56 bits of key material are
/// spread across 64 bits.
fn expand_des_key(key: &[u8]) -> [u8; 8] {
    let mut expanded = [0u8; 8];
    expanded[0] = key[0] >> 1;
    expanded[1] = ((key[0] & 0x01) << 6) | (key[1] >> 2);
    expanded[2] = ((key[1] & 0x03) << 5) | (key[2] >> 3);
    expanded[3] = ((key[2] & 0x07) << 4) | (key[3] >> 4);
    expanded[4] = ((key[3] & 0x0F) << 3) | (key[4] >> 5);
    expanded[5] = ((key[4] & 0x1F) << 2) | (key[5] >> 6);
    expanded[6] = ((key[5] & 0x3F) << 1) | (key[6] >> 7);
    expanded[7] = key[6] & 0x7F;

    // Each byte's low bit is parity, so the key material is shifted up.
    for byte in expanded.iter_mut() {
        *byte <<= 1;
    }
    expanded
}

/// Derive the two DES keys an account's RID produces.
pub fn rid_des_keys(rid: u32) -> ([u8; 8], [u8; 8]) {
    let bytes = rid.to_le_bytes();
    // The RID's four bytes are repeated to fill each seven-byte key.
    let first = [
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[0], bytes[1], bytes[2],
    ];
    let second = [
        bytes[3], bytes[0], bytes[1], bytes[2], bytes[3], bytes[0], bytes[1],
    ];
    (expand_des_key(&first), expand_des_key(&second))
}

/// Remove the RID-keyed DES layer from a hash.
pub fn decrypt_hash_des(encrypted: &[u8; 16], rid: u32) -> [u8; 16] {
    let (key1, key2) = rid_des_keys(rid);
    let mut output = [0u8; 16];

    // The two halves are encrypted under different keys.
    let cipher1 = des::Des::new((&key1).into());
    let first: [u8; 8] = encrypted[..8].try_into().unwrap();
    let mut block = first.into();
    cipher1.decrypt_block(&mut block);
    output[..8].copy_from_slice(&block);

    let cipher2 = des::Des::new((&key2).into());
    let second: [u8; 8] = encrypted[8..].try_into().unwrap();
    let mut block = second.into();
    cipher2.decrypt_block(&mut block);
    output[8..].copy_from_slice(&block);

    output
}

/// Remove the outer, boot-key-derived layer from a hash stored the older way.
///
/// The key is derived from the hashed boot key, the account's identifier and a
/// fixed word naming which of the two hashes is being read, so the same stored
/// bytes decrypt differently for the two.
pub fn decrypt_single_hash(
    rid: u32,
    hashed_bootkey: &[u8; 16],
    encrypted: &[u8],
    salt: &[u8],
) -> Option<[u8; 16]> {
    if encrypted.len() < 16 {
        return None;
    }
    let mut hasher = Md5::new();
    hasher.update(&hashed_bootkey[..16]);
    hasher.update(rid.to_le_bytes());
    hasher.update(salt);
    let key = hasher.finalize();

    let mut buffer = encrypted[..16].to_vec();
    rc4(&key, &mut buffer);

    let mut obfuscated = [0u8; 16];
    obfuscated.copy_from_slice(&buffer);
    Some(decrypt_hash_des(&obfuscated, rid))
}

/// Remove the outer layer from a hash stored the newer way.
///
/// The newer layout carries its own salt, which is used as the initialisation
/// vector rather than being mixed into a key.
pub fn decrypt_single_salted_hash(
    rid: u32,
    hashed_bootkey: &[u8; 16],
    encrypted: &[u8],
    salt: &[u8],
) -> Option<[u8; 16]> {
    if salt.len() < 16 || encrypted.is_empty() {
        return None;
    }
    let iv: [u8; 16] = salt[..16].try_into().ok()?;
    let decrypted = aes_cbc_decrypt(hashed_bootkey, &iv, encrypted);
    if decrypted.len() < 16 {
        return None;
    }
    let mut obfuscated = [0u8; 16];
    obfuscated.copy_from_slice(&decrypted[..16]);
    Some(decrypt_hash_des(&obfuscated, rid))
}

pub const LM_SALT: &[u8] = b"LMPASSWORD\0";
pub const NT_SALT: &[u8] = b"NTPASSWORD\0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootkey_assembly_permutes_the_fragments() {
        let fragments = [
            "00112233".to_string(),
            "44556677".to_string(),
            "8899aabb".to_string(),
            "ccddeeff".to_string(),
        ];
        let bootkey = assemble_bootkey(&fragments).unwrap();

        // The permutation moves the scrambled byte at each listed index into
        // the corresponding output position.
        let scrambled: Vec<u8> = (0x00..=0xFFu8).step_by(0x11).collect();
        for (position, source) in BOOTKEY_PERMUTATION.iter().enumerate() {
            assert_eq!(bootkey[position], scrambled[*source]);
        }
    }

    #[test]
    fn bootkey_assembly_rejects_malformed_fragments() {
        let short = [
            "0011".to_string(),
            "44556677".to_string(),
            "8899aabb".to_string(),
            "ccddeeff".to_string(),
        ];
        assert!(assemble_bootkey(&short).is_err());
    }

    #[test]
    fn des_key_expansion_spreads_seven_bytes_over_eight() {
        // A key of all zeroes expands to all zeroes.
        assert_eq!(expand_des_key(&[0u8; 7]), [0u8; 8]);

        // Every output byte has its parity bit clear, since the material is
        // shifted up by one.
        let expanded = expand_des_key(&[0xFF; 7]);
        assert!(expanded.iter().all(|byte| byte & 0x01 == 0));
    }

    #[test]
    fn rid_keys_differ_from_each_other() {
        let (first, second) = rid_des_keys(500);
        assert_ne!(first, second);
        // The same RID always produces the same pair.
        assert_eq!(rid_des_keys(500), (first, second));
    }

    #[test]
    fn rc4_matches_its_published_test_vector() {
        // The vector from RFC 6229: key "Key", plaintext "Plaintext".
        let mut data = b"Plaintext".to_vec();
        rc4(b"Key", &mut data);
        assert_eq!(hex::encode(&data), "bbf316e8d940af0ad3");

        // RC4 is its own inverse, so applying it again restores the input.
        rc4(b"Key", &mut data);
        assert_eq!(&data, b"Plaintext");
    }

    #[test]
    fn aes_cbc_chains_each_block_into_the_next() {
        // Decrypting two identical ciphertext blocks must give different
        // plaintext, since the second is XORed with the first ciphertext.
        let key = [0x42u8; 16];
        let iv = [0u8; 16];
        let ciphertext = [0xAAu8; 32];
        let decrypted = aes_cbc_decrypt(&key, &iv, &ciphertext);
        assert_eq!(decrypted.len(), 32);
        assert_ne!(decrypted[..16], decrypted[16..]);
    }

    #[test]
    fn empty_password_hashes_are_the_documented_constants() {
        // These are the published values for an unset password. A regression
        // here would make every empty-password account unrecognisable.
        assert_eq!(hex::encode(EMPTY_NT_HASH), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(hex::encode(EMPTY_LM_HASH), "aad3b435b51404eeaad3b435b51404ee");
    }
}

/// Derive the LSA key, which protects the system's stored secrets.
///
/// Windows 2000-era systems store it under `PolSecretEncryptionKey` protected
/// by a repeated-MD5 construction. Later systems use `PolEKList` with AES.
pub fn lsa_key(policy_value: &[u8], bootkey: &[u8; 16], is_vista_or_later: bool) -> Result<Vec<u8>> {
    if is_vista_or_later {
        // The value opens with a 32-byte header, then the IV, then ciphertext.
        if policy_value.len() < 0x40 {
            return Err(VolatilityError::Other(
                "Policy value is too short for the AES layout".to_string(),
            ));
        }
        let decrypted = decrypt_lsa_aes(&policy_value[0x3C..], bootkey)?;
        // The key itself sits 68 bytes into the decrypted blob.
        if decrypted.len() < 68 + 32 {
            return Err(VolatilityError::Other(
                "Decrypted policy blob is too short".to_string(),
            ));
        }
        Ok(decrypted[68..100].to_vec())
    } else {
        if policy_value.len() < 0x60 {
            return Err(VolatilityError::Other(
                "Policy value is too short for the RC4 layout".to_string(),
            ));
        }
        // The key is unwrapped by RC4 under a digest of the boot key repeated
        // a thousand times over the value's own salt.
        let mut hasher = Md5::new();
        hasher.update(bootkey);
        for _ in 0..1000 {
            hasher.update(&policy_value[0x3C..0x4C]);
        }
        let key = hasher.finalize();

        let mut buffer = policy_value[0x10..0x3C].to_vec();
        rc4(&key, &mut buffer);
        // The secret key is the second sixteen bytes of the unwrapped blob.
        Ok(buffer[0x10..0x20].to_vec())
    }
}

/// Decrypt an LSA blob using the AES scheme later Windows versions use.
///
/// The key is a SHA-256 digest of the base key and the blob's own salt, run a
/// thousand times, and the blob is then decrypted in ECB mode.
pub fn decrypt_lsa_aes(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::BlockCipherDecrypt;
    use sha2::{Digest as Sha2Digest, Sha256};

    if data.len() < 32 {
        return Err(VolatilityError::Other(
            "LSA blob is too short to decrypt".to_string(),
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(key);
    for _ in 0..1000 {
        hasher.update(&data[..32]);
    }
    let derived = hasher.finalize();
    // SHA-256 always yields 32 bytes, which is exactly an AES-256 key.
    let derived: [u8; 32] = derived
        .as_slice()
        .try_into()
        .expect("SHA-256 produces 32 bytes");

    let cipher = aes::Aes256::new(&derived.into());
    let mut output = Vec::with_capacity(data.len() - 32);

    // The blob after the salt is a whole number of blocks, decrypted
    // independently of each other.
    for chunk in data[32..].chunks_exact(16) {
        let block: [u8; 16] = chunk.try_into().expect("chunks_exact yields 16 bytes");
        let mut block = block.into();
        cipher.decrypt_block(&mut block);
        output.extend_from_slice(&block);
    }
    Ok(output)
}

/// Decrypt one LSA secret under the derived key.
pub fn decrypt_secret(secret: &[u8], lsa_key: &[u8], is_vista_or_later: bool) -> Result<Vec<u8>> {
    if is_vista_or_later {
        let decrypted = decrypt_lsa_aes(secret, lsa_key)?;
        // The plaintext is length-prefixed, with the value following a header.
        if decrypted.len() < 16 {
            return Ok(decrypted);
        }
        let length = u32::from_le_bytes(decrypted[..4].try_into().unwrap()) as usize;
        Ok(decrypted
            .get(16..16 + length.min(decrypted.len().saturating_sub(16)))
            .unwrap_or_default()
            .to_vec())
    } else {
        // The older scheme applies DES in a chain keyed by successive slices of
        // the LSA key, which is not reimplemented here.
        Err(VolatilityError::Other(
            "Pre-Vista LSA secret decryption is not supported".to_string(),
        ))
    }
}
