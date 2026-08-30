//! Where the framework keeps what it works out between runs.
//!
//! Parsed symbol files, fetched debugging databases and the facts learned about
//! an image are all kept under one directory, which the command line can move
//! or empty.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

/// The directory in use, once something has asked for it.
fn chosen() -> &'static RwLock<Option<PathBuf>> {
    static CHOSEN: OnceLock<RwLock<Option<PathBuf>>> = OnceLock::new();
    CHOSEN.get_or_init(|| RwLock::new(None))
}

/// Use a different directory from here on.
pub fn set(path: PathBuf) {
    *chosen().write().unwrap() = Some(path);
}

/// Where cached items live, which is under the user's cache directory unless
/// they asked for somewhere else.
pub fn directory() -> Option<PathBuf> {
    if let Some(path) = chosen().read().unwrap().clone() {
        return Some(path);
    }
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    Some(base.join("vol-rs"))
}

/// A named place inside the cache.
pub fn entry(name: &str) -> Option<PathBuf> {
    directory().map(|base| base.join(name))
}

/// Throw away everything cached, so the next run works it all out again.
pub fn clear() {
    let Some(directory) = directory() else {
        return;
    };
    if !Path::new(&directory).is_dir() {
        return;
    }
    match std::fs::remove_dir_all(&directory) {
        Ok(()) => log::info!("Cleared the cache at {}", directory.display()),
        Err(error) => log::warn!(
            "Could not clear the cache at {}: {error}",
            directory.display()
        ),
    }
}

/// Whether the network may be used to fetch what is missing.
fn offline_flag() -> &'static RwLock<bool> {
    static OFFLINE: OnceLock<RwLock<bool>> = OnceLock::new();
    OFFLINE.get_or_init(|| RwLock::new(false))
}

pub fn set_offline(offline: bool) {
    *offline_flag().write().unwrap() = offline;
}

pub fn offline() -> bool {
    *offline_flag().read().unwrap()
}

/// Where symbol files are fetched from, when they are.
fn remote() -> &'static RwLock<Option<String>> {
    static REMOTE: OnceLock<RwLock<Option<String>>> = OnceLock::new();
    REMOTE.get_or_init(|| RwLock::new(None))
}

pub fn set_remote_url(url: String) {
    *remote().write().unwrap() = Some(url);
}

pub fn remote_url() -> Option<String> {
    remote().read().unwrap().clone()
}
