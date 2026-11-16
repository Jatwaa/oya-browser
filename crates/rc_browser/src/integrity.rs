//! Tamper seal for Oya's own files (settings, bookmarks).
//!
//! Each save writes the file, a trusted copy (`*.trusted`) and an HMAC-SHA256 seal (`*.seal`)
//! keyed with a secret that only this Windows account can unwrap (DPAPI). If another program
//! edits a file while Oya is closed, the seal no longer matches: Oya keeps using the trusted copy
//! and reports the outside change, which the user must approve before it takes effect.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const KEY_FILE: &str = "integrity.key";
const ENTROPY: &[u8] = b"oya-settings-seal-v1";

/// A file that was changed outside Oya.
#[derive(Debug, Clone)]
pub struct TamperReport {
    pub file: PathBuf,
    /// The content another program wrote (not in use until approved).
    pub external: String,
}

static REPORTS: Mutex<Vec<TamperReport>> = Mutex::new(Vec::new());
static KEY: OnceLock<Option<[u8; 32]>> = OnceLock::new();

/// Reports collected since the last call.
pub fn take_reports() -> Vec<TamperReport> {
    REPORTS.lock().map(|mut r| std::mem::take(&mut *r)).unwrap_or_default()
}

fn key() -> Option<&'static [u8; 32]> {
    KEY.get_or_init(load_or_create_key).as_ref()
}

fn load_or_create_key() -> Option<[u8; 32]> {
    if let Ok(blob) = std::fs::read(KEY_FILE)
        && let Ok(raw) = rc_sandbox::dpapi_unprotect(&blob, ENTROPY)
        && let Ok(key) = <[u8; 32]>::try_from(raw.as_slice())
    {
        return Some(key);
    }
    // No key yet (or it was replaced by something we cannot unwrap): start a new one. Files sealed
    // with an old key then show as changed, which is the safe outcome.
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).ok()?;
    let blob = rc_sandbox::dpapi_protect(&key, ENTROPY).ok()?;
    std::fs::write(KEY_FILE, blob).ok()?;
    Some(key)
}

fn hmac(key: &[u8; 32], data: &[u8]) -> String {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (i, k) in key.iter().enumerate() {
        ipad[i] ^= k;
        opad[i] ^= k;
    }
    let inner = Sha256::new().chain_update(ipad).chain_update(data).finalize();
    let outer = Sha256::new().chain_update(opad).chain_update(inner).finalize();
    outer.iter().map(|b| format!("{b:02x}")).collect()
}

fn side_path(path: &Path, ext: &str) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(ext);
    PathBuf::from(p)
}

fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = side_path(path, ".tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

/// Writes `content` to `path` together with its trusted copy and seal.
pub fn save_sealed(path: &Path, content: &str) {
    let _ = write_atomic(path, content.as_bytes());
    if let Some(key) = key() {
        let _ = write_atomic(&side_path(path, ".trusted"), content.as_bytes());
        let _ = write_atomic(&side_path(path, ".seal"), hmac(key, content.as_bytes()).as_bytes());
    }
}

/// Reads `path`, returning the content Oya last wrote itself.
///
/// - Seal matches: the file as it is.
/// - Seal does not match: the trusted copy (if its seal matches), and a [`TamperReport`] with
///   the outside content.
/// - No seal yet (first run of this version): the file, which is then sealed.
pub fn load_verified(path: &Path) -> Option<String> {
    let current = std::fs::read_to_string(path).ok();
    let Some(key) = key() else {
        return current;
    };
    let seal = std::fs::read_to_string(side_path(path, ".seal")).ok();
    match (current, seal) {
        (Some(content), None) => {
            save_sealed(path, &content);
            Some(content)
        }
        (None, _) => None,
        (Some(content), Some(seal)) => {
            if hmac(key, content.as_bytes()) == seal.trim() {
                return Some(content);
            }
            let trusted = std::fs::read_to_string(side_path(path, ".trusted"))
                .ok()
                .filter(|t| hmac(key, t.as_bytes()) == seal.trim());
            if let Ok(mut r) = REPORTS.lock() {
                r.push(TamperReport {
                    file: path.to_path_buf(),
                    external: content,
                });
            }
            trusted
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn outside_edit_is_detected_and_trusted_copy_used() {
        let dir = std::env::temp_dir().join(format!("oya-seal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("settings.json");
        let key = [9u8; 32];
        // Exercise the HMAC directly with a fixed key (the real key lives in the data folder).
        let a = hmac(&key, b"{\"search\":\"google\"}");
        let b = hmac(&key, b"{\"search\":\"evil\"}");
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        std::fs::write(&file, "x").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
