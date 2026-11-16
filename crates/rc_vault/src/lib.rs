#![forbid(unsafe_code)]

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64_URL};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Pre-`%APPDATA%` location (relative to the working directory). Only read for one-time migration.
const LEGACY_VAULT_FILE: &str = "logs/rustchrome_vault.json";
const VERIFIER_LABEL: &str = "vault:verifier";
const VERIFIER_PLAINTEXT: &[u8] = b"RUSTCHROME_VAULT_OK";

/// Minimum length of a new vault PIN / passphrase. Longer passphrases are strongly preferable.
pub const MIN_PIN_LEN: usize = 8;
/// Extra input for Windows data protection, so the blob is useless to other programs' DPAPI calls.
pub const DEVICE_ENTROPY: &[u8] = b"oya-vault-device-v1";

/// Binds vault keys to the current Windows account and PC (implemented with DPAPI by the
/// browser). A vault file copied elsewhere then cannot be opened, even with the right PIN.
pub trait DeviceProtector: Send {
    fn protect(&self, data: &[u8]) -> Result<Vec<u8>, String>;
    fn unprotect(&self, data: &[u8]) -> Result<Vec<u8>, String>;
}

/// How good a proposed PIN is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinStrength {
    /// 0 (very weak) to 4 (strong).
    pub score: u8,
    pub acceptable: bool,
    pub label: &'static str,
    pub advice: &'static str,
}

/// Rates a PIN / passphrase. Accepted only with at least [`MIN_PIN_LEN`] characters and not a
/// well-known, repeated or sequential pattern.
pub fn pin_strength(pin: &str) -> PinStrength {
    const COMMON: [&str; 16] = [
        "password", "password1", "passw0rd", "12345678", "123456789", "1234567890", "qwertyui",
        "qwerty123", "iloveyou", "11111111", "00000000", "abcdefgh", "letmein1", "welcome1",
        "admin123", "87654321",
    ];
    let len = pin.chars().count();
    let lower = pin.to_lowercase();
    let chars: Vec<char> = pin.chars().collect();
    let repeated = chars.windows(2).all(|w| w[0] == w[1]);
    let sequential = chars.len() > 2
        && (chars.windows(2).all(|w| w[1] as i32 - w[0] as i32 == 1)
            || chars.windows(2).all(|w| w[0] as i32 - w[1] as i32 == 1));
    let classes = [
        pin.chars().any(|c| c.is_ascii_lowercase()),
        pin.chars().any(|c| c.is_ascii_uppercase()),
        pin.chars().any(|c| c.is_ascii_digit()),
        pin.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|b| **b)
    .count();
    if len < MIN_PIN_LEN {
        return PinStrength {
            score: 0,
            acceptable: false,
            label: "Too short",
            advice: "Use at least 8 characters; a few words with numbers or symbols is best",
        };
    }
    if repeated || sequential || COMMON.contains(&lower.as_str()) {
        return PinStrength {
            score: 0,
            acceptable: false,
            label: "Too easy to guess",
            advice: "Avoid common, repeated or sequential PINs",
        };
    }
    let mut score = 1u8;
    if len >= 12 {
        score += 1;
    }
    if classes >= 2 {
        score += 1;
    }
    if classes >= 3 || len >= 16 {
        score += 1;
    }
    let label = match score {
        1 => "Fair",
        2 => "Good",
        3 => "Strong",
        _ => "Very strong",
    };
    PinStrength {
        score,
        acceptable: true,
        label,
        advice: "",
    }
}

/// Argon2id work for one PIN check, safe to run on another thread.
pub struct KeyJob {
    pin: Zeroizing<String>,
    salt: [u8; 32],
    kdf: KdfParams,
    device_secret: Option<Zeroizing<[u8; 32]>>,
    weak_pin: bool,
}

impl KeyJob {
    pub fn run(self) -> Result<DerivedKeys, VaultError> {
        let keys = derive_keys(
            &self.pin,
            &self.salt,
            self.kdf,
            self.device_secret.as_deref(),
        )?;
        Ok(DerivedKeys {
            keys,
            weak_pin: self.weak_pin,
        })
    }
}

/// Keys produced by a [`KeyJob`]; wiped when dropped.
pub struct DerivedKeys {
    keys: MasterKeys,
    weak_pin: bool,
}

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        wipe_keys(&mut self.keys);
    }
}

/// Key derivation for a new PIN, safe to run on another thread.
pub struct NewPinJob {
    job: KeyJob,
    device_blob: Option<Vec<u8>>,
}

impl NewPinJob {
    pub fn run(self) -> Result<NewPinKeys, VaultError> {
        let (salt, kdf) = (self.job.salt, self.job.kdf);
        let derived = self.job.run()?;
        Ok(NewPinKeys {
            derived,
            salt,
            kdf,
            device_blob: self.device_blob,
        })
    }
}

pub struct NewPinKeys {
    derived: DerivedKeys,
    salt: [u8; 32],
    kdf: KdfParams,
    device_blob: Option<Vec<u8>>,
}

/// Result of a Windows Hello prompt. Only this crate can create one.
pub struct HelloOutcome(BiometricPromptOutcome);

impl HelloOutcome {
    pub fn is_verified(&self) -> bool {
        matches!(self.0, BiometricPromptOutcome::Verified(_))
    }

    pub fn message(&self) -> &str {
        match &self.0 {
            BiometricPromptOutcome::Verified(m)
            | BiometricPromptOutcome::Unavailable(m)
            | BiometricPromptOutcome::Denied(m) => m,
        }
    }
}

/// Asks Windows Hello to confirm the user. Blocks until the prompt closes, so a UI should call it
/// from a worker thread.
pub fn windows_hello_prompt(reason: &str) -> HelloOutcome {
    HelloOutcome(trigger_windows_biometric_prompt(
        BiometricModality::Fingerprint,
        reason,
    ))
}
/// Wrong-PIN attempts allowed before a growing delay is enforced.
const MAX_FREE_ATTEMPTS: u32 = 5;

type MasterKeys = ([u8; 32], [u8; 32]);

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Vault is locked: enter your vault PIN to unlock it")]
    VerificationRequired,
    #[error("Biometric or PIN verification failed: {0}")]
    VerificationFailed(String),
    #[error("No vault PIN has been set yet: create one first")]
    PinNotSet,
    #[error("Invalid Vault PIN or corrupted ciphertext")]
    DecryptionFailed,
    #[error("Cryptographic operation failed: {0}")]
    Crypto(String),
    #[error("Could not write the vault file: {0}")]
    Io(String),
    #[error("No credential or passkey found for origin: {0}")]
    NotFound(String),
}

/// Supported identity verification modalities required before automated login or Passkey signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BiometricModality {
    Fingerprint,
    FacialScan,
    HandPalmScan,
    MasterPin,
    CrossDevicePasskey,
}

impl BiometricModality {
    pub fn all() -> &'static [BiometricModality] {
        &[
            BiometricModality::Fingerprint,
            BiometricModality::FacialScan,
            BiometricModality::HandPalmScan,
            BiometricModality::MasterPin,
            BiometricModality::CrossDevicePasskey,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            BiometricModality::Fingerprint => "Fingerprint Scan (Windows Hello / FIDO2)",
            BiometricModality::FacialScan => "3D Facial Recognition (Windows Hello IR)",
            BiometricModality::HandPalmScan => "Hand / Palm Vein Biometric Sensor",
            BiometricModality::MasterPin => "Vault Security PIN (Argon2id Hardware-Hardened)",
            BiometricModality::CrossDevicePasskey => {
                "Passkey on Another Device (Phone / QR / Security Key)"
            }
        }
    }
}

/// Argon2id cost parameters, stored in the vault file so they can be raised without breaking
/// vaults created with older settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    /// Parameters used by vault files written before the parameters were persisted.
    fn legacy() -> Self {
        Self {
            m_kib: 19456,
            t: 2,
            p: 1,
        }
    }

    /// Parameters applied whenever a PIN is set or changed.
    fn current() -> Self {
        #[cfg(test)]
        return Self {
            m_kib: 8192,
            t: 1,
            p: 1,
        };
        #[cfg(not(test))]
        Self {
            m_kib: 65536,
            t: 3,
            p: 1,
        }
    }
}

/// Encrypted password credential bound to an exact Web Origin via AEAD Additional Authenticated Data (AAD).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPasswordEntry {
    pub origin: String,
    pub username: String,
    /// Base64 of `aes_nonce(12) || xchacha_nonce(24) || XChaCha20Poly1305(AES256GCM(plaintext))`
    pub envelope_ciphertext_b64: String,
    pub created_at_ms: u64,
    pub auto_submit: bool,
}

/// WebAuthn / FIDO2 Passkey record with encrypted P-256 (`ES256`) private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyRecord {
    pub credential_id_b64url: String,
    pub rp_id: String,
    pub origin: String,
    pub user_name: String,
    pub user_handle_b64url: String,
    /// Public key uncompressed SEC1 bytes (Base64URL)
    pub public_key_b64url: String,
    /// Dual-AEAD encrypted 32-byte P-256 secret scalar
    pub encrypted_private_key_b64: String,
    pub sign_count: u32,
    pub created_at_ms: u64,
}

/// Output of a W3C WebAuthn `navigator.credentials.create({ publicKey })` ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnRegistrationResult {
    pub credential_id_b64url: String,
    pub client_data_json_b64url: String,
    pub authenticator_data_b64url: String,
    pub public_key_b64url: String,
    pub rp_id: String,
}

/// Output of a W3C WebAuthn `navigator.credentials.get({ publicKey })` ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnAssertionResult {
    pub credential_id_b64url: String,
    pub client_data_json_b64url: String,
    pub authenticator_data_b64url: String,
    pub signature_der_b64url: String,
    pub user_handle_b64url: String,
    pub sign_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedVault {
    pub version: u32,
    pub kdf_salt_b64: String,
    #[serde(default = "KdfParams::legacy")]
    pub kdf: KdfParams,
    pub pin_verifier_b64: String,
    /// DPAPI-protected 32-byte secret mixed into the keys (absent in older vaults).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_secret_b64: Option<String>,
    pub preferred_modality: BiometricModality,
    pub passwords: Vec<EncryptedPasswordEntry>,
    pub passkeys: Vec<PasskeyRecord>,
}

/// Password & Passkey Vault:
/// - **Argon2id** key derivation from the vault PIN (parameters stored in the vault file;
///   64 MiB / 3 passes for PINs set from this version on) -> 512-bit split key
/// - **Inner Cipher**: AES-256-GCM (256-bit key, 96-bit nonce, origin-bound AAD)
/// - **Outer Cipher**: XChaCha20-Poly1305 (256-bit key, 192-bit extended nonce, origin-bound AAD)
/// - **Randomness**: salts, nonces and passkey private keys come from the operating system CSPRNG
/// - **WebAuthn Passkeys**: NIST P-256 (`ES256`, COSE `-7`)
///
/// The keys come from the vault PIN combined with a secret that only this Windows account on this
/// PC can unwrap (DPAPI), so a copied vault file is useless elsewhere even with the PIN. There is
/// no default PIN: nothing can be stored until the user sets one, and nothing can be read or
/// written while locked. Windows Hello is an extra confirmation on top of an unlocked vault, never
/// a substitute for it.
pub struct SecurityVault {
    kdf_salt: [u8; 32],
    kdf: KdfParams,
    pin_verifier_b64: String,
    pub preferred_modality: BiometricModality,
    pub passwords: Vec<EncryptedPasswordEntry>,
    pub passkeys: Vec<PasskeyRecord>,
    /// Ephemeral 512-bit master key split into `k_aes` (32B) + `k_xchacha` (32B), present only while unlocked.
    master_keys: Option<MasterKeys>,
    /// True only immediately after a successful Biometric (Fingerprint/Face/Hand) or PIN scan for the active ceremony.
    pub identity_verified_for_ceremony: bool,
    pub last_verification_modality: Option<BiometricModality>,
    /// Where the vault is persisted. `None` keeps it in memory only (unit tests).
    path: Option<PathBuf>,
    failed_attempts: u32,
    locked_out_until: Option<Instant>,
    device: Option<Box<dyn DeviceProtector>>,
    device_secret_blob: Option<Vec<u8>>,
    /// Set when the last successful unlock used a PIN that no longer meets the rules.
    weak_pin: bool,
    last_pin_entry: Option<Instant>,
    last_activity: Instant,
}

impl Drop for SecurityVault {
    fn drop(&mut self) {
        self.lock();
    }
}

impl Default for SecurityVault {
    fn default() -> Self {
        Self::load_or_init()
    }
}

impl SecurityVault {
    /// `%APPDATA%\OyaBrowser\vault.json`, independent of the directory the browser was started from.
    pub fn default_vault_path() -> PathBuf {
        match std::env::var_os("APPDATA") {
            Some(base) if !base.is_empty() => {
                PathBuf::from(base).join("OyaBrowser").join("vault.json")
            }
            _ => PathBuf::from(LEGACY_VAULT_FILE),
        }
    }

    pub fn load_or_init() -> Self {
        let path = Self::default_vault_path();
        if path.exists() {
            if let Some(v) = Self::read_from(&path, path.clone()) {
                return v;
            }
            // Unreadable vault: keep it aside instead of overwriting it with an empty one.
            let _ = std::fs::rename(&path, path.with_extension(format!("corrupt-{}", now_ms())));
        } else if let Some(v) = Self::read_from(Path::new(LEGACY_VAULT_FILE), path.clone()) {
            // One-time migration from the old working-directory-relative file. The old file is
            // left in place; the vault is written to the new location on the next change.
            v.save();
            return v;
        }
        Self::empty(Some(path))
    }

    /// A vault that is never written to disk.
    pub fn in_memory() -> Self {
        Self::empty(None)
    }

    fn empty(path: Option<PathBuf>) -> Self {
        Self {
            // Placeholder: a fresh random salt is generated when the PIN is set.
            kdf_salt: [0u8; 32],
            kdf: KdfParams::current(),
            pin_verifier_b64: String::new(),
            preferred_modality: BiometricModality::MasterPin,
            passwords: Vec::new(),
            passkeys: Vec::new(),
            master_keys: None,
            identity_verified_for_ceremony: false,
            last_verification_modality: None,
            path,
            failed_attempts: 0,
            locked_out_until: None,
            device: None,
            device_secret_blob: None,
            weak_pin: false,
            last_pin_entry: None,
            last_activity: Instant::now(),
        }
    }

    /// Supplies the PC binding (DPAPI). New and changed PINs are then bound to this PC, and
    /// vaults that are already bound can be opened.
    pub fn set_device_protector(&mut self, protector: Box<dyn DeviceProtector>) {
        self.device = Some(protector);
    }

    fn read_from(source: &Path, save_path: PathBuf) -> Option<Self> {
        let raw = std::fs::read_to_string(source).ok()?;
        let parsed = serde_json::from_str::<PersistedVault>(&raw).ok()?;
        let salt_vec = B64.decode(&parsed.kdf_salt_b64).ok()?;
        let kdf_salt: [u8; 32] = salt_vec.try_into().ok()?;
        let device_secret_blob = match &parsed.device_secret_b64 {
            Some(b) => Some(B64.decode(b).ok()?),
            None => None,
        };
        Some(Self {
            kdf_salt,
            kdf: parsed.kdf,
            pin_verifier_b64: parsed.pin_verifier_b64,
            preferred_modality: parsed.preferred_modality,
            passwords: parsed.passwords,
            passkeys: parsed.passkeys,
            master_keys: None,
            identity_verified_for_ceremony: false,
            last_verification_modality: None,
            path: Some(save_path),
            failed_attempts: 0,
            locked_out_until: None,
            device: None,
            device_secret_blob,
            weak_pin: false,
            last_pin_entry: None,
            last_activity: Instant::now(),
        })
    }

    /// Persists the vault, ignoring write errors. Use for non-critical changes (preferences).
    pub fn save(&self) {
        let _ = self.try_save();
    }

    /// Writes the vault atomically (temp file + rename) so a crash cannot leave a truncated file.
    fn try_save(&self) -> Result<(), VaultError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let io = |e: std::io::Error| VaultError::Io(e.to_string());
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(io)?;
        }
        let persisted = PersistedVault {
            version: 1,
            kdf_salt_b64: B64.encode(self.kdf_salt),
            kdf: self.kdf,
            pin_verifier_b64: self.pin_verifier_b64.clone(),
            device_secret_b64: self.device_secret_blob.as_ref().map(|b| B64.encode(b)),
            preferred_modality: self.preferred_modality,
            passwords: self.passwords.clone(),
            passkeys: self.passkeys.clone(),
        };
        let json = serde_json::to_string_pretty(&persisted)
            .map_err(|e| VaultError::Io(e.to_string()))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json).map_err(io)?;
        std::fs::rename(&tmp, path).map_err(io)
    }

    /// Wipes derived master keys from memory and revokes ceremony verification.
    pub fn lock(&mut self) {
        if let Some((mut k1, mut k2)) = self.master_keys.take() {
            k1.zeroize();
            k2.zeroize();
        }
        self.identity_verified_for_ceremony = false;
        self.last_pin_entry = None;
    }

    pub fn is_unlocked(&self) -> bool {
        self.master_keys.is_some()
    }

    /// False until the user has created a vault PIN. Nothing can be stored before that.
    pub fn has_master_pin(&self) -> bool {
        !self.pin_verifier_b64.is_empty()
    }

    /// Checks `pin` against the stored verifier and, if it matches, keeps the derived keys in
    /// memory until [`lock`](Self::lock). Repeated wrong PINs are delayed.
    ///
    /// This runs Argon2id on the calling thread. A UI should instead call
    /// [`unlock_job`](Self::unlock_job), run the job on a worker thread and pass the result to
    /// [`finish_unlock`](Self::finish_unlock).
    pub fn unlock_with_pin(&mut self, pin: &str) -> Result<(), VaultError> {
        let job = self.unlock_job(pin)?;
        let keys = job.run();
        self.finish_unlock(keys)
    }

    /// Prepares a PIN check that can run on another thread (see [`KeyJob::run`]).
    pub fn unlock_job(&self, pin: &str) -> Result<KeyJob, VaultError> {
        if !self.has_master_pin() {
            return Err(VaultError::PinNotSet);
        }
        let pin = pin.trim();
        if pin.is_empty() {
            return Err(VaultError::VerificationFailed(
                "Please enter your Vault Security PIN".to_string(),
            ));
        }
        if let Some(until) = self.locked_out_until {
            let now = Instant::now();
            if now < until {
                return Err(VaultError::VerificationFailed(format!(
                    "Too many wrong PIN attempts. Try again in {} seconds",
                    (until - now).as_secs() + 1
                )));
            }
        }
        let device_secret = self.unwrap_device_secret()?;
        Ok(KeyJob {
            pin: Zeroizing::new(pin.to_string()),
            salt: self.kdf_salt,
            kdf: self.kdf,
            device_secret,
            weak_pin: !pin_strength(pin).acceptable,
        })
    }

    /// Completes an unlock started with [`unlock_job`](Self::unlock_job).
    pub fn finish_unlock(&mut self, result: Result<DerivedKeys, VaultError>) -> Result<(), VaultError> {
        let mut derived = result?;
        let matches = matches!(
            open_envelope(&derived.keys, VERIFIER_LABEL, &self.pin_verifier_b64),
            Ok(bytes) if bytes.as_slice() == VERIFIER_PLAINTEXT
        );
        if !matches {
            self.failed_attempts = self.failed_attempts.saturating_add(1);
            if self.failed_attempts >= MAX_FREE_ATTEMPTS {
                let doublings = (self.failed_attempts - MAX_FREE_ATTEMPTS).min(6);
                self.locked_out_until =
                    Some(Instant::now() + Duration::from_secs(30u64 << doublings));
            }
            return Err(VaultError::VerificationFailed(
                "Invalid Vault PIN".to_string(),
            ));
        }

        self.failed_attempts = 0;
        self.locked_out_until = None;
        self.weak_pin = derived.weak_pin;
        let keys = std::mem::take(&mut derived.keys);
        if let Some(mut old) = self.master_keys.replace(keys) {
            wipe_keys(&mut old);
        }
        self.last_pin_entry = Some(Instant::now());
        self.touch();
        Ok(())
    }

    /// True if the vault PIN was typed (and checked) within `window`. Used to make sensitive
    /// actions require the PIN *now*, not merely an unlocked vault from earlier.
    pub fn pin_entered_within(&self, window: Duration) -> bool {
        self.last_pin_entry.is_some_and(|t| t.elapsed() <= window)
    }

    /// Creates the vault PIN (when none exists) or changes it, on the calling thread.
    ///
    /// Changing requires the current PIN. Every stored password and passkey is decrypted with the
    /// current keys and re-encrypted under the new ones; if any single entry cannot be decrypted
    /// the change is refused and the vault is left exactly as it was.
    pub fn set_master_pin(
        &mut self,
        current_pin: Option<&str>,
        new_pin: &str,
    ) -> Result<(), VaultError> {
        if self.has_master_pin() {
            let current = current_pin.ok_or_else(|| {
                VaultError::VerificationFailed(
                    "Enter your current vault PIN to change it".to_string(),
                )
            })?;
            self.unlock_with_pin(current)?;
        }
        let job = self.new_pin_job(new_pin)?;
        let keys = job.run();
        self.commit_new_pin(keys)
    }

    /// Prepares the key derivation for a new PIN (fresh salt, current Argon2id settings and, when
    /// available, a fresh secret bound to this PC). Run it with [`NewPinJob::run`] and pass the
    /// result to [`commit_new_pin`](Self::commit_new_pin).
    pub fn new_pin_job(&self, new_pin: &str) -> Result<NewPinJob, VaultError> {
        let new_pin = new_pin.trim();
        let strength = pin_strength(new_pin);
        if !strength.acceptable {
            return Err(VaultError::VerificationFailed(strength.advice.to_string()));
        }
        let salt = random_bytes::<32>()?;
        let (device_secret, device_blob) = match &self.device {
            Some(protector) => {
                let raw = Zeroizing::new(random_bytes::<32>()?);
                let blob = protector
                    .protect(raw.as_ref())
                    .map_err(|e| VaultError::Crypto(format!("Could not bind the vault to this PC: {e}")))?;
                (Some(raw), Some(blob))
            }
            None => (None, None),
        };
        Ok(NewPinJob {
            job: KeyJob {
                pin: Zeroizing::new(new_pin.to_string()),
                salt,
                kdf: KdfParams::current(),
                device_secret,
                weak_pin: false,
            },
            device_blob,
        })
    }

    /// Re-keys the vault with keys from [`new_pin_job`](Self::new_pin_job).
    ///
    /// When a PIN already exists, the vault must have been unlocked with the current PIN within
    /// the last two minutes, so someone at an unattended, unlocked browser cannot change it.
    pub fn commit_new_pin(&mut self, result: Result<NewPinKeys, VaultError>) -> Result<(), VaultError> {
        let mut new = result?;
        if self.has_master_pin() {
            if !self.is_unlocked() || !self.pin_entered_within(Duration::from_secs(120)) {
                return Err(VaultError::VerificationFailed(
                    "Enter your current vault PIN to change it".to_string(),
                ));
            }
        } else if !self.passwords.is_empty() || !self.passkeys.is_empty() {
            return Err(VaultError::Crypto(
                "Vault holds entries but no PIN verifier; refusing to re-key it".to_string(),
            ));
        }

        // 1. Decrypt everything under the current keys (all-or-nothing).
        let mut plain: Vec<Vec<u8>> = Vec::with_capacity(self.passwords.len() + self.passkeys.len());
        let decrypted: Result<(), VaultError> = (|| {
            for entry in &self.passwords {
                plain.push(self.decrypt_envelope(&entry.origin, &entry.envelope_ciphertext_b64)?);
            }
            for pk in &self.passkeys {
                plain.push(self.decrypt_envelope(&pk.rp_id, &pk.encrypted_private_key_b64)?);
            }
            Ok(())
        })();
        if let Err(e) = decrypted {
            plain.iter_mut().for_each(|p| p.zeroize());
            return Err(e);
        }

        // 2. Re-encrypt under the new keys into temporaries; nothing is committed on failure.
        let sealed: Result<_, VaultError> = (|| {
            let verifier = seal_envelope(&new.derived.keys, VERIFIER_LABEL, VERIFIER_PLAINTEXT)?;
            let labels = self
                .passwords
                .iter()
                .map(|e| e.origin.as_str())
                .chain(self.passkeys.iter().map(|pk| pk.rp_id.as_str()));
            let mut cts = Vec::with_capacity(plain.len());
            for (label, pt) in labels.zip(plain.iter()) {
                cts.push(seal_envelope(&new.derived.keys, label, pt)?);
            }
            Ok((verifier, cts))
        })();
        plain.iter_mut().for_each(|p| p.zeroize());
        let (verifier, cts) = sealed?;

        // 3. Commit.
        let mut cts = cts.into_iter();
        for entry in &mut self.passwords {
            entry.envelope_ciphertext_b64 = cts.next().expect("one ciphertext per password");
        }
        for pk in &mut self.passkeys {
            pk.encrypted_private_key_b64 = cts.next().expect("one ciphertext per passkey");
        }
        self.kdf_salt = new.salt;
        self.kdf = new.kdf;
        self.device_secret_blob = new.device_blob.take();
        self.pin_verifier_b64 = verifier;
        let keys = std::mem::take(&mut new.derived.keys);
        if let Some(mut old) = self.master_keys.replace(keys) {
            wipe_keys(&mut old);
        }
        self.weak_pin = false;
        self.identity_verified_for_ceremony = false;
        self.touch();
        self.try_save()
    }

    /// Why the vault should be re-keyed with a new PIN (empty when it is up to date). Saving and
    /// filling passwords are refused until this is empty.
    pub fn upgrade_reasons(&self) -> Vec<&'static str> {
        let mut reasons = Vec::new();
        if !self.has_master_pin() {
            return reasons;
        }
        if self.weak_pin {
            reasons.push("the PIN is too short or too easy to guess");
        }
        if self.kdf != KdfParams::current() {
            reasons.push("it uses older, weaker key-strengthening settings");
        }
        if self.device.is_some() && self.device_secret_blob.is_none() {
            reasons.push("it is not yet bound to this PC, so a copied vault file could be attacked elsewhere");
        }
        reasons
    }

    /// True when the vault file can only be opened by this Windows account on this PC.
    pub fn is_device_bound(&self) -> bool {
        self.device_secret_blob.is_some()
    }

    /// Locks the vault if it has not been used for `idle`. Returns `true` if it was locked.
    pub fn lock_if_idle(&mut self, idle: Duration) -> bool {
        if self.is_unlocked() && self.last_activity.elapsed() >= idle {
            self.lock();
            return true;
        }
        false
    }

    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    fn unwrap_device_secret(&self) -> Result<Option<Zeroizing<[u8; 32]>>, VaultError> {
        let Some(blob) = &self.device_secret_blob else {
            return Ok(None);
        };
        let protector = self.device.as_ref().ok_or_else(|| {
            VaultError::VerificationFailed(
                "This vault is locked to a Windows account on another PC and cannot be opened here"
                    .to_string(),
            )
        })?;
        let mut raw = protector.unprotect(blob).map_err(|_| {
            VaultError::VerificationFailed(
                "This vault is locked to a different Windows account or PC and cannot be opened here"
                    .to_string(),
            )
        })?;
        let secret: Result<[u8; 32], _> = raw.as_slice().try_into();
        raw.zeroize();
        secret
            .map(|s| Some(Zeroizing::new(s)))
            .map_err(|_| VaultError::Crypto("Device secret has the wrong length".to_string()))
    }

    /// Verifies the user before a credential is released.
    ///
    /// - With a PIN: the PIN must match (this also unlocks the vault).
    /// - `MasterPin` without a PIN: accepted only if the PIN was checked in the last 30 seconds
    ///   (used after an off-thread unlock), and only once.
    /// - A biometric modality: the vault must already be unlocked, and Windows Hello must confirm
    ///   the user. If Windows Hello is unavailable the verification fails; it is never skipped.
    pub fn verify_user_identity(
        &mut self,
        modality: BiometricModality,
        pin: &str,
        origin_reason: &str,
    ) -> Result<String, VaultError> {
        self.identity_verified_for_ceremony = false;
        if !self.has_master_pin() {
            return Err(VaultError::PinNotSet);
        }

        if !pin.trim().is_empty() {
            self.unlock_with_pin(pin)?;
        } else if modality == BiometricModality::MasterPin {
            if !(self.is_unlocked() && self.pin_entered_within(Duration::from_secs(30))) {
                return Err(VaultError::VerificationFailed(
                    "Please enter your Vault Security PIN".to_string(),
                ));
            }
        } else if !self.is_unlocked() {
            return Err(VaultError::VerificationFailed(
                "Vault is locked. Enter your vault PIN once; after that Windows Hello can confirm each login"
                    .to_string(),
            ));
        }

        let summary = match modality {
            BiometricModality::MasterPin => {
                // A typed PIN counts for one ceremony only.
                self.last_pin_entry = None;
                format!("Verified via Argon2id Master PIN for {origin_reason}")
            }
            BiometricModality::Fingerprint
            | BiometricModality::FacialScan
            | BiometricModality::HandPalmScan => {
                let outcome =
                    HelloOutcome(trigger_windows_biometric_prompt(modality, origin_reason));
                return self.complete_hello_ceremony(outcome, modality);
            }
            BiometricModality::CrossDevicePasskey => {
                return Err(VaultError::VerificationFailed(
                    "Cross-device passkey ceremonies must be run via the Windows FIDO2 hybrid transport prompt"
                        .into(),
                ));
            }
        };

        self.identity_verified_for_ceremony = true;
        self.last_verification_modality = Some(modality);
        self.touch();
        Ok(summary)
    }

    /// Finishes a sign-in confirmation with the result of [`windows_hello_prompt`] (which a UI can
    /// run on a worker thread). The vault must be unlocked.
    pub fn complete_hello_ceremony(
        &mut self,
        outcome: HelloOutcome,
        modality: BiometricModality,
    ) -> Result<String, VaultError> {
        self.identity_verified_for_ceremony = false;
        if !self.is_unlocked() {
            return Err(VaultError::VerificationRequired);
        }
        match outcome.0 {
            BiometricPromptOutcome::Verified(detail) => {
                self.identity_verified_for_ceremony = true;
                self.last_verification_modality = Some(modality);
                self.touch();
                Ok(detail)
            }
            BiometricPromptOutcome::Unavailable(why) => Err(VaultError::VerificationFailed(format!(
                "Windows Hello is not available on this device ({why}). Use your vault PIN instead"
            ))),
            BiometricPromptOutcome::Denied(reason) => {
                self.lock();
                Err(VaultError::VerificationFailed(reason))
            }
        }
    }

    /// Finishes a sign-in confirmation with a cross-device passkey / FIDO2 hybrid transport
    /// assertion result. The vault must be unlocked.
    pub fn complete_cross_device_ceremony(
        &mut self,
        detail: &str,
    ) -> Result<String, VaultError> {
        self.identity_verified_for_ceremony = false;
        if !self.is_unlocked() {
            return Err(VaultError::VerificationRequired);
        }
        self.identity_verified_for_ceremony = true;
        self.last_verification_modality = Some(BiometricModality::CrossDevicePasskey);
        self.touch();
        Ok(detail.to_string())
    }

    fn encrypt_envelope(&self, label: &str, plaintext: &[u8]) -> Result<String, VaultError> {
        let keys = self
            .master_keys
            .as_ref()
            .ok_or(VaultError::VerificationRequired)?;
        seal_envelope(keys, label, plaintext)
    }

    fn decrypt_envelope(&self, label: &str, envelope_b64: &str) -> Result<Vec<u8>, VaultError> {
        let keys = self
            .master_keys
            .as_ref()
            .ok_or(VaultError::VerificationRequired)?;
        open_envelope(keys, label, envelope_b64)
    }

    /// Saves or updates an encrypted password credential for `origin`.
    ///
    /// Fails with [`VaultError::PinNotSet`] if no PIN exists yet and with
    /// [`VaultError::VerificationRequired`] if the vault is locked.
    pub fn store_password(
        &mut self,
        origin: &str,
        username: &str,
        password: &str,
        auto_submit: bool,
    ) -> Result<(), VaultError> {
        if !self.has_master_pin() {
            return Err(VaultError::PinNotSet);
        }
        if origin.trim().is_empty() {
            return Err(VaultError::NotFound("(empty origin)".to_string()));
        }
        self.touch();
        let ct = self.encrypt_envelope(origin, password.as_bytes())?;
        if let Some(existing) = self
            .passwords
            .iter_mut()
            .find(|p| p.origin == origin && p.username == username)
        {
            existing.envelope_ciphertext_b64 = ct;
            existing.auto_submit = auto_submit;
            existing.created_at_ms = now_ms();
        } else {
            self.passwords.push(EncryptedPasswordEntry {
                origin: origin.to_string(),
                username: username.to_string(),
                envelope_ciphertext_b64: ct,
                created_at_ms: now_ms(),
                auto_submit,
            });
        }
        self.try_save()
    }

    pub fn has_credential_for_origin(&self, origin: &str) -> bool {
        self.passwords.iter().any(|p| p.origin == origin)
            || self.passkeys.iter().any(|pk| pk.origin == origin)
    }

    pub fn saved_username_for_origin(&self, origin: &str) -> Option<String> {
        self.passwords
            .iter()
            .find(|p| p.origin == origin)
            .map(|p| p.username.clone())
    }

    /// Releases the decrypted `(username, password, auto_submit)` ONLY if `identity_verified_for_ceremony` is true,
    /// and immediately consumes the single-use ceremony verification token so the next login requires re-verification.
    pub fn consume_verified_password_for_origin(
        &mut self,
        origin: &str,
    ) -> Result<(String, String, bool), VaultError> {
        if !self.identity_verified_for_ceremony {
            return Err(VaultError::VerificationRequired);
        }
        let entry = self
            .passwords
            .iter()
            .find(|p| p.origin == origin)
            .cloned()
            .ok_or_else(|| VaultError::NotFound(origin.to_string()))?;

        let pt_bytes = self.decrypt_envelope(origin, &entry.envelope_ciphertext_b64)?;
        // Single-use biometric/PIN verification token consumed on release
        self.identity_verified_for_ceremony = false;
        self.touch();
        let password = String::from_utf8(pt_bytes).map_err(|e| {
            e.into_bytes().zeroize();
            VaultError::DecryptionFailed
        })?;
        Ok((entry.username, password, entry.auto_submit))
    }

    /// Creates a new W3C WebAuthn Passkey (`ES256` NIST P-256) bound to `rp_id` and `origin`.
    /// Requires `identity_verified_for_ceremony == true` and `rp_id` to be the origin's host or
    /// a parent domain of it.
    pub fn create_passkey(
        &mut self,
        origin: &str,
        rp_id: &str,
        user_name: &str,
        challenge_b64url: &str,
    ) -> Result<WebAuthnRegistrationResult, VaultError> {
        if !self.identity_verified_for_ceremony {
            return Err(VaultError::VerificationRequired);
        }
        if !origin_matches_rp_id(origin, rp_id) {
            return Err(VaultError::VerificationFailed(format!(
                "Relying party '{rp_id}' is not valid for origin {origin}"
            )));
        }

        let (signing_key, mut secret_scalar) = generate_p256_key()?;
        let verifying_key = VerifyingKey::from(&signing_key);
        let pubkey_sec1 = verifying_key.to_encoded_point(false);

        let cred_id_bytes = random_bytes::<20>()?;
        let user_handle_bytes = random_bytes::<12>()?;
        let credential_id_b64url = B64_URL.encode(cred_id_bytes);
        let user_handle_b64url = B64_URL.encode(user_handle_bytes);
        let public_key_b64url = B64_URL.encode(pubkey_sec1.as_bytes());

        let encrypted = self.encrypt_envelope(rp_id, &secret_scalar);
        secret_scalar.zeroize();
        let encrypted_private_key_b64 = encrypted?;

        // Remove any prior passkey for same (rp_id, user_name)
        self.passkeys
            .retain(|pk| !(pk.rp_id == rp_id && pk.user_name == user_name));
        self.passkeys.push(PasskeyRecord {
            credential_id_b64url: credential_id_b64url.clone(),
            rp_id: rp_id.to_string(),
            origin: origin.to_string(),
            user_name: user_name.to_string(),
            user_handle_b64url,
            public_key_b64url: public_key_b64url.clone(),
            encrypted_private_key_b64,
            sign_count: 1,
            created_at_ms: now_ms(),
        });
        self.identity_verified_for_ceremony = false;
        self.try_save()?;

        let client_data_json = client_data_json("webauthn.create", challenge_b64url, origin);
        let auth_data = build_authenticator_data(
            rp_id,
            0x45,
            1,
            Some((&cred_id_bytes, pubkey_sec1.as_bytes())),
        );

        Ok(WebAuthnRegistrationResult {
            credential_id_b64url,
            client_data_json_b64url: B64_URL.encode(client_data_json.as_bytes()),
            authenticator_data_b64url: B64_URL.encode(auth_data),
            public_key_b64url,
            rp_id: rp_id.to_string(),
        })
    }

    /// Signs a W3C WebAuthn Passkey assertion (`navigator.credentials.get({ publicKey })`)
    /// using the decrypted P-256 private key for `rp_id`. Requires `identity_verified_for_ceremony == true`
    /// and `rp_id` to be the origin's host or a parent domain of it.
    pub fn authenticate_passkey(
        &mut self,
        origin: &str,
        rp_id: &str,
        challenge_b64url: &str,
    ) -> Result<WebAuthnAssertionResult, VaultError> {
        if !self.identity_verified_for_ceremony {
            return Err(VaultError::VerificationRequired);
        }
        if !origin_matches_rp_id(origin, rp_id) {
            return Err(VaultError::VerificationFailed(format!(
                "Relying party '{rp_id}' is not valid for origin {origin}"
            )));
        }

        let idx = self
            .passkeys
            .iter()
            .position(|pk| pk.rp_id == rp_id)
            .ok_or_else(|| VaultError::NotFound(rp_id.to_string()))?;

        let record = self.passkeys[idx].clone();
        let mut scalar_bytes =
            self.decrypt_envelope(&record.rp_id, &record.encrypted_private_key_b64)?;

        let signing_key = SigningKey::from_slice(&scalar_bytes);
        scalar_bytes.zeroize();
        let signing_key =
            signing_key.map_err(|e| VaultError::Crypto(format!("Invalid P-256 key: {e}")))?;

        let next_count = record.sign_count.wrapping_add(1);
        self.passkeys[idx].sign_count = next_count;
        self.identity_verified_for_ceremony = false;
        self.try_save()?;

        let client_data_json = client_data_json("webauthn.get", challenge_b64url, origin);
        let client_data_hash = Sha256::digest(client_data_json.as_bytes());
        // Flags: 0x05 = UP (User Present, bit 0) | UV (User Verified, bit 2)
        let auth_data = build_authenticator_data(&record.rp_id, 0x05, next_count, None);

        let mut signed_payload = Vec::with_capacity(auth_data.len() + 32);
        signed_payload.extend_from_slice(&auth_data);
        signed_payload.extend_from_slice(&client_data_hash);

        let signature: Signature = signing_key.sign(&signed_payload);
        let verifying_key = VerifyingKey::from(&signing_key);
        verifying_key
            .verify(&signed_payload, &signature)
            .map_err(|e| VaultError::Crypto(format!("Self-verification of Passkey signature failed: {e}")))?;

        let sig_der = signature.to_der();

        Ok(WebAuthnAssertionResult {
            credential_id_b64url: record.credential_id_b64url,
            client_data_json_b64url: B64_URL.encode(client_data_json.as_bytes()),
            authenticator_data_b64url: B64_URL.encode(auth_data),
            signature_der_b64url: B64_URL.encode(sig_der.as_bytes()),
            user_handle_b64url: record.user_handle_b64url,
            sign_count: next_count,
        })
    }
}

/// Fills a buffer from the operating system's cryptographic random generator.
fn random_bytes<const N: usize>() -> Result<[u8; N], VaultError> {
    let mut out = [0u8; N];
    OsRng
        .try_fill_bytes(&mut out)
        .map_err(|e| VaultError::Crypto(format!("OS random generator failed: {e}")))?;
    Ok(out)
}

fn generate_p256_key() -> Result<(SigningKey, [u8; 32]), VaultError> {
    // A random 32-byte string is a valid P-256 scalar except with probability ~2^-32; retry then.
    for _ in 0..8 {
        let mut secret = random_bytes::<32>()?;
        if let Ok(key) = SigningKey::from_slice(&secret) {
            return Ok((key, secret));
        }
        secret.zeroize();
    }
    Err(VaultError::Crypto(
        "P-256 key generation failed".to_string(),
    ))
}

fn wipe_keys(keys: &mut MasterKeys) {
    keys.0.zeroize();
    keys.1.zeroize();
}

/// Derives 512 bits with Argon2id and splits them into the AES-256-GCM and XChaCha20-Poly1305 keys.
fn derive_keys(
    pin: &str,
    salt: &[u8; 32],
    kdf: KdfParams,
    device_secret: Option<&[u8; 32]>,
) -> Result<MasterKeys, VaultError> {
    let params = Params::new(kdf.m_kib, kdf.t, kdf.p, Some(64))
        .map_err(|e| VaultError::Crypto(format!("Argon2 params error: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 64];
    argon
        .hash_password_into(pin.as_bytes(), salt, &mut out)
        .map_err(|e| VaultError::Crypto(format!("Argon2id KDF failed: {e}")))?;

    let mut k_aes = [0u8; 32];
    let mut k_xchacha = [0u8; 32];
    match device_secret {
        // Bound vaults: each key also depends on the PC-bound secret.
        Some(secret) => {
            let mix = |label: &[u8]| -> [u8; 32] {
                let mut h = Sha256::new();
                h.update(label);
                h.update(out);
                h.update(secret);
                h.finalize().into()
            };
            k_aes = mix(b"oya-vault-v2:aes");
            k_xchacha = mix(b"oya-vault-v2:xchacha");
        }
        None => {
            k_aes.copy_from_slice(&out[0..32]);
            k_xchacha.copy_from_slice(&out[32..64]);
        }
    }
    out.zeroize();
    Ok((k_aes, k_xchacha))
}

/// Dual-cipher envelope encryption:
/// `Inner = AES-256-GCM(key=k_aes, nonce=12B, aad="rc_vault:v1:aes:"||label, plaintext)`
/// `Outer = XChaCha20-Poly1305(key=k_xchacha, nonce=24B, aad="rc_vault:v1:xchacha:"||label, Inner)`
fn seal_envelope(keys: &MasterKeys, label: &str, plaintext: &[u8]) -> Result<String, VaultError> {
    let (k_aes, k_xchacha) = keys;
    let aes_nonce_bytes = random_bytes::<12>()?;
    let xchacha_nonce_bytes = random_bytes::<24>()?;

    let aes = Aes256Gcm::new_from_slice(k_aes)
        .map_err(|e| VaultError::Crypto(format!("AES init: {e}")))?;
    let aes_aad = format!("rc_vault:v1:aes:{label}");
    let mut inner_ct = aes
        .encrypt(
            AesNonce::from_slice(&aes_nonce_bytes),
            Payload {
                msg: plaintext,
                aad: aes_aad.as_bytes(),
            },
        )
        .map_err(|_| VaultError::Crypto("AES-256-GCM encryption failed".to_string()))?;

    let xchacha = XChaCha20Poly1305::new_from_slice(k_xchacha)
        .map_err(|e| VaultError::Crypto(format!("XChaCha init: {e}")))?;
    let xchacha_aad = format!("rc_vault:v1:xchacha:{label}");
    let outer_ct = xchacha.encrypt(
        XNonce::from_slice(&xchacha_nonce_bytes),
        Payload {
            msg: &inner_ct,
            aad: xchacha_aad.as_bytes(),
        },
    );
    inner_ct.zeroize();
    let outer_ct = outer_ct
        .map_err(|_| VaultError::Crypto("XChaCha20-Poly1305 encryption failed".to_string()))?;

    let mut envelope = Vec::with_capacity(12 + 24 + outer_ct.len());
    envelope.extend_from_slice(&aes_nonce_bytes);
    envelope.extend_from_slice(&xchacha_nonce_bytes);
    envelope.extend_from_slice(&outer_ct);
    Ok(B64.encode(envelope))
}

fn open_envelope(keys: &MasterKeys, label: &str, envelope_b64: &str) -> Result<Vec<u8>, VaultError> {
    let (k_aes, k_xchacha) = keys;
    let raw = B64
        .decode(envelope_b64)
        .map_err(|_| VaultError::DecryptionFailed)?;
    if raw.len() < 12 + 24 + 32 {
        return Err(VaultError::DecryptionFailed);
    }
    let aes_nonce = &raw[0..12];
    let xchacha_nonce = &raw[12..36];
    let outer_ct = &raw[36..];

    let xchacha =
        XChaCha20Poly1305::new_from_slice(k_xchacha).map_err(|_| VaultError::DecryptionFailed)?;
    let xchacha_aad = format!("rc_vault:v1:xchacha:{label}");
    let mut inner_ct = xchacha
        .decrypt(
            XNonce::from_slice(xchacha_nonce),
            Payload {
                msg: outer_ct,
                aad: xchacha_aad.as_bytes(),
            },
        )
        .map_err(|_| VaultError::DecryptionFailed)?;

    let aes = Aes256Gcm::new_from_slice(k_aes).map_err(|_| VaultError::DecryptionFailed)?;
    let aes_aad = format!("rc_vault:v1:aes:{label}");
    let plaintext = aes.decrypt(
        AesNonce::from_slice(aes_nonce),
        Payload {
            msg: &inner_ct,
            aad: aes_aad.as_bytes(),
        },
    );
    inner_ct.zeroize();
    plaintext.map_err(|_| VaultError::DecryptionFailed)
}

/// WebAuthn: the relying-party ID must be the origin's host or a registrable parent of it,
/// and the origin must be HTTPS.
fn origin_matches_rp_id(origin: &str, rp_id: &str) -> bool {
    let Some(rest) = origin.strip_prefix("https://") else {
        return false;
    };
    let host = rest.split(['/', ':']).next().unwrap_or("");
    if rp_id.is_empty() || !rp_id.contains('.') || host.is_empty() {
        return false;
    }
    host == rp_id || host.ends_with(&format!(".{rp_id}"))
}

fn client_data_json(kind: &str, challenge_b64url: &str, origin: &str) -> String {
    serde_json::json!({
        "type": kind,
        "challenge": challenge_b64url,
        "origin": origin,
        "crossOrigin": false,
    })
    .to_string()
}

fn build_authenticator_data(
    rp_id: &str,
    flags: u8,
    sign_count: u32,
    attested_cred: Option<(&[u8], &[u8])>,
) -> Vec<u8> {
    let rp_id_hash = Sha256::digest(rp_id.as_bytes());
    let mut auth_data = Vec::with_capacity(128);
    auth_data.extend_from_slice(&rp_id_hash);
    auth_data.push(flags);
    auth_data.extend_from_slice(&sign_count.to_be_bytes());

    if let Some((cred_id, pubkey_sec1)) = attested_cred {
        // AAGUID (16 bytes targeting RustChrome Hardware Passkey Vault)
        auth_data.extend_from_slice(b"RUSTCHROMEPASSKY");
        let len = (cred_id.len() as u16).to_be_bytes();
        auth_data.extend_from_slice(&len);
        auth_data.extend_from_slice(cred_id);
        auth_data.extend_from_slice(pubkey_sec1);
    }
    auth_data
}

#[allow(dead_code)]
enum BiometricPromptOutcome {
    Verified(String),
    /// Windows Hello could not be asked at all. Treated as a failed verification.
    Unavailable(String),
    Denied(String),
}

/// Asks Windows Hello (`Windows.Security.Credentials.UI.UserConsentVerifier`) to confirm the user.
/// Windows decides which enrolled factor (fingerprint, face or Hello PIN) is used.
#[cfg(all(not(test), windows))]
fn trigger_windows_biometric_prompt(
    modality: BiometricModality,
    origin_reason: &str,
) -> BiometricPromptOutcome {
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    // The prompt text is passed through the environment, never spliced into the script.
    const PS_SCRIPT: &str = r#"
try {
    $null = [Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType = WindowsRuntime]
    $availOp = [Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()
    while ($availOp.Status -eq 0) { Start-Sleep -Milliseconds 25 }
    $avail = $availOp.GetResults()
    if ($avail.ToString() -ne 'Available') {
        Write-Output "UNAVAILABLE:$($avail.ToString())"
        exit 0
    }
    $reqOp = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync($env:OYA_HELLO_PROMPT)
    while ($reqOp.Status -eq 0) { Start-Sleep -Milliseconds 50 }
    $res = $reqOp.GetResults()
    Write-Output "RESULT:$($res.ToString())"
} catch {
    Write-Output "UNAVAILABLE:WinRT"
}
"#;

    let prompt_msg = format!("Oya Browser: confirm it is you to sign in to {origin_reason}");

    // Absolute path: never resolve `powershell` through PATH or the working directory.
    let system_root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let powershell = system_root
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe");

    let output = Command::new(powershell)
        .args(["-NoProfile", "-NonInteractive", "-Command", PS_SCRIPT])
        .env("OYA_HELLO_PROMPT", prompt_msg)
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let stdout = match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Err(e) => return BiometricPromptOutcome::Unavailable(e.to_string()),
    };
    if stdout.contains("RESULT:Verified") {
        BiometricPromptOutcome::Verified(format!(
            "Windows Hello ({}) verified user identity for {origin_reason}",
            modality.label()
        ))
    } else if stdout.contains("RESULT:") {
        BiometricPromptOutcome::Denied(format!(
            "Windows Hello check was canceled or did not match ({stdout})"
        ))
    } else if let Some(why) = stdout.strip_prefix("UNAVAILABLE:") {
        BiometricPromptOutcome::Unavailable(why.to_string())
    } else {
        BiometricPromptOutcome::Unavailable("no response".to_string())
    }
}

#[cfg(all(not(test), not(windows)))]
fn trigger_windows_biometric_prompt(
    _modality: BiometricModality,
    _origin_reason: &str,
) -> BiometricPromptOutcome {
    BiometricPromptOutcome::Unavailable("unsupported platform".to_string())
}

#[cfg(test)]
fn trigger_windows_biometric_prompt(
    modality: BiometricModality,
    _origin_reason: &str,
) -> BiometricPromptOutcome {
    // Hand/Palm stands in for "no sensor" so the fail-closed path is exercised.
    match modality {
        BiometricModality::HandPalmScan => {
            BiometricPromptOutcome::Unavailable("test: no sensor".to_string())
        }
        _ => BiometricPromptOutcome::Verified("test: verified".to_string()),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOGLE: &str = "https://accounts.google.com";
    const PIN: &str = "Correct-Horse-9";
    const PIN2: &str = "new-passphrase-42";

    /// Stand-in for DPAPI: XOR with a per-"machine" byte.
    struct FakeMachine(u8);
    impl DeviceProtector for FakeMachine {
        fn protect(&self, data: &[u8]) -> Result<Vec<u8>, String> {
            let mut v: Vec<u8> = data.iter().map(|b| b ^ self.0).collect();
            v.push(self.0);
            Ok(v)
        }
        fn unprotect(&self, data: &[u8]) -> Result<Vec<u8>, String> {
            match data.split_last() {
                Some((tag, body)) if *tag == self.0 => Ok(body.iter().map(|b| b ^ self.0).collect()),
                _ => Err("wrong machine".to_string()),
            }
        }
    }

    #[test]
    fn dual_aead_encryption_and_biometric_pin_gate_work() {
        let mut vault = SecurityVault::in_memory();
        vault.set_master_pin(None, PIN).unwrap();
        vault
            .store_password(GOOGLE, "alice@gmail.com", "UltraSecret!2026", true)
            .unwrap();
        assert!(vault.consume_verified_password_for_origin(GOOGLE).is_err());
        assert!(
            vault
                .verify_user_identity(BiometricModality::Fingerprint, "wrong-pin-000", GOOGLE)
                .is_err()
        );
        vault
            .verify_user_identity(BiometricModality::Fingerprint, PIN, GOOGLE)
            .unwrap();
        let (user, pass, auto) = vault.consume_verified_password_for_origin(GOOGLE).unwrap();
        assert_eq!(user, "alice@gmail.com");
        assert_eq!(pass, "UltraSecret!2026");
        assert!(auto);
        assert!(vault.consume_verified_password_for_origin(GOOGLE).is_err());
    }

    #[test]
    fn nothing_works_without_a_pin_and_weak_pins_are_refused() {
        let mut vault = SecurityVault::in_memory();
        assert!(matches!(
            vault.store_password(GOOGLE, "alice", "pw", true),
            Err(VaultError::PinNotSet)
        ));
        for pin in ["", "1234"] {
            assert!(matches!(
                vault.verify_user_identity(BiometricModality::Fingerprint, pin, GOOGLE),
                Err(VaultError::PinNotSet)
            ));
        }
        for weak in ["1234", "987654", "12345678", "password", "aaaaaaaa", "abcdefgh"] {
            assert!(vault.set_master_pin(None, weak).is_err(), "{weak} accepted");
        }
        assert!(!vault.has_master_pin());
        assert!(pin_strength(PIN).acceptable);
        assert!(pin_strength("tulip-river-castle-77").score >= 3);
    }

    #[test]
    fn locked_vault_refuses_to_store_and_biometrics_alone_do_not_unlock() {
        let mut vault = SecurityVault::in_memory();
        vault.set_master_pin(None, PIN).unwrap();
        vault.store_password(GOOGLE, "alice", "pw-1", true).unwrap();
        vault.lock();

        assert!(matches!(
            vault.store_password(GOOGLE, "alice", "pw-2", true),
            Err(VaultError::VerificationRequired)
        ));
        assert!(
            vault
                .verify_user_identity(BiometricModality::Fingerprint, "", GOOGLE)
                .is_err()
        );
        assert!(!vault.is_unlocked());

        vault.unlock_with_pin(PIN).unwrap();
        vault
            .verify_user_identity(BiometricModality::Fingerprint, "", GOOGLE)
            .unwrap();
        assert_eq!(vault.consume_verified_password_for_origin(GOOGLE).unwrap().1, "pw-1");
        // Unavailable sensor fails closed even with the right PIN.
        assert!(
            vault
                .verify_user_identity(BiometricModality::HandPalmScan, PIN, GOOGLE)
                .is_err()
        );
        assert!(vault.consume_verified_password_for_origin(GOOGLE).is_err());
    }

    #[test]
    fn off_thread_unlock_then_pin_ceremony_is_single_use() {
        let mut vault = SecurityVault::in_memory();
        vault.set_master_pin(None, PIN).unwrap();
        vault.store_password(GOOGLE, "alice", "pw", false).unwrap();
        vault.lock();

        let job = vault.unlock_job(PIN).unwrap();
        let result = std::thread::spawn(move || job.run()).join().unwrap();
        vault.finish_unlock(result).unwrap();
        vault
            .verify_user_identity(BiometricModality::MasterPin, "", GOOGLE)
            .unwrap();
        assert!(vault.consume_verified_password_for_origin(GOOGLE).is_ok());
        // The typed PIN counted once; a second PIN ceremony needs the PIN again.
        assert!(
            vault
                .verify_user_identity(BiometricModality::MasterPin, "", GOOGLE)
                .is_err()
        );
    }

    #[test]
    fn pin_change_needs_current_pin_and_keeps_every_entry() {
        let mut vault = SecurityVault::in_memory();
        vault.set_master_pin(None, PIN).unwrap();
        vault.store_password(GOOGLE, "alice", "pw-google", true).unwrap();
        vault
            .store_password("https://example.com", "bob", "pw-example", false)
            .unwrap();
        vault
            .verify_user_identity(BiometricModality::MasterPin, PIN, "github.com")
            .unwrap();
        let reg = vault
            .create_passkey("https://github.com", "github.com", "octocat", "CHAL")
            .unwrap();
        let before = vault.passwords[0].envelope_ciphertext_b64.clone();

        vault.lock();
        assert!(vault.set_master_pin(None, PIN2).is_err());
        assert!(vault.set_master_pin(Some("wrong-pin-000"), PIN2).is_err());
        assert_eq!(vault.passwords[0].envelope_ciphertext_b64, before);
        // Unlocked earlier but no fresh PIN: a new-PIN commit alone is refused.
        let job = vault.new_pin_job(PIN2).unwrap();
        assert!(vault.commit_new_pin(job.run()).is_err());

        vault.set_master_pin(Some(PIN), PIN2).unwrap();
        assert_ne!(vault.passwords[0].envelope_ciphertext_b64, before);
        vault.lock();

        assert!(vault.unlock_with_pin(PIN).is_err(), "old PIN is dead");
        vault
            .verify_user_identity(BiometricModality::MasterPin, PIN2, GOOGLE)
            .unwrap();
        assert_eq!(vault.consume_verified_password_for_origin(GOOGLE).unwrap().1, "pw-google");
        vault
            .verify_user_identity(BiometricModality::MasterPin, PIN2, "example")
            .unwrap();
        assert_eq!(
            vault
                .consume_verified_password_for_origin("https://example.com")
                .unwrap()
                .1,
            "pw-example"
        );
        vault
            .verify_user_identity(BiometricModality::MasterPin, PIN2, "github.com")
            .unwrap();
        let assertion = vault
            .authenticate_passkey("https://github.com", "github.com", "CHAL2")
            .unwrap();
        assert_eq!(assertion.credential_id_b64url, reg.credential_id_b64url);
    }

    #[test]
    fn device_binding_stops_a_copied_vault() {
        let mut home = SecurityVault::in_memory();
        home.set_device_protector(Box::new(FakeMachine(7)));
        home.set_master_pin(None, PIN).unwrap();
        home.store_password(GOOGLE, "alice", "pw", false).unwrap();
        assert!(home.is_device_bound());
        assert!(home.upgrade_reasons().is_empty());

        // Simulate copying the vault file to another PC.
        let persisted = PersistedVault {
            version: 1,
            kdf_salt_b64: B64.encode(home.kdf_salt),
            kdf: home.kdf,
            pin_verifier_b64: home.pin_verifier_b64.clone(),
            device_secret_b64: home.device_secret_blob.as_ref().map(|b| B64.encode(b)),
            preferred_modality: home.preferred_modality,
            passwords: home.passwords.clone(),
            passkeys: Vec::new(),
        };
        let path = std::env::temp_dir().join(format!("oya-vault-test-{}.json", now_ms()));
        std::fs::write(&path, serde_json::to_string(&persisted).unwrap()).unwrap();
        let mut stolen = SecurityVault::read_from(&path, path.clone()).unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(stolen.unlock_with_pin(PIN).is_err(), "no protector at all");
        stolen.set_device_protector(Box::new(FakeMachine(9)));
        assert!(stolen.unlock_with_pin(PIN).is_err(), "other machine");
        stolen.device = Some(Box::new(FakeMachine(7)));
        stolen.unlock_with_pin(PIN).unwrap();
    }

    #[test]
    fn unbound_or_legacy_vault_asks_for_upgrade_and_idle_lock_works() {
        let mut vault = SecurityVault::in_memory();
        vault.set_master_pin(None, PIN).unwrap();
        assert!(vault.upgrade_reasons().is_empty(), "no protector: nothing to bind");
        vault.set_device_protector(Box::new(FakeMachine(3)));
        assert_eq!(vault.upgrade_reasons().len(), 1);
        vault.kdf = KdfParams::legacy();
        assert_eq!(vault.upgrade_reasons().len(), 2);

        assert!(vault.is_unlocked());
        assert!(!vault.lock_if_idle(Duration::from_secs(600)));
        assert!(vault.lock_if_idle(Duration::ZERO));
        assert!(!vault.is_unlocked());
    }

    #[test]
    fn repeated_wrong_pins_are_throttled() {
        let mut vault = SecurityVault::in_memory();
        vault.set_master_pin(None, PIN).unwrap();
        vault.lock();
        for _ in 0..MAX_FREE_ATTEMPTS {
            assert!(vault.unlock_with_pin("wrong-pin-000").is_err());
        }
        assert!(vault.unlock_with_pin(PIN).is_err());
    }

    #[test]
    fn random_values_are_unique() {
        let a = random_bytes::<32>().unwrap();
        let b = random_bytes::<32>().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);

        let mut vault = SecurityVault::in_memory();
        vault.set_master_pin(None, PIN).unwrap();
        let c1 = vault.encrypt_envelope("x", b"same").unwrap();
        let c2 = vault.encrypt_envelope("x", b"same").unwrap();
        assert_ne!(c1, c2, "fresh nonces per encryption");
    }

    #[test]
    fn webauthn_passkey_create_and_assertion_signing_work() {
        let mut vault = SecurityVault::in_memory();
        vault.set_master_pin(None, PIN).unwrap();
        vault
            .verify_user_identity(BiometricModality::FacialScan, PIN, "github.com")
            .unwrap();
        assert!(
            vault
                .create_passkey("https://evil.example", "github.com", "octocat", "C")
                .is_err()
        );
        let reg = vault
            .create_passkey("https://github.com", "github.com", "octocat", "CHALLENGE_REG_123")
            .unwrap();
        assert!(!reg.credential_id_b64url.is_empty());
        vault
            .verify_user_identity(BiometricModality::Fingerprint, PIN, "github.com")
            .unwrap();
        let assertion = vault
            .authenticate_passkey("https://github.com", "github.com", "CHALLENGE_AUTH_456")
            .unwrap();
        assert_eq!(assertion.credential_id_b64url, reg.credential_id_b64url);
        assert_eq!(assertion.sign_count, 2);
        assert!(!assertion.signature_der_b64url.is_empty());
    }
}
