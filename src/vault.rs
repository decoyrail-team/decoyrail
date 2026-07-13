//! Real + decoy credential vaults.
//!
//! The **real vault** holds live secrets, encrypted at rest with
//! ChaCha20-Poly1305. The key lives in `~/.decoyrail/vault.key` (`0600`) by
//! default, or, after `decoyrail key migrate --to keychain` on macOS, in a
//! login-keychain item readable silently only by this binary and bound to the
//! default home (see [`resolve_backend`]).
//!
//! Every real secret gets a deterministic, **format-correct decoy** — a fake
//! that looks like the real thing (`sk-ant-…`, `ghp_…`, `AKIA…`). Agents only
//! ever see decoys. The proxy swaps decoy→real at destinations whose policy
//! rule releases the secret (`allow_secrets`), and treats a decoy seen
//! anywhere else as an exfil tripwire.

use anyhow::{anyhow, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::config;

/// Where in the request a secret is carried — determines how the proxy swaps it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Location {
    /// `Authorization: Bearer <secret>`
    Bearer,
    /// A named header carries the raw secret, e.g. `x-api-key`.
    Header(String),
    /// The secret appears somewhere in the request body.
    Body,
    /// Search headers and body (default; robust but slightly more work).
    #[default]
    Any,
}

/// Where a secret may travel lives in the policy: a rule's `allow_secrets`
/// lists the secret names and provider labels (`provider:github`) it releases.
/// The vault entry only says what the credential is and how it rides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub name: String,
    pub real: String,
    pub decoy: String,
    /// Env var to inject the *decoy* into for `decoyrail run` (e.g. `ANTHROPIC_API_KEY`).
    #[serde(default)]
    pub env: Option<String>,
    #[serde(default)]
    pub location: Location,
    /// Provider label inferred from the value's format (`anthropic`, `github`,
    /// ...), so a policy rule can release it as `provider:<label>` without
    /// knowing the entry's name. `None` for unrecognized formats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Vault {
    pub secrets: Vec<Secret>,
}

impl Vault {
    pub fn load_or_init() -> Result<Self> {
        config::ensure_home()?;
        let path = config::vault_path()?;
        if !path.exists() {
            return Ok(Vault::default());
        }
        let blob = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let plaintext = decrypt(&blob)?; // Zeroizing: wiped on drop
        let vault: Vault = serde_json::from_slice(&plaintext).context("parsing vault JSON")?;
        Ok(vault)
    }

    pub fn save(&self) -> Result<()> {
        config::ensure_home()?;
        let plaintext = serde_json::to_vec(self)?;
        let blob = encrypt(&plaintext)?;
        std::fs::write(config::vault_path()?, blob)?;
        Ok(())
    }

    /// Add a real secret; generate its decoy and persist. Returns the decoy.
    pub fn add(
        &mut self,
        name: &str,
        real: &str,
        env: Option<String>,
        location: Location,
    ) -> Result<String> {
        if self.secrets.iter().any(|s| s.name == name) {
            return Err(anyhow!("a secret named '{name}' already exists"));
        }
        let decoy = make_decoy(name, real);
        self.secrets.push(Secret {
            name: name.to_string(),
            real: real.to_string(),
            decoy: decoy.clone(),
            env,
            location,
            provider: infer_provider(real).map(str::to_string),
        });
        self.save()?;
        Ok(decoy)
    }

    pub fn remove(&mut self, name: &str) -> Result<()> {
        let before = self.secrets.len();
        self.secrets.retain(|s| s.name != name);
        if self.secrets.len() == before {
            return Err(anyhow!("no secret named '{name}'"));
        }
        self.save()
    }

    /// Reverse-lookup a secret by its decoy value (used by the menubar UI and
    /// future response-side scanning).
    #[allow(dead_code)]
    pub fn by_decoy(&self, needle: &str) -> Option<&Secret> {
        self.secrets.iter().find(|s| s.decoy == needle)
    }
}

/// Provider labels a policy rule can release with `provider:<label>`.
pub const PROVIDER_LABELS: &[&str] = &["anthropic", "openai", "github", "gitlab", "slack", "npm"];

/// Value-format prefixes mapped to provider labels, most specific first.
const PROVIDER_PREFIXES: &[(&str, &str)] = &[
    ("sk-ant-", "anthropic"),
    ("sk-", "openai"),
    ("github_pat_", "github"),
    ("ghp_", "github"),
    ("gho_", "github"),
    ("ghs_", "github"),
    ("glpat-", "gitlab"),
    ("xoxb-", "slack"),
    ("xoxp-", "slack"),
    ("xoxa-", "slack"),
    ("npm_", "npm"),
];

/// Recognize a credential's provider from its value format, so policy rules
/// can release it by label. AWS keys are deliberately unrecognized: SigV4
/// signs requests with the secret instead of sending it, so a swap can't
/// restore a signature computed from a decoy (re-signing is roadmap work).
pub fn infer_provider(real: &str) -> Option<&'static str> {
    PROVIDER_PREFIXES
        .iter()
        .find(|(prefix, _)| real.starts_with(prefix))
        .map(|(_, label)| *label)
}

/// Build a deterministic, format-correct decoy for a real secret. Deterministic
/// so the decoy is stable across vault edits (tripwire matching stays valid).
pub fn make_decoy(name: &str, real: &str) -> String {
    // Deterministic entropy from name+real so re-adds reproduce the same decoy.
    let mut hasher = Sha256::new();
    hasher.update(b"decoyrail-decoy-v1");
    hasher.update(name.as_bytes());
    hasher.update(real.as_bytes());
    let digest = hasher.finalize();
    let hexed = hex::encode(digest);

    if real.starts_with("sk-ant-") {
        format!("sk-ant-api03-{}", alnum(&hexed, 93))
    } else if real.starts_with("sk-") {
        format!("sk-proj-{}", alnum(&hexed, 48))
    } else if real.starts_with("github_pat_") {
        format!("github_pat_{}", alnum(&hexed, 70))
    } else if real.starts_with("ghp_") {
        format!("ghp_{}", alnum(&hexed, 36))
    } else if real.starts_with("AKIA") {
        format!("AKIA{}", alnum(&hexed, 16).to_uppercase())
    } else if real.starts_with("xoxb-") {
        format!("xoxb-{}", alnum(&hexed, 48))
    } else if real.contains("://") && real.contains('@') {
        // Connection-string-shaped secret: keep scheme, fake the credentials.
        format!("postgres://decoy:{}@db.invalid:5432/app", alnum(&hexed, 24))
    } else {
        // Generic opaque token, same length class as the original.
        let len = real.len().clamp(16, 64);
        alnum(&hexed, len)
    }
}

/// Expand a hex digest into `n` alphanumeric chars (repeating the digest hash).
fn alnum(seed_hex: &str, n: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(n);
    let bytes = seed_hex.as_bytes();
    let mut i = 0usize;
    while out.len() < n {
        // Re-hash when we run past the seed to get more deterministic entropy.
        let b = if i < bytes.len() {
            bytes[i]
        } else {
            let mut h = Sha256::new();
            h.update(seed_hex.as_bytes());
            h.update((i as u64).to_le_bytes());
            hex::encode(h.finalize()).as_bytes()[i % 32]
        };
        out.push(CHARS[(b as usize) % CHARS.len()] as char);
        i += 1;
    }
    out
}

// --- encryption at rest ---------------------------------------------------

/// Which store holds the vault key for this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyBackend {
    /// Raw 32-byte `vault.key` in the home dir (the default everywhere).
    File,
    /// macOS login-keychain item bound to the default home (opt-in via
    /// `decoyrail key migrate --to keychain`).
    Keychain,
}

/// Decide where the vault key lives for this run. Presence-based, never a
/// config flag: the keychain backend is active exactly when this run uses
/// the default home *and* a keychain item bound to that home exists.
///
/// The `is_default_home` short-circuit runs before the keychain is consulted
/// at all. That is the home binding: an overridden `DECOYRAIL_HOME` (say, a
/// copied state dir with an attacker's policy) can never reach the real key,
/// and reaching the real key means running against the real home, which
/// enforces the real policy.
pub fn resolve_backend() -> Result<KeyBackend> {
    if !config::is_default_home() {
        return Ok(KeyBackend::File);
    }
    #[cfg(target_os = "macos")]
    {
        let home = config::canonical_home()?;
        if crate::keyring::exists(&home.to_string_lossy())? {
            return Ok(KeyBackend::Keychain);
        }
    }
    Ok(KeyBackend::File)
}

fn load_or_create_key() -> Result<[u8; 32]> {
    config::ensure_home()?;
    match resolve_backend()? {
        KeyBackend::File => load_or_create_file_key(),
        KeyBackend::Keychain => {
            let home = config::canonical_home()?;
            keychain_key_from(&OsKeyStore::new(home.to_string_lossy().into_owned()))
        }
    }
}

fn load_or_create_file_key() -> Result<[u8; 32]> {
    let path = config::vault_key_path()?;
    if path.exists() {
        let bytes = std::fs::read(&path)?;
        if bytes.len() != 32 {
            return Err(anyhow!("vault key is corrupt (expected 32 bytes)"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        return Ok(key);
    }
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    config::write_private(&path, &key)?;
    Ok(key)
}

/// The keychain arm, fail closed. The backend was selected because an item
/// exists, so a denied or failed read is a hard error, never a cue to mint a
/// fresh file key: that would silently orphan the vault ciphertext behind an
/// empty new vault and mask the failure.
fn keychain_key_from(store: &dyn KeyStore) -> Result<[u8; 32]> {
    match store.fetch() {
        Ok(Some(key)) => Ok(key),
        Ok(None) => Err(anyhow!(
            "the keychain vault-key item disappeared mid-run; refusing to \
             generate a new key (restore the item or run against a backup)"
        )),
        Err(e) => Err(e.context(
            "reading the vault key from the keychain; refusing to fall back \
             to a file key",
        )),
    }
}

// --- key backend migration -------------------------------------------------

/// Key storage the migration commands run against. A trait so the migration
/// and fail-closed logic is unit-testable without the OS keychain (tests must
/// never touch the real login keychain).
pub trait KeyStore {
    fn exists(&self) -> Result<bool>;
    fn fetch(&self) -> Result<Option<[u8; 32]>>;
    fn store(&self, key: &[u8; 32]) -> Result<()>;
    fn delete(&self) -> Result<bool>;
}

/// The real login-keychain item bound to one canonical home path.
pub struct OsKeyStore {
    home: String,
}

impl OsKeyStore {
    pub fn new(home: String) -> Self {
        Self { home }
    }
}

impl KeyStore for OsKeyStore {
    fn exists(&self) -> Result<bool> {
        crate::keyring::exists(&self.home)
    }
    fn fetch(&self) -> Result<Option<[u8; 32]>> {
        crate::keyring::fetch(&self.home)
    }
    fn store(&self, key: &[u8; 32]) -> Result<()> {
        crate::keyring::store(&self.home, key)
    }
    fn delete(&self) -> Result<bool> {
        crate::keyring::delete(&self.home)
    }
}

/// Move the vault key from the on-disk file into `store`. Returns true when
/// anything changed (false: already fully on the keychain). Idempotent, and
/// it verifies the stored copy round-trips before destroying the file, so an
/// interruption at any step leaves at least one good copy of the key.
pub fn migrate_key_to_store(store: &dyn KeyStore) -> Result<bool> {
    config::ensure_home()?;
    let path = config::vault_key_path()?;
    if store.exists()? {
        if !path.exists() {
            return Ok(false);
        }
        // An earlier migration was interrupted after storing but before
        // removing the file. Finish it, but only if both copies agree; two
        // different keys means two vault histories collided and destroying
        // either would be a guess.
        let file_key = Zeroizing::new(load_or_create_file_key()?);
        let item_key = Zeroizing::new(store.fetch()?.ok_or_else(|| {
            anyhow!("the keychain item vanished mid-migration; nothing was changed")
        })?);
        if *file_key != *item_key {
            return Err(anyhow!(
                "a keychain item for this home already exists but holds a \
                 different key than vault.key; refusing to destroy either. \
                 Run `decoyrail key migrate --to file` first if the keychain \
                 copy is stale, or move vault.key aside if the file is."
            ));
        }
        shred(&path)?;
        return Ok(true);
    }
    // Fresh install without a key yet: create one, then migrate it, so the
    // command works before the first `vault add` too.
    let key = Zeroizing::new(load_or_create_file_key()?);
    store.store(&key)?;
    let back = store.fetch().unwrap_or(None).map(Zeroizing::new);
    if back.as_deref() != Some(&*key) {
        return Err(anyhow!(
            "keychain round-trip verification failed; vault.key left in place"
        ));
    }
    shred(&path)?;
    Ok(true)
}

/// Move the vault key from `store` back to the on-disk file, then remove the
/// keychain item. Returns true when anything changed (false: no item, already
/// on the file backend).
pub fn migrate_key_to_file(store: &dyn KeyStore) -> Result<bool> {
    config::ensure_home()?;
    let path = config::vault_key_path()?;
    let Some(key) = store.fetch()? else {
        return Ok(false);
    };
    let key = Zeroizing::new(key);
    if path.exists() {
        // Interrupted earlier migrate-out: the file is already written. Only
        // proceed to delete the item if the copies agree.
        let existing = Zeroizing::new(load_or_create_file_key()?);
        if *existing != *key {
            return Err(anyhow!(
                "vault.key already exists and differs from the keychain item; \
                 refusing to overwrite it (move vault.key aside first)"
            ));
        }
    } else {
        config::write_private(&path, key.as_slice())?;
    }
    store.delete()?;
    Ok(true)
}

/// Best-effort secure removal: overwrite with random bytes, sync, unlink.
/// On copy-on-write filesystems and SSDs the overwrite may not touch the
/// original blocks; this reduces recoverability, it doesn't guarantee it.
fn shred(path: &std::path::Path) -> Result<()> {
    if let Ok(meta) = std::fs::metadata(path) {
        let mut junk = vec![0u8; meta.len() as usize];
        rand::thread_rng().fill_bytes(&mut junk);
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
            use std::io::Write;
            let _ = f.write_all(&junk);
            let _ = f.sync_all();
        }
    }
    std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))
}

fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut key_bytes = load_or_create_key()?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    key_bytes.zeroize();
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("vault encrypt failed: {e}"))?;
    // Layout: [12-byte nonce][ciphertext+tag]
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < 12 {
        return Err(anyhow!("vault file is truncated"));
    }
    let mut key_bytes = load_or_create_key()?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    key_bytes.zeroize();
    let (nonce_bytes, ct) = blob.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ct)
        .map(Zeroizing::new)
        .map_err(|e| anyhow!("vault decrypt failed (wrong key or corrupt file): {e}"))
}

/// Minimal glob: supports a single leading `*.` wildcard plus exact match.
/// Hostnames are case-insensitive (RFC 4343), so both sides are folded.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let value = value.to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        value == suffix || value.ends_with(&format!(".{suffix}"))
    } else {
        pattern == "*" || pattern == value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoys_are_format_correct_and_deterministic() {
        let d1 = make_decoy("anthropic", "sk-ant-api03-REALVALUE");
        let d2 = make_decoy("anthropic", "sk-ant-api03-REALVALUE");
        assert_eq!(d1, d2, "decoys must be deterministic");
        assert!(d1.starts_with("sk-ant-api03-"));
        assert_ne!(d1, "sk-ant-api03-REALVALUE");

        assert!(make_decoy("gh", "ghp_abc").starts_with("ghp_"));
        assert!(make_decoy("aws", "AKIAxyz").starts_with("AKIA"));
    }

    #[test]
    fn provider_inference_by_value_prefix() {
        assert_eq!(infer_provider("sk-ant-api03-xyz"), Some("anthropic"));
        assert_eq!(infer_provider("sk-proj-xyz"), Some("openai"));
        assert_eq!(infer_provider("ghp_xyz"), Some("github"));
        assert_eq!(infer_provider("github_pat_xyz"), Some("github"));
        assert_eq!(infer_provider("xoxb-xyz"), Some("slack"));
        // AWS signs with the secret; no swap destination, no label.
        assert_eq!(infer_provider("AKIAIOSFODNN7EXAMPLE"), None);
        assert_eq!(infer_provider("opaque-token"), None);
    }

    #[test]
    fn legacy_vault_json_with_binding_still_parses() {
        // A pre-007 vault entry carries a `binding` object and no
        // location/provider. It must load (fields ignored/defaulted) so the
        // secret stays present as a tripwire until policy releases it.
        let legacy = r#"{"secrets":[{
            "name":"old","real":"r-value","decoy":"d-value",
            "binding":{"hosts":["api.example.com"],"location":"bearer"}}]}"#;
        let vault: Vault = serde_json::from_str(legacy).unwrap();
        assert_eq!(vault.secrets[0].name, "old");
        assert_eq!(vault.secrets[0].location, Location::Any);
        assert!(vault.secrets[0].provider.is_none());
    }

    #[test]
    fn glob_wildcard() {
        assert!(glob_match("*.amazonaws.com", "s3.amazonaws.com"));
        assert!(glob_match("*.amazonaws.com", "amazonaws.com"));
        assert!(!glob_match("*.amazonaws.com", "amazonaws.com.evil.com"));
        assert!(glob_match("api.anthropic.com", "api.anthropic.com"));
    }

    #[test]
    fn glob_is_case_insensitive() {
        assert!(glob_match("api.anthropic.com", "API.Anthropic.COM"));
        assert!(glob_match(
            "*.githubusercontent.com",
            "RAW.GITHUBUSERCONTENT.COM"
        ));
        assert!(glob_match(
            "*.GitHubUserContent.com",
            "raw.githubusercontent.com"
        ));
    }

    #[test]
    fn encrypt_roundtrip() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());
        let pt = b"hello vault";
        let blob = encrypt(pt).unwrap();
        assert_ne!(&blob[12..], pt);
        assert_eq!(decrypt(&blob).unwrap().as_slice(), pt);
    }

    // --- key backend ---

    use std::cell::RefCell;

    /// In-memory stand-in for the login keychain. Tests must never touch the
    /// real one (they'd bind items to the developer's machine and prompt).
    struct MemStore(RefCell<Option<[u8; 32]>>);

    impl MemStore {
        fn empty() -> Self {
            Self(RefCell::new(None))
        }
    }

    impl KeyStore for MemStore {
        fn exists(&self) -> Result<bool> {
            Ok(self.0.borrow().is_some())
        }
        fn fetch(&self) -> Result<Option<[u8; 32]>> {
            Ok(*self.0.borrow())
        }
        fn store(&self, key: &[u8; 32]) -> Result<()> {
            if self.0.borrow().is_some() {
                return Err(anyhow!("duplicate item"));
            }
            *self.0.borrow_mut() = Some(*key);
            Ok(())
        }
        fn delete(&self) -> Result<bool> {
            Ok(self.0.borrow_mut().take().is_some())
        }
    }

    /// A store whose item exists but every data access is denied, like a
    /// user clicking Deny on the consent prompt.
    struct DeniedStore;

    impl KeyStore for DeniedStore {
        fn exists(&self) -> Result<bool> {
            Ok(true)
        }
        fn fetch(&self) -> Result<Option<[u8; 32]>> {
            Err(anyhow!("simulated keychain denial"))
        }
        fn store(&self, _key: &[u8; 32]) -> Result<()> {
            Err(anyhow!("simulated keychain denial"))
        }
        fn delete(&self) -> Result<bool> {
            Err(anyhow!("simulated keychain denial"))
        }
    }

    /// The test condition itself: every run with `DECOYRAIL_HOME` set (all of
    /// the suite, the e2e script) must resolve to the file backend without
    /// ever consulting the keychain.
    #[test]
    fn overridden_home_resolves_to_file_backend() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());
        assert_eq!(resolve_backend().unwrap(), KeyBackend::File);
    }

    #[test]
    fn key_migration_round_trip_keeps_vault_decryptable() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        let mut vault = Vault::default();
        vault
            .add("gh", "ghp_realrealreal", None, Location::Any)
            .unwrap();
        let key_path = config::vault_key_path().unwrap();
        let original = std::fs::read(&key_path).unwrap();

        // In: file removed, store holds the same key, second run is a no-op.
        let store = MemStore::empty();
        assert!(migrate_key_to_store(&store).unwrap());
        assert!(!key_path.exists());
        assert_eq!(store.fetch().unwrap().unwrap().as_slice(), original);
        assert!(!migrate_key_to_store(&store).unwrap());

        // Out: file restored byte-for-byte, item gone, second run is a no-op.
        assert!(migrate_key_to_file(&store).unwrap());
        assert_eq!(std::fs::read(&key_path).unwrap(), original);
        assert!(!store.exists().unwrap());
        assert!(!migrate_key_to_file(&store).unwrap());

        // And the secret added before the round trip still decrypts.
        let vault = Vault::load_or_init().unwrap();
        assert_eq!(vault.secrets[0].real, "ghp_realrealreal");
    }

    /// Interrupted migrate-in (item stored, file still present): a re-run
    /// finishes the file removal when the copies agree, and refuses when the
    /// keychain holds a different key.
    #[test]
    fn interrupted_migration_resumes_or_refuses() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        let key = load_or_create_file_key().unwrap();
        let key_path = config::vault_key_path().unwrap();

        let agreeing = MemStore(RefCell::new(Some(key)));
        assert!(migrate_key_to_store(&agreeing).unwrap());
        assert!(!key_path.exists());

        let other = load_or_create_file_key().unwrap(); // fresh random key
        assert_ne!(other, key);
        let stale = MemStore(RefCell::new(Some(key)));
        assert!(migrate_key_to_store(&stale).is_err());
        assert!(
            key_path.exists(),
            "a refused migration must not delete the file"
        );
        assert!(
            migrate_key_to_file(&stale).is_err(),
            "migrate-out must also refuse to overwrite a differing vault.key"
        );
    }

    /// Fail closed: a selected-but-denied keychain read aborts and never
    /// writes a fresh vault.key (which would orphan the real ciphertext).
    #[test]
    fn denied_keychain_read_fails_closed_without_new_key() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());
        config::ensure_home().unwrap();

        assert!(keychain_key_from(&DeniedStore).is_err());
        assert!(
            !config::vault_key_path().unwrap().exists(),
            "no vault.key may appear after a failed keychain read"
        );
    }
}
