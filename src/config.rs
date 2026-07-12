//! Decoyrail home directory and path resolution.

use anyhow::{Context, Result};
use std::path::PathBuf;

/// Resolves `~/.decoyrail`, honoring `DECOYRAIL_HOME` for tests and isolated runs.
pub fn home() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("DECOYRAIL_HOME") {
        return Ok(PathBuf::from(dir));
    }
    default_home()
}

/// The default state dir (`~/.decoyrail`), ignoring any `DECOYRAIL_HOME` override.
pub fn default_home() -> Result<PathBuf> {
    let base = dirs::home_dir().context("could not determine home directory")?;
    Ok(base.join(".decoyrail"))
}

/// True when this run uses the default home: no `DECOYRAIL_HOME`, or an
/// override that canonicalizes to the same directory. The keychain vault-key
/// backend is consulted only when this is true; a run against any other home
/// sticks to the file backend. That rule welds the real key to the genuine
/// state dir, so a copied home with an attacker's policy can never reach it.
pub fn is_default_home() -> bool {
    let Some(overridden) = std::env::var_os("DECOYRAIL_HOME") else {
        return true;
    };
    let Ok(default) = default_home() else {
        return false;
    };
    // Canonicalize both sides so a symlink or `..` can't disguise a foreign
    // dir as the default. A path that doesn't exist can't be the default
    // home in any sense that matters here.
    match (
        PathBuf::from(overridden).canonicalize(),
        default.canonicalize(),
    ) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Canonicalized absolute path of the active home. This is the keychain
/// item's binding attribute; canonicalizing once here means store and lookup
/// can never disagree about symlinks.
pub fn canonical_home() -> Result<PathBuf> {
    let h = ensure_home()?;
    h.canonicalize()
        .with_context(|| format!("canonicalizing {}", h.display()))
}

pub fn ensure_home() -> Result<PathBuf> {
    let h = home()?;
    std::fs::create_dir_all(&h).with_context(|| format!("creating {}", h.display()))?;
    // The home dir holds the CA private key and the vault; nothing in it is
    // any other user's business. 0700 regardless of umask, repairing existing
    // dirs from installs that predate this.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&h)?.permissions();
        if perms.mode() & 0o077 != 0 {
            perms.set_mode(0o700);
            std::fs::set_permissions(&h, perms)
                .with_context(|| format!("restricting {}", h.display()))?;
        }
    }
    Ok(h)
}

/// Write a file that must stay private (private keys, vault key): created
/// 0600, and re-restricted after the write in case it already existed.
pub fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    let mut f = opts
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = f.metadata()?.permissions();
        if perms.mode() & 0o077 != 0 {
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)
                .with_context(|| format!("restricting {}", path.display()))?;
        }
    }
    Ok(())
}

pub fn ca_cert_path() -> Result<PathBuf> {
    Ok(home()?.join("ca-cert.pem"))
}

pub fn ca_key_path() -> Result<PathBuf> {
    Ok(home()?.join("ca-key.pem"))
}

pub fn vault_path() -> Result<PathBuf> {
    Ok(home()?.join("vault.json"))
}

pub fn vault_key_path() -> Result<PathBuf> {
    Ok(home()?.join("vault.key"))
}

pub fn policy_path() -> Result<PathBuf> {
    Ok(home()?.join("policy.toml"))
}

/// Single most-recent backup of the policy, written before any CLI mutation so
/// a destructive `decoyrail policy` edit can be undone by copying it back.
pub fn policy_backup_path() -> Result<PathBuf> {
    Ok(home()?.join("policy.toml.bak"))
}

pub fn audit_path() -> Result<PathBuf> {
    Ok(home()?.join("audit.jsonl"))
}

/// Side file anchoring the latest audit head (seq + hash), so tail truncation
/// of the log is detectable even though a valid prefix chain still verifies.
pub fn audit_head_path() -> Result<PathBuf> {
    Ok(home()?.join("audit.head"))
}

pub fn meter_path() -> Result<PathBuf> {
    Ok(home()?.join("meter.json"))
}

/// Budget lives in its own file, not meter.json: the proxy flushes usage into
/// meter.json on every request, which would clobber a budget the user set via
/// `decoyrail budget` while the proxy was running.
pub fn budget_path() -> Result<PathBuf> {
    Ok(home()?.join("budget.json"))
}

/// Optional per-model pricing overrides (hosts, rates, billing); hot-reloaded.
pub fn pricing_path() -> Result<PathBuf> {
    Ok(home()?.join("pricing.json"))
}

/// The installed license file (signed, offline; see `license.rs`). Absence is
/// the defined Free state, so nothing creates this except `license install`.
pub fn license_path() -> Result<PathBuf> {
    Ok(home()?.join("license.toml"))
}

/// Local-only salt for DLP hit fingerprints in the audit log. Never exported:
/// fingerprints correlate on this machine but can't be matched across
/// machines or reversed by a log consumer.
pub fn dlp_salt_path() -> Result<PathBuf> {
    Ok(home()?.join("dlp.salt"))
}

/// Where DLP debug mode dumps the full payload of each request that carried a
/// hit (real secrets scrubbed, owner-only permissions). One file per request;
/// the audit note for the event names the file.
pub fn dlp_debug_dir() -> Result<PathBuf> {
    Ok(home()?.join("dlp-debug"))
}

/// Aggregate cache for `decoyrail stats`: hour-granular rollups of the audit
/// log plus the byte offset they cover, so repeat queries only ingest new
/// events. Safe to delete at any time; it rebuilds from the audit log.
pub fn stats_cache_path() -> Result<PathBuf> {
    Ok(home()?.join("stats-cache.json"))
}

/// Lock file serializing meter.json read-merge-write cycles across processes.
/// A side file because `atomic_write` replaces meter.json's inode on every
/// save, so a lock held on the data file itself would guard a dead inode.
pub fn meter_lock_path() -> Result<PathBuf> {
    Ok(home()?.join("meter.lock"))
}

/// Prompt-cache doctor stats: hygiene counters per host+model (offsets and
/// section labels only, never prompt content).
pub fn cache_path() -> Result<PathBuf> {
    Ok(home()?.join("cache.json"))
}

/// Lock file serializing cache.json read-merge-write cycles (a side file for
/// the same inode-replacement reason as `meter_lock_path`).
pub fn cache_lock_path() -> Result<PathBuf> {
    Ok(home()?.join("cache.lock"))
}

/// Atomically replace `path`'s contents (write temp in the same dir, rename).
/// A crash can't leave a half-written file that later parses as garbage.
pub fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(())
}

/// Last-modified time of a path, if it exists. Used for hot-reload change
/// detection so the running proxy picks up vault/policy/budget edits.
pub fn mtime(path: &std::path::Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Default listen address for the local proxy.
pub const DEFAULT_PROXY_ADDR: &str = "127.0.0.1:9077";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overridden_home_is_not_default() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());
        assert!(!is_default_home());
        std::env::remove_var("DECOYRAIL_HOME");
        assert!(is_default_home());
    }

    #[test]
    fn nonexistent_override_is_not_default() {
        let _g = crate::util::env_guard();
        std::env::set_var("DECOYRAIL_HOME", "/nonexistent/decoyrail-test-home");
        assert!(!is_default_home());
        std::env::remove_var("DECOYRAIL_HOME");
    }

    /// Canonicalization drift guard: a symlinked home must resolve to the
    /// same binding path as the directory it points at, so a keychain item
    /// stored under one spelling is found under the other.
    #[cfg(unix)]
    #[test]
    fn canonical_home_resolves_symlinks() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real-home");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link-home");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        std::env::set_var("DECOYRAIL_HOME", &link);
        let via_link = canonical_home().unwrap();
        std::env::set_var("DECOYRAIL_HOME", &real);
        let via_real = canonical_home().unwrap();
        std::env::remove_var("DECOYRAIL_HOME");

        assert_eq!(via_link, via_real);
    }
}
