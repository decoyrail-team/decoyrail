//! Policy integrity: out-of-band edits to `policy.toml` never load.
//!
//! Every policy Decoyrail writes or blesses gets a record in
//! `policy.toml.sig`: an HMAC-SHA256 over the exact file bytes, keyed from
//! the vault key ([`crate::vault::policy_mac_key`]), plus a public SHA-256
//! fingerprint and the blessed text itself. The proxy loads a policy only
//! when the record verifies; a file with no record, a mismatching record,
//! and a record whose file is gone all fail closed. `decoyrail policy sign`
//! blesses a hand-edited file after showing what changed.
//!
//! The MAC covers raw bytes, not a parsed form: a byte-identical restore
//! must verify, and any canonicalization would give tampering room to hide
//! in what the canonical form drops. The embedded text is the diff baseline
//! `policy sign` shows; it authenticates against the same MAC, so a
//! scribbled-on record can't present a forged baseline as truth.

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config;

type HmacSha256 = Hmac<Sha256>;

const RECORD_VERSION: u32 = 1;

/// What sits in `policy.toml.sig`. Nothing here is secret (the MAC reveals
/// nothing about the key), so the file is world-readable like the policy.
#[derive(Serialize, Deserialize)]
struct Record {
    version: u32,
    /// Public SHA-256 fingerprint of the blessed policy bytes, echoed into
    /// the audit event so the log answers "when did the policy change, and
    /// to what".
    sha256: String,
    /// HMAC-SHA256 over the blessed policy bytes under the derived key.
    mac: String,
    blessed_at: String,
    /// The blessed bytes themselves: the baseline `policy sign` diffs a
    /// hand-edited file against. Self-authenticating via `mac`.
    trusted_text: String,
}

/// The outcome of checking policy text against the record on disk. Only
/// `Trusted` loads; the other two produce the same fail-closed refusal with
/// differently-worded instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Trusted,
    /// No record exists: the upgrade case, or a file dropped in from
    /// outside. Never a trust-on-first-use cue.
    NoRecord,
    /// A record exists but does not authenticate this text (edited file,
    /// mangled record, or a record from another home or key).
    Mismatch,
}

/// Public SHA-256 fingerprint of policy text (hex).
pub fn fingerprint(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn mac_over(text: &str) -> Result<HmacSha256> {
    let key = crate::vault::policy_mac_key()?;
    let mut mac = HmacSha256::new_from_slice(key.as_slice()).expect("any key size works");
    mac.update(text.as_bytes());
    Ok(mac)
}

/// Constant-time check that `expected_hex` authenticates `text`. A garbled
/// hex string is simply a non-match, not an error: a mangled record is
/// tampering, and tampering must read as a mismatch, never as a crash.
fn mac_matches(text: &str, expected_hex: &str) -> Result<bool> {
    let Ok(expected) = hex::decode(expected_hex) else {
        return Ok(false);
    };
    Ok(mac_over(text)?.verify_slice(&expected).is_ok())
}

/// Check `text` against the record on disk. Errors (unreadable record file,
/// failed key read) propagate: the caller fails closed on them exactly like
/// on a mismatch, but with the underlying cause named.
pub fn verify(text: &str) -> Result<Verdict> {
    let path = config::policy_sig_path()?;
    if !path.exists() {
        return Ok(Verdict::NoRecord);
    }
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let Ok(rec) = serde_json::from_str::<Record>(&raw) else {
        return Ok(Verdict::Mismatch);
    };
    Ok(if mac_matches(text, &rec.mac)? {
        Verdict::Trusted
    } else {
        Verdict::Mismatch
    })
}

/// The last blessed policy text and when it was blessed, if the record still
/// authenticates it. `None` when there is no record or the embedded baseline
/// fails its own MAC (a scribbled-on record must not present a forged
/// baseline for the `policy sign` diff).
pub fn baseline() -> Result<Option<(String, String)>> {
    let path = config::policy_sig_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let Ok(rec) = serde_json::from_str::<Record>(&raw) else {
        return Ok(None);
    };
    Ok(if mac_matches(&rec.trusted_text, &rec.mac)? {
        Some((rec.trusted_text, rec.blessed_at))
    } else {
        None
    })
}

/// Write the integrity record for `text` (atomically; the record is complete
/// or absent, never torn).
fn write_record(text: &str) -> Result<()> {
    let mac = mac_over(text)?.finalize().into_bytes();
    let rec = Record {
        version: RECORD_VERSION,
        sha256: fingerprint(text),
        mac: hex::encode(mac),
        blessed_at: crate::util::now_rfc3339(),
        trusted_text: text.to_string(),
    };
    config::atomic_write(
        &config::policy_sig_path()?,
        serde_json::to_string_pretty(&rec)?.as_bytes(),
    )
}

/// Append a request-free `policy` event to the audit log, so every policy
/// change through a Decoyrail surface is a matter of record.
fn audit_policy_event(note: String) -> Result<()> {
    crate::audit::Auditor::open()?
        .append(
            crate::audit::Entry::note("policy", note),
            crate::util::now_rfc3339(),
        )
        .map(|_| ())
}

/// The one path that puts policy text on disk: validate, back up the
/// previous file, record, atomically replace, audit. Returns the backup
/// path. Record-then-rename order matters: the proxy re-verifies only when
/// an mtime moved, and the policy rename is the last mtime to move, so a
/// hot reload never sees a Decoyrail write half-applied.
///
/// This skips the is-the-current-file-trusted check on purpose (it is the
/// recovery path for `policy reset` and the first-run materialization);
/// CLI edits go through [`crate::policy_edit::write_policy`], which adds it.
pub fn install(new_text: &str, source: &str) -> Result<std::path::PathBuf> {
    toml::from_str::<crate::policy::Policy>(new_text)
        .context("refusing to write: the result is not a valid policy")?;
    config::ensure_home()?;
    let path = config::policy_path()?;
    let backup = config::policy_backup_path()?;
    if path.exists() {
        std::fs::copy(&path, &backup)
            .with_context(|| format!("backing up {} to {}", path.display(), backup.display()))?;
    }
    write_record(new_text)?;
    config::atomic_write(&path, new_text.as_bytes())?;
    audit_policy_event(format!(
        "policy updated ({source}); sha256={}",
        fingerprint(new_text)
    ))?;
    Ok(backup)
}

/// Bless the policy exactly as it sits on disk: write the record and the
/// audit event without touching `policy.toml` itself. This is the tail of
/// `decoyrail policy sign`, after the human reviewed the diff and confirmed
/// on a TTY. Refuses text that doesn't parse: blessing broken TOML would
/// convert a typo into a deny-all restart surprise. Returns the fingerprint.
pub fn bless_current() -> Result<String> {
    let path = config::policy_path()?;
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str::<crate::policy::Policy>(&text)
        .context("refusing to bless: the file does not parse as a policy")?;
    write_record(&text)?;
    let fp = fingerprint(&text);
    audit_policy_event(format!("policy blessed (policy sign); sha256={fp}"))?;
    Ok(fp)
}

/// The instructive fail-closed message for an unverifiable policy, shared by
/// the startup refusal, the hot-reload rejection, and the CLI edit refusal.
pub fn untrusted_message(verdict: Verdict) -> String {
    let path = config::policy_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "policy.toml".into());
    let why = match verdict {
        Verdict::NoRecord => {
            "has no integrity record (first start after an upgrade, or a file dropped in from outside)"
        }
        _ => "was changed outside decoyrail",
    };
    format!(
        "{path} {why}. Review the file, then bless it with `decoyrail policy sign`. \
         Decoyrail does not load a policy it cannot verify."
    )
}

/// Line diff between the last trusted text and an edited file, for the
/// `policy sign` review. Plain LCS over lines (policies are small); removed
/// lines carry `-`, added lines `+`, unchanged lines are omitted.
pub fn diff(old: &str, new: &str) -> Vec<String> {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let (n, m) = (a.len(), b.len());
    let mut lcs = vec![vec![0usize; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let mut out = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < n && j < m {
        if a[i] == b[j] {
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push(format!("- {}", a[i]));
            i += 1;
        } else {
            out.push(format!("+ {}", b[j]));
            j += 1;
        }
    }
    out.extend(a[i..].iter().map(|l| format!("- {l}")));
    out.extend(b[j..].iter().map(|l| format!("+ {l}")));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::DEFAULT_POLICY_TOML;

    fn with_home() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
        let g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());
        (g, dir)
    }

    #[test]
    fn install_verifies_and_any_byte_change_fails() {
        let (_g, _dir) = with_home();
        install(DEFAULT_POLICY_TOML, "test").unwrap();
        let path = config::policy_path().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(verify(&text).unwrap(), Verdict::Trusted);

        // One appended byte: mismatch. Byte-identical restore: trusted again,
        // with no re-blessing.
        let tampered = format!("{text}#");
        assert_eq!(verify(&tampered).unwrap(), Verdict::Mismatch);
        assert_eq!(verify(&text).unwrap(), Verdict::Trusted);

        // No record at all is its own verdict (the upgrade case).
        std::fs::remove_file(config::policy_sig_path().unwrap()).unwrap();
        assert_eq!(verify(&text).unwrap(), Verdict::NoRecord);
    }

    #[test]
    fn record_from_another_home_does_not_verify() {
        let _g = crate::util::env_guard();
        let home_a = tempfile::tempdir().unwrap();
        let home_b = tempfile::tempdir().unwrap();

        std::env::set_var("DECOYRAIL_HOME", home_a.path());
        install(DEFAULT_POLICY_TOML, "test").unwrap();
        let policy = std::fs::read(config::policy_path().unwrap()).unwrap();
        let sig = std::fs::read(config::policy_sig_path().unwrap()).unwrap();

        // Copy policy + record wholesale into home B (which has its own
        // vault key): the record must not verify there.
        std::env::set_var("DECOYRAIL_HOME", home_b.path());
        config::ensure_home().unwrap();
        std::fs::write(config::policy_path().unwrap(), &policy).unwrap();
        std::fs::write(config::policy_sig_path().unwrap(), &sig).unwrap();
        let text = std::fs::read_to_string(config::policy_path().unwrap()).unwrap();
        assert_eq!(verify(&text).unwrap(), Verdict::Mismatch);
    }

    #[test]
    fn deleted_vault_key_fails_closed_not_silently_reblessed() {
        let (_g, _dir) = with_home();
        install(DEFAULT_POLICY_TOML, "test").unwrap();
        std::fs::remove_file(config::vault_key_path().unwrap()).unwrap();
        // A fresh key gets minted on the next read; the old record can never
        // authenticate under it, so the load fails closed instead of quietly
        // trusting whatever is on disk.
        let text = std::fs::read_to_string(config::policy_path().unwrap()).unwrap();
        assert_eq!(verify(&text).unwrap(), Verdict::Mismatch);
    }

    #[test]
    fn mangled_record_is_a_mismatch_not_a_crash() {
        let (_g, _dir) = with_home();
        install(DEFAULT_POLICY_TOML, "test").unwrap();
        let text = std::fs::read_to_string(config::policy_path().unwrap()).unwrap();

        std::fs::write(config::policy_sig_path().unwrap(), "not json").unwrap();
        assert_eq!(verify(&text).unwrap(), Verdict::Mismatch);
        assert!(baseline().unwrap().is_none());

        // Valid JSON, garbled hex mac: same story.
        std::fs::write(
            config::policy_sig_path().unwrap(),
            r#"{"version":1,"sha256":"x","mac":"zz-not-hex","blessed_at":"t","trusted_text":""}"#,
        )
        .unwrap();
        assert_eq!(verify(&text).unwrap(), Verdict::Mismatch);
    }

    #[test]
    fn baseline_self_authenticates() {
        let (_g, _dir) = with_home();
        install(DEFAULT_POLICY_TOML, "test").unwrap();
        let (text, _at) = baseline().unwrap().unwrap();
        assert_eq!(text, DEFAULT_POLICY_TOML);

        // An attacker editing the embedded baseline breaks its MAC; the diff
        // must then run against nothing rather than against a forgery.
        let raw = std::fs::read_to_string(config::policy_sig_path().unwrap()).unwrap();
        let forged = raw.replace("default_action", "default_actiom");
        assert_ne!(raw, forged, "the replace must hit");
        std::fs::write(config::policy_sig_path().unwrap(), forged).unwrap();
        assert!(baseline().unwrap().is_none());
    }

    #[test]
    fn install_and_bless_write_audit_events_with_fingerprint() {
        let (_g, _dir) = with_home();
        install(DEFAULT_POLICY_TOML, "unit test").unwrap();

        // Hand-edit, then bless: the record follows the file.
        let path = config::policy_path().unwrap();
        let edited = format!("{DEFAULT_POLICY_TOML}\n# reviewed by hand\n");
        std::fs::write(&path, &edited).unwrap();
        assert_eq!(verify(&edited).unwrap(), Verdict::Mismatch);
        let fp = bless_current().unwrap();
        assert_eq!(fp, fingerprint(&edited));
        assert_eq!(verify(&edited).unwrap(), Verdict::Trusted);

        let log = std::fs::read_to_string(config::audit_path().unwrap()).unwrap();
        assert!(log.contains(&format!(
            "policy updated (unit test); sha256={}",
            fingerprint(DEFAULT_POLICY_TOML)
        )));
        assert!(log.contains(&format!("policy blessed (policy sign); sha256={fp}")));
    }

    #[test]
    fn install_and_bless_refuse_broken_toml() {
        let (_g, _dir) = with_home();
        assert!(install("default_action = \"sideways\"", "test").is_err());

        install(DEFAULT_POLICY_TOML, "test").unwrap();
        std::fs::write(config::policy_path().unwrap(), "not = toml [").unwrap();
        assert!(
            bless_current().is_err(),
            "blessing broken TOML would turn a typo into a deny-all restart surprise"
        );
    }

    #[test]
    fn diff_marks_changed_lines_only() {
        let old = "a\nb\nc\n";
        let new = "a\nB\nc\nd\n";
        assert_eq!(diff(old, new), vec!["- b", "+ B", "+ d"]);
        assert!(diff(old, old).is_empty());
    }

    #[test]
    fn untrusted_messages_name_the_cure() {
        let (_g, _dir) = with_home();
        for v in [Verdict::NoRecord, Verdict::Mismatch] {
            let msg = untrusted_message(v);
            assert!(msg.contains("policy sign"), "{msg}");
            assert!(msg.contains("policy.toml"), "{msg}");
        }
        assert!(untrusted_message(Verdict::NoRecord).contains("no integrity record"));
        assert!(untrusted_message(Verdict::Mismatch).contains("changed outside"));
    }
}
