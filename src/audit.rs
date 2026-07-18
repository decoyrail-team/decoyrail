//! Append-only, hash-chained audit log.
//!
//! Each event embeds the SHA-256 of the previous event, so any deletion or edit
//! of history breaks the chain and is detectable by `decoyrail log --verify`. This
//! is the tamper-evident record enterprises need for AI-agent egress.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{BufRead, Write};

use crate::config;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub seq: u64,
    pub ts: String,
    pub host: String,
    pub path: String,
    pub method: String,
    pub action: String,
    pub rule: String,
    #[serde(default)]
    pub escalated: bool,
    #[serde(default)]
    pub swaps: Vec<String>,
    #[serde(default)]
    pub tripwires: Vec<String>,
    #[serde(default)]
    pub status: u16,
    #[serde(default)]
    pub note: String,
    /// Process id of the decoyrail process that recorded the event. Lets
    /// `decoyrail log --pid` isolate one session when several `decoyrail run`s
    /// share the log. 0 marks events written before this field existed.
    #[serde(default)]
    pub pid: u32,
    /// Session id of the recording process (one `decoyrail run` or `proxy`
    /// invocation). Stable across the session's lifetime, unlike pid, which
    /// the OS can reuse. Empty for events written before this field existed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sid: String,
    /// Wall-clock duration of the request in milliseconds. For streamed
    /// responses the allow event omits it and the follow-up `usage` event
    /// carries the full-drain duration, so no request is measured twice.
    /// None for events written before this field existed (analytics shows
    /// those as unknown, never zero).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dur_ms: Option<u64>,
    /// Request/response body sizes, as seen at the proxy.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub bytes_up: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub bytes_down: u64,
    /// Provider-reported token usage, structured (the human-readable `note`
    /// keeps its greppable rendering). Only on events that carry tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<UsageRec>,
    /// For deferred `usage` events: the seq of the allow event this usage
    /// belongs to, so analytics counts the request exactly once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub req_seq: Option<u64>,
    /// SHA-256 of the previous event's `hash` concatenated with this event's
    /// canonical payload. First event chains from all-zero.
    pub prev_hash: String,
    pub hash: String,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// Structured token accounting for one request: the meter key (model name,
/// billing-tagged), the normalized token split, and what it cost. Everything
/// here is metadata the audit note already carried in prose.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UsageRec {
    pub model: String,
    pub input: u64,
    pub output: u64,
    #[serde(default)]
    pub cache_read: u64,
    #[serde(default)]
    pub cache_write: u64,
    pub cost_usd: f64,
    /// API-equivalent reference cost for subscription traffic (plan 019):
    /// what these tokens would have billed at API rates. Zero (and omitted)
    /// for usage-billed requests; never summed into `cost_usd`.
    #[serde(default, skip_serializing_if = "ref_is_zero")]
    pub ref_cost_usd: f64,
}

fn ref_is_zero(n: &f64) -> bool {
    *n == 0.0
}

/// What the caller wants recorded; the auditor stamps seq/ts/hashes.
#[derive(Default)]
pub struct Entry {
    pub host: String,
    pub path: String,
    pub method: String,
    pub action: String,
    pub rule: String,
    pub escalated: bool,
    pub swaps: Vec<String>,
    pub tripwires: Vec<String>,
    pub status: u16,
    pub note: String,
    pub sid: String,
    pub dur_ms: Option<u64>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub usage: Option<UsageRec>,
    pub req_seq: Option<u64>,
}

impl Entry {
    /// A request-free event (reload failures, license and tier changes):
    /// host, path, and method carry the "-" placeholder.
    pub fn note(action: &str, note: String) -> Self {
        Entry {
            host: "-".into(),
            path: "-".into(),
            method: "-".into(),
            action: action.into(),
            note,
            ..Default::default()
        }
    }
}

pub struct Auditor {
    seq: u64,
    prev_hash: String,
    /// File length (bytes) as of our last known state. If the file has grown
    /// beyond this when we go to append, another process wrote concurrently
    /// and we re-derive seq/prev_hash from the tail before chaining.
    known_len: u64,
}

pub(crate) const ZERO_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Hash payload generations. Each generation appends fields to the previous
/// one's JSON-array payload; an event's stored hash commits to the payload it
/// was written with, so `verify` tries newest-first and only falls back when
/// the newer fields are absent (their serde defaults). Rewriting a newer
/// event's fields to defaults still breaks the chain: its hash committed to a
/// longer payload than the fallback recomputes.
#[derive(Clone, Copy, PartialEq, PartialOrd)]
enum PayloadVersion {
    /// Original fields, before pid existed.
    Legacy,
    /// + pid.
    Pid,
    /// + sid, dur_ms, bytes_up, bytes_down, usage, req_seq (analytics).
    Analytics,
}

/// Compute an event's chain hash from the previous hash and the event fields.
///
/// The payload is a JSON array, not a delimiter-joined string: with the old
/// `field|field|…` form a `|` inside `path` or `note` could shift field
/// boundaries so two distinct events hashed identically. JSON escaping and
/// array structure make the encoding unambiguous. Shared by append + verify so
/// the two can never drift. New events always hash with the newest version.
fn chain_hash(prev_hash: &str, ev: &AuditEvent, version: PayloadVersion) -> Result<String> {
    use serde_json::json;
    let mut fields = vec![
        json!(ev.seq),
        json!(ev.ts),
        json!(ev.host),
        json!(ev.path),
        json!(ev.method),
        json!(ev.action),
        json!(ev.rule),
        json!(ev.swaps),
        json!(ev.tripwires),
        json!(ev.status),
        json!(ev.note),
    ];
    if version >= PayloadVersion::Pid {
        fields.push(json!(ev.pid));
    }
    if version >= PayloadVersion::Analytics {
        fields.push(json!(ev.sid));
        fields.push(json!(ev.dur_ms));
        fields.push(json!(ev.bytes_up));
        fields.push(json!(ev.bytes_down));
        fields.push(serde_json::to_value(&ev.usage).context("serializing usage")?);
        fields.push(json!(ev.req_seq));
    }
    let payload = serde_json::to_vec(&fields).context("serializing audit payload")?;
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(b"|");
    hasher.update(&payload);
    Ok(hex::encode(hasher.finalize()))
}

/// True if `ev` chains correctly from `prev_hash`. Tries the newest payload
/// first; events written before a field existed deserialize with its default
/// and verify via the matching older payload. Used by both `verify` and the
/// stats ingester, which verifies incrementally from a cached tail.
pub fn verify_link(prev_hash: &str, ev: &AuditEvent) -> bool {
    if ev.prev_hash != prev_hash {
        return false;
    }
    let Ok(expect) = chain_hash(prev_hash, ev, PayloadVersion::Analytics) else {
        return false;
    };
    if ev.hash == expect {
        return true;
    }
    // Pre-analytics events carry none of the new fields.
    let pre_analytics = ev.sid.is_empty()
        && ev.dur_ms.is_none()
        && ev.bytes_up == 0
        && ev.bytes_down == 0
        && ev.usage.is_none()
        && ev.req_seq.is_none();
    if pre_analytics {
        if let Ok(expect) = chain_hash(prev_hash, ev, PayloadVersion::Pid) {
            if ev.hash == expect {
                return true;
            }
        }
        // Pre-pid events deserialize with pid == 0, a pid no user process can
        // have; a real event's pid rewritten to 0 still fails because its
        // stored hash committed to the pid-bearing payload.
        if ev.pid == 0 {
            if let Ok(expect) = chain_hash(prev_hash, ev, PayloadVersion::Legacy) {
                return ev.hash == expect;
            }
        }
    }
    false
}

impl Auditor {
    /// Open the log, recovering seq + last hash from the tail so appends chain.
    pub fn open() -> Result<Self> {
        config::ensure_home()?;
        let path = config::audit_path()?;
        // Stat before scanning the tail. If another process appends between
        // the two, known_len undercounts and the next append resyncs under
        // its lock. The reverse order could pair a fresh length with a stale
        // tail, so append would skip the resync and fork the chain.
        let known_len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let (seq, prev_hash) = recover_tail(&path)?;
        Ok(Self {
            seq,
            prev_hash,
            known_len,
        })
    }

    /// `ts` is passed in so the proxy controls the clock source (and tests can
    /// pin it). Returns the sealed event.
    ///
    /// Appends are serialized across processes with an exclusive OS file lock:
    /// `decoyrail proxy` and `decoyrail run` can run at once, and without the lock
    /// each would chain from its own stale `prev_hash`, forking the chain and
    /// tripping a false tamper alarm in `verify`. Under the lock we re-derive
    /// seq/prev_hash from the tail if another process wrote since we last knew.
    pub fn append(&mut self, entry: Entry, ts: String) -> Result<AuditEvent> {
        use fs2::FileExt as _;

        let path = config::audit_path()?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)
            .context("opening audit log for append")?;
        file.lock_exclusive().context("locking audit log")?;
        // Ensure the lock is released even on an early return.
        let _guard = LockGuard(&file);

        // If another process appended since our cached state, resync from tail.
        let current_len = file.metadata().map(|m| m.len()).unwrap_or(self.known_len);
        if current_len != self.known_len {
            let (seq, prev_hash) = recover_tail(&path)?;
            self.seq = seq;
            self.prev_hash = prev_hash;
        }

        let pid = std::process::id();
        let mut ev = AuditEvent {
            seq: self.seq,
            ts,
            host: entry.host,
            path: entry.path,
            method: entry.method,
            action: entry.action,
            rule: entry.rule,
            escalated: entry.escalated,
            swaps: entry.swaps,
            tripwires: entry.tripwires,
            status: entry.status,
            note: entry.note,
            pid,
            sid: entry.sid,
            dur_ms: entry.dur_ms,
            bytes_up: entry.bytes_up,
            bytes_down: entry.bytes_down,
            usage: entry.usage,
            req_seq: entry.req_seq,
            prev_hash: self.prev_hash.clone(),
            hash: String::new(),
        };
        let hash = chain_hash(&self.prev_hash, &ev, PayloadVersion::Analytics)?;
        ev.hash = hash.clone();

        let line = format!("{}\n", serde_json::to_string(&ev)?);
        {
            let mut f = &file;
            f.write_all(line.as_bytes())?;
            f.flush()?;
        }

        // Anchor the new head while still holding the lock. Tail truncation of
        // the log leaves a valid prefix chain that `verify` alone would accept;
        // the anchor lets verify notice the log no longer reaches the last
        // sealed event. (An attacker with write access to ~/.decoyrail can rewrite
        // both; real tamper resistance is Keychain/fleet-console storage of the
        // head — see the threat model. This still defeats naive truncation.)
        write_head_anchor(self.seq, &hash);

        self.prev_hash = hash;
        self.seq += 1;
        self.known_len = current_len + line.len() as u64;
        Ok(ev)
    }
}

#[derive(Serialize, Deserialize)]
struct HeadAnchor {
    seq: u64,
    hash: String,
}

/// Atomically persist the latest head (seq, hash). Best-effort: a failure here
/// must not fail the append (the event is already durably written).
fn write_head_anchor(seq: u64, hash: &str) {
    let Ok(path) = config::audit_head_path() else {
        return;
    };
    let anchor = HeadAnchor {
        seq,
        hash: hash.to_string(),
    };
    let Ok(json) = serde_json::to_vec(&anchor) else {
        return;
    };
    let tmp = path.with_extension("head.tmp");
    if std::fs::write(&tmp, &json).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

fn read_head_anchor() -> Option<HeadAnchor> {
    let path = config::audit_head_path().ok()?;
    let bytes = std::fs::read(&path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The anchored head (seq, hash), if one exists. The stats ingester compares
/// it against the last event it saw to flag tail truncation, same as `verify`.
pub fn head_anchor() -> Option<(u64, String)> {
    read_head_anchor().map(|a| (a.seq, a.hash))
}

/// Test support: seal a pre-built event into the chain without the per-append
/// file locking `Auditor` does, so tests can synthesize large logs fast.
#[cfg(test)]
pub(crate) fn seal_for_test(prev_hash: &str, ev: &mut AuditEvent) {
    ev.prev_hash = prev_hash.to_string();
    ev.hash = chain_hash(prev_hash, ev, PayloadVersion::Analytics).unwrap();
}

/// Releases a file lock on drop.
struct LockGuard<'a>(&'a std::fs::File);

impl Drop for LockGuard<'_> {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(self.0);
    }
}

/// Recover (next_seq, last_hash) by scanning the log tail.
fn recover_tail(path: &std::path::Path) -> Result<(u64, String)> {
    match std::fs::File::open(path) {
        Ok(file) => {
            let mut last: Option<AuditEvent> = None;
            for line in std::io::BufReader::new(file).lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(ev) = serde_json::from_str::<AuditEvent>(&line) {
                    last = Some(ev);
                }
            }
            Ok(match last {
                Some(ev) => (ev.seq + 1, ev.hash),
                None => (0, ZERO_HASH.to_string()),
            })
        }
        Err(_) => Ok((0, ZERO_HASH.to_string())),
    }
}

/// Verify the full chain on disk. Returns Ok(count) or the seq that broke it.
///
/// Beyond checking the hash links (which catches edits and mid-file deletions),
/// this compares the last event against the persisted head anchor, so tail
/// truncation — dropping the most recent events, which leaves a valid prefix
/// chain — is also detected.
pub fn verify() -> Result<u64> {
    let path = config::audit_path()?;
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => {
            // No log. If an anchor claims events existed, the log was deleted.
            if let Some(anchor) = read_head_anchor() {
                return Err(anyhow::anyhow!(
                    "audit log missing but head anchor expects seq {} (log deleted)",
                    anchor.seq
                ));
            }
            return Ok(0);
        }
    };
    // Read under a shared lock. An append holds the exclusive lock across
    // both the log line and the head anchor; verifying without a lock can
    // catch the pair half-done (anchor already advanced, line not yet read)
    // and report truncation on a healthy log.
    fs2::FileExt::lock_shared(&file).context("locking audit log for verify")?;
    let _guard = LockGuard(&file);
    let mut prev = ZERO_HASH.to_string();
    let mut count = 0u64;
    let mut last: Option<(u64, String)> = None;
    for line in std::io::BufReader::new(&file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let ev: AuditEvent = serde_json::from_str(&line)?;
        if !verify_link(&prev, &ev) {
            return Err(anyhow::anyhow!(
                "audit chain broken at seq {} (tampering or truncation)",
                ev.seq
            ));
        }
        prev = ev.hash.clone();
        last = Some((ev.seq, ev.hash));
        count += 1;
    }

    // Compare the tail against the anchored head. A truncated log verifies as a
    // valid prefix, but its last seq/hash won't match the anchor.
    if let Some(anchor) = read_head_anchor() {
        match &last {
            Some((seq, hash)) if *seq == anchor.seq && *hash == anchor.hash => {}
            Some((seq, _)) => {
                return Err(anyhow::anyhow!(
                    "audit log truncated: head anchor expects seq {} but log ends at seq {}",
                    anchor.seq,
                    seq
                ));
            }
            None => {
                return Err(anyhow::anyhow!(
                    "audit log emptied but head anchor expects seq {}",
                    anchor.seq
                ));
            }
        }
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_appends_and_verifies() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        let mut a = Auditor::open().unwrap();
        a.append(
            Entry {
                host: "api.anthropic.com".into(),
                action: "allow".into(),
                ..Default::default()
            },
            "2026-07-05T00:00:00Z".into(),
        )
        .unwrap();
        a.append(
            Entry {
                host: "evil.com".into(),
                action: "deny".into(),
                tripwires: vec!["anthropic".into()],
                ..Default::default()
            },
            "2026-07-05T00:00:01Z".into(),
        )
        .unwrap();

        assert_eq!(verify().unwrap(), 2);
    }

    #[test]
    fn concurrent_auditors_keep_one_valid_chain() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        // Two independent Auditor instances (as two processes would have),
        // interleaving appends against the same file.
        let mut a = Auditor::open().unwrap();
        let mut b = Auditor::open().unwrap();
        a.append(
            Entry {
                host: "a1".into(),
                action: "allow".into(),
                ..Default::default()
            },
            "t0".into(),
        )
        .unwrap();
        b.append(
            Entry {
                host: "b1".into(),
                action: "allow".into(),
                ..Default::default()
            },
            "t1".into(),
        )
        .unwrap();
        a.append(
            Entry {
                host: "a2".into(),
                action: "allow".into(),
                ..Default::default()
            },
            "t2".into(),
        )
        .unwrap();
        b.append(
            Entry {
                host: "b2".into(),
                action: "allow".into(),
                ..Default::default()
            },
            "t3".into(),
        )
        .unwrap();

        // A single unbroken, correctly-sequenced chain of 4 events.
        assert_eq!(verify().unwrap(), 4);
    }

    #[test]
    fn verify_never_false_alarms_during_appends() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        let mut a = Auditor::open().unwrap();
        a.append(
            Entry {
                host: "seed".into(),
                action: "allow".into(),
                ..Default::default()
            },
            "t0".into(),
        )
        .unwrap();

        // A live proxy keeps appending while `decoyrail log --verify` reads.
        // The shared lock in `verify` makes each read see whole appends only;
        // without it, an anchor written just after the log was read presents
        // as truncation of a healthy log.
        let writer = std::thread::spawn(move || {
            for i in 1..=200 {
                a.append(
                    Entry {
                        host: format!("h{i}"),
                        action: "allow".into(),
                        ..Default::default()
                    },
                    format!("t{i}"),
                )
                .unwrap();
            }
        });
        while !writer.is_finished() {
            verify().expect("verify raced a concurrent append");
        }
        writer.join().unwrap();
        assert_eq!(verify().unwrap(), 201);
    }

    #[test]
    fn open_mid_append_does_not_fork_the_chain() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        // One long-lived auditor (the proxy) appends while other "processes"
        // open fresh auditors and append (`decoyrail run` starting up). `open`
        // stats the file before scanning the tail; pairing a fresh length
        // with a stale tail would make append skip its under-lock resync and
        // chain from a stale hash, forking the chain for good.
        let writer = std::thread::spawn(move || {
            let mut a = Auditor::open().unwrap();
            for i in 0..100 {
                a.append(
                    Entry {
                        host: format!("w{i}"),
                        action: "allow".into(),
                        ..Default::default()
                    },
                    format!("t{i}"),
                )
                .unwrap();
            }
        });
        let mut opened = 0u64;
        loop {
            let done = writer.is_finished();
            let mut b = Auditor::open().unwrap();
            b.append(
                Entry {
                    host: "opener".into(),
                    action: "allow".into(),
                    ..Default::default()
                },
                "t".into(),
            )
            .unwrap();
            opened += 1;
            if done {
                break;
            }
        }
        writer.join().unwrap();
        assert_eq!(verify().unwrap(), 100 + opened);
    }

    #[test]
    fn tail_truncation_is_detected() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        let mut a = Auditor::open().unwrap();
        for i in 0..3 {
            a.append(
                Entry {
                    host: format!("h{i}"),
                    action: "allow".into(),
                    ..Default::default()
                },
                format!("t{i}"),
            )
            .unwrap();
        }
        assert_eq!(verify().unwrap(), 3);

        // Drop the last line — a valid 2-event prefix, but the anchor knows 3.
        let path = config::audit_path().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.pop();
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

        assert!(
            verify().is_err(),
            "tail truncation must be detected via the head anchor"
        );
    }

    /// An event skeleton for hand-hashing tests.
    fn raw_event(host: &str, path: &str) -> AuditEvent {
        AuditEvent {
            seq: 0,
            ts: "t".into(),
            host: host.into(),
            path: path.into(),
            method: "GET".into(),
            action: "allow".into(),
            rule: "r".into(),
            escalated: false,
            swaps: vec![],
            tripwires: vec![],
            status: 200,
            note: String::new(),
            pid: 1,
            sid: String::new(),
            dur_ms: None,
            bytes_up: 0,
            bytes_down: 0,
            usage: None,
            req_seq: None,
            prev_hash: ZERO_HASH.into(),
            hash: String::new(),
        }
    }

    #[test]
    fn delimiter_injection_does_not_collide() {
        // Two events that the old pipe-joined payload would hash identically:
        // ("a|b", "c") vs ("a", "b|c") in adjacent fields.
        let h1 = chain_hash(ZERO_HASH, &raw_event("a|b", "c"), PayloadVersion::Analytics).unwrap();
        let h2 = chain_hash(ZERO_HASH, &raw_event("a", "b|c"), PayloadVersion::Analytics).unwrap();
        assert_ne!(h1, h2, "distinct events must not share a hash");
    }

    #[test]
    fn analytics_fields_append_and_verify() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        let mut a = Auditor::open().unwrap();
        a.append(
            Entry {
                host: "api.anthropic.com".into(),
                action: "allow".into(),
                sid: "s1".into(),
                dur_ms: Some(340),
                bytes_up: 900,
                bytes_down: 4200,
                usage: Some(UsageRec {
                    model: "claude-sonnet-5".into(),
                    input: 1000,
                    output: 200,
                    cache_read: 5000,
                    cache_write: 100,
                    cost_usd: 0.007875,
                    ref_cost_usd: 0.0,
                }),
                ..Default::default()
            },
            "t0".into(),
        )
        .unwrap();
        a.append(
            Entry {
                host: "api.anthropic.com".into(),
                action: "usage".into(),
                sid: "s1".into(),
                req_seq: Some(0),
                bytes_down: 8000,
                ..Default::default()
            },
            "t1".into(),
        )
        .unwrap();
        assert_eq!(verify().unwrap(), 2);

        // Round trip: the structured fields survive serialization.
        let text = std::fs::read_to_string(config::audit_path().unwrap()).unwrap();
        let ev: AuditEvent = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(ev.sid, "s1");
        assert_eq!(ev.dur_ms, Some(340));
        assert_eq!(ev.usage.as_ref().unwrap().cache_read, 5000);
    }

    #[test]
    fn tampered_analytics_fields_break_chain() {
        let _g = crate::util::env_guard();
        // Each rewrite targets one new field; every one must break the chain,
        // including rewrites back to the field's default (absent) form.
        for (needle, replacement) in [
            ("\"dur_ms\":340", "\"dur_ms\":1"),
            ("\"bytes_up\":900", "\"bytes_up\":1"),
            ("\"sid\":\"s1\"", "\"sid\":\"s2\""),
            ("\"cost_usd\":0.007875", "\"cost_usd\":0.0"),
            (",\"dur_ms\":340", ""),
        ] {
            let dir = tempfile::tempdir().unwrap();
            std::env::set_var("DECOYRAIL_HOME", dir.path());
            let mut a = Auditor::open().unwrap();
            a.append(
                Entry {
                    host: "h".into(),
                    action: "allow".into(),
                    sid: "s1".into(),
                    dur_ms: Some(340),
                    bytes_up: 900,
                    usage: Some(UsageRec {
                        model: "m".into(),
                        input: 1,
                        output: 1,
                        cache_read: 0,
                        cache_write: 0,
                        cost_usd: 0.007875,
                        ref_cost_usd: 0.0,
                    }),
                    ..Default::default()
                },
                "t0".into(),
            )
            .unwrap();
            let path = config::audit_path().unwrap();
            let content = std::fs::read_to_string(&path).unwrap();
            assert!(content.contains(needle), "fixture must contain {needle}");
            std::fs::write(&path, content.replacen(needle, replacement, 1)).unwrap();
            assert!(verify().is_err(), "tampering {needle} must break the chain");
        }
    }

    #[test]
    fn legacy_events_without_pid_verify_and_chain_forward() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        // Hand-write an event as the pre-pid format did: no pid field, hash
        // over the legacy payload.
        let mut legacy = raw_event("legacy.example", "/");
        legacy.ts = "t0".into();
        legacy.pid = 0;
        let hash = chain_hash(ZERO_HASH, &legacy, PayloadVersion::Legacy).unwrap();
        let line = format!(
            r#"{{"seq":0,"ts":"t0","host":"legacy.example","path":"/","method":"GET","action":"allow","rule":"r","escalated":false,"swaps":[],"tripwires":[],"status":200,"note":"","prev_hash":"{ZERO_HASH}","hash":"{hash}"}}"#
        );
        crate::config::ensure_home().unwrap();
        std::fs::write(config::audit_path().unwrap(), format!("{line}\n")).unwrap();
        assert_eq!(
            verify().unwrap(),
            1,
            "legacy event must verify via fallback"
        );

        // A new append chains onto the legacy tail and both keep verifying.
        let mut a = Auditor::open().unwrap();
        let ev = a
            .append(
                Entry {
                    host: "new.example".into(),
                    action: "allow".into(),
                    ..Default::default()
                },
                "t1".into(),
            )
            .unwrap();
        assert_eq!(ev.pid, std::process::id());
        assert_eq!(verify().unwrap(), 2);
    }

    #[test]
    fn pid_era_events_verify_via_fallback() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        // Hand-write an event as the pid-era format did: pid present, none of
        // the analytics fields, hash over the pid payload.
        let mut ev = raw_event("pid-era.example", "/");
        ev.ts = "t0".into();
        ev.pid = 4242;
        ev.hash = chain_hash(ZERO_HASH, &ev, PayloadVersion::Pid).unwrap();
        crate::config::ensure_home().unwrap();
        std::fs::write(
            config::audit_path().unwrap(),
            format!("{}\n", serde_json::to_string(&ev).unwrap()),
        )
        .unwrap();
        assert_eq!(verify().unwrap(), 1, "pid-era event must verify");

        // A new append chains onto it and both keep verifying.
        let mut a = Auditor::open().unwrap();
        a.append(
            Entry {
                host: "new.example".into(),
                action: "allow".into(),
                sid: "s1".into(),
                dur_ms: Some(5),
                ..Default::default()
            },
            "t1".into(),
        )
        .unwrap();
        assert_eq!(verify().unwrap(), 2);
    }

    #[test]
    fn tampered_pid_breaks_chain() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());
        let mut a = Auditor::open().unwrap();
        a.append(
            Entry {
                host: "a".into(),
                action: "allow".into(),
                ..Default::default()
            },
            "t0".into(),
        )
        .unwrap();

        // Zeroing the pid must not slip through the legacy fallback: the
        // stored hash committed to the real pid.
        let path = config::audit_path().unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let needle = format!("\"pid\":{}", std::process::id());
        assert!(content.contains(&needle));
        let tampered = content.replacen(&needle, "\"pid\":0", 1);
        std::fs::write(&path, tampered).unwrap();

        assert!(verify().is_err());
    }

    #[test]
    fn tampering_breaks_chain() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());
        let mut a = Auditor::open().unwrap();
        a.append(
            Entry {
                host: "a".into(),
                action: "allow".into(),
                ..Default::default()
            },
            "t0".into(),
        )
        .unwrap();
        a.append(
            Entry {
                host: "b".into(),
                action: "allow".into(),
                ..Default::default()
            },
            "t1".into(),
        )
        .unwrap();

        // Rewrite a field in the first line without fixing hashes.
        let path = config::audit_path().unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replacen("\"host\":\"a\"", "\"host\":\"z\"", 1);
        std::fs::write(&path, tampered).unwrap();

        assert!(verify().is_err());
    }
}
