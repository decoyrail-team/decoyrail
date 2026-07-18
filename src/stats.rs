//! Local analytics over the audit log: the engine behind `decoyrail stats`.
//!
//! The audit log is the source of truth (unlike the meter, it never resets at
//! month rollover and it carries every security event). Reading months of
//! history per query would be slow, so ingestion is incremental: events are
//! rolled up into hour-granular rows keyed by (UTC hour, session, host,
//! model), persisted in `stats-cache.json` alongside the byte offset they
//! cover. A repeat query only parses lines appended since the last one. Every
//! ingested line is chain-verified as it streams past; a broken or truncated
//! chain flags the report but never stops it, so a tampered log still yields
//! whatever numbers it can, loudly.
//!
//! Windows (today, week, month, custom) resolve in local time against the UTC
//! hour keys. Human, JSON, and one-line outputs all render from the same
//! `Report`, so they cannot disagree.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{BufRead, Seek};

use crate::audit::{self, AuditEvent};
use crate::config;

/// Version of the machine-readable output (`stats --json`). Documented in
/// docs/stats.md; bump only with the doc.
pub const SCHEMA_VERSION: u32 = 1;

/// On-disk cache format; a mismatch discards the cache and rebuilds.
// v2: policy integrity counters (plan 018); older caches rebuild from the log.
const CACHE_VERSION: u32 = 2;

/// Duration histogram: bucket `i` covers [2^(i-1), 2^i) milliseconds (bucket
/// 0 is exactly 0ms), the last bucket is open-ended. 22 buckets reach ~35min.
const DUR_BUCKETS: usize = 22;

/// Streamed requests whose follow-up `usage` event never arrived (crashed
/// stream, killed proxy) would pin correlation state forever; beyond this many
/// outstanding, the oldest are dropped and stay in the no-usage bucket.
const PENDING_CAP: usize = 4096;

/// Approximate latency distribution, mergeable across rows. Exact average and
/// max, log-scale histogram for the slow tail.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct DurStat {
    pub count: u64,
    pub sum_ms: u64,
    pub max_ms: u64,
    pub buckets: Vec<u64>,
}

impl DurStat {
    fn observe(&mut self, ms: u64) {
        if self.buckets.len() != DUR_BUCKETS {
            self.buckets = vec![0; DUR_BUCKETS];
        }
        self.count += 1;
        self.sum_ms += ms;
        self.max_ms = self.max_ms.max(ms);
        let idx = (64 - ms.leading_zeros() as usize).min(DUR_BUCKETS - 1);
        self.buckets[idx] += 1;
    }

    fn merge(&mut self, other: &DurStat) {
        if other.count == 0 {
            return;
        }
        if self.buckets.len() != DUR_BUCKETS {
            self.buckets = vec![0; DUR_BUCKETS];
        }
        self.count += other.count;
        self.sum_ms += other.sum_ms;
        self.max_ms = self.max_ms.max(other.max_ms);
        for (i, n) in other.buckets.iter().enumerate().take(DUR_BUCKETS) {
            self.buckets[i] += n;
        }
    }

    pub fn avg_ms(&self) -> Option<u64> {
        (self.count > 0).then(|| self.sum_ms / self.count)
    }

    /// Approximate 95th percentile: the upper edge of the histogram bucket
    /// the 95% mark falls in, capped at the exact max.
    pub fn p95_ms(&self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        let threshold = (self.count * 95).div_ceil(100);
        let mut cumulative = 0u64;
        for (i, n) in self.buckets.iter().enumerate() {
            cumulative += n;
            if cumulative >= threshold {
                let upper = if i == 0 { 0 } else { (1u64 << i) - 1 };
                return Some(upper.min(self.max_ms));
            }
        }
        Some(self.max_ms)
    }
}

/// One aggregate cell: everything the spec wants per bucket. Purely additive,
/// so rows merge into windows and breakdowns by summation.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct Bucket {
    pub requests: u64,
    pub allows: u64,
    /// Warn resolutions: forwarded with a recorded alert (plan 017). Their
    /// own category so "what would break if I went back to deny" is
    /// answerable per host. serde(default) keeps pre-warn caches loading.
    #[serde(default)]
    pub warns: u64,
    pub denies: u64,
    pub deny_policy: u64,
    pub deny_tripwire: u64,
    pub deny_dlp: u64,
    pub deny_budget: u64,
    /// Tripwire events: request-side denies plus response-echo alerts.
    pub tripwires: u64,
    /// DLP warn/mask alerts (blocking hits count under `deny_dlp`).
    pub dlp_alerts: u64,
    /// Policy loads rejected as tampered (`tamper` events): out-of-band
    /// edits, deleted records, unblessed files.
    pub policy_tamper: u64,
    /// Policy writes and blessings through Decoyrail surfaces (`policy`
    /// events).
    pub policy_changes: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub cost_usd: f64,
    /// Allowed requests whose provider response carried no usage: visible,
    /// never silently priced by estimate.
    pub no_usage: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub dur: DurStat,
}

impl Bucket {
    fn merge(&mut self, o: &Bucket) {
        self.requests += o.requests;
        self.allows += o.allows;
        self.warns += o.warns;
        self.denies += o.denies;
        self.deny_policy += o.deny_policy;
        self.deny_tripwire += o.deny_tripwire;
        self.deny_dlp += o.deny_dlp;
        self.deny_budget += o.deny_budget;
        self.tripwires += o.tripwires;
        self.dlp_alerts += o.dlp_alerts;
        self.policy_tamper += o.policy_tamper;
        self.policy_changes += o.policy_changes;
        self.input_tokens += o.input_tokens;
        self.output_tokens += o.output_tokens;
        self.cache_read_tokens += o.cache_read_tokens;
        self.cache_write_tokens += o.cache_write_tokens;
        self.cost_usd += o.cost_usd;
        self.no_usage += o.no_usage;
        self.bytes_up += o.bytes_up;
        self.bytes_down += o.bytes_down;
        self.dur.merge(&o.dur);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct RowKey {
    /// UTC hour, `YYYY-MM-DDTHH`, sliced straight off the event timestamp.
    hour: String,
    sid: String,
    host: String,
    /// Meter model key for token-bearing cells, empty otherwise.
    model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Row {
    #[serde(flatten)]
    key: RowKey,
    bucket: Bucket,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionInfo {
    pub label: String,
    pub started: String,
    pub pid: u32,
}

/// Correlation state for a streamed request: where its allow event landed, so
/// the follow-up `usage` event can move it out of the no-usage bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingReq {
    hour: String,
    sid: String,
    host: String,
    /// The allow event's upload size, moved along with the request when it
    /// resolves to a model row.
    bytes_up: u64,
    /// True when the pending request was a warn resolution, so its follow-up
    /// usage event moves the right counter.
    #[serde(default)]
    warn: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Cache {
    cache_version: u32,
    /// Audit log byte offset covered by `rows`.
    offset: u64,
    last_seq: Option<u64>,
    /// Hash of the last ingested event; new lines chain-verify against it.
    /// Empty means chain start.
    last_hash: String,
    /// First chain break seen, if any. Sticky: the break stays in the log.
    integrity: Option<String>,
    rows: Vec<Row>,
    sessions: BTreeMap<String, SessionInfo>,
    pending: BTreeMap<u64, PendingReq>,
}

impl Default for Cache {
    fn default() -> Self {
        Cache {
            cache_version: CACHE_VERSION,
            offset: 0,
            last_seq: None,
            last_hash: String::new(),
            integrity: None,
            rows: Vec::new(),
            sessions: BTreeMap::new(),
            pending: BTreeMap::new(),
        }
    }
}

struct Aggregator {
    rows: BTreeMap<RowKey, Bucket>,
    sessions: BTreeMap<String, SessionInfo>,
    pending: BTreeMap<u64, PendingReq>,
    integrity: Option<String>,
    offset: u64,
    last_seq: Option<u64>,
    last_hash: String,
}

impl Aggregator {
    fn from_cache(c: Cache) -> Self {
        Aggregator {
            rows: c.rows.into_iter().map(|r| (r.key, r.bucket)).collect(),
            sessions: c.sessions,
            pending: c.pending,
            integrity: c.integrity,
            offset: c.offset,
            last_seq: c.last_seq,
            last_hash: c.last_hash,
        }
    }

    fn to_cache(&self) -> Cache {
        Cache {
            cache_version: CACHE_VERSION,
            offset: self.offset,
            last_seq: self.last_seq,
            last_hash: self.last_hash.clone(),
            integrity: self.integrity.clone(),
            rows: self
                .rows
                .iter()
                .map(|(k, b)| Row {
                    key: k.clone(),
                    bucket: b.clone(),
                })
                .collect(),
            sessions: self.sessions.clone(),
            pending: self.pending.clone(),
        }
    }

    fn flag(&mut self, detail: String) {
        if self.integrity.is_none() {
            self.integrity = Some(detail);
        }
    }

    fn ingest_line(&mut self, line: &str) {
        let ev: AuditEvent = match serde_json::from_str(line) {
            Ok(ev) => ev,
            Err(_) => {
                self.flag("unparseable audit line".to_string());
                return;
            }
        };
        // Verify each link as it streams past; after the first break the
        // chain can't recover, so stop checking but keep aggregating (the
        // report stays useful, just flagged).
        if self.integrity.is_none() {
            let prev = if self.last_hash.is_empty() {
                audit::ZERO_HASH
            } else {
                &self.last_hash
            };
            if !audit::verify_link(prev, &ev) {
                self.flag(format!(
                    "audit chain broken at seq {} (tampering or truncation)",
                    ev.seq
                ));
            }
        }
        self.last_hash = ev.hash.clone();
        self.last_seq = Some(ev.seq);
        self.apply(&ev);
    }

    fn bucket(&mut self, hour: &str, sid: &str, host: &str, model: &str) -> &mut Bucket {
        self.rows
            .entry(RowKey {
                hour: hour.to_string(),
                sid: sid.to_string(),
                host: host.to_string(),
                model: model.to_string(),
            })
            .or_default()
    }

    fn apply(&mut self, ev: &AuditEvent) {
        let hour = hour_of(&ev.ts);
        match ev.action.as_str() {
            "session" => {
                if !ev.sid.is_empty() {
                    self.sessions.insert(
                        ev.sid.clone(),
                        SessionInfo {
                            label: ev.note.clone(),
                            started: ev.ts.clone(),
                            pid: ev.pid,
                        },
                    );
                }
            }
            // A warn is a forwarded request like an allow — same traffic,
            // usage, and correlation handling — counted in its own category.
            "allow" | "warn" => {
                let warn = ev.action == "warn";
                let model = ev
                    .usage
                    .as_ref()
                    .map(|u| u.model.clone())
                    .unwrap_or_default();
                let b = self.bucket(&hour, &ev.sid, &ev.host, &model);
                b.requests += 1;
                if warn {
                    b.warns += 1;
                } else {
                    b.allows += 1;
                }
                b.bytes_up += ev.bytes_up;
                b.bytes_down += ev.bytes_down;
                if let Some(ms) = ev.dur_ms {
                    b.dur.observe(ms);
                }
                match &ev.usage {
                    Some(u) => {
                        b.input_tokens += u.input;
                        b.output_tokens += u.output;
                        b.cache_read_tokens += u.cache_read;
                        b.cache_write_tokens += u.cache_write;
                        b.cost_usd += u.cost_usd;
                    }
                    None => {
                        b.no_usage += 1;
                        // Streamed responses (recognizable by their missing
                        // duration) may still resolve via a follow-up `usage`
                        // event; remember where the request landed. Buffered
                        // requests already carry everything they ever will.
                        if ev.dur_ms.is_none() {
                            self.pending.insert(
                                ev.seq,
                                PendingReq {
                                    hour: hour.clone(),
                                    sid: ev.sid.clone(),
                                    host: ev.host.clone(),
                                    bytes_up: ev.bytes_up,
                                    warn,
                                },
                            );
                            while self.pending.len() > PENDING_CAP {
                                let oldest = *self.pending.keys().next().expect("nonempty");
                                self.pending.remove(&oldest);
                            }
                        }
                    }
                }
            }
            "deny" => {
                let b = self.bucket(&hour, &ev.sid, &ev.host, "");
                b.requests += 1;
                b.denies += 1;
                b.bytes_up += ev.bytes_up;
                if let Some(ms) = ev.dur_ms {
                    b.dur.observe(ms);
                }
                if !ev.tripwires.is_empty() || ev.note.starts_with("tripwire:") {
                    b.deny_tripwire += 1;
                    b.tripwires += 1;
                } else if ev.note.starts_with("dlp:") {
                    b.deny_dlp += 1;
                } else if ev.note.starts_with("budget") {
                    b.deny_budget += 1;
                } else {
                    b.deny_policy += 1;
                }
            }
            "alert" => {
                // Response-echo tripwires and DLP warn/mask advisories. Other
                // alerts (reload failures) carry no security counter.
                if !ev.tripwires.is_empty() {
                    self.bucket(&hour, &ev.sid, &ev.host, "").tripwires += 1;
                } else if ev.note.starts_with("dlp:") {
                    self.bucket(&hour, &ev.sid, &ev.host, "").dlp_alerts += 1;
                }
            }
            // Policy integrity (plan 018): rejected loads and Decoyrail-made
            // changes are both part of the security story stats tells.
            "tamper" => self.bucket(&hour, &ev.sid, &ev.host, "").policy_tamper += 1,
            "policy" => self.bucket(&hour, &ev.sid, &ev.host, "").policy_changes += 1,
            "usage" => self.apply_usage(ev, &hour),
            _ => {}
        }
    }

    /// A deferred usage event completes a streamed request: tokens, final
    /// size, and full-drain duration arrive after the allow event was
    /// written. `req_seq` names that allow event, so the request moves from
    /// the no-usage cell to its model cell and is never counted twice.
    fn apply_usage(&mut self, ev: &AuditEvent, own_hour: &str) {
        let base = ev.req_seq.and_then(|s| self.pending.remove(&s));
        let model = ev
            .usage
            .as_ref()
            .map(|u| u.model.clone())
            .unwrap_or_default();
        match (base, &ev.usage) {
            (Some(base), Some(u)) => {
                let from = self.bucket(&base.hour, &base.sid, &base.host, "");
                from.requests = from.requests.saturating_sub(1);
                if base.warn {
                    from.warns = from.warns.saturating_sub(1);
                } else {
                    from.allows = from.allows.saturating_sub(1);
                }
                from.no_usage = from.no_usage.saturating_sub(1);
                from.bytes_up = from.bytes_up.saturating_sub(base.bytes_up);
                let to = self.bucket(&base.hour, &base.sid, &base.host, &model);
                to.requests += 1;
                if base.warn {
                    to.warns += 1;
                } else {
                    to.allows += 1;
                }
                to.bytes_up += base.bytes_up;
                to.input_tokens += u.input;
                to.output_tokens += u.output;
                to.cache_read_tokens += u.cache_read;
                to.cache_write_tokens += u.cache_write;
                to.cost_usd += u.cost_usd;
                to.bytes_down += ev.bytes_down;
                if let Some(ms) = ev.dur_ms {
                    to.dur.observe(ms);
                }
            }
            (Some(base), None) => {
                // Stream ended without parseable usage: stays in the
                // no-usage bucket, but its size and duration still count.
                let b = self.bucket(&base.hour, &base.sid, &base.host, "");
                b.bytes_down += ev.bytes_down;
                if let Some(ms) = ev.dur_ms {
                    b.dur.observe(ms);
                }
            }
            (None, Some(u)) => {
                // No correlation (pruned, or a log that starts mid-session):
                // tokens still count, attributed to the event's own hour.
                let b = self.bucket(own_hour, &ev.sid, &ev.host, &model);
                b.input_tokens += u.input;
                b.output_tokens += u.output;
                b.cache_read_tokens += u.cache_read;
                b.cache_write_tokens += u.cache_write;
                b.cost_usd += u.cost_usd;
                b.bytes_down += ev.bytes_down;
            }
            (None, None) => {
                if ev.bytes_down > 0 {
                    self.bucket(own_hour, &ev.sid, &ev.host, "").bytes_down += ev.bytes_down;
                }
            }
        }
    }
}

/// `YYYY-MM-DDTHH` from an RFC-3339 UTC timestamp; odd timestamps (hand-made
/// test logs) pass through whole so nothing is dropped.
fn hour_of(ts: &str) -> String {
    if ts.len() >= 13 && ts.as_bytes()[10] == b'T' {
        ts[..13].to_string()
    } else {
        ts.to_string()
    }
}

// ---------------------------------------------------------------------------
// Windows

#[derive(Debug, Clone, PartialEq)]
pub enum Window {
    Today,
    Week,
    Month,
    All,
    /// Inclusive local dates.
    Range {
        since: chrono::NaiveDate,
        until: chrono::NaiveDate,
    },
}

impl Window {
    pub fn kind(&self) -> &'static str {
        match self {
            Window::Today => "today",
            Window::Week => "week",
            Window::Month => "month",
            Window::All => "all",
            Window::Range { .. } => "range",
        }
    }

    /// Half-open [from, to) bounds as UTC hour keys. Local midnights convert
    /// to UTC, so "today" means the user's day, not the server's.
    fn bounds(&self, now: chrono::DateTime<chrono::Local>) -> (Option<String>, Option<String>) {
        use chrono::{Datelike, Duration, NaiveDate};
        let today = now.date_naive();
        let (from, to) = match self {
            Window::All => return (None, None),
            Window::Today => (today, today + Duration::days(1)),
            Window::Week => {
                let monday = today - Duration::days(today.weekday().num_days_from_monday() as i64);
                (monday, today + Duration::days(1))
            }
            Window::Month => {
                let first =
                    NaiveDate::from_ymd_opt(today.year(), today.month(), 1).unwrap_or(today);
                (first, today + Duration::days(1))
            }
            Window::Range { since, until } => (*since, *until + Duration::days(1)),
        };
        (
            Some(local_midnight_hour_key(from)),
            Some(local_midnight_hour_key(to)),
        )
    }
}

/// The UTC hour key for local midnight of `date`.
fn local_midnight_hour_key(date: chrono::NaiveDate) -> String {
    use chrono::TimeZone;
    let naive = date.and_hms_opt(0, 0, 0).expect("midnight exists");
    // A DST gap can make local midnight nonexistent; fall back to now rather
    // than fail the query over one ambiguous hour.
    let local = chrono::Local
        .from_local_datetime(&naive)
        .earliest()
        .unwrap_or_else(chrono::Local::now);
    local
        .with_timezone(&chrono::Utc)
        .format("%Y-%m-%dT%H")
        .to_string()
}

/// The local calendar day a UTC hour key falls in.
fn local_day_of_hour(hour: &str) -> String {
    use chrono::TimeZone;
    let Ok(naive) =
        chrono::NaiveDateTime::parse_from_str(&format!("{hour}:00:00"), "%Y-%m-%dT%H:%M:%S")
    else {
        return "unknown".to_string();
    };
    chrono::Utc
        .from_utc_datetime(&naive)
        .with_timezone(&chrono::Local)
        .format("%Y-%m-%d")
        .to_string()
}

// ---------------------------------------------------------------------------
// Report

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub window: WindowOut,
    pub integrity: IntegrityOut,
    pub totals: BucketOut,
    pub by_session: Vec<SessionOut>,
    pub by_model: Vec<NamedOut>,
    pub by_host: Vec<NamedOut>,
    pub by_day: Vec<NamedOut>,
}

#[derive(Debug, Serialize)]
pub struct WindowOut {
    pub kind: String,
    /// UTC hour keys, half-open; null means unbounded.
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IntegrityOut {
    pub ok: bool,
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeniesOut {
    pub total: u64,
    pub policy: u64,
    pub tripwire: u64,
    pub dlp: u64,
    pub budget: u64,
}

#[derive(Debug, Serialize)]
pub struct TokensOut {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub total: u64,
}

#[derive(Debug, Serialize)]
pub struct BytesOut {
    pub up: u64,
    pub down: u64,
}

#[derive(Debug, Serialize)]
pub struct DurOut {
    pub avg: u64,
    pub p95: u64,
    pub max: u64,
    /// Requests with a recorded duration; events from older decoyrail
    /// versions have none and are excluded rather than counted as zero.
    pub measured: u64,
}

#[derive(Debug, Serialize)]
pub struct BucketOut {
    pub requests: u64,
    pub allows: u64,
    /// Forwarded-with-alert resolutions (action `warn`); additive to schema
    /// v1, so existing consumers are unaffected.
    pub warns: u64,
    pub denies: DeniesOut,
    pub tripwires: u64,
    pub dlp_alerts: u64,
    /// Policy loads rejected as tampered, and policy changes made through
    /// Decoyrail surfaces (writes and blessings).
    pub policy_tamper: u64,
    pub policy_changes: u64,
    pub tokens: TokensOut,
    pub cache_hit_ratio: Option<f64>,
    pub cost_usd: f64,
    pub no_usage_requests: u64,
    pub bytes: BytesOut,
    pub duration_ms: Option<DurOut>,
}

impl BucketOut {
    fn from_bucket(b: &Bucket) -> Self {
        let context = b.input_tokens + b.cache_read_tokens;
        BucketOut {
            requests: b.requests,
            allows: b.allows,
            warns: b.warns,
            denies: DeniesOut {
                total: b.denies,
                policy: b.deny_policy,
                tripwire: b.deny_tripwire,
                dlp: b.deny_dlp,
                budget: b.deny_budget,
            },
            tripwires: b.tripwires,
            dlp_alerts: b.dlp_alerts,
            policy_tamper: b.policy_tamper,
            policy_changes: b.policy_changes,
            tokens: TokensOut {
                input: b.input_tokens,
                output: b.output_tokens,
                cache_read: b.cache_read_tokens,
                cache_write: b.cache_write_tokens,
                total: b.input_tokens
                    + b.output_tokens
                    + b.cache_read_tokens
                    + b.cache_write_tokens,
            },
            cache_hit_ratio: (context > 0).then(|| b.cache_read_tokens as f64 / context as f64),
            cost_usd: b.cost_usd,
            no_usage_requests: b.no_usage,
            bytes: BytesOut {
                up: b.bytes_up,
                down: b.bytes_down,
            },
            duration_ms: b.dur.avg_ms().map(|avg| DurOut {
                avg,
                p95: b.dur.p95_ms().unwrap_or(0),
                max: b.dur.max_ms,
                measured: b.dur.count,
            }),
        }
    }

    /// Alerts a surface should surface: everything denied plus everything
    /// that fired while traffic flowed — DLP advisories, response-echo
    /// tripwires, and warn resolutions (forwarded, but each one recorded an
    /// alert by design). Tripwire denies live in both the deny and tripwire
    /// counters, so they are subtracted back out; each security event counts
    /// once. This is the `--line` alert count.
    pub fn alert_count(&self) -> u64 {
        self.denies.total
            + self.dlp_alerts
            + self.policy_tamper
            + self.warns
            + self.tripwires.saturating_sub(self.denies.tripwire)
    }
}

#[derive(Debug, Serialize)]
pub struct NamedOut {
    pub name: String,
    #[serde(flatten)]
    pub stats: BucketOut,
}

#[derive(Debug, Serialize)]
pub struct SessionOut {
    pub sid: String,
    pub label: String,
    pub started: String,
    pub pid: u32,
    #[serde(flatten)]
    pub stats: BucketOut,
}

// ---------------------------------------------------------------------------
// Query

/// Run one analytics query: catch the cache up with any new audit lines,
/// persist it, then aggregate the window. Purely local, no network.
pub fn query(window: &Window) -> Result<Report> {
    // Snapshot the anchor before reading the log. An append writes the log
    // line first, then the anchor; reading in the opposite order here would
    // let an append land in between, presenting a healthy log as truncated —
    // the same mid-append race `audit::verify` takes a shared lock against.
    let anchor = audit::head_anchor();
    let agg = load_and_catch_up()?;

    // Tail truncation leaves a valid prefix chain; the head anchor knows how
    // far the log once reached. (Computed per query, not persisted: unlike a
    // mid-chain break, it heals if the log grows back past the anchor.)
    let mut integrity = agg.integrity.clone();
    if integrity.is_none() {
        if let Some((anchor_seq, _)) = anchor {
            if agg.last_seq.map(|s| s < anchor_seq).unwrap_or(true) {
                integrity = Some(format!(
                    "audit log truncated: head anchor expects seq {anchor_seq} but log ends at {}",
                    agg.last_seq
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "empty".to_string())
                ));
            }
        }
    }

    let (from, to) = window.bounds(chrono::Local::now());
    let in_window = |hour: &str| {
        from.as_deref().map(|f| hour >= f).unwrap_or(true)
            && to.as_deref().map(|t| hour < t).unwrap_or(true)
    };

    let mut totals = Bucket::default();
    let mut by_session: BTreeMap<String, Bucket> = BTreeMap::new();
    let mut by_model: BTreeMap<String, Bucket> = BTreeMap::new();
    let mut by_host: BTreeMap<String, Bucket> = BTreeMap::new();
    let mut by_day: BTreeMap<String, Bucket> = BTreeMap::new();
    for (key, bucket) in agg.rows.iter().filter(|(k, _)| in_window(&k.hour)) {
        totals.merge(bucket);
        // Sessionless rows either predate session tracking (they carry
        // traffic) or are request-free CLI events like a `policy add` from
        // another terminal; only the former deserve a session row. Totals
        // count both either way.
        if !key.sid.is_empty() || bucket.requests > 0 || bucket.bytes_up > 0 {
            by_session.entry(key.sid.clone()).or_default().merge(bucket);
        }
        if !key.model.is_empty() {
            by_model.entry(key.model.clone()).or_default().merge(bucket);
        } else if bucket.requests > 0 || bucket.bytes_up > 0 || bucket.bytes_down > 0 {
            by_model
                .entry("(no usage data)".to_string())
                .or_default()
                .merge(bucket);
        }
        by_host.entry(key.host.clone()).or_default().merge(bucket);
        by_day
            .entry(local_day_of_hour(&key.hour))
            .or_default()
            .merge(bucket);
    }

    let mut by_session: Vec<SessionOut> = by_session
        .into_iter()
        .map(|(sid, b)| {
            let info = agg.sessions.get(&sid).cloned().unwrap_or_default();
            SessionOut {
                label: if !info.label.is_empty() {
                    info.label
                } else if sid.is_empty() {
                    "(before session tracking)".to_string()
                } else {
                    "(unlabeled)".to_string()
                },
                started: info.started,
                pid: info.pid,
                sid,
                stats: BucketOut::from_bucket(&b),
            }
        })
        .collect();
    by_session.sort_by(|a, b| {
        cost_order(a.stats.cost_usd, b.stats.cost_usd)
            .then(b.stats.requests.cmp(&a.stats.requests))
            .then(a.sid.cmp(&b.sid))
    });

    let named = |m: BTreeMap<String, Bucket>, by_cost: bool| -> Vec<NamedOut> {
        let mut v: Vec<NamedOut> = m
            .into_iter()
            .map(|(name, b)| NamedOut {
                name,
                stats: BucketOut::from_bucket(&b),
            })
            .collect();
        if by_cost {
            v.sort_by(|a, b| {
                cost_order(a.stats.cost_usd, b.stats.cost_usd)
                    .then(b.stats.requests.cmp(&a.stats.requests))
                    .then(a.name.cmp(&b.name))
            });
        }
        v
    };

    Ok(Report {
        schema: SCHEMA_VERSION,
        window: WindowOut {
            kind: window.kind().to_string(),
            from,
            to,
        },
        integrity: IntegrityOut {
            ok: integrity.is_none(),
            detail: integrity,
        },
        totals: BucketOut::from_bucket(&totals),
        by_session,
        by_model: named(by_model, true),
        by_host: named(by_host, true),
        by_day: named(by_day, false),
    })
}

/// Descending by cost, total order (costs are finite sums).
fn cost_order(a: f64, b: f64) -> std::cmp::Ordering {
    b.partial_cmp(&a).unwrap_or(std::cmp::Ordering::Equal)
}

/// Load the cache and ingest any audit lines it hasn't covered yet, saving
/// the refreshed cache. A log that shrank (replaced state dir, truncation)
/// forces a rebuild from byte zero.
fn load_and_catch_up() -> Result<Aggregator> {
    let cache_path = config::stats_cache_path()?;
    let cache: Cache = std::fs::read(&cache_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .filter(|c: &Cache| c.cache_version == CACHE_VERSION)
        .unwrap_or_default();

    let audit_path = config::audit_path()?;
    let log_len = std::fs::metadata(&audit_path).map(|m| m.len()).unwrap_or(0);

    let mut agg = if log_len < cache.offset {
        Aggregator::from_cache(Cache::default())
    } else {
        Aggregator::from_cache(cache)
    };

    if log_len > agg.offset {
        let file = std::fs::File::open(&audit_path).context("opening audit log")?;
        let mut reader = std::io::BufReader::new(file);
        reader.seek(std::io::SeekFrom::Start(agg.offset))?;
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line)?;
            if n == 0 {
                break;
            }
            // A partially flushed final line is left for the next query.
            if !line.ends_with('\n') {
                break;
            }
            agg.offset += n as u64;
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                agg.ingest_line(trimmed);
            }
        }
        config::ensure_home()?;
        config::atomic_write(&cache_path, serde_json::to_vec(&agg.to_cache())?.as_slice())?;
    }
    Ok(agg)
}

// ---------------------------------------------------------------------------
// Rendering

/// Human-readable token count: 950, 12.3k, 1.2M, 3.1B.
pub fn fmt_tokens(n: u64) -> String {
    let n = n as f64;
    if n < 1e3 {
        format!("{n:.0}")
    } else if n < 1e6 {
        format!("{:.1}k", n / 1e3)
    } else if n < 1e9 {
        format!("{:.1}M", n / 1e6)
    } else {
        format!("{:.2}B", n / 1e9)
    }
}

/// Human-readable byte count: 512 B, 1.4 KB, 40.1 MB, 2.0 GB.
pub fn fmt_bytes(n: u64) -> String {
    let n = n as f64;
    if n < 1e3 {
        format!("{n:.0} B")
    } else if n < 1e6 {
        format!("{:.1} KB", n / 1e3)
    } else if n < 1e9 {
        format!("{:.1} MB", n / 1e6)
    } else {
        format!("{:.2} GB", n / 1e9)
    }
}

fn fmt_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        format!("{:.1}s", ms as f64 / 1000.0)
    }
}

/// The embeddable one-liner: today's tokens, dollars, and alert count.
/// Exactly one line, three fields, stable; an integrity failure prefixes it.
pub fn render_line(report: &Report) -> String {
    let t = &report.totals;
    let prefix = if report.integrity.ok {
        ""
    } else {
        "[audit integrity FAILED] "
    };
    format!(
        "{prefix}{} tok  ${:.2}  {} alerts",
        fmt_tokens(t.tokens.total),
        t.cost_usd,
        t.alert_count()
    )
}

pub fn render_json(report: &Report) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

/// Which breakdown table the human view prints.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Breakdown {
    Session,
    Model,
    Host,
    Day,
}

pub fn render_human(report: &Report, by: Breakdown) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    if let Some(detail) = &report.integrity.detail {
        let _ = writeln!(out, "AUDIT INTEGRITY FAILED: {detail}");
        let _ = writeln!(out, "The numbers below cover what could still be read.\n");
    }
    let t = &report.totals;
    let window_desc = match (&report.window.from, &report.window.to) {
        (Some(f), Some(to)) => format!("{} ({f} to {to} UTC)", report.window.kind),
        _ => report.window.kind.to_string(),
    };
    let _ = writeln!(out, "Window: {window_desc}");
    let _ = writeln!(
        out,
        "Requests: {} ({} allowed, {} warned, {} denied: {} policy, {} tripwire, {} dlp, {} budget)",
        t.requests,
        t.allows,
        t.warns,
        t.denies.total,
        t.denies.policy,
        t.denies.tripwire,
        t.denies.dlp,
        t.denies.budget
    );
    // Zeros print on purpose: a quiet window is itself a report.
    let _ = writeln!(
        out,
        "Security: {} tripwire hits, {} DLP alerts, {} policy tampers",
        t.tripwires, t.dlp_alerts, t.policy_tamper
    );
    if t.policy_changes > 0 {
        let _ = writeln!(
            out,
            "Policy: {} change(s) through decoyrail surfaces",
            t.policy_changes
        );
    }
    let cached = t
        .cache_hit_ratio
        .map(|r| format!("  cached {:.0}%", r * 100.0))
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "Tokens: in {}  out {}  cache read {}  cache write {}{cached}",
        fmt_tokens(t.tokens.input),
        fmt_tokens(t.tokens.output),
        fmt_tokens(t.tokens.cache_read),
        fmt_tokens(t.tokens.cache_write),
    );
    let no_usage = if t.no_usage_requests > 0 {
        format!(
            "  ({} requests with no provider usage)",
            t.no_usage_requests
        )
    } else {
        String::new()
    };
    let _ = writeln!(out, "Spend: ${:.4}{no_usage}", t.cost_usd);
    let _ = writeln!(
        out,
        "Bytes: up {}  down {}",
        fmt_bytes(t.bytes.up),
        fmt_bytes(t.bytes.down)
    );
    match &t.duration_ms {
        Some(d) => {
            let _ = writeln!(
                out,
                "Latency: avg {}  p95 ~{}  max {}  ({} measured)",
                fmt_ms(d.avg),
                fmt_ms(d.p95),
                fmt_ms(d.max),
                d.measured
            );
        }
        None => {
            let _ = writeln!(out, "Latency: (no measured requests)");
        }
    }

    let (title, rows): (&str, Vec<(String, &BucketOut)>) = match by {
        Breakdown::Session => (
            "By session:",
            report
                .by_session
                .iter()
                .map(|s| {
                    let when = if s.started.is_empty() {
                        String::new()
                    } else {
                        format!("  [{}]", s.started)
                    };
                    (format!("{}{when}", s.label), &s.stats)
                })
                .collect(),
        ),
        Breakdown::Model => (
            "By model:",
            report
                .by_model
                .iter()
                .map(|n| (n.name.clone(), &n.stats))
                .collect(),
        ),
        Breakdown::Host => (
            "By host:",
            report
                .by_host
                .iter()
                .map(|n| (n.name.clone(), &n.stats))
                .collect(),
        ),
        Breakdown::Day => (
            "By day:",
            report
                .by_day
                .iter()
                .map(|n| (n.name.clone(), &n.stats))
                .collect(),
        ),
    };
    if rows.is_empty() {
        let _ = writeln!(out, "\n{title} (nothing in this window)");
        return out;
    }
    let _ = writeln!(out, "\n{title}");
    let name_w = rows.iter().map(|(n, _)| n.len()).max().unwrap_or(0).max(8);
    for (name, s) in rows {
        let alerts = s.alert_count();
        let cached = s
            .cache_hit_ratio
            .map(|r| format!("  cached {:.0}%", r * 100.0))
            .unwrap_or_default();
        // Warned counts print by name so "which hosts ride the warn default"
        // is answerable straight off the --by host table.
        let alert_chip = match (alerts > 0, s.warns > 0) {
            (true, true) => format!("  [{alerts} alerts, {} warned]", s.warns),
            (true, false) => format!("  [{alerts} alerts]"),
            _ => String::new(),
        };
        let _ = writeln!(
            out,
            "  {name:<name_w$}  {:>5} req  in {:>8}  out {:>8}  ${:.4}{cached}{alert_chip}",
            s.requests,
            fmt_tokens(s.tokens.input + s.tokens.cache_read + s.tokens.cache_write),
            fmt_tokens(s.tokens.output),
            s.cost_usd,
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Auditor, Entry, UsageRec};
    use chrono::NaiveDate;

    fn setup() -> (std::sync::MutexGuard<'static, ()>, tempfile::TempDir) {
        let guard = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());
        (guard, dir)
    }

    fn usage(model: &str, input: u64, output: u64, cache_read: u64, cost: f64) -> UsageRec {
        UsageRec {
            model: model.into(),
            input,
            output,
            cache_read,
            cache_write: 0,
            cost_usd: cost,
        }
    }

    fn range(since: (i32, u32, u32), until: (i32, u32, u32)) -> Window {
        Window::Range {
            since: NaiveDate::from_ymd_opt(since.0, since.1, since.2).unwrap(),
            until: NaiveDate::from_ymd_opt(until.0, until.1, until.2).unwrap(),
        }
    }

    /// A window wide enough to hold every fixture regardless of the local
    /// timezone the test runs in.
    fn wide() -> Window {
        range((2026, 1, 1), (2026, 12, 31))
    }

    #[test]
    fn windows_breakdowns_and_deny_classification() {
        let (_g, _dir) = setup();
        let mut a = Auditor::open().unwrap();
        a.append(
            Entry {
                host: "-".into(),
                action: "session".into(),
                note: "claude -p hello".into(),
                sid: "s1".into(),
                ..Default::default()
            },
            "2026-06-05T10:00:00.000Z".into(),
        )
        .unwrap();
        a.append(
            Entry {
                host: "api.anthropic.com".into(),
                action: "allow".into(),
                sid: "s1".into(),
                dur_ms: Some(400),
                bytes_up: 900,
                bytes_down: 4000,
                usage: Some(usage("claude-sonnet-5", 1000, 200, 3000, 0.01)),
                ..Default::default()
            },
            "2026-06-05T10:01:00.000Z".into(),
        )
        .unwrap();
        a.append(
            Entry {
                host: "evil.example".into(),
                action: "deny".into(),
                tripwires: vec!["svc@header".into()],
                note: "tripwire: decoy for 'svc' seen".into(),
                sid: "s1".into(),
                dur_ms: Some(3),
                ..Default::default()
            },
            "2026-06-05T10:02:00.000Z".into(),
        )
        .unwrap();
        a.append(
            Entry {
                host: "denied.example".into(),
                action: "deny".into(),
                sid: "s1".into(),
                dur_ms: Some(2),
                ..Default::default()
            },
            "2026-06-05T10:03:00.000Z".into(),
        )
        .unwrap();
        a.append(
            Entry {
                host: "api.anthropic.com".into(),
                action: "deny".into(),
                note: "budget exhausted".into(),
                sid: "s1".into(),
                dur_ms: Some(1),
                ..Default::default()
            },
            "2026-06-05T10:04:00.000Z".into(),
        )
        .unwrap();
        a.append(
            Entry {
                host: "api.anthropic.com".into(),
                action: "alert".into(),
                note: "dlp: warned pan@body fp=abc".into(),
                sid: "s1".into(),
                ..Default::default()
            },
            "2026-06-05T10:05:00.000Z".into(),
        )
        .unwrap();
        // A different session in a different month.
        a.append(
            Entry {
                host: "api.openai.com".into(),
                action: "allow".into(),
                sid: "s2".into(),
                dur_ms: Some(100),
                usage: Some(usage("gpt-5", 10, 5, 0, 0.002)),
                ..Default::default()
            },
            "2026-07-02T08:00:00.000Z".into(),
        )
        .unwrap();

        let report = query(&wide()).unwrap();
        assert!(report.integrity.ok);
        let t = &report.totals;
        assert_eq!(t.requests, 5);
        assert_eq!(t.allows, 2);
        assert_eq!(t.denies.total, 3);
        assert_eq!(t.denies.tripwire, 1);
        assert_eq!(t.denies.policy, 1);
        assert_eq!(t.denies.budget, 1);
        assert_eq!(t.tripwires, 1);
        assert_eq!(t.dlp_alerts, 1);
        assert_eq!(t.tokens.input, 1010);
        assert!((t.cost_usd - 0.012).abs() < 1e-12);
        assert_eq!(t.bytes.up, 900);
        assert_eq!(t.bytes.down, 4000);
        let d = t.duration_ms.as_ref().unwrap();
        assert_eq!(d.measured, 5);
        assert_eq!(d.max, 400);

        // Session breakdown carries the launch label.
        let s1 = report.by_session.iter().find(|s| s.sid == "s1").unwrap();
        assert_eq!(s1.label, "claude -p hello");
        assert_eq!(s1.stats.requests, 4);
        let s2 = report.by_session.iter().find(|s| s.sid == "s2").unwrap();
        assert_eq!(s2.label, "(unlabeled)");

        // Model and host breakdowns.
        let sonnet = report
            .by_model
            .iter()
            .find(|m| m.name == "claude-sonnet-5")
            .unwrap();
        assert_eq!(sonnet.stats.tokens.cache_read, 3000);
        let ratio = sonnet.stats.cache_hit_ratio.unwrap();
        assert!((ratio - 3000.0 / 4000.0).abs() < 1e-9);
        assert!(report.by_host.iter().any(|h| h.name == "evil.example"));

        // A narrower window sees only June's session.
        let june = query(&range((2026, 6, 1), (2026, 6, 30))).unwrap();
        assert_eq!(june.totals.requests, 4);
        assert!((june.totals.cost_usd - 0.01).abs() < 1e-12);

        // Zero is reported, not omitted: June had no DLP denies.
        assert_eq!(june.totals.denies.dlp, 0);
        let human = render_human(&june, Breakdown::Model);
        assert!(human.contains("0 dlp"), "zeros must print:\n{human}");
    }

    #[test]
    fn policy_tamper_and_change_events_are_counted() {
        let (_g, _dir) = setup();
        let mut a = Auditor::open().unwrap();
        let mut tamper = Entry::note("tamper", "policy rejected; previous stays active".into());
        tamper.sid = "s1".into();
        a.append(tamper, "2026-06-05T10:00:00.000Z".into()).unwrap();
        let mut change = Entry::note("policy", "policy updated (policy add); sha256=abc".into());
        change.sid = "s1".into();
        a.append(change, "2026-06-05T10:01:00.000Z".into()).unwrap();

        let report = query(&wide()).unwrap();
        assert_eq!(report.totals.policy_tamper, 1);
        assert_eq!(report.totals.policy_changes, 1);
        // A tamper counts as an alert; a Decoyrail-made change does not.
        assert_eq!(report.totals.alert_count(), 1);
        let human = render_human(&report, Breakdown::Host);
        assert!(human.contains("1 policy tampers"), "{human}");
        assert!(human.contains("1 change(s)"), "{human}");
    }

    #[test]
    fn warn_events_are_their_own_category_with_per_host_detail() {
        let (_g, _dir) = setup();
        let mut a = Auditor::open().unwrap();
        for host in [
            "unknown-a.example",
            "unknown-a.example",
            "unknown-b.example",
        ] {
            a.append(
                Entry {
                    host: host.into(),
                    action: "warn".into(),
                    rule: "default".into(),
                    sid: "s1".into(),
                    dur_ms: Some(30),
                    bytes_up: 100,
                    bytes_down: 200,
                    ..Default::default()
                },
                "2026-06-05T10:00:00.000Z".into(),
            )
            .unwrap();
        }
        a.append(
            Entry {
                host: "api.anthropic.com".into(),
                action: "allow".into(),
                sid: "s1".into(),
                dur_ms: Some(50),
                ..Default::default()
            },
            "2026-06-05T10:01:00.000Z".into(),
        )
        .unwrap();

        let report = query(&wide()).unwrap();
        let t = &report.totals;
        assert_eq!(t.requests, 4);
        assert_eq!(t.allows, 1);
        assert_eq!(t.warns, 3, "warns count in their own category");
        assert_eq!(t.denies.total, 0);
        // Warn records an alert by design, so it surfaces in the alert count.
        assert_eq!(t.alert_count(), 3);
        // "What would break if I went back to deny": per-host warn counts.
        let host_a = report
            .by_host
            .iter()
            .find(|h| h.name == "unknown-a.example")
            .unwrap();
        assert_eq!(host_a.stats.warns, 2);
        let host_b = report
            .by_host
            .iter()
            .find(|h| h.name == "unknown-b.example")
            .unwrap();
        assert_eq!(host_b.stats.warns, 1);
        assert_eq!(
            report
                .by_host
                .iter()
                .find(|h| h.name == "api.anthropic.com")
                .unwrap()
                .stats
                .warns,
            0
        );
        let human = render_human(&report, Breakdown::Host);
        assert!(
            human.contains("3 warned"),
            "totals name the warns:\n{human}"
        );
        assert!(
            human.contains("2 warned"),
            "per-host rows name the warns:\n{human}"
        );
        let json = render_json(&report).unwrap();
        assert!(json.contains("\"warns\": 3"), "{json}");
    }

    #[test]
    fn streamed_warn_usage_counts_exactly_once() {
        let (_g, _dir) = setup();
        let mut a = Auditor::open().unwrap();
        // A streamed warn (LLM traffic riding a warn resolution): the allow
        // event's warn twin, then the deferred usage event referencing it.
        a.append(
            Entry {
                host: "llm.example".into(),
                action: "warn".into(),
                rule: "default".into(),
                sid: "s1".into(),
                bytes_up: 500,
                ..Default::default()
            },
            "2026-06-05T10:00:00.000Z".into(),
        )
        .unwrap();
        a.append(
            Entry {
                host: "llm.example".into(),
                action: "usage".into(),
                sid: "s1".into(),
                dur_ms: Some(1500),
                bytes_down: 4000,
                usage: Some(usage("claude-sonnet-5", 100, 40, 0, 0.0009)),
                req_seq: Some(0),
                ..Default::default()
            },
            "2026-06-05T10:00:02.000Z".into(),
        )
        .unwrap();
        let report = query(&wide()).unwrap();
        let t = &report.totals;
        assert_eq!(t.requests, 1, "streamed warn must count once");
        assert_eq!(t.warns, 1, "and stay in the warn category");
        assert_eq!(t.allows, 0);
        assert_eq!(t.no_usage_requests, 0);
        assert_eq!(t.tokens.output, 40);
        let m = &report.by_model;
        assert_eq!(m.len(), 1, "moved to its model row: {m:?}");
        assert_eq!(m[0].stats.warns, 1);
    }

    #[test]
    fn streamed_usage_counts_exactly_once() {
        let (_g, _dir) = setup();
        let mut a = Auditor::open().unwrap();
        // Streamed request: allow with no usage (seq 0), then the deferred
        // usage event referencing it.
        a.append(
            Entry {
                host: "api.anthropic.com".into(),
                action: "allow".into(),
                sid: "s1".into(),
                bytes_up: 500,
                ..Default::default()
            },
            "2026-06-05T10:00:00.000Z".into(),
        )
        .unwrap();
        a.append(
            Entry {
                host: "api.anthropic.com".into(),
                action: "usage".into(),
                sid: "s1".into(),
                dur_ms: Some(2500),
                bytes_down: 9000,
                usage: Some(usage("claude-sonnet-5", 200, 75, 50, 0.00174)),
                req_seq: Some(0),
                ..Default::default()
            },
            "2026-06-05T10:00:03.000Z".into(),
        )
        .unwrap();

        let report = query(&wide()).unwrap();
        let t = &report.totals;
        assert_eq!(t.requests, 1, "streamed request must count once");
        assert_eq!(t.allows, 1);
        assert_eq!(t.no_usage_requests, 0, "usage arrived, so not unpriced");
        assert_eq!(t.tokens.output, 75);
        assert_eq!(t.bytes.up, 500);
        assert_eq!(t.bytes.down, 9000);
        assert_eq!(t.duration_ms.as_ref().unwrap().measured, 1);
        let m = &report.by_model;
        assert_eq!(m.len(), 1, "the request moved to its model row: {m:?}");
        assert_eq!(m[0].name, "claude-sonnet-5");
        assert_eq!(m[0].stats.requests, 1);
        let s = &report.by_session[0];
        assert_eq!(s.stats.requests, 1);
        assert_eq!(report.by_host[0].stats.requests, 1);
        assert_eq!(report.by_day[0].stats.requests, 1);
    }

    #[test]
    fn stream_without_usage_stays_unpriced() {
        let (_g, _dir) = setup();
        let mut a = Auditor::open().unwrap();
        a.append(
            Entry {
                host: "big.example".into(),
                action: "allow".into(),
                sid: "s1".into(),
                bytes_up: 100,
                ..Default::default()
            },
            "2026-06-05T10:00:00.000Z".into(),
        )
        .unwrap();
        a.append(
            Entry {
                host: "big.example".into(),
                action: "usage".into(),
                sid: "s1".into(),
                dur_ms: Some(800),
                bytes_down: 50_000,
                req_seq: Some(0),
                ..Default::default()
            },
            "2026-06-05T10:00:01.000Z".into(),
        )
        .unwrap();
        let report = query(&wide()).unwrap();
        assert_eq!(report.totals.requests, 1);
        assert_eq!(report.totals.no_usage_requests, 1);
        assert_eq!(report.totals.bytes.down, 50_000);
        assert_eq!(report.totals.cost_usd, 0.0);
    }

    #[test]
    fn repeat_queries_are_byte_identical_and_incremental() {
        let (_g, _dir) = setup();
        let mut a = Auditor::open().unwrap();
        a.append(
            Entry {
                host: "api.anthropic.com".into(),
                action: "allow".into(),
                sid: "s1".into(),
                dur_ms: Some(10),
                usage: Some(usage("claude-sonnet-5", 100, 10, 0, 0.001)),
                ..Default::default()
            },
            "2026-06-05T10:00:00.000Z".into(),
        )
        .unwrap();

        let w = wide();
        let first = render_json(&query(&w).unwrap()).unwrap();
        let second = render_json(&query(&w).unwrap()).unwrap();
        assert_eq!(first, second, "same query twice must be byte-identical");
        assert!(
            config::stats_cache_path().unwrap().exists(),
            "the aggregate cache must persist"
        );

        // New traffic is picked up by the next query (incremental ingest).
        a.append(
            Entry {
                host: "api.anthropic.com".into(),
                action: "allow".into(),
                sid: "s1".into(),
                dur_ms: Some(20),
                usage: Some(usage("claude-sonnet-5", 100, 10, 0, 0.001)),
                ..Default::default()
            },
            "2026-06-05T11:00:00.000Z".into(),
        )
        .unwrap();
        let report = query(&w).unwrap();
        assert_eq!(report.totals.requests, 2);
        assert!((report.totals.cost_usd - 0.002).abs() < 1e-12);
    }

    #[test]
    fn tampered_log_is_flagged_but_still_reported() {
        let (_g, _dir) = setup();
        let mut a = Auditor::open().unwrap();
        for i in 0..3 {
            a.append(
                Entry {
                    host: format!("h{i}.example"),
                    action: "allow".into(),
                    sid: "s1".into(),
                    dur_ms: Some(5),
                    ..Default::default()
                },
                format!("2026-06-05T10:0{i}:00.000Z"),
            )
            .unwrap();
        }
        let path = config::audit_path().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replacen("h1.example", "hX.example", 1)).unwrap();

        let report = query(&wide()).unwrap();
        assert!(!report.integrity.ok);
        assert!(report.integrity.detail.as_ref().unwrap().contains("seq 1"));
        // Still reports what it can: all three events aggregated.
        assert_eq!(report.totals.requests, 3);
        // Every output mode carries the flag.
        assert!(render_human(&report, Breakdown::Host).contains("AUDIT INTEGRITY FAILED"));
        assert!(render_line(&report).starts_with("[audit integrity FAILED] "));
        assert!(render_json(&report).unwrap().contains("\"ok\": false"));
    }

    #[test]
    fn truncated_log_is_flagged_via_head_anchor() {
        let (_g, _dir) = setup();
        let mut a = Auditor::open().unwrap();
        for i in 0..3 {
            a.append(
                Entry {
                    host: "h.example".into(),
                    action: "allow".into(),
                    sid: "s1".into(),
                    ..Default::default()
                },
                format!("2026-06-05T10:0{i}:00.000Z"),
            )
            .unwrap();
        }
        // Warm the cache, then drop the last line: a valid prefix chain.
        assert!(query(&wide()).unwrap().integrity.ok);
        let path = config::audit_path().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.pop();
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

        let report = query(&wide()).unwrap();
        assert!(!report.integrity.ok, "truncation must be flagged");
        assert!(report
            .integrity
            .detail
            .as_ref()
            .unwrap()
            .contains("truncated"));
        assert_eq!(report.totals.requests, 2, "prefix still reported");
    }

    #[test]
    fn query_never_false_alarms_during_appends() {
        let (_g, _dir) = setup();
        let mut a = Auditor::open().unwrap();
        a.append(
            Entry {
                host: "seed".into(),
                action: "allow".into(),
                sid: "s1".into(),
                ..Default::default()
            },
            "2026-06-05T10:00:00.000Z".into(),
        )
        .unwrap();

        // A live proxy keeps appending while `decoyrail stats` runs. The
        // anchor is snapshotted before the log is read; sampling it after
        // would let an append land in between, and the fresher anchor would
        // present the healthy log as truncated.
        let writer = std::thread::spawn(move || {
            for i in 1..=200 {
                a.append(
                    Entry {
                        host: format!("h{i}"),
                        action: "allow".into(),
                        sid: "s1".into(),
                        ..Default::default()
                    },
                    "2026-06-05T10:00:01.000Z".into(),
                )
                .unwrap();
            }
        });
        while !writer.is_finished() {
            let report = query(&wide()).unwrap();
            assert!(
                report.integrity.ok,
                "stats raced a concurrent append: {:?}",
                report.integrity.detail
            );
        }
        writer.join().unwrap();
        assert_eq!(query(&wide()).unwrap().totals.requests, 201);
    }

    #[test]
    fn events_without_duration_are_unknown_not_zero() {
        let (_g, _dir) = setup();
        let mut a = Auditor::open().unwrap();
        // An event from an older decoyrail: no duration recorded.
        a.append(
            Entry {
                host: "h.example".into(),
                action: "allow".into(),
                sid: "s1".into(),
                ..Default::default()
            },
            "2026-06-05T10:00:00.000Z".into(),
        )
        .unwrap();
        a.append(
            Entry {
                host: "h.example".into(),
                action: "allow".into(),
                sid: "s1".into(),
                dur_ms: Some(1000),
                ..Default::default()
            },
            "2026-06-05T10:01:00.000Z".into(),
        )
        .unwrap();
        let report = query(&wide()).unwrap();
        let d = report.totals.duration_ms.as_ref().unwrap();
        assert_eq!(d.measured, 1, "unmeasured requests must not dilute stats");
        assert_eq!(d.avg, 1000, "average excludes the unknown, not zeroes it");
        assert_eq!(report.totals.requests, 2);
    }

    #[test]
    fn out_of_order_timestamps_bucket_by_their_own_time() {
        let (_g, _dir) = setup();
        let mut a = Auditor::open().unwrap();
        for ts in [
            "2026-06-05T10:00:00.000Z",
            "2026-06-04T23:00:00.000Z", // clock stepped back
            "2026-06-05T10:00:01.000Z",
        ] {
            a.append(
                Entry {
                    host: "h.example".into(),
                    action: "allow".into(),
                    sid: "s1".into(),
                    ..Default::default()
                },
                ts.into(),
            )
            .unwrap();
        }
        let report = query(&wide()).unwrap();
        assert_eq!(report.totals.requests, 3, "nothing dropped");
        assert_eq!(
            report.by_day.iter().map(|d| d.stats.requests).sum::<u64>(),
            3
        );
        assert!(report.integrity.ok, "out-of-order is not tampering");
    }

    #[test]
    fn meter_month_rollover_does_not_erase_history() {
        let (_g, _dir) = setup();
        let mut a = Auditor::open().unwrap();
        a.append(
            Entry {
                host: "api.anthropic.com".into(),
                action: "allow".into(),
                sid: "s1".into(),
                usage: Some(usage("claude-sonnet-5", 100, 10, 0, 0.5)),
                ..Default::default()
            },
            "2026-06-15T10:00:00.000Z".into(),
        )
        .unwrap();
        // The meter zeroes itself at rollover; analytics must not care.
        let mut m = crate::meter::Meter::load().unwrap();
        m.roll_period("2026-06");
        m.record("api.anthropic.com", 1000, 1000);
        m.save().unwrap();
        let mut m = crate::meter::Meter::load().unwrap();
        m.roll_period("2026-07");
        m.save().unwrap();
        assert!(m.per_host.is_empty(), "meter did reset");

        let report = query(&range((2026, 6, 1), (2026, 6, 30))).unwrap();
        assert_eq!(report.totals.requests, 1);
        assert!((report.totals.cost_usd - 0.5).abs() < 1e-12);
    }

    #[test]
    fn one_line_mode_is_exactly_one_line() {
        let (_g, _dir) = setup();
        let mut a = Auditor::open().unwrap();
        a.append(
            Entry {
                host: "api.anthropic.com".into(),
                action: "allow".into(),
                sid: "s1".into(),
                usage: Some(usage("claude-sonnet-5", 1_000_000, 200_000, 0, 4.31)),
                ..Default::default()
            },
            crate::util::now_rfc3339(),
        )
        .unwrap();
        a.append(
            Entry {
                host: "evil.example".into(),
                action: "deny".into(),
                tripwires: vec!["svc@header".into()],
                sid: "s1".into(),
                ..Default::default()
            },
            crate::util::now_rfc3339(),
        )
        .unwrap();
        let line = render_line(&query(&Window::Today).unwrap());
        assert_eq!(line.lines().count(), 1);
        assert_eq!(line, "1.2M tok  $4.31  1 alerts");
    }

    #[test]
    fn hundred_k_events_repeat_query_under_a_second() {
        let (_g, _dir) = setup();
        crate::config::ensure_home().unwrap();

        // Synthesize a valid 100k-event chain in memory (per-append file
        // locking would dominate the test), one line per event.
        let n = 100_000;
        let mut log = String::with_capacity(n * 320);
        let mut prev = crate::audit::ZERO_HASH.to_string();
        for i in 0..n as u64 {
            let mut ev = crate::audit::AuditEvent {
                seq: i,
                ts: format!(
                    "2026-{:02}-{:02}T{:02}:00:{:02}.000Z",
                    3 + (i / 40_000),
                    1 + (i / 2_000) % 20,
                    (i / 100) % 24,
                    i % 60
                ),
                host: "api.anthropic.com".into(),
                path: "/v1/messages".into(),
                method: "POST".into(),
                action: "allow".into(),
                rule: "anthropic".into(),
                escalated: false,
                swaps: vec![],
                tripwires: vec![],
                status: 200,
                note: String::new(),
                pid: 1,
                sid: format!("s{}", i / 10_000),
                dur_ms: Some(200 + i % 800),
                bytes_up: 900,
                bytes_down: 4000,
                usage: Some(usage("claude-sonnet-5", 1000, 200, 3000, 0.0014)),
                req_seq: None,
                prev_hash: String::new(),
                hash: String::new(),
            };
            crate::audit::seal_for_test(&prev, &mut ev);
            prev = ev.hash.clone();
            log.push_str(&serde_json::to_string(&ev).unwrap());
            log.push('\n');
        }
        std::fs::write(config::audit_path().unwrap(), &log).unwrap();

        // First query pays the catch-up.
        let report = query(&wide()).unwrap();
        assert!(report.integrity.ok);
        assert_eq!(report.totals.requests, n as u64);

        // Repeat query must come back near-instantly off the warm cache.
        let start = std::time::Instant::now();
        let report = query(&wide()).unwrap();
        let elapsed = start.elapsed();
        assert_eq!(report.totals.requests, n as u64);
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "repeat query took {elapsed:?}"
        );
    }
}
