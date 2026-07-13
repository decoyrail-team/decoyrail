//! Prompt-cache doctor: observe-only diagnosis of provider prompt-cache
//! hygiene (plan 004, phase 1).
//!
//! Agent traffic wastes provider prompt caches constantly — a timestamp in
//! the system prompt, an unsorted tool list, a request landing just past the
//! TTL — and each miss re-bills the whole prefix at the full input rate. The
//! doctor watches consecutive Anthropic-protocol requests per (host, model),
//! compares a canonical, marker-stripped serialization of the cacheable
//! prefix (tools, then system, then messages — provider cache order), and
//! records where and why the prefix stopped matching. It mutates nothing:
//! the wire bytes are identical with the doctor on or off, and its state
//! holds offsets, section labels, and counters — never prompt content, which
//! also means never anything the swap engine touches (it observes the
//! pre-swap body).
//!
//! Hit rates and cache token counts come from the meter (the provider
//! reports them in `usage`); the doctor explains the misses.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

use crate::config;

/// Default provider cache TTL (Anthropic ephemeral, 5 minutes). A preserved
/// prefix arriving after a longer gap re-pays the cache write anyway.
const CACHE_TTL_SECS: u64 = 300;

/// Cacheable-minimum estimate: prefixes shorter than the model's minimum
/// (1024 tokens, 2048 on Haiku) can carry markers but never hit.
const MIN_CACHEABLE_TOKENS: u64 = 1024;
const MIN_CACHEABLE_TOKENS_HAIKU: u64 = 2048;

/// Rough tokens-per-byte for the minimum check (same 4 bytes/token blend the
/// meter's byte estimate uses).
const BYTES_PER_TOKEN: u64 = 4;

/// Bodies beyond this are counted but not diffed: the doctor's request-path
/// work stays bounded.
const OBSERVE_CAP: usize = 4 << 20; // 4 MiB

/// Previous prefixes are kept in memory up to this size; a divergence past
/// the cap can't be located, so such pairs count as preserved.
const PREFIX_CAP: usize = 1 << 20; // 1 MiB

/// Previous-request state is kept for at most this many (host, model) keys.
const MAX_KEYS: usize = 32;

/// A cacheable prefix must repeat at least this many times (a streak of
/// consecutive byte-identical, at-or-above-minimum cacheable regions) before
/// repair injects a marker: 1 means "from the second identical prefix on",
/// so the proxy never mutates a prefix it has seen only once.
const REPAIR_MIN_REPEATS: u32 = 1;

/// Where the last observed prefix stopped matching the current one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Divergence {
    /// Byte offset into the canonical prefix stream (not the raw body).
    pub offset: u64,
    /// Section the offset falls in: `tools[i]`, `system`/`system[i]`, or
    /// `messages[i]`.
    pub section: String,
    /// Seconds since the previous request on this key.
    pub gap_secs: u64,
    pub ts: String,
}

/// Hygiene counters for one host + model.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyStats {
    /// Messages-shaped requests observed.
    pub requests: u64,
    /// Requests carrying at least one `cache_control` marker.
    pub marked: u64,
    /// Prefix identical to or extending the previous request (cache-friendly).
    pub preserved: u64,
    /// Preserved prefix that arrived past the cache TTL, so the cache had
    /// lapsed anyway.
    pub ttl_gaps: u64,
    /// First divergence in `messages[0]` with stable tools/system: reads as a
    /// new conversation, not a hygiene failure.
    pub resets: u64,
    /// Prefix diverged in tools, system, or a non-initial message: something
    /// upstream of the conversation turn is unstable.
    pub diverged: u64,
    /// Prefix under the model's cacheable minimum: markers can't help yet.
    pub below_min: u64,
    /// Requests whose cacheable prefix demonstrably repeats at or above the
    /// minimum but carry no `cache_control` of their own — an injection the
    /// repair pass could make (counted whether or not repair is licensed/on,
    /// so the report can quantify the opportunity).
    #[serde(default)]
    pub repairable: u64,
    /// Requests the proxy actually repaired (a marker spliced in). Zero unless
    /// Pro + `[cache] repair` is on.
    #[serde(default)]
    pub repaired: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_divergence: Option<Divergence>,
}

impl KeyStats {
    fn merge(&mut self, other: &KeyStats) {
        self.requests += other.requests;
        self.marked += other.marked;
        self.preserved += other.preserved;
        self.ttl_gaps += other.ttl_gaps;
        self.resets += other.resets;
        self.diverged += other.diverged;
        self.below_min += other.below_min;
        self.repairable += other.repairable;
        self.repaired += other.repaired;
        // Latest divergence wins; RFC-3339 strings compare chronologically.
        match (&self.last_divergence, &other.last_divergence) {
            (_, None) => {}
            (None, Some(d)) => self.last_divergence = Some(d.clone()),
            (Some(a), Some(b)) => {
                if b.ts >= a.ts {
                    self.last_divergence = Some(b.clone());
                }
            }
        }
    }
}

/// The persisted doctor state (`cache.json`), merged across sessions like
/// the meter. Keys are `"<host> <model>"`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    pub period: String,
    pub per_key: BTreeMap<String, KeyStats>,
}

impl CacheStats {
    pub fn load() -> Result<Self> {
        let path = config::cache_path()?;
        Ok(if path.exists() {
            let text = std::fs::read_to_string(&path)?;
            serde_json::from_str(&text).unwrap_or_default()
        } else {
            CacheStats::default()
        })
    }

    fn roll_period(&mut self, now_period: &str) {
        if self.period != now_period {
            self.period = now_period.to_string();
            self.per_key.clear();
        }
    }
}

/// What one request looked like, kept to diff the next one against. Only
/// the canonical bytes are needed: a divergence offset is reported against
/// the *current* request's section boundaries.
struct PrevRequest {
    prefix: Vec<u8>,
    seen_unix: u64,
    /// The stored prefix was cut at PREFIX_CAP; divergences past it are
    /// unlocatable and treated as preserved.
    truncated: bool,
    /// The canonical cacheable region alone (tools + system, the bytes before
    /// `messages[0]`). Compared across requests to detect a stable, repeating
    /// prefix worth marking — messages churn every turn, this doesn't.
    cacheable: Vec<u8>,
    /// Consecutive requests whose cacheable region matched this one at or
    /// above the model's minimum. Reset to 0 the moment it changes.
    streak: u32,
    /// Inter-request gaps observed while the streak held, and how many of
    /// them exceeded the 5m TTL — the signal for tuning a marker to 1h.
    gaps_total: u32,
    gaps_over_ttl: u32,
}

/// What the repair pass should do with the current request, when the doctor
/// judges it a positive-economics injection. The proxy applies it (splicing
/// the raw body) only when Pro-licensed and `[cache] repair` is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPlan {
    /// Mark the prefix for the 1-hour TTL rather than the default 5 minutes
    /// (most observed gaps outran 5m).
    pub ttl_1h: bool,
    /// The cacheable section the marker lands on (`system[i]` or `tools[i]`),
    /// for the audit note.
    pub section: String,
}

/// The session-local doctor: in-memory previous prefixes for diffing, plus a
/// counter delta flushed into `cache.json` under a lock (the meter pattern),
/// so concurrent sessions add up and the CLI reads one file.
#[derive(Default)]
pub struct Doctor {
    prev: BTreeMap<String, PrevRequest>,
    delta: CacheStats,
}

/// A parsed request the doctor extracted; `model` is handed back to the
/// caller so the pipeline doesn't parse the body a second time.
pub struct Observation {
    pub model: String,
    /// Set when this request's cacheable prefix repeats stably, is at or above
    /// the minimum, and carries no `cache_control` of its own: a marker the
    /// repair pass can splice in (Pro + `[cache] repair`).
    pub repair: Option<RepairPlan>,
}

impl Doctor {
    /// Diagnose one Anthropic-protocol request body. Returns the model name
    /// when the body was a Messages-shaped request; anything else (or a body
    /// over the observe cap) is skipped. Never mutates the body.
    pub fn observe(&mut self, host: &str, body: &[u8], now_unix: u64) -> Option<Observation> {
        if body.len() > OBSERVE_CAP {
            return None;
        }
        let root: Value = serde_json::from_slice(body).ok()?;
        let model = root.get("model")?.as_str()?.to_string();
        root.get("messages")?.as_array()?;

        let canon = canonicalize(&root);
        let key = format!("{host} {model}");
        let now_period = crate::util::current_period();
        self.delta.roll_period(&now_period);
        let stats = self.delta.per_key.entry(key.clone()).or_default();
        stats.requests += 1;
        if canon.markers > 0 {
            stats.marked += 1;
        }
        let min_tokens = if model.contains("haiku") {
            MIN_CACHEABLE_TOKENS_HAIKU
        } else {
            MIN_CACHEABLE_TOKENS
        };
        if (canon.prefix.len() as u64) / BYTES_PER_TOKEN < min_tokens {
            stats.below_min += 1;
        }

        // The cacheable region is everything before the first message turn:
        // tools + system, the part that repeats verbatim across turns. Repair
        // reasons about this alone, since messages churn every request.
        let cut = messages_start(&canon.sections).unwrap_or(canon.prefix.len());
        let cacheable = canon.prefix[..cut.min(canon.prefix.len())].to_vec();
        let cacheable_ok = (cacheable.len() as u64) / BYTES_PER_TOKEN >= min_tokens;

        // Carry the repair streak/gap counters forward only while the
        // cacheable region holds byte-for-byte; any change resets the streak.
        let (mut streak, mut gaps_total, mut gaps_over_ttl) = (0u32, 0u32, 0u32);
        if let Some(prev) = self.prev.get(&key) {
            let gap = now_unix.saturating_sub(prev.seen_unix);
            if cacheable_ok && prev.cacheable == cacheable {
                streak = prev.streak.saturating_add(1);
                gaps_total = prev.gaps_total.saturating_add(1);
                gaps_over_ttl = prev.gaps_over_ttl;
                if gap > CACHE_TTL_SECS {
                    gaps_over_ttl = gaps_over_ttl.saturating_add(1);
                }
            }
            match first_mismatch(&prev.prefix, &canon.prefix) {
                None if prev.truncated || canon.truncated => stats.preserved += 1,
                None => {
                    stats.preserved += 1;
                    if gap > CACHE_TTL_SECS {
                        stats.ttl_gaps += 1;
                    }
                }
                Some(offset) => {
                    let section = section_at(&canon.sections, offset);
                    if section == "messages[0]" {
                        stats.resets += 1;
                    } else {
                        stats.diverged += 1;
                        stats.last_divergence = Some(Divergence {
                            offset: offset as u64,
                            section,
                            gap_secs: gap,
                            ts: crate::util::now_rfc3339(),
                        });
                    }
                }
            }
        }

        // A repair opportunity: the prefix repeats stably at or above the
        // minimum and the client set no markers of its own. Counted even when
        // repair isn't licensed/enabled, so the report can size the waste.
        let repair = if canon.markers == 0 && cacheable_ok && streak >= REPAIR_MIN_REPEATS {
            stats.repairable += 1;
            Some(RepairPlan {
                ttl_1h: gaps_total > 0 && gaps_over_ttl * 2 >= gaps_total,
                section: section_at(&canon.sections, cut.saturating_sub(1)),
            })
        } else {
            None
        };

        self.remember(
            key,
            canon,
            cacheable,
            streak,
            gaps_total,
            gaps_over_ttl,
            now_unix,
        );
        Some(Observation { model, repair })
    }

    /// Record that the proxy actually spliced a marker into a request for this
    /// (host, model): bumps the persisted `repaired` counter.
    pub fn note_repaired(&mut self, host: &str, model: &str) {
        let now_period = crate::util::current_period();
        self.delta.roll_period(&now_period);
        self.delta
            .per_key
            .entry(format!("{host} {model}"))
            .or_default()
            .repaired += 1;
    }

    #[allow(clippy::too_many_arguments)]
    fn remember(
        &mut self,
        key: String,
        canon: Canonical,
        cacheable: Vec<u8>,
        streak: u32,
        gaps_total: u32,
        gaps_over_ttl: u32,
        now_unix: u64,
    ) {
        if self.prev.len() >= MAX_KEYS && !self.prev.contains_key(&key) {
            if let Some(oldest) = self
                .prev
                .iter()
                .min_by_key(|(_, p)| p.seen_unix)
                .map(|(k, _)| k.clone())
            {
                self.prev.remove(&oldest);
            }
        }
        let truncated = canon.truncated || canon.prefix.len() > PREFIX_CAP;
        let mut prefix = canon.prefix;
        prefix.truncate(PREFIX_CAP);
        self.prev.insert(
            key,
            PrevRequest {
                prefix,
                seen_unix: now_unix,
                truncated,
                cacheable,
                streak,
                gaps_total,
                gaps_over_ttl,
            },
        );
    }

    /// Merge this session's counter delta into `cache.json` under an
    /// exclusive lock, so concurrent sessions add up instead of clobbering.
    pub fn flush(&mut self, now_period: &str) -> Result<()> {
        self.delta.roll_period(now_period);
        if self.delta.per_key.is_empty() {
            return Ok(());
        }
        config::ensure_home()?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(config::cache_lock_path()?)
            .context("opening cache lock file")?;
        fs2::FileExt::lock_exclusive(&lock).context("locking cache stats")?;

        let mut disk = CacheStats::load()?;
        disk.roll_period(now_period);
        for (key, stats) in &self.delta.per_key {
            disk.per_key.entry(key.clone()).or_default().merge(stats);
        }
        config::atomic_write(
            &config::cache_path()?,
            serde_json::to_string_pretty(&disk)?.as_bytes(),
        )?;
        self.delta.per_key.clear();
        Ok(())
    }
}

/// The canonical prefix stream for one request: sections in provider cache
/// order, deterministically serialized, `cache_control` stripped (moving a
/// marker is not a content change) and counted.
struct Canonical {
    prefix: Vec<u8>,
    /// (label, start offset), in order.
    sections: Vec<(String, usize)>,
    markers: u64,
    truncated: bool,
}

fn canonicalize(root: &Value) -> Canonical {
    let mut out = Canonical {
        prefix: Vec::new(),
        sections: Vec::new(),
        markers: 0,
        truncated: false,
    };
    let push = |label: String, v: &Value, out: &mut Canonical| {
        if out.prefix.len() > PREFIX_CAP {
            out.truncated = true;
            return;
        }
        let mut v = v.clone();
        out.markers += strip_markers(&mut v);
        out.sections.push((label, out.prefix.len()));
        // serde_json's default map is ordered (BTreeMap), so this
        // serialization is stable across key-order differences in the body.
        out.prefix
            .extend_from_slice(&serde_json::to_vec(&v).unwrap_or_default());
        // Section separator: an item can't extend into the next section and
        // silently shift every later boundary.
        out.prefix.push(0x1f);
    };

    if let Some(tools) = root.get("tools").and_then(Value::as_array) {
        for (i, t) in tools.iter().enumerate() {
            push(format!("tools[{i}]"), t, &mut out);
        }
    }
    match root.get("system") {
        Some(Value::Array(blocks)) => {
            for (i, b) in blocks.iter().enumerate() {
                push(format!("system[{i}]"), b, &mut out);
            }
        }
        Some(v) if !v.is_null() => push("system".to_string(), v, &mut out),
        _ => {}
    }
    if let Some(messages) = root.get("messages").and_then(Value::as_array) {
        for (i, m) in messages.iter().enumerate() {
            push(format!("messages[{i}]"), m, &mut out);
        }
    }
    out
}

/// Remove every `cache_control` key in the tree, returning how many there
/// were. Markers are metadata: the model never reads them, so they must not
/// count as content changes.
fn strip_markers(v: &mut Value) -> u64 {
    match v {
        Value::Object(map) => {
            let mut n = u64::from(map.remove("cache_control").is_some());
            for child in map.values_mut() {
                n += strip_markers(child);
            }
            n
        }
        Value::Array(items) => items.iter_mut().map(strip_markers).sum(),
        _ => 0,
    }
}

/// First differing byte index, or None when one side is a prefix of the
/// other (identical or extended: both cache-friendly).
fn first_mismatch(prev: &[u8], curr: &[u8]) -> Option<usize> {
    prev.iter().zip(curr.iter()).position(|(a, b)| a != b)
}

/// The section label a canonical-prefix offset falls in.
fn section_at(sections: &[(String, usize)], offset: usize) -> String {
    sections
        .iter()
        .rev()
        .find(|(_, start)| *start <= offset)
        .map(|(label, _)| label.clone())
        .unwrap_or_else(|| "(unknown)".to_string())
}

/// The canonical-stream offset where the first `messages[...]` section starts,
/// i.e. the end of the cacheable (tools + system) region.
fn messages_start(sections: &[(String, usize)]) -> Option<usize> {
    sections
        .iter()
        .find(|(label, _)| label.starts_with("messages["))
        .map(|(_, start)| *start)
}

// ---------------------------------------------------------------------------
// Repair: byte-surgical `cache_control` injection (plan 004 phase 2).
//
// The splice edits the client's original bytes in place rather than
// re-serializing: serde_json has no `preserve_order`, so a round-trip would
// reorder object keys and the proxy would itself churn the prefix it exists
// to stabilize. A tiny JSON span scanner finds the last cacheable content
// block and inserts the marker right after its opening brace.
// ---------------------------------------------------------------------------

/// Splice an ephemeral `cache_control` marker onto the last cacheable content
/// block (last `system` block, else last `tools` entry) of a Messages body.
/// Returns the edited bytes on success; `None` when there is no object to mark
/// or the edit wouldn't re-parse (fail safe: forward the original untouched).
/// Never runs on a body that already carries a marker (the repair gate ensures
/// that), so it never doubles up.
pub fn splice_marker(body: &[u8], ttl_1h: bool) -> Option<Vec<u8>> {
    let obj_open = injection_point(body)?;
    // Insert just after the opening brace; a comma separates from an existing
    // first member, and is omitted for an empty object.
    let marker: &str = if ttl_1h {
        r#""cache_control":{"type":"ephemeral","ttl":"1h"}"#
    } else {
        r#""cache_control":{"type":"ephemeral"}"#
    };
    let mut i = obj_open + 1;
    while i < body.len() && (body[i] as char).is_whitespace() {
        i += 1;
    }
    let empty = body.get(i) == Some(&b'}');
    let insert = if empty {
        marker.to_string()
    } else {
        format!("{marker},")
    };
    let mut out = Vec::with_capacity(body.len() + insert.len());
    out.extend_from_slice(&body[..obj_open + 1]);
    out.extend_from_slice(insert.as_bytes());
    out.extend_from_slice(&body[obj_open + 1..]);
    // Sanity: a splice that doesn't parse is a bug in the span finder; drop it
    // rather than send malformed JSON upstream.
    serde_json::from_slice::<Value>(&out).ok()?;
    Some(out)
}

/// Byte offset of the opening brace of the object to attach the marker to:
/// the last `system` array block, else the last `tools` array entry. Returns
/// `None` when neither is an array of objects.
fn injection_point(body: &[u8]) -> Option<usize> {
    let root_open = skip_ws(body, 0);
    if body.get(root_open) != Some(&b'{') {
        return None;
    }
    for key in ["system", "tools"] {
        if let Some((vstart, vend)) = object_member_value(body, root_open, key) {
            if body.get(vstart) == Some(&b'[') {
                if let Some((estart, _)) = array_last_element(body, vstart, vend) {
                    if body.get(estart) == Some(&b'{') {
                        return Some(estart);
                    }
                }
            }
        }
    }
    None
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && (b[i] as char).is_whitespace() {
        i += 1;
    }
    i
}

/// Index just past a JSON string that starts at `i` (a `"`), honoring escapes.
fn skip_string(b: &[u8], i: usize) -> Option<usize> {
    if b.get(i) != Some(&b'"') {
        return None;
    }
    let mut i = i + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// Index just past the JSON value that starts at `i` (first non-ws byte of the
/// value). Handles the shapes a request body actually contains.
fn skip_value(b: &[u8], i: usize) -> Option<usize> {
    let i = skip_ws(b, i);
    match b.get(i)? {
        b'"' => skip_string(b, i),
        b'{' | b'[' => {
            let (open, close) = if b[i] == b'{' {
                (b'{', b'}')
            } else {
                (b'[', b']')
            };
            let mut depth = 0i32;
            let mut j = i;
            while j < b.len() {
                match b[j] {
                    b'"' => j = skip_string(b, j)?,
                    c if c == open => {
                        depth += 1;
                        j += 1;
                    }
                    c if c == close => {
                        depth -= 1;
                        j += 1;
                        if depth == 0 {
                            return Some(j);
                        }
                    }
                    _ => j += 1,
                }
            }
            None
        }
        // Number, true, false, null: run to the next structural byte.
        _ => {
            let mut j = i;
            while j < b.len() && !matches!(b[j], b',' | b'}' | b']') {
                j += 1;
            }
            (j > i).then_some(j)
        }
    }
}

/// The value span (start..end) of member `key` in the object whose `{` is at
/// `obj_open`. `start` is the first non-ws byte of the value.
fn object_member_value(b: &[u8], obj_open: usize, key: &str) -> Option<(usize, usize)> {
    let mut i = skip_ws(b, obj_open + 1);
    while i < b.len() && b[i] != b'}' {
        // Member key.
        let key_end = skip_string(b, i)?;
        let name = std::str::from_utf8(&b[i + 1..key_end - 1]).ok()?;
        let colon = skip_ws(b, key_end);
        if b.get(colon) != Some(&b':') {
            return None;
        }
        let vstart = skip_ws(b, colon + 1);
        let vend = skip_value(b, vstart)?;
        if name == key {
            return Some((vstart, vend));
        }
        i = skip_ws(b, vend);
        if b.get(i) == Some(&b',') {
            i = skip_ws(b, i + 1);
        }
    }
    None
}

/// The span of the last element of the array whose `[` is at `arr_open` and
/// whose matching `]` is at `arr_end - 1`. `start` is the element's first
/// non-ws byte.
fn array_last_element(b: &[u8], arr_open: usize, arr_end: usize) -> Option<(usize, usize)> {
    let mut i = skip_ws(b, arr_open + 1);
    let mut last: Option<(usize, usize)> = None;
    while i < arr_end && b[i] != b']' {
        let start = i;
        let end = skip_value(b, start)?;
        last = Some((start, end));
        i = skip_ws(b, end);
        if b.get(i) == Some(&b',') {
            i = skip_ws(b, i + 1);
        }
    }
    last
}

// ---------------------------------------------------------------------------
// Active management (plan 004 phase 3): fan-out serialization + keep-alive.
// ---------------------------------------------------------------------------

/// A stable identity for the cacheable prefix of a request: `host model
/// <hash>`, where the hash is over the canonical, marker-stripped tools +
/// system bytes. Two requests that share a warm cache entry share this key;
/// injecting a marker (repair) doesn't change it, since markers are stripped.
/// `None` for a body that isn't a Messages request.
pub fn cacheable_key(host: &str, model: &str, body: &[u8]) -> Option<String> {
    let root: Value = serde_json::from_slice(body).ok()?;
    root.get("messages")?.as_array()?;
    let canon = canonicalize(&root);
    let cut = messages_start(&canon.sections).unwrap_or(canon.prefix.len());
    let cacheable = &canon.prefix[..cut.min(canon.prefix.len())];
    let mut h = Sha256::new();
    h.update(cacheable);
    Some(format!("{host} {model} {:x}", h.finalize()))
}

/// Serializes concurrent requests that share a cacheable prefix: the first
/// (leader) forwards immediately and writes the cache; siblings wait for its
/// first response byte (or a timeout) and then read the now-warm cache. Turns
/// N cache writes into 1 write + N-1 reads.
#[derive(Default)]
pub struct FanoutGate {
    slots: std::sync::Mutex<HashMap<String, Slot>>,
}

struct Slot {
    /// Woken when the leader's first response byte arrives.
    notify: Arc<Notify>,
    /// The leader has forwarded and the cache is being written: late siblings
    /// can proceed straight to a read.
    ready: Arc<AtomicBool>,
    /// A leader is currently in flight for this prefix.
    has_leader: bool,
    /// Live participants (leader + siblings); the slot is dropped at zero.
    refs: u32,
}

/// One request's participation in the gate. Leaves the gate (and signals the
/// leader's readiness if it was the leader and didn't already) on drop.
pub struct FanoutGuard {
    gate: Arc<FanoutGate>,
    key: String,
    notify: Arc<Notify>,
    ready: Arc<AtomicBool>,
    leader: bool,
}

impl FanoutGate {
    /// Join the gate for `key`, becoming the leader if none is in flight.
    pub fn enter(self: &Arc<Self>, key: String) -> FanoutGuard {
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let slot = slots.entry(key.clone()).or_insert_with(|| Slot {
            notify: Arc::new(Notify::new()),
            ready: Arc::new(AtomicBool::new(false)),
            has_leader: false,
            refs: 0,
        });
        slot.refs += 1;
        let (notify, ready) = (slot.notify.clone(), slot.ready.clone());
        let leader = !slot.has_leader && !slot.ready.load(Ordering::Acquire);
        if leader {
            slot.has_leader = true;
        }
        FanoutGuard {
            gate: self.clone(),
            key,
            notify,
            ready,
            leader,
        }
    }
}

impl FanoutGuard {
    pub fn is_leader(&self) -> bool {
        self.leader
    }

    /// Leader signals its first response byte: siblings may now read the cache.
    pub fn leader_ready(&self) {
        self.ready.store(true, Ordering::Release);
        if let Ok(mut slots) = self.gate.slots.lock() {
            if let Some(slot) = slots.get_mut(&self.key) {
                slot.has_leader = false;
            }
        }
        self.notify.notify_waiters();
    }

    /// Sibling waits for the leader's first byte, up to `timeout`, then
    /// proceeds regardless (a stalled leader must never wedge its siblings).
    pub async fn wait_for_leader(&self, timeout: Duration) {
        if self.ready.load(Ordering::Acquire) {
            return;
        }
        // Arm the waiter, then re-check to close the notify-before-wait race.
        let notified = self.notify.notified();
        if self.ready.load(Ordering::Acquire) {
            return;
        }
        let _ = tokio::time::timeout(timeout, notified).await;
    }
}

impl Drop for FanoutGuard {
    fn drop(&mut self) {
        // A leader that never reached `leader_ready` (an error before the
        // response) must still release its siblings.
        if self.leader && !self.ready.load(Ordering::Acquire) {
            self.notify.notify_waiters();
        }
        if let Ok(mut slots) = self.gate.slots.lock() {
            if let Some(slot) = slots.get_mut(&self.key) {
                slot.refs = slot.refs.saturating_sub(1);
                if self.leader {
                    slot.has_leader = false;
                }
                if slot.refs == 0 {
                    slots.remove(&self.key);
                }
            }
        }
    }
}

/// A representative request the proxy can replay to keep a cache warm. Held in
/// memory only, session-local — never persisted, so the doctor's "no prompt
/// content on disk" guarantee is untouched. The body is the pre-swap (decoy)
/// form; the pre-warm re-runs the swap so real secrets are placed under the
/// same policy checks as any forwarded request.
#[derive(Clone)]
pub struct KeepAliveTemplate {
    pub method: String,
    pub path: String,
    /// Upstream port, so a pre-warm reaches the same authority the original
    /// request did (provider APIs are 443; test upstreams are not).
    pub port: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

struct KeepAliveEntry {
    template: KeepAliveTemplate,
    /// Unix time of the last real request on this key; idle is measured from
    /// here, and a pre-warm never advances it.
    last_seen_unix: u64,
    /// Pre-warms fired since the last real request, capped at `max`.
    fired: u32,
    max: u32,
    /// A watcher task is already running for this key.
    watching: bool,
}

/// Tracks, per (host, model), the last request seen and how many pre-warms
/// have fired, so a single watcher task per key can decide when the cache
/// needs refreshing. Session-local; dies with the process.
#[derive(Default)]
pub struct KeepAlive {
    entries: HashMap<String, KeepAliveEntry>,
}

impl KeepAlive {
    /// Record a real request as the freshest activity for `key`, resetting the
    /// pre-warm budget. Returns true when this key had no watcher yet, so the
    /// caller should spawn one.
    pub fn arm(
        &mut self,
        key: String,
        template: KeepAliveTemplate,
        max: u32,
        now_unix: u64,
    ) -> bool {
        let e = self.entries.entry(key).or_insert(KeepAliveEntry {
            template: template.clone(),
            last_seen_unix: now_unix,
            fired: 0,
            max,
            watching: false,
        });
        e.template = template;
        e.last_seen_unix = now_unix;
        e.fired = 0;
        e.max = max;
        let spawn = !e.watching;
        e.watching = true;
        spawn
    }

    /// If `key` has been idle for at least `idle_secs` and has pre-warm budget
    /// left, claim one fire and hand back the request to replay.
    pub fn due(&mut self, key: &str, idle_secs: u64, now_unix: u64) -> Option<KeepAliveTemplate> {
        let e = self.entries.get_mut(key)?;
        if now_unix.saturating_sub(e.last_seen_unix) >= idle_secs && e.fired < e.max {
            e.fired += 1;
            Some(e.template.clone())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(system: &str, messages: &[&str]) -> Vec<u8> {
        let msgs: Vec<Value> = messages
            .iter()
            .map(|m| serde_json::json!({"role": "user", "content": *m}))
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "model": "claude-sonnet-5",
            "system": system,
            "messages": msgs,
        }))
        .unwrap()
    }

    fn stats(d: &Doctor) -> &KeyStats {
        d.delta.per_key.values().next().unwrap()
    }

    #[test]
    fn extended_prefix_is_preserved() {
        let mut d = Doctor::default();
        d.observe("h", &body("stable system", &["hi"]), 100);
        d.observe("h", &body("stable system", &["hi", "more"]), 110);
        let s = stats(&d);
        assert_eq!(s.requests, 2);
        assert_eq!(s.preserved, 1);
        assert_eq!(s.diverged, 0);
        assert_eq!(s.ttl_gaps, 0);
    }

    #[test]
    fn timestamp_in_system_diverges_with_offset_and_section() {
        let mut d = Doctor::default();
        d.observe("h", &body("helpful. now: 10:00:00", &["hi"]), 100);
        d.observe("h", &body("helpful. now: 10:00:05", &["hi"]), 140);
        let s = stats(&d);
        assert_eq!(s.diverged, 1);
        assert_eq!(s.preserved, 0);
        let div = s.last_divergence.as_ref().expect("divergence recorded");
        assert_eq!(div.section, "system");
        assert!(div.offset > 0, "offset should land inside the section");
        assert_eq!(div.gap_secs, 40);
    }

    #[test]
    fn new_conversation_counts_as_reset_not_divergence() {
        let mut d = Doctor::default();
        d.observe("h", &body("stable system", &["first conversation"]), 100);
        d.observe("h", &body("stable system", &["second conversation"]), 110);
        let s = stats(&d);
        assert_eq!(s.resets, 1);
        assert_eq!(s.diverged, 0);
        assert!(s.last_divergence.is_none());
    }

    #[test]
    fn moving_a_marker_is_not_a_content_change() {
        let mut d = Doctor::default();
        let with_marker = serde_json::to_vec(&serde_json::json!({
            "model": "claude-sonnet-5",
            "system": [{"type": "text", "text": "stable",
                        "cache_control": {"type": "ephemeral"}}],
            "messages": [{"role": "user", "content": "hi"}],
        }))
        .unwrap();
        let without_marker = serde_json::to_vec(&serde_json::json!({
            "model": "claude-sonnet-5",
            "system": [{"type": "text", "text": "stable"}],
            "messages": [{"role": "user", "content": "hi"}],
        }))
        .unwrap();
        d.observe("h", &with_marker, 100);
        d.observe("h", &without_marker, 110);
        let s = stats(&d);
        assert_eq!(s.preserved, 1);
        assert_eq!(s.diverged, 0);
        assert_eq!(s.marked, 1, "only the first request carried a marker");
    }

    #[test]
    fn ttl_gap_counted_on_preserved_prefix_past_ttl() {
        let mut d = Doctor::default();
        d.observe("h", &body("stable", &["hi"]), 100);
        d.observe(
            "h",
            &body("stable", &["hi", "again"]),
            100 + CACHE_TTL_SECS + 1,
        );
        let s = stats(&d);
        assert_eq!(s.preserved, 1);
        assert_eq!(s.ttl_gaps, 1);
    }

    #[test]
    fn below_min_flags_small_prefixes_only() {
        let mut d = Doctor::default();
        d.observe("h", &body("tiny", &["hi"]), 100);
        let big = "x".repeat((MIN_CACHEABLE_TOKENS * BYTES_PER_TOKEN) as usize + 64);
        d.observe("h", &body(&big, &["hi"]), 110);
        let s = stats(&d);
        assert_eq!(s.below_min, 1);
    }

    #[test]
    fn models_do_not_cross_diagnose() {
        let mut d = Doctor::default();
        let mut b1 = body("system A", &["hi"]);
        let mut b2 = body("system B", &["hi"]);
        // Same host, different models: no divergence between them.
        let v1: Value = serde_json::from_slice(&b1).unwrap();
        let mut v1 = v1;
        v1["model"] = "claude-sonnet-5".into();
        b1 = serde_json::to_vec(&v1).unwrap();
        let v2: Value = serde_json::from_slice(&b2).unwrap();
        let mut v2 = v2;
        v2["model"] = "claude-haiku-4-5".into();
        b2 = serde_json::to_vec(&v2).unwrap();
        d.observe("h", &b1, 100);
        d.observe("h", &b2, 110);
        assert_eq!(d.delta.per_key.len(), 2);
        for s in d.delta.per_key.values() {
            assert_eq!(s.diverged, 0);
        }
    }

    #[test]
    fn non_messages_bodies_are_skipped() {
        let mut d = Doctor::default();
        assert!(d.observe("h", br#"{"model":"m"}"#, 100).is_none());
        assert!(d.observe("h", b"not json", 100).is_none());
        assert!(d.delta.per_key.is_empty());
    }

    #[test]
    fn observe_returns_the_model() {
        let mut d = Doctor::default();
        let obs = d.observe("h", &body("s", &["hi"]), 100).unwrap();
        assert_eq!(obs.model, "claude-sonnet-5");
    }

    /// A Messages body with a `system` array (one large stable block) and an
    /// optional trailing message, so the cacheable region clears the minimum.
    fn repair_body(msg: &str) -> Vec<u8> {
        let big = "You are a careful assistant. ".repeat(200); // ~5.8 KiB
        serde_json::to_vec(&serde_json::json!({
            "model": "claude-sonnet-5",
            "tools": [{"name": "read", "description": "read a file"}],
            "system": [{"type": "text", "text": big}],
            "messages": [{"role": "user", "content": msg}],
        }))
        .unwrap()
    }

    #[test]
    fn splice_marks_last_system_block_leaving_content_identical() {
        let body = repair_body("hi");
        let spliced = splice_marker(&body, false).expect("splice");
        let v: Value = serde_json::from_slice(&spliced).unwrap();
        let block = &v["system"][0];
        assert_eq!(block["cache_control"]["type"], "ephemeral");
        assert!(block["cache_control"].get("ttl").is_none());
        // The text the model reads is untouched.
        let orig: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(block["text"], orig["system"][0]["text"]);
    }

    #[test]
    fn splice_honors_1h_ttl() {
        let body = repair_body("hi");
        let spliced = splice_marker(&body, true).expect("splice");
        let v: Value = serde_json::from_slice(&spliced).unwrap();
        assert_eq!(v["system"][0]["cache_control"]["ttl"], "1h");
    }

    #[test]
    fn splice_falls_back_to_last_tool_without_system() {
        let body = serde_json::to_vec(&serde_json::json!({
            "model": "claude-sonnet-5",
            "tools": [{"name": "a"}, {"name": "b"}],
            "messages": [{"role": "user", "content": "hi"}],
        }))
        .unwrap();
        let spliced = splice_marker(&body, false).expect("splice");
        let v: Value = serde_json::from_slice(&spliced).unwrap();
        assert!(v["tools"][0].get("cache_control").is_none());
        assert_eq!(v["tools"][1]["cache_control"]["type"], "ephemeral");
        assert_eq!(v["tools"][1]["name"], "b");
    }

    #[test]
    fn no_injection_target_returns_none() {
        // system is a bare string (not an array of blocks) and no tools.
        let body = br#"{"model":"m","system":"be brief","messages":[]}"#;
        assert!(splice_marker(body, false).is_none());
    }

    #[test]
    fn repair_waits_for_a_repeat_and_skips_marked_requests() {
        let mut d = Doctor::default();
        // First sight of the prefix: nothing to repair yet.
        assert!(d
            .observe("h", &repair_body("first"), 100)
            .unwrap()
            .repair
            .is_none());
        // Same cacheable prefix, new turn: now it's a demonstrated repeat.
        let plan = d.observe("h", &repair_body("second"), 110).unwrap().repair;
        let plan = plan.expect("repeat prefix is repairable");
        assert!(!plan.ttl_1h, "gaps under 5m stay on the default TTL");
        assert_eq!(plan.section, "system[0]");
        let s = stats(&d);
        assert_eq!(s.repairable, 1);
    }

    #[test]
    fn repair_declines_when_client_already_marks() {
        let mut d = Doctor::default();
        let marked = || {
            let big = "You are a careful assistant. ".repeat(200);
            serde_json::to_vec(&serde_json::json!({
                "model": "claude-sonnet-5",
                "system": [{"type": "text", "text": big,
                            "cache_control": {"type": "ephemeral"}}],
                "messages": [{"role": "user", "content": "hi"}],
            }))
            .unwrap()
        };
        d.observe("h", &marked(), 100);
        assert!(
            d.observe("h", &marked(), 110).unwrap().repair.is_none(),
            "a client that sets its own markers is left alone"
        );
    }

    #[test]
    fn repair_skips_below_minimum_prefixes() {
        let mut d = Doctor::default();
        let tiny = || {
            serde_json::to_vec(&serde_json::json!({
                "model": "claude-sonnet-5",
                "system": [{"type": "text", "text": "short"}],
                "messages": [{"role": "user", "content": "hi"}],
            }))
            .unwrap()
        };
        d.observe("h", &tiny(), 100);
        assert!(d.observe("h", &tiny(), 110).unwrap().repair.is_none());
    }

    #[test]
    fn repair_tunes_to_1h_when_gaps_outrun_the_ttl() {
        let mut d = Doctor::default();
        d.observe("h", &repair_body("a"), 0);
        // Two repeats, both landing well past the 5m TTL: tune up to 1h.
        d.observe("h", &repair_body("b"), CACHE_TTL_SECS + 100);
        let plan = d
            .observe("h", &repair_body("c"), 2 * (CACHE_TTL_SECS + 100))
            .unwrap()
            .repair
            .expect("repairable");
        assert!(plan.ttl_1h, "most gaps outran 5m, so mark for 1h");
    }

    #[test]
    fn note_repaired_counts_injections() {
        let mut d = Doctor::default();
        d.observe("h", &repair_body("x"), 100);
        d.note_repaired("h", "claude-sonnet-5");
        assert_eq!(stats(&d).repaired, 1);
    }

    #[test]
    fn cacheable_key_ignores_messages_and_markers() {
        // Same tools+system, different conversation turn: identical key.
        let a = cacheable_key("h", "m", &repair_body("first")).unwrap();
        let b = cacheable_key("h", "m", &repair_body("second")).unwrap();
        assert_eq!(a, b);
        // A repaired body (marker spliced in) keys the same as the original.
        let repaired = splice_marker(&repair_body("first"), false).unwrap();
        assert_eq!(cacheable_key("h", "m", &repaired).unwrap(), a);
        // A different host or model is a different cache.
        assert_ne!(cacheable_key("h2", "m", &repair_body("first")).unwrap(), a);
        assert!(cacheable_key("h", "m", b"not json").is_none());
    }

    #[tokio::test]
    async fn fanout_first_is_leader_siblings_follow() {
        let gate = Arc::new(FanoutGate::default());
        let leader = gate.enter("k".into());
        assert!(leader.is_leader());
        let sib = gate.enter("k".into());
        assert!(!sib.is_leader(), "second concurrent request is a follower");

        // The sibling blocks until the leader signals its first byte.
        let sib_ready = Arc::new(AtomicBool::new(false));
        let flag = sib_ready.clone();
        let waiter = tokio::spawn(async move {
            sib.wait_for_leader(Duration::from_secs(5)).await;
            flag.store(true, Ordering::Release);
        });
        tokio::task::yield_now().await;
        assert!(
            !sib_ready.load(Ordering::Acquire),
            "still waiting on the leader"
        );
        leader.leader_ready();
        waiter.await.unwrap();
        assert!(
            sib_ready.load(Ordering::Acquire),
            "released once the leader was ready"
        );
    }

    #[tokio::test]
    async fn fanout_wait_times_out_on_a_stalled_leader() {
        let gate = Arc::new(FanoutGate::default());
        let _leader = gate.enter("k".into()); // never signals ready
        let sib = gate.enter("k".into());
        // Must return on the timeout rather than hang forever.
        sib.wait_for_leader(Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn fanout_dropped_leader_releases_siblings() {
        let gate = Arc::new(FanoutGate::default());
        let leader = gate.enter("k".into());
        let sib = gate.enter("k".into());
        drop(leader); // leader errored before responding
                      // The sibling isn't wedged; the drop woke it.
        sib.wait_for_leader(Duration::from_secs(5)).await;
    }

    #[test]
    fn keepalive_arms_once_and_fires_when_idle() {
        let mut k = KeepAlive::default();
        let tmpl = KeepAliveTemplate {
            method: "POST".into(),
            path: "/v1/messages".into(),
            port: 443,
            headers: vec![],
            body: b"{}".to_vec(),
        };
        assert!(
            k.arm("key".into(), tmpl.clone(), 2, 100),
            "first arm spawns a watcher"
        );
        assert!(
            !k.arm("key".into(), tmpl.clone(), 2, 100),
            "re-arm reuses the watcher"
        );
        // Not idle yet.
        assert!(k.due("key", 60, 130).is_none());
        // Idle past the threshold: fires, up to the cap.
        assert!(k.due("key", 60, 200).is_some());
        assert!(k.due("key", 60, 300).is_some());
        assert!(k.due("key", 60, 400).is_none(), "cap of 2 reached");
        // A real request re-arms and refills the budget.
        k.arm("key".into(), tmpl, 2, 500);
        assert!(k.due("key", 60, 600).is_some());
    }

    #[test]
    fn flush_merges_across_sessions() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        let period = crate::util::current_period();
        let mut a = Doctor::default();
        a.observe("h", &body("now: 1", &["hi"]), 100);
        a.observe("h", &body("now: 2", &["hi"]), 110);
        a.flush(&period).unwrap();
        let mut b = Doctor::default();
        b.observe("h", &body("stable", &["hi"]), 100);
        b.observe("h", &body("stable", &["hi", "more"]), 120);
        b.flush(&period).unwrap();

        let disk = CacheStats::load().unwrap();
        let s = &disk.per_key["h claude-sonnet-5"];
        assert_eq!(s.requests, 4);
        assert_eq!(s.diverged, 1);
        assert_eq!(s.preserved, 1);
        assert!(s.last_divergence.is_some());
    }
}
