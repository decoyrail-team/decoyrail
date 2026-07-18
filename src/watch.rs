//! Spend tripwire (plan 002): near-real-time runaway detection.
//!
//! Agents get stuck: retrying the same failing request, re-running the same
//! tool call, burning tokens unattended. The monthly budget kill switch fires
//! far too late for a doom loop that started at 2am, so this watches for two
//! purely mechanical signals — the same request repeated many times inside a
//! sliding window, and a spend rate far above the session's own baseline —
//! and trips before the loop becomes a bill. No semantics, no "is the agent
//! making progress" judgment; those wait for the judge tier.
//!
//! Detection state lives in memory (a bounded ring per engine); only a trip
//! itself is persisted, to `trip.json`, so enforcement survives a proxy
//! restart and clearing is an explicit operator command (`decoyrail trip
//! clear`), never a timeout or a bounce. Requests are identified by a salted
//! fingerprint (destination + method + pre-swap body) — the same
//! salt-and-hash treatment DLP hits get, so the audit log can carry the
//! fingerprint without carrying anything derivable back to content.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;

use crate::config;
use crate::policy::{SpendTripwireConfig, TripwireMode};

/// Ring capacity backstop, independent of the configured window: a client
/// hammering thousands of requests per window must not grow proxy memory.
const MAX_EVENTS: usize = 4096;

/// The session must be at least this old before a spend-rate baseline exists.
/// A young session has no meaningful "usual pace", and a burst right after
/// startup is what agents legitimately do (load context, fan out reads).
const BASELINE_MIN_SECS: u64 = 600;

/// Salted fingerprint of one request's identity: host, path, method, and the
/// pre-swap body (the bytes as the agent sent them — decoys are stable within
/// a machine, so a replayed request fingerprints identically, while the salt
/// keeps the hash unlinkable to content for anyone reading the audit log).
pub fn fingerprint(salt: &[u8; 32], host: &str, path: &str, method: &str, body: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(host.as_bytes());
    h.update([0]);
    h.update(path.as_bytes());
    h.update([0]);
    h.update(method.as_bytes());
    h.update([0]);
    h.update(body);
    hex::encode(&h.finalize()[..8])
}

/// A tripped state, persisted verbatim as `trip.json`. Carries the trigger
/// and counts, never request content (the fingerprint is salted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trip {
    /// RFC 3339 timestamp of the moment the detector tripped.
    pub ts: String,
    /// `repeat` or `rate`.
    pub kind: String,
    /// Human-readable trigger, e.g. `identical request repeated 15x in 300s`.
    pub reason: String,
    /// Salted fingerprint of the repeated request (empty for rate trips).
    #[serde(default)]
    pub fingerprint: String,
    /// Repeats observed inside the window (0 for rate trips).
    #[serde(default)]
    pub count: u32,
    pub window_secs: u64,
    /// Session id of the process whose traffic tripped.
    #[serde(default)]
    pub sid: String,
}

/// What the detector saw when it fired; the pipeline turns this into a
/// `Trip` (adding timestamp and session id) and decides block vs alert.
#[derive(Debug, Clone, PartialEq)]
pub enum Signal {
    Repeat {
        fingerprint: String,
        count: u32,
    },
    Rate {
        window_usd: f64,
        per_min: f64,
        baseline_per_min: f64,
    },
}

impl Signal {
    /// The `Trip` fields this signal justifies, ready for the audit note and
    /// the machine-readable error body.
    pub fn to_trip(&self, window_secs: u64, ts: String, sid: String) -> Trip {
        match self {
            Signal::Repeat { fingerprint, count } => Trip {
                ts,
                kind: "repeat".into(),
                reason: format!(
                    "identical request repeated {count}x in {window_secs}s \
                     (fingerprint {fingerprint})"
                ),
                fingerprint: fingerprint.clone(),
                count: *count,
                window_secs,
                sid,
            },
            Signal::Rate {
                window_usd,
                per_min,
                baseline_per_min,
            } => Trip {
                ts,
                kind: "rate".into(),
                reason: format!(
                    "spend rate ${per_min:.2}/min (${window_usd:.2} in {window_secs}s) is \
                     {}x the session baseline of ${baseline_per_min:.2}/min",
                    (per_min / baseline_per_min).round()
                ),
                fingerprint: String::new(),
                count: 0,
                window_secs,
                sid,
            },
        }
    }
}

/// Per-engine detector state: recent request fingerprints and recent metered
/// spend, both pruned to the configured window, plus the session totals the
/// rate baseline reads. One `Watch` per engine matches the spec's "session"
/// (one `decoyrail run` or `proxy` invocation).
pub struct Watch {
    /// (unix seconds, fingerprint) of recent LLM-bound requests.
    recent: VecDeque<(u64, String)>,
    /// (unix seconds, USD) of recently metered billable spend.
    costs: VecDeque<(u64, f64)>,
    session_started: u64,
    session_spend: f64,
    /// The persisted trip in force, if any (loaded at boot, hot-reloaded on
    /// `trip.json` changes, set when this session's own detector fires).
    tripped: Option<Trip>,
}

impl Watch {
    pub fn new(now_unix: u64, persisted: Option<Trip>) -> Self {
        Watch {
            recent: VecDeque::new(),
            costs: VecDeque::new(),
            session_started: now_unix,
            session_spend: 0.0,
            tripped: persisted,
        }
    }

    pub fn tripped(&self) -> Option<&Trip> {
        self.tripped.as_ref()
    }

    /// Replace the trip state (hot-reload from `trip.json`, or the pipeline
    /// recording the trip it just persisted). A clear also resets detection
    /// state: the window that justified the trip must not re-trip on the
    /// very next request after an operator explicitly cleared it.
    pub fn set_tripped(&mut self, trip: Option<Trip>) {
        if trip.is_none() {
            self.recent.clear();
            self.costs.clear();
        }
        self.tripped = trip;
    }

    /// Record one LLM-bound request and check both detectors. Returns the
    /// signal when one fires; the caller owns enforcement, persistence, and
    /// audit. `Off` records nothing and never fires.
    pub fn observe(
        &mut self,
        cfg: &SpendTripwireConfig,
        now_unix: u64,
        fp: &str,
    ) -> Option<Signal> {
        if cfg.mode == TripwireMode::Off {
            return None;
        }
        self.prune(cfg.window_secs, now_unix);
        self.recent.push_back((now_unix, fp.to_string()));
        if self.recent.len() > MAX_EVENTS {
            self.recent.pop_front();
        }

        if cfg.repeats > 0 {
            let count = self.recent.iter().filter(|(_, f)| f == fp).count() as u32;
            if count >= cfg.repeats {
                return Some(Signal::Repeat {
                    fingerprint: fp.to_string(),
                    count,
                });
            }
        }

        // Rate spike, only once the session has enough history *before* the
        // current window to call a baseline: the burst under test must not
        // inflate the pace it is measured against. A session with no prior
        // spend has no baseline, so it can't rate-trip (the repeat detector
        // and the budget kill switch still stand).
        let elapsed = now_unix.saturating_sub(self.session_started);
        let baseline_secs = elapsed.saturating_sub(cfg.window_secs);
        if cfg.rate_multiplier > 0.0 && baseline_secs >= BASELINE_MIN_SECS {
            let window_usd: f64 = self.costs.iter().map(|(_, c)| c).sum();
            let prior_usd = (self.session_spend - window_usd).max(0.0);
            let per_min = window_usd / (cfg.window_secs as f64 / 60.0);
            let baseline_per_min = prior_usd / (baseline_secs as f64 / 60.0);
            if prior_usd > 0.0
                && window_usd >= cfg.rate_floor_usd
                && per_min > baseline_per_min * cfg.rate_multiplier
            {
                return Some(Signal::Rate {
                    window_usd,
                    per_min,
                    baseline_per_min,
                });
            }
        }
        None
    }

    /// Fold one request's billable cost in, as metering learns it (buffered
    /// responses synchronously, streamed ones when the stream drains). Only
    /// exactly-metered billable dollars: byte estimates are too coarse to
    /// rate-limit on, and subscription traffic's reference cost is not spend.
    pub fn observe_cost(&mut self, now_unix: u64, usd: f64) {
        if usd <= 0.0 {
            return;
        }
        self.session_spend += usd;
        self.costs.push_back((now_unix, usd));
        if self.costs.len() > MAX_EVENTS {
            self.costs.pop_front();
        }
    }

    fn prune(&mut self, window_secs: u64, now_unix: u64) {
        let cutoff = now_unix.saturating_sub(window_secs);
        while self.recent.front().is_some_and(|(t, _)| *t < cutoff) {
            self.recent.pop_front();
        }
        while self.costs.front().is_some_and(|(t, _)| *t < cutoff) {
            self.costs.pop_front();
        }
    }
}

/// Read the persisted trip, if any. The file's absence is the defined clear
/// state; a file that exists but cannot be read or parsed reads as
/// tripped-unknown rather than clear, so enforcement state fails closed and
/// `decoyrail trip clear` removes it either way.
pub fn load_trip() -> Result<Option<Trip>> {
    let path = config::trip_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let parsed = std::fs::read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok());
    Ok(Some(parsed.unwrap_or_else(|| Trip {
        ts: String::new(),
        kind: "unknown".into(),
        reason: "trip.json is unreadable; treating the session as tripped".into(),
        fingerprint: String::new(),
        count: 0,
        window_secs: 0,
        sid: String::new(),
    })))
}

pub fn save_trip(trip: &Trip) -> Result<()> {
    config::ensure_home()?;
    config::atomic_write(
        &config::trip_path()?,
        serde_json::to_string_pretty(trip)?.as_bytes(),
    )
}

/// Remove the persisted trip. Clearing an already-clear state is a no-op.
pub fn clear_trip() -> Result<()> {
    let path = config::trip_path()?;
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SpendTripwireConfig {
        SpendTripwireConfig::default()
    }

    #[test]
    fn fingerprint_is_stable_and_salted() {
        let salt_a = [7u8; 32];
        let salt_b = [8u8; 32];
        let fp = fingerprint(&salt_a, "api.anthropic.com", "/v1/messages", "POST", b"{}");
        assert_eq!(
            fp,
            fingerprint(&salt_a, "api.anthropic.com", "/v1/messages", "POST", b"{}"),
            "same request, same fingerprint"
        );
        assert_eq!(fp.len(), 16);
        assert_ne!(
            fp,
            fingerprint(&salt_b, "api.anthropic.com", "/v1/messages", "POST", b"{}"),
            "a different salt must unlink the hash"
        );
        assert_ne!(
            fp,
            fingerprint(
                &salt_a,
                "api.anthropic.com",
                "/v1/messages",
                "POST",
                b"{'x'}"
            ),
            "a different body is a different request"
        );
        assert_ne!(
            fp,
            fingerprint(&salt_a, "api.openai.com", "/v1/messages", "POST", b"{}"),
            "a different destination is a different request"
        );
    }

    #[test]
    fn identical_requests_trip_at_the_threshold() {
        let mut w = Watch::new(1000, None);
        let c = cfg();
        for i in 0..c.repeats - 1 {
            assert_eq!(w.observe(&c, 1000 + i as u64, "aabbccdd11223344"), None);
        }
        let sig = w
            .observe(&c, 1000 + c.repeats as u64, "aabbccdd11223344")
            .expect("threshold repeat must trip");
        assert_eq!(
            sig,
            Signal::Repeat {
                fingerprint: "aabbccdd11223344".into(),
                count: c.repeats,
            }
        );
    }

    #[test]
    fn distinct_requests_never_trip_repeat() {
        let mut w = Watch::new(1000, None);
        let c = cfg();
        for i in 0..200u64 {
            assert_eq!(
                w.observe(&c, 1000 + i, &format!("{i:016x}")),
                None,
                "distinct traffic must not trip"
            );
        }
    }

    #[test]
    fn window_expiry_forgets_old_repeats() {
        let mut w = Watch::new(1000, None);
        let c = cfg();
        // Spread the same request thinly: never `repeats` inside one window.
        let gap = c.window_secs / (c.repeats as u64 / 2);
        for i in 0..100u64 {
            assert_eq!(
                w.observe(&c, 1000 + i * gap, "aabbccdd11223344"),
                None,
                "slow polling below the windowed threshold must not trip (i={i})"
            );
        }
    }

    #[test]
    fn rate_spike_trips_only_past_floor_baseline_and_age() {
        let mut w = Watch::new(0, None);
        let c = cfg();
        // A modest baseline: $0.01/min for the first 20 minutes.
        for min in 0..20u64 {
            w.observe_cost(min * 60, 0.01);
        }
        let now = 20 * 60;
        // Well past the floor inside the current window.
        w.observe_cost(now, c.rate_floor_usd * 2.0);
        let sig = w.observe(&c, now, "0000000000000001");
        match sig {
            Some(Signal::Rate {
                window_usd,
                per_min,
                baseline_per_min,
            }) => {
                assert!(window_usd >= c.rate_floor_usd);
                assert!(per_min > baseline_per_min * c.rate_multiplier);
            }
            other => panic!("expected a rate trip, got {other:?}"),
        }

        // The same burst without the age: a young session has no baseline.
        let mut young = Watch::new(0, None);
        young.observe_cost(10, 0.01);
        young.observe_cost(20, c.rate_floor_usd * 2.0);
        assert_eq!(young.observe(&c, 30, "0000000000000002"), None);

        // Below the absolute floor: a spiky-but-cheap burst never trips.
        let mut cheap = Watch::new(0, None);
        for min in 0..20u64 {
            cheap.observe_cost(min * 60, 0.001);
        }
        cheap.observe_cost(20 * 60, c.rate_floor_usd / 2.0);
        assert_eq!(cheap.observe(&c, 20 * 60, "0000000000000003"), None);
    }

    #[test]
    fn off_mode_records_nothing_and_never_fires() {
        let mut w = Watch::new(1000, None);
        let mut c = cfg();
        c.mode = TripwireMode::Off;
        for i in 0..100u64 {
            assert_eq!(w.observe(&c, 1000 + i, "aabbccdd11223344"), None);
        }
        assert!(w.recent.is_empty(), "off must not accumulate state");
    }

    #[test]
    fn ring_is_bounded() {
        let mut w = Watch::new(1000, None);
        let mut c = cfg();
        c.repeats = 0; // disable repeat detection so nothing fires
        c.window_secs = u64::MAX / 2; // nothing ever expires
        for i in 0..(MAX_EVENTS + 500) as u64 {
            w.observe(&c, 1000, &format!("{i:016x}"));
            w.observe_cost(1000, 0.0001);
        }
        assert!(w.recent.len() <= MAX_EVENTS);
        assert!(w.costs.len() <= MAX_EVENTS);
    }

    #[test]
    fn clearing_a_trip_resets_detection_state() {
        let mut w = Watch::new(1000, None);
        let c = cfg();
        let mut fired = None;
        for i in 0..c.repeats {
            fired = w.observe(&c, 1000 + i as u64, "aabbccdd11223344");
        }
        let trip = fired.expect("threshold repeat must trip").to_trip(
            c.window_secs,
            "t".into(),
            "s".into(),
        );
        w.set_tripped(Some(trip));
        assert!(w.tripped().is_some());

        // The operator clears: the window that justified the trip must not
        // re-trip on the very next request.
        w.set_tripped(None);
        assert!(w.tripped().is_none());
        assert_eq!(
            w.observe(&c, 1000 + c.repeats as u64, "aabbccdd11223344"),
            None,
            "detection must start fresh after an explicit clear"
        );
    }

    #[test]
    fn signals_render_into_trips() {
        let t = Signal::Repeat {
            fingerprint: "aabbccdd11223344".into(),
            count: 15,
        }
        .to_trip(300, "2026-07-18T00:00:00Z".into(), "sid-1".into());
        assert_eq!(t.kind, "repeat");
        assert!(t.reason.contains("repeated 15x in 300s"), "{}", t.reason);
        assert!(t.reason.contains("aabbccdd11223344"), "{}", t.reason);
        assert_eq!(t.sid, "sid-1");

        let t = Signal::Rate {
            window_usd: 6.0,
            per_min: 1.2,
            baseline_per_min: 0.1,
        }
        .to_trip(300, "2026-07-18T00:00:00Z".into(), "sid-2".into());
        assert_eq!(t.kind, "rate");
        assert!(t.reason.contains("$1.20/min"), "{}", t.reason);
        assert!(
            t.reason.contains("12x the session baseline"),
            "{}",
            t.reason
        );
        assert!(t.fingerprint.is_empty());
    }

    #[test]
    fn trip_persists_loads_and_clears() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        assert!(load_trip().unwrap().is_none());
        clear_trip().unwrap(); // clearing nothing is a quiet no-op

        let trip = Signal::Repeat {
            fingerprint: "aabbccdd11223344".into(),
            count: 15,
        }
        .to_trip(300, crate::util::now_rfc3339(), "sid-1".into());
        save_trip(&trip).unwrap();
        let loaded = load_trip().unwrap().expect("saved trip loads");
        assert_eq!(loaded.kind, "repeat");
        assert_eq!(loaded.count, 15);

        // A corrupted file fails closed: still tripped, reason says why.
        std::fs::write(config::trip_path().unwrap(), "not json").unwrap();
        let loaded = load_trip().unwrap().expect("corrupt file reads as tripped");
        assert_eq!(loaded.kind, "unknown");

        clear_trip().unwrap();
        assert!(load_trip().unwrap().is_none());

        std::env::remove_var("DECOYRAIL_HOME");
    }
}
