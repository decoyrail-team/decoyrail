//! The waste report (plan 001): dollars identifiably wasted, and why.
//!
//! Metering says what was spent; this says what was spent for nothing. Three
//! causes, all mechanical and all priced from data the proxy already keeps:
//! retried identical requests (the same fingerprint re-sent within a short
//! gap), runaway loops (the same, but past the spend tripwire's repeat
//! threshold), and prompt-cache waste (repeating context re-billed at the
//! full input rate for want of a cache marker, priced by the cache doctor).
//!
//! Everything is read locally: the audit log (request events carry the
//! salted fingerprint `fp` since plan 002, plus usage and cost), the cache
//! doctor's counters, and the policy's tripwire thresholds, which double as
//! the retry/loop boundary so the report and the enforcement agree on what a
//! loop is. Billable dollars and plan-absorbed reference dollars are kept
//! apart, exactly as the meter keeps them; the report never claims savings,
//! only what was identifiably wasted.

use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeMap;

use crate::audit::AuditEvent;
use crate::config;
use crate::stats::Window;

/// One request event that can participate in repeat grouping.
struct Req {
    ts_unix: i64,
    host: String,
    path: String,
    method: String,
    fp: String,
    cost_usd: f64,
    ref_cost_usd: f64,
    priced: bool,
}

/// One chain of repeats of a single fingerprint: the first send plus every
/// re-send that followed within the gap. Only the re-sends are waste.
#[derive(Debug, Serialize)]
pub struct Chain {
    pub fingerprint: String,
    pub host: String,
    pub path: String,
    pub method: String,
    /// Requests in the chain, the first send included.
    pub count: u64,
    /// Waste of the re-sends (everything after the first), split the way the
    /// meter splits it.
    pub wasted_usd: f64,
    pub wasted_ref_usd: f64,
    /// Re-sends whose responses carried no parseable usage: counted, never
    /// priced, and flagged rather than guessed at.
    pub unpriced: u64,
    /// Further repeats the spend tripwire denied (they cost nothing; the
    /// report notes them so the loop's true length is visible).
    pub blocked: u64,
    /// True when the chain reached the tripwire's repeat threshold.
    pub is_loop: bool,
}

/// Totals for one waste bucket (retries, or runaway loops).
#[derive(Debug, Default, Serialize)]
pub struct BucketTotals {
    pub chains: u64,
    pub wasted_requests: u64,
    pub wasted_usd: f64,
    pub wasted_ref_usd: f64,
    pub unpriced: u64,
}

impl BucketTotals {
    fn add(&mut self, c: &Chain) {
        self.chains += 1;
        self.wasted_requests += c.count - 1;
        self.wasted_usd += c.wasted_usd;
        self.wasted_ref_usd += c.wasted_ref_usd;
        self.unpriced += c.unpriced;
    }
}

#[derive(Debug, Serialize)]
pub struct WasteReport {
    pub schema: u32,
    pub window: String,
    /// The gap that makes a re-send a retry, and the count that makes a
    /// chain a loop; both read from the policy's `[spend_tripwire]` table.
    pub gap_secs: u64,
    pub loop_threshold: u32,
    /// Request events that carried a fingerprint (older events can't be
    /// grouped and are invisible here, not zero-cost).
    pub fingerprinted_requests: u64,
    pub retries: BucketTotals,
    pub loops: BucketTotals,
    /// Repeats the tripwire blocked across all chains.
    pub blocked_repeats: u64,
    /// The worst chains, costliest first.
    pub top: Vec<Chain>,
    /// Prompt-cache waste this billing period, from the cache doctor:
    /// repeating context that re-billed at the full input rate for want of a
    /// marker. Period-scoped (the doctor's state is), whatever the window.
    pub cache_repairable_usd: f64,
}

impl WasteReport {
    pub fn total_usd(&self) -> f64 {
        self.retries.wasted_usd + self.loops.wasted_usd + self.cache_repairable_usd
    }

    pub fn total_ref_usd(&self) -> f64 {
        self.retries.wasted_ref_usd + self.loops.wasted_ref_usd
    }
}

/// Build the report for `window`. Reads the audit log, the cache doctor's
/// state, and the policy; touches nothing else and never the network.
pub fn report(window: &Window) -> Result<WasteReport> {
    // An unreadable policy must not take the report down: the shipped
    // defaults stand in, same thresholds the tripwire itself defaults to.
    let trip_cfg = crate::policy::Policy::load_or_default()
        .map(|p| p.spend_tripwire)
        .unwrap_or_default();
    let gap_secs = trip_cfg.window_secs.max(1);
    let loop_threshold = if trip_cfg.repeats > 0 {
        trip_cfg.repeats
    } else {
        crate::policy::SpendTripwireConfig::default().repeats
    };

    let (from, to) = window.bounds(chrono::Local::now());
    let in_window = |ts: &str| {
        let hour = ts.get(..13).unwrap_or(ts);
        from.as_deref().map(|f| hour >= f).unwrap_or(true)
            && to.as_deref().map(|t| hour < t).unwrap_or(true)
    };

    // One pass over the log: fingerprinted request events, their deferred
    // usage (streamed responses cost later, linked by req_seq), and the
    // tripwire's denies per fingerprint.
    let mut reqs: Vec<Req> = Vec::new();
    let mut by_seq: BTreeMap<u64, usize> = BTreeMap::new();
    let mut blocked_by_fp: BTreeMap<String, u64> = BTreeMap::new();
    let path = config::audit_path()?;
    let text = if path.exists() {
        std::fs::read_to_string(&path)?
    } else {
        String::new()
    };
    for line in text.lines() {
        let Ok(ev) = serde_json::from_str::<AuditEvent>(line) else {
            continue;
        };
        if !in_window(&ev.ts) {
            continue;
        }
        match ev.action.as_str() {
            "allow" | "warn" => {
                let Some(fp) = ev.fp else { continue };
                let ts_unix = chrono::DateTime::parse_from_rfc3339(&ev.ts)
                    .map(|t| t.timestamp())
                    .unwrap_or(0);
                let (cost, ref_cost, priced) = match &ev.usage {
                    Some(u) => (u.cost_usd, u.ref_cost_usd, true),
                    None => (0.0, 0.0, false),
                };
                by_seq.insert(ev.seq, reqs.len());
                reqs.push(Req {
                    ts_unix,
                    host: ev.host,
                    path: ev.path,
                    method: ev.method,
                    fp,
                    cost_usd: cost,
                    ref_cost_usd: ref_cost,
                    priced,
                });
            }
            "usage" => {
                // A streamed response's costs arrive in a follow-up event,
                // linked to its request by req_seq.
                if let Some(seq) = ev.req_seq {
                    if let (Some(&i), Some(u)) = (by_seq.get(&seq), ev.usage) {
                        reqs[i].cost_usd += u.cost_usd;
                        reqs[i].ref_cost_usd += u.ref_cost_usd;
                        reqs[i].priced = true;
                    }
                }
            }
            "deny" => {
                if let Some(fp) = ev.fp {
                    if ev.note.starts_with("spend tripwire") {
                        *blocked_by_fp.entry(fp).or_default() += 1;
                    }
                }
            }
            _ => {}
        }
    }

    // Group by fingerprint (the log is append-ordered, so each group is in
    // time order) and split into gap-bounded chains.
    let fingerprinted_requests = reqs.len() as u64;
    let mut by_fp: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, r) in reqs.iter().enumerate() {
        by_fp.entry(r.fp.clone()).or_default().push(i);
    }

    let mut retries = BucketTotals::default();
    let mut loops = BucketTotals::default();
    let mut blocked_repeats = 0u64;
    let mut chains: Vec<Chain> = Vec::new();
    for (fp, idxs) in &by_fp {
        let mut start = 0usize;
        while start < idxs.len() {
            let mut end = start;
            while end + 1 < idxs.len()
                && reqs[idxs[end + 1]].ts_unix - reqs[idxs[end]].ts_unix <= gap_secs as i64
            {
                end += 1;
            }
            if end > start {
                let members = &idxs[start..=end];
                let first = &reqs[members[0]];
                // The tripwire's denies attach to the fingerprint's last
                // chain: the one that tripped it.
                let blocked = if end == idxs.len() - 1 {
                    blocked_by_fp.get(fp).copied().unwrap_or(0)
                } else {
                    0
                };
                let mut chain = Chain {
                    fingerprint: fp.clone(),
                    host: first.host.clone(),
                    path: first.path.clone(),
                    method: first.method.clone(),
                    count: members.len() as u64,
                    wasted_usd: 0.0,
                    wasted_ref_usd: 0.0,
                    unpriced: 0,
                    blocked,
                    is_loop: members.len() as u64 + blocked >= loop_threshold as u64,
                };
                for &i in &members[1..] {
                    chain.wasted_usd += reqs[i].cost_usd;
                    chain.wasted_ref_usd += reqs[i].ref_cost_usd;
                    if !reqs[i].priced {
                        chain.unpriced += 1;
                    }
                }
                if chain.is_loop {
                    loops.add(&chain);
                } else {
                    retries.add(&chain);
                }
                blocked_repeats += chain.blocked;
                chains.push(chain);
            }
            start = end + 1;
        }
    }
    chains.sort_by(|a, b| {
        (b.wasted_usd + b.wasted_ref_usd)
            .partial_cmp(&(a.wasted_usd + a.wasted_ref_usd))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.count.cmp(&a.count))
            .then(a.fingerprint.cmp(&b.fingerprint))
    });
    chains.truncate(5);

    Ok(WasteReport {
        schema: 1,
        window: window.kind().to_string(),
        gap_secs,
        loop_threshold,
        fingerprinted_requests,
        retries,
        loops,
        blocked_repeats,
        top: chains,
        cache_repairable_usd: cache_repairable_usd().unwrap_or(0.0),
    })
}

/// Prompt-cache waste this period, priced the way `decoyrail cache` prices
/// it: the doctor's repairable prefix bytes at the input-rate/cache-rate
/// spread, summed across host+model keys.
fn cache_repairable_usd() -> Result<f64> {
    let period = crate::util::current_period();
    let mut stats = crate::cache::CacheStats::load()?;
    if stats.period != period {
        stats.per_key.clear();
    }
    let pricing = crate::pricing::Pricing::load()?;
    let mut total = 0.0;
    for (key, s) in &stats.per_key {
        if s.repairable_bytes == 0 {
            continue;
        }
        let Some((host, model)) = key.split_once(' ') else {
            continue;
        };
        if let Some(p) = pricing.provider_for_host(host) {
            let rate = pricing.rate_for(p, Some(model));
            total += crate::cache::repairable_waste_usd(s.repairable_bytes, &rate);
        }
    }
    Ok(total)
}

/// Render the report as terminal text.
pub fn render(r: &WasteReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "Waste report: {}", r.window);
    if r.fingerprinted_requests == 0 {
        let _ = writeln!(
            out,
            "No fingerprinted LLM requests in this window (events written \
             before the spend tripwire shipped carry no fingerprint)."
        );
    }

    let bucket = |out: &mut String, name: &str, b: &BucketTotals| {
        if b.chains == 0 {
            return;
        }
        let mut line = format!(
            "{name}: ${:.4} wasted across {} re-sent request(s) in {} chain(s)",
            b.wasted_usd, b.wasted_requests, b.chains
        );
        if b.wasted_ref_usd > 0.0 {
            line.push_str(&format!(
                " (+ ~${:.4} plan-absorbed API-equivalent)",
                b.wasted_ref_usd
            ));
        }
        if b.unpriced > 0 {
            line.push_str(&format!(
                "; {} re-send(s) carried no parseable usage and are counted unpriced",
                b.unpriced
            ));
        }
        let _ = writeln!(out, "{line}");
    };
    bucket(
        &mut out,
        &format!(
            "Retried identical requests (re-sent within {}s)",
            r.gap_secs
        ),
        &r.retries,
    );
    bucket(
        &mut out,
        &format!("Runaway loops ({}+ repeats)", r.loop_threshold),
        &r.loops,
    );
    if r.blocked_repeats > 0 {
        let _ = writeln!(
            out,
            "The spend tripwire blocked {} further repeat(s); those cost nothing.",
            r.blocked_repeats
        );
    }
    if !r.top.is_empty() {
        let _ = writeln!(out, "Worst offenders:");
        for c in &r.top {
            let mut line = format!("  {} {}{}  {}x", c.method, c.host, c.path, c.count);
            if c.blocked > 0 {
                line.push_str(&format!(" (+{} blocked)", c.blocked));
            }
            line.push_str(&format!(
                "  ${:.4} wasted  (fingerprint {})",
                c.wasted_usd + c.wasted_ref_usd,
                c.fingerprint
            ));
            let _ = writeln!(out, "{line}");
        }
    }
    if r.cache_repairable_usd > 0.0 {
        let _ = writeln!(
            out,
            "Prompt-cache waste (this billing period): ~${:.4} of repeating \
             context re-billed at the full input rate for want of a cache \
             marker; `decoyrail cache` has the per-model breakdown.",
            r.cache_repairable_usd
        );
    }
    let total = r.total_usd();
    if total > 0.0 || r.total_ref_usd() > 0.0 {
        let mut line = format!("Identified waste: ${total:.4}");
        if r.total_ref_usd() > 0.0 {
            line.push_str(&format!(
                " (+ ~${:.4} plan-absorbed API-equivalent)",
                r.total_ref_usd()
            ));
        }
        let _ = writeln!(out, "{line}");
    } else {
        let _ = writeln!(out, "No identifiable waste in this window.");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Auditor, Entry, UsageRec};

    fn usage(cost: f64, ref_cost: f64) -> UsageRec {
        UsageRec {
            model: "claude-sonnet-5".into(),
            input: 100,
            output: 50,
            cache_read: 0,
            cache_write: 0,
            cost_usd: cost,
            ref_cost_usd: ref_cost,
        }
    }

    fn request(fp: &str, u: Option<UsageRec>) -> Entry {
        Entry {
            host: "api.anthropic.com".into(),
            path: "/v1/messages".into(),
            method: "POST".into(),
            action: "allow".into(),
            rule: "anthropic".into(),
            fp: Some(fp.into()),
            usage: u,
            ..Default::default()
        }
    }

    fn ts(offset_secs: u64) -> String {
        format!(
            "2026-07-10T10:{:02}:{:02}.000Z",
            offset_secs / 60,
            offset_secs % 60
        )
    }

    #[test]
    fn repeats_group_price_and_split_into_buckets() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());
        // A tight loop threshold so the fixture stays small.
        crate::policy_edit::write_policy(
            "default_action = \"deny\"\n[spend_tripwire]\nrepeats = 3\nwindow_secs = 300\n",
            "test",
        )
        .unwrap();

        let fp_retry = "aaaaaaaaaaaaaaaa";
        let fp_loop = "bbbbbbbbbbbbbbbb";
        let fp_stream = "cccccccccccccccc";
        let mut a = Auditor::open().unwrap();
        // A retry pair: the re-send is priced, one later isolated send is a
        // fresh chain start, not waste.
        a.append(request(fp_retry, Some(usage(0.01, 0.0))), ts(0))
            .unwrap();
        let second = a.append(request(fp_retry, None), ts(10)).unwrap();
        assert!(second.fp.is_some());
        a.append(request(fp_retry, Some(usage(0.04, 0.0))), ts(2400))
            .unwrap();
        // A loop of three, subscription-billed, plus a tripwire deny after.
        a.append(request(fp_loop, Some(usage(0.0, 0.02))), ts(20))
            .unwrap();
        a.append(request(fp_loop, Some(usage(0.0, 0.02))), ts(30))
            .unwrap();
        a.append(request(fp_loop, Some(usage(0.0, 0.02))), ts(40))
            .unwrap();
        let mut deny = request(fp_loop, None);
        deny.action = "deny".into();
        deny.note = "spend tripwire: identical request repeated 3x in 300s".into();
        a.append(deny, ts(50)).unwrap();
        // A streamed pair: the re-send's cost arrives via a usage event.
        let streamed = a.append(request(fp_stream, None), ts(60)).unwrap();
        a.append(request(fp_stream, None), ts(70)).unwrap();
        let follow = a.append(request(fp_stream, None), ts(80)).unwrap();
        let mut u = Entry {
            action: "usage".into(),
            usage: Some(usage(0.08, 0.0)),
            req_seq: Some(follow.seq),
            ..Entry::note("usage", String::new())
        };
        u.action = "usage".into();
        a.append(u, ts(81)).unwrap();
        // The first streamed request's own usage event, linking nothing new.
        let _ = streamed;

        let r = report(&Window::All).unwrap();
        assert_eq!(r.gap_secs, 300);
        assert_eq!(r.loop_threshold, 3);
        assert_eq!(r.fingerprinted_requests, 9);

        // fp_retry: one chain of 2 (the third send came after the gap), one
        // unpriced re-send.
        assert_eq!(r.retries.chains, 1);
        assert_eq!(r.retries.wasted_requests, 1);
        assert_eq!(r.retries.unpriced, 1);
        assert!(r.retries.wasted_usd.abs() < 1e-9);

        // fp_loop reaches the threshold: a loop, priced at reference rates,
        // with the blocked repeat counted.
        // fp_stream's chain of 3 also crosses it, priced via the usage event.
        assert_eq!(r.loops.chains, 2);
        assert_eq!(r.blocked_repeats, 1);
        assert!((r.loops.wasted_ref_usd - 0.04).abs() < 1e-9);
        assert!((r.loops.wasted_usd - 0.08).abs() < 1e-9);

        // Worst offender first: the streamed loop wasted the most dollars.
        assert_eq!(r.top[0].fingerprint, fp_stream);
        assert!(r
            .top
            .iter()
            .any(|c| c.fingerprint == fp_loop && c.blocked == 1 && c.is_loop));

        let text = render(&r);
        assert!(text.contains("Runaway loops (3+ repeats)"), "{text}");
        assert!(text.contains("Retried identical requests"), "{text}");
        assert!(text.contains("blocked 1 further repeat"), "{text}");
        assert!(text.contains("counted unpriced"), "{text}");
        assert!(text.contains("Identified waste: $0.0800"), "{text}");
        assert!(text.contains("plan-absorbed API-equivalent"), "{text}");

        // A window that excludes everything reports the fingerprint gap
        // honestly instead of claiming zero waste from silence.
        let empty = report(&Window::Range {
            since: chrono::NaiveDate::from_ymd_opt(2020, 1, 1).unwrap(),
            until: chrono::NaiveDate::from_ymd_opt(2020, 1, 2).unwrap(),
        })
        .unwrap();
        assert_eq!(empty.fingerprinted_requests, 0);
        let text = render(&empty);
        assert!(text.contains("No fingerprinted LLM requests"), "{text}");
        assert!(text.contains("No identifiable waste"), "{text}");

        std::env::remove_var("DECOYRAIL_HOME");
    }

    #[test]
    fn zero_repeats_policy_falls_back_to_the_default_loop_threshold() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());
        crate::policy_edit::write_policy(
            "default_action = \"deny\"\n[spend_tripwire]\nrepeats = 0\n",
            "test",
        )
        .unwrap();
        let r = report(&Window::All).unwrap();
        assert_eq!(r.loop_threshold, 15);
        std::env::remove_var("DECOYRAIL_HOME");
    }

    #[test]
    fn cache_doctor_waste_folds_into_the_total() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());
        crate::config::ensure_home().unwrap();

        let key_stats = r#"{"requests": 8, "marked": 0, "preserved": 6, "ttl_gaps": 0,
            "resets": 1, "diverged": 0, "below_min": 0,
            "repairable": 6, "repairable_bytes": 4000000, "repaired": 0}"#;
        std::fs::write(
            crate::config::cache_path().unwrap(),
            format!(
                r#"{{"period": "{}", "per_key": {{"api.anthropic.com claude-sonnet-5": {key_stats}}}}}"#,
                crate::util::current_period()
            ),
        )
        .unwrap();

        let r = report(&Window::All).unwrap();
        assert!(r.cache_repairable_usd > 0.0, "repairable bytes must price");
        assert!((r.total_usd() - r.cache_repairable_usd).abs() < 1e-9);
        let text = render(&r);
        assert!(text.contains("Prompt-cache waste"), "{text}");

        // A stale period prices nothing: last month's hygiene is not this
        // window's waste.
        std::fs::write(
            crate::config::cache_path().unwrap(),
            format!(r#"{{"period": "1999-01", "per_key": {{"api.anthropic.com claude-sonnet-5": {key_stats}}}}}"#),
        )
        .unwrap();
        let r = report(&Window::All).unwrap();
        assert_eq!(r.cache_repairable_usd, 0.0);

        std::env::remove_var("DECOYRAIL_HOME");
    }
}
