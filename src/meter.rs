//! Spend metering, per-seat budgets, and a kill switch.
//!
//! Two kinds of cost accrue per destination. LLM requests whose responses
//! carry provider `usage` fields are metered exactly: token counts per model
//! (see `pricing`), priced per model, and costed at zero when the request
//! rode a flat-rate subscription instead of usage credits. Everything else
//! falls back to a coarse byte-derived estimate from a per-provider blended
//! rate, kept deliberately and labeled as such. The monthly budget kill
//! switch trips on the sum of both.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::SystemTime;

use crate::config;

/// Exact, provider-reported token counts for one model at one host. The map
/// key carries the billing mode (`pricing::model_key`), so plan-covered
/// traffic never blends into a pay-per-token row; `cost_usd` is what was
/// actually billed (zero for subscription traffic).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelUsage {
    pub requests: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub cost_usd: f64,
    /// API-equivalent reference cost of subscription traffic: what these
    /// tokens would have billed at API rates (plan 019). Never summed into
    /// `cost_usd` or the budget; zero for usage-billed rows.
    #[serde(default)]
    pub ref_cost_usd: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostUsage {
    pub requests: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    /// Byte-derived estimate, only for traffic whose usage couldn't be
    /// parsed. Metered cost lives in `models`.
    pub est_cost_usd: f64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub models: BTreeMap<String, ModelUsage>,
}

impl HostUsage {
    /// Exactly-metered spend at this host (excludes the byte estimate).
    pub fn metered_cost_usd(&self) -> f64 {
        self.models.values().map(|m| m.cost_usd).sum()
    }

    pub fn cost_usd(&self) -> f64 {
        self.est_cost_usd + self.metered_cost_usd()
    }

    /// API-equivalent dollars the plan absorbed at this host (plan 019).
    pub fn ref_cost_usd(&self) -> f64 {
        self.models.values().map(|m| m.ref_cost_usd).sum()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meter {
    /// Billing period this state covers, `YYYY-MM`. Reset when it rolls over.
    pub period: String,
    /// 0.0 means unlimited (no budget enforced). Persisted in its own file
    /// (budget.json), not meter.json, so the proxy's per-request usage writes
    /// can't overwrite a budget the user set while the proxy was running.
    #[serde(skip)]
    pub budget_usd: f64,
    pub per_host: BTreeMap<String, HostUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BudgetFile {
    budget_usd: f64,
}

impl Default for Meter {
    fn default() -> Self {
        Meter {
            period: String::new(),
            budget_usd: 0.0,
            per_host: BTreeMap::new(),
        }
    }
}

/// Blended $/million-token estimate per provider host: the fallback when a
/// response carried no parseable usage. Rough, but enough to keep the budget
/// guardrail honest for the traffic exact metering can't see.
fn blended_rate_per_mtok(host: &str) -> f64 {
    match host {
        "api.anthropic.com" => 9.0,
        "api.openai.com" => 6.0,
        _ => 0.0, // non-LLM egress costs nothing to meter
    }
}

impl Meter {
    pub fn load() -> Result<Self> {
        let mut meter = Self::load_usage()?;
        meter.budget_usd = load_budget()?;
        Ok(meter)
    }

    /// Read persisted usage only (no budget), for callers that merge or
    /// display usage without caring about enforcement.
    fn load_usage() -> Result<Self> {
        config::ensure_home()?;
        let path = config::meter_path()?;
        Ok(if path.exists() {
            let text = std::fs::read_to_string(&path)?;
            serde_json::from_str(&text).unwrap_or_default()
        } else {
            Meter::default()
        })
    }

    /// Persist usage only (atomically). Budget is written separately via
    /// `save_budget`, so a running proxy's usage writes never clobber it.
    pub fn save(&self) -> Result<()> {
        config::ensure_home()?;
        config::atomic_write(
            &config::meter_path()?,
            serde_json::to_string_pretty(self)?.as_bytes(),
        )
    }

    /// Roll the period if `now_period` (YYYY-MM) differs, zeroing usage.
    pub fn roll_period(&mut self, now_period: &str) {
        if self.period != now_period {
            self.period = now_period.to_string();
            self.per_host.clear();
        }
    }

    pub fn total_cost(&self) -> f64 {
        self.per_host.values().map(|u| u.cost_usd()).sum()
    }

    /// Spend metered exactly from provider-reported token counts.
    pub fn metered_cost(&self) -> f64 {
        self.per_host.values().map(|u| u.metered_cost_usd()).sum()
    }

    /// Spend estimated from byte volume (usage fields unavailable).
    pub fn estimated_cost(&self) -> f64 {
        self.per_host.values().map(|u| u.est_cost_usd).sum()
    }

    /// API-equivalent dollars absorbed by flat-rate plans this period: the
    /// reference cost of subscription traffic (plan 019). Reported alongside
    /// spend, never added to it; the budget never sees this figure.
    pub fn plan_absorbed(&self) -> f64 {
        self.per_host.values().map(|u| u.ref_cost_usd()).sum()
    }

    /// Budget is enforced only when set (> 0).
    pub fn over_budget(&self) -> bool {
        self.budget_usd > 0.0 && self.total_cost() >= self.budget_usd
    }

    /// Count one forwarded request's traffic, with no cost attached yet: the
    /// cost lands later as either exact tokens (`record_tokens`) or a byte
    /// estimate (`add_estimated`), once the response has been seen.
    pub fn record_traffic(&mut self, host: &str, bytes_up: u64, bytes_down: u64) {
        let entry = self.per_host.entry(host.to_string()).or_default();
        entry.requests += 1;
        entry.bytes_up += bytes_up;
        entry.bytes_down += bytes_down;
    }

    /// Record one completed request, costed by the byte estimate. Convenience
    /// for `record_traffic` + `add_estimated` where no usage will follow.
    pub fn record(&mut self, host: &str, bytes_up: u64, bytes_down: u64) {
        self.record_traffic(host, bytes_up, bytes_down);
        self.add_estimated(host, bytes_up + bytes_down);
    }

    /// Fold in the byte-derived cost estimate for `bytes` of traffic — the
    /// fallback when a response carried no parseable usage. Zero for hosts
    /// with no blended rate, so non-LLM egress stays free to meter.
    pub fn add_estimated(&mut self, host: &str, bytes: u64) {
        let entry = self.per_host.entry(host.to_string()).or_default();
        entry.est_cost_usd += cost_of(host, bytes);
    }

    /// Record exact provider-reported tokens for one request under
    /// `model_key` (see `pricing::model_key`). `cost_usd` is what the tokens
    /// actually cost (zero when subscription-billed); `ref_cost_usd` is the
    /// API-equivalent reference for subscription traffic (zero when billed).
    /// `pricing::split_cost` produces the pair.
    pub fn record_tokens(
        &mut self,
        host: &str,
        model_key: &str,
        usage: &crate::pricing::TokenUsage,
        cost_usd: f64,
        ref_cost_usd: f64,
    ) {
        let entry = self.per_host.entry(host.to_string()).or_default();
        let m = entry.models.entry(model_key.to_string()).or_default();
        m.requests += 1;
        m.input_tokens += usage.input;
        m.output_tokens += usage.output;
        m.cache_read_tokens += usage.cache_read;
        m.cache_write_tokens += usage.cache_write;
        m.cost_usd += cost_usd;
        m.ref_cost_usd += ref_cost_usd;
    }

    /// Add downstream bytes to an already-counted request, with no cost.
    /// Used when the response is streamed (SSE, or a body too large to
    /// buffer): traffic is counted when forwarding, the response size folds
    /// in as the stream drains, and cost follows separately.
    pub fn add_downstream_bytes(&mut self, host: &str, bytes_down: u64) {
        if bytes_down == 0 {
            return;
        }
        let entry = self.per_host.entry(host.to_string()).or_default();
        entry.bytes_down += bytes_down;
    }
}

/// Coarse USD estimate for `bytes` of traffic to `host` (~4 bytes/token).
fn cost_of(host: &str, bytes: u64) -> f64 {
    let est_tokens = bytes as f64 / 4.0;
    est_tokens / 1_000_000.0 * blended_rate_per_mtok(host)
}

/// Read the persisted budget (0.0 = unlimited) from budget.json.
pub fn load_budget() -> Result<f64> {
    let path = config::budget_path()?;
    if !path.exists() {
        return Ok(0.0);
    }
    let text = std::fs::read_to_string(&path)?;
    let bf: BudgetFile = serde_json::from_str(&text).unwrap_or_default();
    Ok(bf.budget_usd)
}

/// A running proxy's view of the meter. Usage recorded locally accrues in a
/// delta; `flush` merges the delta into meter.json under an exclusive OS file
/// lock. Concurrent decoyrail sessions (two `decoyrail run`s, or `run` + `proxy`)
/// therefore add up on disk, where a plain rewrite of in-memory state would
/// leave the file at whichever session saved last, undercounting global spend
/// and reducing the budget kill switch to per-session enforcement.
pub struct SessionMeter {
    /// Usage recorded by this process since the last successful flush.
    delta: Meter,
    /// Global cost across all sessions as of the last flush/reload.
    merged_cost: f64,
    /// Period the merged cost belongs to; a rollover zeroes it.
    merged_period: String,
    /// meter.json mtime backing `merged_cost`, so `Engine::refresh` reloads
    /// only when another process wrote the file since we last read or wrote it.
    seen_mtime: Option<SystemTime>,
    /// From budget.json (0.0 = unlimited); hot-reloaded by `Engine::refresh`.
    pub budget_usd: f64,
}

impl SessionMeter {
    pub fn load() -> Result<Self> {
        let merged = Meter::load()?;
        let seen_mtime = config::mtime(&config::meter_path()?);
        Ok(SessionMeter {
            budget_usd: merged.budget_usd,
            merged_cost: merged.total_cost(),
            merged_period: merged.period.clone(),
            seen_mtime,
            delta: Meter::default(),
        })
    }

    /// Roll both the local delta and the merged view to `now_period`, so spend
    /// from a previous month neither survives into this one nor keeps the
    /// kill switch tripped after the budget resets.
    fn roll(&mut self, now_period: &str) {
        self.delta.roll_period(now_period);
        if self.merged_period != now_period {
            self.merged_period = now_period.to_string();
            self.merged_cost = 0.0;
        }
    }

    pub fn record(&mut self, now_period: &str, host: &str, bytes_up: u64, bytes_down: u64) {
        self.roll(now_period);
        self.delta.record(host, bytes_up, bytes_down);
    }

    pub fn record_traffic(&mut self, now_period: &str, host: &str, bytes_up: u64, bytes_down: u64) {
        self.roll(now_period);
        self.delta.record_traffic(host, bytes_up, bytes_down);
    }

    pub fn add_estimated(&mut self, now_period: &str, host: &str, bytes: u64) {
        self.roll(now_period);
        self.delta.add_estimated(host, bytes);
    }

    pub fn record_tokens(
        &mut self,
        now_period: &str,
        host: &str,
        model_key: &str,
        usage: &crate::pricing::TokenUsage,
        cost_usd: f64,
        ref_cost_usd: f64,
    ) {
        self.roll(now_period);
        self.delta
            .record_tokens(host, model_key, usage, cost_usd, ref_cost_usd);
    }

    pub fn add_downstream_bytes(&mut self, now_period: &str, host: &str, bytes_down: u64) {
        self.roll(now_period);
        self.delta.add_downstream_bytes(host, bytes_down);
    }

    /// The kill switch is global: last-merged cost from all sessions plus the
    /// local delta not yet flushed.
    pub fn over_budget(&mut self, now_period: &str) -> bool {
        self.roll(now_period);
        self.budget_usd > 0.0 && self.merged_cost + self.delta.total_cost() >= self.budget_usd
    }

    /// True if meter.json changed on disk since we last read or wrote it,
    /// i.e. another decoyrail process flushed usage.
    pub fn stale(&self, disk_mtime: Option<SystemTime>) -> bool {
        disk_mtime != self.seen_mtime
    }

    /// Re-read the merged global usage after another session's flush.
    /// `disk_mtime` is the stat that detected the change (see `stale`).
    pub fn reload_merged(&mut self, disk_mtime: Option<SystemTime>) {
        if let Ok(disk) = Meter::load_usage() {
            self.merged_cost = disk.total_cost();
            self.merged_period = disk.period.clone();
            self.seen_mtime = disk_mtime;
        }
    }

    /// Merge the local delta into meter.json and clear it. The read-merge-write
    /// runs under an exclusive lock on a side file (see `meter_lock_path`), so
    /// concurrent sessions serialize and none loses the others' usage.
    pub fn flush(&mut self, now_period: &str) -> Result<()> {
        self.roll(now_period);
        config::ensure_home()?;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(config::meter_lock_path()?)
            .context("opening meter lock file")?;
        fs2::FileExt::lock_exclusive(&lock).context("locking meter")?;
        // The lock releases when `lock` closes on return, including `?` exits.

        let mut disk = Meter::load_usage()?;
        disk.roll_period(now_period);
        for (host, u) in &self.delta.per_host {
            let entry = disk.per_host.entry(host.clone()).or_default();
            entry.requests += u.requests;
            entry.bytes_up += u.bytes_up;
            entry.bytes_down += u.bytes_down;
            entry.est_cost_usd += u.est_cost_usd;
            for (model, mu) in &u.models {
                let m = entry.models.entry(model.clone()).or_default();
                m.requests += mu.requests;
                m.input_tokens += mu.input_tokens;
                m.output_tokens += mu.output_tokens;
                m.cache_read_tokens += mu.cache_read_tokens;
                m.cache_write_tokens += mu.cache_write_tokens;
                m.cost_usd += mu.cost_usd;
                m.ref_cost_usd += mu.ref_cost_usd;
            }
        }
        disk.save()?;

        self.merged_cost = disk.total_cost();
        self.merged_period = disk.period.clone();
        // Stat under the lock: nobody can write between our save and here.
        self.seen_mtime = config::mtime(&config::meter_path()?);
        self.delta.per_host.clear();
        Ok(())
    }
}

/// Atomically persist the budget to budget.json.
pub fn save_budget(budget_usd: f64) -> Result<()> {
    config::ensure_home()?;
    let bf = BudgetFile { budget_usd };
    config::atomic_write(
        &config::budget_path()?,
        serde_json::to_string_pretty(&bf)?.as_bytes(),
    )
}

/// A user-declared flat plan price (plan 019): what the subscription costs
/// per month, so plan-absorbed totals can be read against it. Purely local
/// and purely informational; nothing enforces on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanPrice {
    pub usd: f64,
    #[serde(default)]
    pub label: String,
}

impl PlanPrice {
    fn name(&self) -> &str {
        if self.label.is_empty() {
            "plan"
        } else {
            &self.label
        }
    }
}

/// Read the declared plan price, if any. A missing or malformed file means
/// none declared: totals render without a verdict.
pub fn load_plan_price() -> Result<Option<PlanPrice>> {
    let path = config::plan_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&text).ok())
}

pub fn save_plan_price(price: &PlanPrice) -> Result<()> {
    config::ensure_home()?;
    config::atomic_write(
        &config::plan_path()?,
        serde_json::to_string_pretty(price)?.as_bytes(),
    )
}

pub fn clear_plan_price() -> Result<()> {
    let path = config::plan_path()?;
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

/// One sentence reading this period's plan-absorbed total against the
/// declared plan price. The figures speak for themselves: no upgrade or
/// downgrade advice, and the absorbed number is framed as a reference
/// (API-equivalent), never as savings owed to Decoyrail.
pub fn plan_verdict(price: &PlanPrice, absorbed_usd: f64) -> String {
    let name = price.name();
    if absorbed_usd <= 0.0 {
        return format!(
            "{name} (${:.2}/mo): no plan-covered traffic this period, so it absorbed nothing.",
            price.usd
        );
    }
    if absorbed_usd >= price.usd {
        format!(
            "{name} (${:.2}/mo): absorbed ~${absorbed_usd:.2} of API-equivalent usage this \
             period; the plan absorbed more than it costs.",
            price.usd
        )
    } else {
        format!(
            "{name} (${:.2}/mo): absorbed ~${absorbed_usd:.2} of API-equivalent usage this \
             period; ${:.2} of headroom went unused.",
            price.usd,
            price.usd - absorbed_usd
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_kill_switch_trips() {
        let mut m = Meter {
            period: "2026-07".into(),
            budget_usd: 0.01,
            per_host: BTreeMap::new(),
        };
        assert!(!m.over_budget());
        // Push a large amount of Anthropic traffic through.
        m.record("api.anthropic.com", 5_000_000, 5_000_000);
        assert!(m.total_cost() > 0.0);
        assert!(m.over_budget());
    }

    #[test]
    fn period_rollover_resets() {
        let mut m = Meter::default();
        m.roll_period("2026-07");
        m.record("api.openai.com", 1000, 1000);
        assert_eq!(m.per_host.len(), 1);
        m.roll_period("2026-08");
        assert!(m.per_host.is_empty());
        assert_eq!(m.period, "2026-08");
    }

    #[test]
    fn zero_budget_means_unlimited() {
        let mut m = Meter::default();
        m.record("api.anthropic.com", 100_000_000, 100_000_000);
        assert!(!m.over_budget());
    }

    #[test]
    fn concurrent_sessions_merge_instead_of_clobbering() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        // Two sessions boot from the same (empty) meter, then each flushes its
        // own usage. Before delta-merging, B's flush would erase A's.
        let mut a = SessionMeter::load().unwrap();
        let mut b = SessionMeter::load().unwrap();
        a.record("2026-07", "api.anthropic.com", 1000, 1000);
        a.flush("2026-07").unwrap();
        b.record("2026-07", "api.anthropic.com", 500, 500);
        b.record("2026-07", "api.openai.com", 200, 200);
        b.flush("2026-07").unwrap();

        let disk = Meter::load().unwrap();
        let anthropic = &disk.per_host["api.anthropic.com"];
        assert_eq!(anthropic.requests, 2);
        assert_eq!(anthropic.bytes_up, 1500);
        assert_eq!(anthropic.bytes_down, 1500);
        assert_eq!(disk.per_host["api.openai.com"].requests, 1);
    }

    #[test]
    fn parallel_flushes_lose_nothing() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        // Four "sessions" racing read-merge-write cycles; the file lock must
        // serialize them so every recorded request survives.
        let threads: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    let mut s = SessionMeter::load().unwrap();
                    for _ in 0..25 {
                        s.record("2026-07", "api.anthropic.com", 10, 10);
                        s.flush("2026-07").unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }

        let disk = Meter::load().unwrap();
        let u = &disk.per_host["api.anthropic.com"];
        assert_eq!(u.requests, 100);
        assert_eq!(u.bytes_up, 1000);
        assert_eq!(u.bytes_down, 1000);
    }

    #[test]
    fn token_usage_merges_across_sessions_and_prices_subscription_at_zero() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        let usage = crate::pricing::TokenUsage {
            input: 1000,
            output: 200,
            cache_read: 5000,
            cache_write: 100,
        };
        let mut a = SessionMeter::load().unwrap();
        let mut b = SessionMeter::load().unwrap();
        a.record_traffic("2026-07", "api.anthropic.com", 900, 4000);
        a.record_tokens(
            "2026-07",
            "api.anthropic.com",
            "claude-sonnet-5",
            &usage,
            0.0075,
            0.0,
        );
        a.flush("2026-07").unwrap();
        b.record_traffic("2026-07", "api.anthropic.com", 900, 4000);
        b.record_tokens(
            "2026-07",
            "api.anthropic.com",
            "claude-sonnet-5 [subscription]",
            &usage,
            0.0,
            0.0075,
        );
        b.record_tokens(
            "2026-07",
            "api.anthropic.com",
            "claude-sonnet-5",
            &usage,
            0.0075,
            0.0,
        );
        b.flush("2026-07").unwrap();

        let disk = Meter::load().unwrap();
        let host = &disk.per_host["api.anthropic.com"];
        assert_eq!(host.requests, 2);
        let billed = &host.models["claude-sonnet-5"];
        assert_eq!(billed.requests, 2);
        assert_eq!(billed.input_tokens, 2000);
        assert_eq!(billed.cache_read_tokens, 10000);
        assert_eq!(billed.ref_cost_usd, 0.0);
        let sub = &host.models["claude-sonnet-5 [subscription]"];
        assert_eq!(sub.input_tokens, 1000);
        assert_eq!(sub.cost_usd, 0.0);
        // The subscription row's reference cost survives the flush merge and
        // rolls up as plan-absorbed, never into spend.
        assert!((sub.ref_cost_usd - 0.0075).abs() < 1e-9);
        assert!((disk.plan_absorbed() - 0.0075).abs() < 1e-9);
        // Total = billed cost only; subscription tokens cost nothing, and
        // no byte estimate accrued because usage was parsed.
        assert!((disk.total_cost() - 0.015).abs() < 1e-9);
        assert!((disk.metered_cost() - 0.015).abs() < 1e-9);
        assert_eq!(disk.estimated_cost(), 0.0);
    }

    #[test]
    fn budget_kill_switch_sees_other_sessions_after_reload() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());
        save_budget(0.01).unwrap();

        let mut a = SessionMeter::load().unwrap();
        let mut b = SessionMeter::load().unwrap();
        a.record("2026-07", "api.anthropic.com", 5_000_000, 5_000_000);
        assert!(a.over_budget("2026-07"));
        a.flush("2026-07").unwrap();

        // B is idle so its own view is under budget; the mtime change from
        // A's flush is what `Engine::refresh` uses to fold A's spend in.
        assert!(!b.over_budget("2026-07"));
        let mtime = config::mtime(&config::meter_path().unwrap());
        assert!(b.stale(mtime));
        b.reload_merged(mtime);
        assert!(!b.stale(mtime));
        assert!(b.over_budget("2026-07"));
    }

    #[test]
    fn flush_rolls_stale_period_on_disk() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        let mut a = SessionMeter::load().unwrap();
        a.record("2026-06", "api.anthropic.com", 1000, 1000);
        a.flush("2026-06").unwrap();

        let mut b = SessionMeter::load().unwrap();
        b.record("2026-07", "api.openai.com", 400, 400);
        b.flush("2026-07").unwrap();

        let disk = Meter::load().unwrap();
        assert_eq!(disk.period, "2026-07");
        assert!(!disk.per_host.contains_key("api.anthropic.com"));
        assert_eq!(disk.per_host["api.openai.com"].requests, 1);
    }

    #[test]
    fn plan_price_round_trips_and_clears() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        assert!(load_plan_price().unwrap().is_none());
        // Clearing with nothing declared is a quiet no-op, not an error.
        clear_plan_price().unwrap();
        save_plan_price(&PlanPrice {
            usd: 200.0,
            label: "Claude Max".into(),
        })
        .unwrap();
        let p = load_plan_price().unwrap().expect("saved plan price");
        assert_eq!(p.usd, 200.0);
        assert_eq!(p.label, "Claude Max");
        clear_plan_price().unwrap();
        assert!(load_plan_price().unwrap().is_none());
    }

    #[test]
    fn plan_verdict_states_the_three_cases() {
        let price = PlanPrice {
            usd: 200.0,
            label: "Claude Max".into(),
        };
        // Absorbed more than it costs: the plan is paying for itself.
        let v = plan_verdict(&price, 340.0);
        assert!(v.contains("$340.00"), "{v}");
        assert!(v.contains("absorbed more than it costs"), "{v}");
        // Absorbed much less: headroom went unused, stated without scolding.
        let v = plan_verdict(&price, 60.0);
        assert!(v.contains("$60.00"), "{v}");
        assert!(v.contains("$140.00 of headroom went unused"), "{v}");
        // No plan traffic in the window: no division error, plain statement.
        let v = plan_verdict(&price, 0.0);
        assert!(v.contains("absorbed nothing"), "{v}");
        // An unlabeled plan reads as just "plan".
        let v = plan_verdict(
            &PlanPrice {
                usd: 100.0,
                label: String::new(),
            },
            50.0,
        );
        assert!(v.starts_with("plan ("), "{v}");
    }

    #[test]
    fn over_budget_clears_on_period_rollover() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());
        save_budget(0.01).unwrap();

        let mut m = SessionMeter::load().unwrap();
        m.record("2026-06", "api.anthropic.com", 5_000_000, 5_000_000);
        m.flush("2026-06").unwrap();
        assert!(m.over_budget("2026-06"));
        // New month, fresh budget: the switch must not stay latched on last
        // month's spend (which previously required a restart to clear).
        assert!(!m.over_budget("2026-07"));
    }
}
