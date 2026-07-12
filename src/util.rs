//! Small shared helpers.

/// Current UTC time as an RFC-3339 string, for audit timestamps.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Current billing period as `YYYY-MM`, for the meter.
pub fn current_period() -> String {
    chrono::Utc::now().format("%Y-%m").to_string()
}

/// Current Unix time in seconds, for gap measurements that must compare
/// across processes (in-process monotonic clocks don't).
pub fn now_unix() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

/// Serializes tests that mutate the process-global `DECOYRAIL_HOME` env var so
/// they don't clobber each other's temp dirs under the parallel test runner.
#[cfg(test)]
pub fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}
