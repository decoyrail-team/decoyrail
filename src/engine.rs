//! Shared runtime state for the proxy: CA, vault, policy, meter, auditor.

use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::{Mutex, RwLock};

use crate::audit::Auditor;
use crate::ca::CertAuthority;
use crate::config;
use crate::license::{self, LicenseDoc, Tier};
use crate::meter::SessionMeter;
use crate::policy::Policy;
use crate::pricing::Pricing;
use crate::vault::Vault;

/// mtimes last seen for the hot-reloadable files, so `refresh` only reloads on
/// an actual change.
struct ReloadState {
    vault: Option<SystemTime>,
    policy: Option<SystemTime>,
    /// The policy integrity record's mtime, watched as a pair with the
    /// policy's own: deleting or rewriting the record alone (the file
    /// untouched) must re-verify and trip the tamper alarm, and a blessing
    /// (`policy sign` touches only the record) must load the blessed file.
    policy_sig: Option<SystemTime>,
    budget: Option<SystemTime>,
    pricing: Option<SystemTime>,
    license: Option<SystemTime>,
    /// Effective tier as of the last refresh, so crossings (a reload, or an
    /// expiry the clock walked past with no file change) audit exactly once.
    tier: Tier,
}

#[derive(Clone)]
pub struct Engine {
    pub ca: Arc<CertAuthority>,
    pub vault: Arc<RwLock<Vault>>,
    /// Session-scoped secrets (auto-decoyed terminal env) set by
    /// `decoyrail run` before serving. Kept apart from `vault` on purpose:
    /// `refresh` replaces the vault wholesale on a vault.json change, which
    /// would silently drop merged-in session entries. Never persisted.
    pub session: Arc<Vault>,
    pub policy: Arc<RwLock<Policy>>,
    pub meter: Arc<Mutex<SessionMeter>>,
    /// Per-model token rates and provider/billing mappings for exact spend
    /// metering; built-ins overlaid with `pricing.json`, hot-reloaded.
    pub pricing: Arc<RwLock<Pricing>>,
    pub auditor: Arc<Mutex<Auditor>>,
    pub http: reqwest::Client,
    /// Local salt for DLP hit fingerprints in audit events (never the value).
    pub dlp_salt: [u8; 32],
    /// Prompt-cache doctor: observe-only hygiene diagnosis per host+model
    /// (plan 004 phase 1). Session-local diff state; counters flush to
    /// cache.json like the meter.
    pub cache: Arc<Mutex<crate::cache::Doctor>>,
    /// Fan-out serialization gate: one of N concurrent same-prefix requests
    /// writes the cache, the rest read it (plan 004 phase 3, Pro + opt-in).
    pub fanout: Arc<crate::cache::FanoutGate>,
    /// Keep-alive scheduler: session-local request templates and per-prefix
    /// pre-warm budgets (plan 004 phase 3, Pro + opt-in). Templates live in
    /// memory only, never on disk.
    pub keepalive: Arc<Mutex<crate::cache::KeepAlive>>,
    /// Identifies this process's session (one `decoyrail run` or `proxy`
    /// invocation) in every audit event it writes. Stable where pid is not:
    /// the OS reuses pids, so analytics groups by this instead.
    pub session_id: String,
    /// The installed, signature-verified license (None = the Free tier).
    /// Gates paid conveniences only — the pipeline's security verbs never
    /// read it, so no license state can block traffic or weaken enforcement.
    pub license: Arc<RwLock<Option<LicenseDoc>>>,
    /// Session override of the policy's default action (`decoyrail run
    /// --watch` pins it to warn). Never persisted, and reapplied after every
    /// policy hot-reload so a file edit mid-session cannot displace the
    /// operator's explicit choice. Named rules still win over the default.
    default_override: Option<crate::policy::Action>,
    reload: Arc<Mutex<ReloadState>>,
}

/// Session ids embed boot time and pid, plus a counter so two engines booted
/// in one process within one second (tests) stay distinct.
fn new_session_id() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    format!(
        "{}-{}-{}",
        chrono::Utc::now().format("%Y%m%dT%H%M%SZ"),
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

impl Engine {
    pub fn boot() -> Result<Self> {
        let ca = Arc::new(CertAuthority::load_or_create()?);
        let vault = Arc::new(RwLock::new(Vault::load_or_init()?));
        // Only a policy Decoyrail wrote or blessed loads. An unverifiable one
        // is a hard, instructive refusal to start; the refusal itself goes in
        // the tamper-evident log, not just stderr.
        let policy = match Policy::load_trusted() {
            Ok(p) => Arc::new(RwLock::new(p)),
            Err(crate::policy::LoadError::Untrusted(msg)) => {
                note_tamper_at_boot(&msg);
                return Err(anyhow::anyhow!(msg));
            }
            Err(crate::policy::LoadError::Other(e)) => return Err(e),
        };
        let meter = Arc::new(Mutex::new(SessionMeter::load()?));
        let pricing = Arc::new(RwLock::new(Pricing::load()?));
        // Boot-time sanity pass over allow_secrets and route maps (see
        // refresh() for the reload-time counterpart). try_read never fails on
        // the locks we just created and works both inside and outside a
        // tokio runtime.
        if let (Ok(v), Ok(p), Ok(pr)) = (vault.try_read(), policy.try_read(), pricing.try_read()) {
            for w in p.lint(&v.secrets).into_iter().chain(p.lint_routes(&pr)) {
                eprintln!("decoyrail: policy warning: {w}");
            }
        }
        let auditor = Arc::new(Mutex::new(Auditor::open()?));
        let dlp_salt = crate::detect::load_or_create_salt()?;
        // Upstream client. No proxy (we ARE the proxy) — and explicitly so:
        // reqwest otherwise honors HTTP(S)_PROXY from the environment, which
        // detours the already-swapped request through whatever proxy the shell
        // happened to have configured (or loops through another Decoyrail).
        // Upstream TLS verifies against the OS trust store — Decoyrail's MITM is
        // only client-facing.
        //
        // Redirects are NEVER followed here: the swap runs before forwarding,
        // so a followed redirect would carry the real secret to a destination
        // policy never evaluated (reqwest strips Authorization cross-host, but
        // not custom headers like x-api-key). The 3xx is relayed to the client
        // instead; its follow-up request re-enters the pipeline like any other.
        warn_if_trust_env_overridden();
        // Bound connection establishment so a hung upstream can't pin a
        // connection forever. Deliberately no total request timeout: SSE
        // streams from LLM providers are long-lived by design.
        let mut builder = reqwest::Client::builder()
            .use_rustls_tls()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(15))
            .pool_idle_timeout(std::time::Duration::from_secs(90));
        // Optional extra trust root for upstream verification: an enterprise
        // internal CA, or a test's local upstream. Adds to the OS store; never
        // disables verification.
        if let Ok(path) = std::env::var("DECOYRAIL_EXTRA_CA") {
            let pem = std::fs::read(&path)
                .with_context(|| format!("reading DECOYRAIL_EXTRA_CA {path}"))?;
            for cert in reqwest::tls::Certificate::from_pem_bundle(&pem)
                .context("parsing DECOYRAIL_EXTRA_CA bundle")?
            {
                builder = builder.add_root_certificate(cert);
            }
        }
        let http = builder.build()?;
        // A rejected license means the Free tier, never a failed boot: fail
        // open in the direction that keeps security running. The rejection
        // gets the same visibility as one caught on hot-reload: the
        // tamper-evident log, not just stderr.
        let license_doc = match license::load_installed() {
            Ok(d) => d,
            Err(e) => {
                let note =
                    format!("installed license rejected at boot; running the free tier: {e:#}");
                eprintln!("decoyrail: warning: {note}");
                // try_lock never fails on the mutex we just created.
                if let Ok(mut a) = auditor.try_lock() {
                    if let Err(e) = a.append(
                        crate::audit::Entry::note("alert", note),
                        crate::util::now_rfc3339(),
                    ) {
                        eprintln!("decoyrail: audit append failed: {e:#}");
                    }
                }
                None
            }
        };
        let tier = license::current_tier(license_doc.as_ref());
        let reload = Arc::new(Mutex::new(ReloadState {
            vault: config::mtime(&config::vault_path()?),
            policy: config::mtime(&config::policy_path()?),
            policy_sig: config::mtime(&config::policy_sig_path()?),
            budget: config::mtime(&config::budget_path()?),
            pricing: config::mtime(&config::pricing_path()?),
            license: config::mtime(&config::license_path()?),
            tier,
        }));

        Ok(Self {
            ca,
            vault,
            session: Arc::new(Vault::default()),
            policy,
            meter,
            pricing,
            auditor,
            http,
            dlp_salt,
            cache: Arc::new(Mutex::new(crate::cache::Doctor::default())),
            fanout: Arc::new(crate::cache::FanoutGate::default()),
            keepalive: Arc::new(Mutex::new(crate::cache::KeepAlive::default())),
            session_id: new_session_id(),
            license: Arc::new(RwLock::new(license_doc)),
            default_override: None,
            reload,
        })
    }

    /// Record the session-start event that labels this process's traffic in
    /// the audit log (and therefore in `decoyrail stats --by session`).
    pub async fn announce_session(&self, label: &str) -> Result<()> {
        let entry = crate::audit::Entry {
            host: "-".into(),
            path: "-".into(),
            method: "-".into(),
            action: "session".into(),
            note: label.to_string(),
            sid: self.session_id.clone(),
            ..Default::default()
        };
        self.auditor
            .lock()
            .await
            .append(entry, crate::util::now_rfc3339())?;
        Ok(())
    }

    /// The tier in force right now: the licensed tier, or Free with no valid
    /// license. Paid features (soft-landing, cache repair, routing, console
    /// writes) gate on this at their entry points; security code never calls
    /// it.
    pub async fn tier(&self) -> Tier {
        license::current_tier(self.license.read().await.as_ref())
    }

    /// Install session-scoped secrets. Call before the engine is cloned into
    /// the serve task; clones share the same Arc afterwards.
    pub fn set_session_secrets(&mut self, secrets: Vec<crate::vault::Secret>) {
        self.session = Arc::new(Vault { secrets });
    }

    /// Pin the policy's default action for this session (`decoyrail run
    /// --watch`). The policy file is untouched; `refresh` reapplies the
    /// override after every reload. Call before the engine is cloned into
    /// the serve task, like `set_session_secrets`.
    pub fn set_default_action_override(&mut self, action: crate::policy::Action) {
        self.default_override = Some(action);
        // try_write never fails here: the serve task doesn't exist yet.
        if let Ok(mut p) = self.policy.try_write() {
            p.default_action = action;
        }
    }

    /// Reload vault, policy, and budget from disk if their files changed since
    /// last seen, so `decoyrail vault add`, a policy edit, or `decoyrail budget` take
    /// effect on a running proxy without a restart. Called once per request;
    /// three stat() calls when nothing changed.
    pub async fn refresh(&self) {
        let mut st = self.reload.lock().await;

        if let Ok(path) = config::vault_path() {
            let now = config::mtime(&path);
            if now != st.vault {
                st.vault = now;
                match Vault::load_or_init() {
                    Ok(v) => *self.vault.write().await = v,
                    Err(e) => self.reload_failed("vault", &e).await,
                }
            }
        }
        if let (Ok(path), Ok(sig_path)) = (config::policy_path(), config::policy_sig_path()) {
            let now = config::mtime(&path);
            let sig_now = config::mtime(&sig_path);
            if now != st.policy || sig_now != st.policy_sig {
                st.policy = now;
                st.policy_sig = sig_now;
                match Policy::load_trusted() {
                    Ok(mut p) => {
                        // The operator's session override outlives file edits;
                        // rules change as usual, the default stays pinned.
                        if let Some(a) = self.default_override {
                            p.default_action = a;
                        }
                        // Reload-time sanity: allow_secrets entries that can't
                        // match, or releasing rules a broader rule shadows,
                        // silently turn a working credential into a tripwire.
                        // Warn (once per file change), never block the load.
                        let known = {
                            let vault = self.vault.read().await;
                            let mut known = vault.secrets.clone();
                            known.extend(self.session.secrets.iter().cloned());
                            known
                        };
                        let route_warnings = p.lint_routes(&*self.pricing.read().await);
                        for w in p.lint(&known).into_iter().chain(route_warnings) {
                            eprintln!("decoyrail: policy warning: {w}");
                        }
                        *self.policy.write().await = p;
                    }
                    // Tampering is its own audit story (`tamper`, alarm
                    // prominence downstream), distinct from the typo path
                    // below. Either way the last good policy stays active.
                    Err(crate::policy::LoadError::Untrusted(msg)) => {
                        let note = format!("policy rejected; previous policy stays active: {msg}");
                        eprintln!("decoyrail: ALERT: {note}");
                        self.audit_note("tamper", note).await;
                    }
                    Err(crate::policy::LoadError::Other(e)) => {
                        self.reload_failed("policy", &e).await
                    }
                }
            }
        }
        if let Ok(path) = config::budget_path() {
            let now = config::mtime(&path);
            if now != st.budget {
                st.budget = now;
                match crate::meter::load_budget() {
                    Ok(b) => self.meter.lock().await.budget_usd = b,
                    Err(e) => self.reload_failed("budget", &e).await,
                }
            }
        }
        if let Ok(path) = config::pricing_path() {
            let now = config::mtime(&path);
            if now != st.pricing {
                st.pricing = now;
                match Pricing::load() {
                    Ok(p) => *self.pricing.write().await = p,
                    Err(e) => self.reload_failed("pricing", &e).await,
                }
            }
        }
        if let Ok(path) = config::license_path() {
            let now = config::mtime(&path);
            if now != st.license {
                st.license = now;
                match license::load_installed() {
                    Ok(d) => *self.license.write().await = d,
                    Err(e) => {
                        // Unlike policy there is no keep-old here: the safe
                        // direction for licensing is Free (paid conveniences
                        // off, security untouched), not the previous tier.
                        *self.license.write().await = None;
                        let note = format!("license file rejected; running the free tier: {e:#}");
                        eprintln!("decoyrail: warning: {note}");
                        self.audit_note("alert", note).await;
                    }
                }
            }
        }
        // Tier crossings audit exactly once, whether driven by a file change
        // above or by the date walking past expiry/grace with no change.
        let tier_now = license::current_tier(self.license.read().await.as_ref());
        if tier_now != st.tier {
            let note = format!("effective tier changed: {} -> {}", st.tier, tier_now);
            st.tier = tier_now;
            self.audit_note("license", note).await;
        }
        // Keep-old-on-failure is deliberate (a half-written file mid-edit must
        // not take the proxy down), but it must never be silent: an admin who
        // pushed a broken policy would otherwise see it as "deployed" while
        // endpoints run the previous one. The mtime was already recorded above,
        // so a failure is reported once per file change, not once per request.

        // Fold in usage flushed by other decoyrail sessions sharing this home, so
        // the budget kill switch stays global rather than per-session. The
        // meter tracks its own last-seen mtime (not ReloadState) because this
        // session's flushes move it too and shouldn't trigger a re-read.
        if let Ok(path) = config::meter_path() {
            let now = config::mtime(&path);
            let mut meter = self.meter.lock().await;
            if meter.stale(now) {
                meter.reload_merged(now);
            }
        }
    }

    /// A hot-reloadable file changed but could not be loaded: the previous
    /// version stays active. Announce that on stderr and in the audit log so
    /// the failure is visible both locally and downstream in a SIEM.
    async fn reload_failed(&self, what: &str, err: &anyhow::Error) {
        let note = format!("{what} reload failed; previous {what} stays active: {err:#}");
        eprintln!("decoyrail: warning: {note}");
        self.audit_note("alert", note).await;
    }

    /// Append a request-free event (reload failures, license/tier changes) to
    /// the audit log, stamped with this process's session id.
    async fn audit_note(&self, action: &str, note: String) {
        let mut entry = crate::audit::Entry::note(action, note);
        entry.sid = self.session_id.clone();
        let ts = crate::util::now_rfc3339();
        if let Err(e) = self.auditor.lock().await.append(entry, ts) {
            eprintln!("decoyrail: audit append failed: {e:#}");
        }
    }
}

/// Best-effort tamper note when there is no running engine to audit through
/// (the boot refusal). The refusal itself must not be masked by an audit
/// failure, so errors here go to stderr and nowhere else.
fn note_tamper_at_boot(msg: &str) {
    let res = Auditor::open().and_then(|mut a| {
        a.append(
            crate::audit::Entry::note("tamper", format!("proxy refused to start: {msg}")),
            crate::util::now_rfc3339(),
        )
        .map(|_| ())
    });
    if let Err(e) = res {
        eprintln!("decoyrail: audit append failed: {e:#}");
    }
}

/// rustls-native-certs honors SSL_CERT_FILE (and friends) *instead of* the
/// platform trust store. Inside a `decoyrail run` child env those point at the
/// Decoyrail CA, so a nested proxy would reject every real upstream certificate.
/// We can't safely mutate the process env after threads exist, so warn loudly.
fn warn_if_trust_env_overridden() {
    for var in ["SSL_CERT_FILE", "SSL_CERT_DIR"] {
        if let Ok(v) = std::env::var(var) {
            eprintln!(
                "decoyrail: warning: {var}={v} overrides the OS trust store for \
                 upstream TLS verification; unset it if upstream connections \
                 fail with UnknownIssuer"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::license::{generate_keypair, sign_document, LicenseDoc};

    fn signed_license(tier: &str, expires: &str, pkcs8: &[u8]) -> String {
        let doc = LicenseDoc {
            licensee: "Acme Corp".into(),
            tier: tier.into(),
            rank: None,
            seats: 5,
            issued: "2026-01-01".parse().unwrap(),
            expires: expires.parse().unwrap(),
            grace_days: 14,
        };
        sign_document(&doc, pkcs8).unwrap()
    }

    /// AC3/AC4 at the engine level: no license means Free with a running
    /// engine; a license appearing on disk flips the tier on refresh; a
    /// rejected or effectively-expired one drops back to Free; and every
    /// crossing lands in the audit log.
    // env_guard's std MutexGuard is held across awaits on purpose: it
    // serializes the process-global DECOYRAIL_HOME for the whole test.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn license_hot_reload_flips_tier_and_audits() {
        let _g = crate::util::env_guard();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", tmp.path());
        let (pkcs8, pub_hex) = generate_keypair().unwrap();
        std::env::set_var("DECOYRAIL_LICENSE_EXTRA_KEY", &pub_hex);

        let engine = Engine::boot().unwrap();
        assert_eq!(engine.tier().await, Tier::Free);

        // A team license lands on disk (far-future expiry): tier follows.
        let path = config::license_path().unwrap();
        std::fs::write(&path, signed_license("team", "2999-01-01", &pkcs8)).unwrap();
        engine.refresh().await;
        assert_eq!(engine.tier().await, Tier::Team);

        // Replaced by one already past its grace window: Free, not an error.
        std::fs::write(&path, signed_license("team", "2001-01-01", &pkcs8)).unwrap();
        engine.refresh().await;
        assert_eq!(engine.tier().await, Tier::Free);

        // A tampered file is also Free — never fail closed on licensing.
        std::fs::write(&path, "not a license").unwrap();
        engine.refresh().await;
        assert_eq!(engine.tier().await, Tier::Free);

        let log = std::fs::read_to_string(config::audit_path().unwrap()).unwrap();
        assert!(log.contains("effective tier changed: free -> team"));
        assert!(log.contains("effective tier changed: team -> free"));
        assert!(log.contains("license file rejected"));

        std::env::remove_var("DECOYRAIL_LICENSE_EXTRA_KEY");
        std::env::remove_var("DECOYRAIL_HOME");
    }

    /// Plan 018: an out-of-band policy edit never loads. A running proxy
    /// keeps the last good policy and writes the distinct `tamper` event; a
    /// blessing (which touches only the record file) is picked up live; and
    /// a fresh boot against the tampered file refuses to start,
    /// instructively.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn tampered_policy_keeps_last_good_audits_and_blocks_boot() {
        let _g = crate::util::env_guard();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", tmp.path());

        use crate::policy::Action;
        let evaluate =
            |p: &crate::policy::Policy| p.evaluate("evil.example.com", "/", "GET").action;

        // Boot materializes a trusted default, then a CLI write flips the
        // default action; the hot reload follows because the write is
        // recorded.
        let engine = Engine::boot().unwrap();
        crate::policy_edit::write_policy("default_action = \"allow\"\n", "test").unwrap();
        engine.refresh().await;
        assert_eq!(evaluate(&*engine.policy.read().await), Action::Allow);

        // Out-of-band edit: rejected, last good stays, tamper event lands.
        let path = config::policy_path().unwrap();
        std::fs::write(&path, "default_action = \"deny\"\n").unwrap();
        engine.refresh().await;
        assert_eq!(
            evaluate(&*engine.policy.read().await),
            Action::Allow,
            "a tampered policy must not replace the running one"
        );
        let log = std::fs::read_to_string(config::audit_path().unwrap()).unwrap();
        assert!(log.contains("\"tamper\""), "tamper event missing: {log}");

        // Blessing rewrites only the record; the reload watches its mtime
        // too, so the blessed hand-edit takes effect without a restart.
        crate::integrity::bless_current().unwrap();
        engine.refresh().await;
        assert_eq!(evaluate(&*engine.policy.read().await), Action::Deny);

        // An unreadable record is the ordinary broken-file story (`alert`,
        // not `tamper`): the last good policy stays, boot fails plainly.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let sig = config::policy_sig_path().unwrap();
            std::fs::set_permissions(&sig, std::fs::Permissions::from_mode(0o000)).unwrap();
            // Same bytes, fresh mtime: only the record read can fail.
            let text = std::fs::read_to_string(&path).unwrap();
            std::fs::write(&path, &text).unwrap();
            engine.refresh().await;
            assert_eq!(evaluate(&*engine.policy.read().await), Action::Deny);
            let log = std::fs::read_to_string(config::audit_path().unwrap()).unwrap();
            assert!(log.contains("policy reload failed"), "{log}");
            assert!(
                Engine::boot().is_err(),
                "boot must fail on an unreadable record"
            );
            std::fs::set_permissions(&sig, std::fs::Permissions::from_mode(0o644)).unwrap();
        }

        // A new boot against a tampered file is a hard, instructive no.
        std::fs::write(&path, "default_action = \"allow\"\n# extra\n").unwrap();
        let err = Engine::boot()
            .err()
            .expect("boot must refuse a tampered policy")
            .to_string();
        assert!(err.contains("policy sign"), "{err}");
        let log = std::fs::read_to_string(config::audit_path().unwrap()).unwrap();
        assert!(log.contains("proxy refused to start"), "{log}");

        std::env::remove_var("DECOYRAIL_HOME");
    }

    /// The boot-refusal audit note is best-effort: it lands in the log when
    /// the log is writable, and degrades to stderr (never masking the
    /// refusal) when it is not.
    #[test]
    fn boot_tamper_note_is_best_effort() {
        let _g = crate::util::env_guard();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", tmp.path());
        config::ensure_home().unwrap();

        note_tamper_at_boot("test message");
        let log = std::fs::read_to_string(config::audit_path().unwrap()).unwrap();
        assert!(log.contains("proxy refused to start: test message"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let audit = config::audit_path().unwrap();
            std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o444)).unwrap();
            note_tamper_at_boot("unwritable log"); // must not panic or mask
            std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o644)).unwrap();
            let log = std::fs::read_to_string(&audit).unwrap();
            assert!(!log.contains("unwritable log"));
        }

        std::env::remove_var("DECOYRAIL_HOME");
    }

    /// Watch mode (plan 017): the session override pins the default action to
    /// warn, a policy hot-reload keeps the pin while its rule changes land,
    /// and the policy file itself is never modified.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn watch_mode_override_survives_policy_reload() {
        use crate::policy::Action;
        let _g = crate::util::env_guard();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", tmp.path());

        let path = config::policy_path().unwrap();
        crate::policy_edit::write_policy("default_action = \"deny\"\n", "test").unwrap();
        let before = std::fs::read(&path).unwrap();

        let mut engine = Engine::boot().unwrap();
        engine.set_default_action_override(Action::Warn);
        {
            let p = engine.policy.read().await;
            assert_eq!(
                p.evaluate("unknown.example.com", "/", "GET").action,
                Action::Warn
            );
        }
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "policy file untouched"
        );

        // A mid-session policy edit lands its rules but cannot displace the
        // operator's explicit override.
        crate::policy_edit::write_policy(
            "default_action = \"deny\"\n\
             [[rule]]\nname = \"blocked\"\nhosts = [\"evil.example.com\"]\naction = \"deny\"\n",
            "test",
        )
        .unwrap();
        let f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(2))
            .unwrap();
        engine.refresh().await;
        {
            let p = engine.policy.read().await;
            assert_eq!(
                p.evaluate("evil.example.com", "/", "GET").action,
                Action::Deny,
                "the reloaded deny rule still wins over the default"
            );
            assert_eq!(
                p.evaluate("unknown.example.com", "/", "GET").action,
                Action::Warn,
                "the reload must not displace the override"
            );
        }

        // A fresh engine without the flag is back to the file's posture.
        let engine = Engine::boot().unwrap();
        let p = engine.policy.read().await;
        assert_eq!(
            p.evaluate("unknown.example.com", "/", "GET").action,
            Action::Deny
        );

        std::env::remove_var("DECOYRAIL_HOME");
    }
}
