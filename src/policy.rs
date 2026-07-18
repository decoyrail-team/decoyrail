//! Egress policy: rules-first evaluation of every intercepted request.
//!
//! Rules match on destination host (glob), path (prefix), and method; first
//! match wins, with a configurable default action. `escalate` is where an
//! LLM-as-judge or human approval will hook in (v0.5); until then it resolves
//! to `escalate_fallback` (default: deny) so the fail-safe posture is closed,
//! not open.
//!
//! Rules also carry `allow_secrets`: the vault secrets (by name, or by
//! provider label as `provider:github`) that are *expected* at destinations
//! the rule matches. On a rule that resolves to allow, an expected secret's
//! decoy is swapped for the real value. On any other rule, an expected
//! secret's decoy stays quiet instead of sounding the honeytoken alarm (the
//! agent's own credential riding a denied telemetry call is not an exfil
//! signal): deny and escalate block the request, warn forwards it with the
//! decoy still in place. A decoy the winning rule does not expect is always
//! a tripwire.
//!
//! `warn` is the watch-mode action (plan 017): the request forwards exactly
//! like allow, but the audit log records it as a distinct `warn` event and no
//! secret is ever released — the only protection it trades away is the
//! blocking of traffic that carries no secret.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::config;
use crate::vault::{glob_match, Secret, PROVIDER_LABELS};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
    /// Forward like allow but record a visible alert — and never release a
    /// secret. The middle posture between "deny what I haven't listed" and
    /// running unprotected; see plans/017.
    Warn,
    /// Allow, plus rewrite the requested model per the rule's explicit
    /// `route` map (plan 006, Pro). Policy-wise identical to allow — secret
    /// release still rides `allow_secrets`, and deny/tripwire/DLP/budget
    /// outrank it the same way — so no license state ever changes
    /// reachability, only whether the rewrite happens.
    Route,
    /// Defer to judge/human. Resolves to `escalate_fallback` until v0.5.
    Escalate,
}

impl Action {
    /// The lowercase spelling used in policy.toml and the CLI.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Warn => "warn",
            Action::Route => "route",
            Action::Escalate => "escalate",
        }
    }

    /// Parse an action from CLI/user input (case-insensitive).
    pub fn parse(s: &str) -> Result<Action> {
        match s.to_ascii_lowercase().as_str() {
            "allow" => Ok(Action::Allow),
            "deny" => Ok(Action::Deny),
            "warn" => Ok(Action::Warn),
            "route" => Ok(Action::Route),
            "escalate" => Ok(Action::Escalate),
            other => Err(anyhow::anyhow!(
                "unknown action '{other}' (use allow|deny|warn|route|escalate)"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub hosts: Vec<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    /// Optional path-prefix constraint. Empty = any path. Lets a rule target a
    /// sub-path (e.g. escalate only `gist.github.com` writes) instead of the
    /// whole host.
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    pub action: Action,
    /// Secrets expected at destinations this rule matches: vault entry names,
    /// or provider labels as `provider:<label>`. Released (decoy swapped for
    /// the real value) only when the rule resolves to allow (or route, which
    /// is allow plus a model rewrite).
    #[serde(default)]
    pub allow_secrets: Vec<String>,
    /// Model map for `action = "route"` (plan 006): requested model to the
    /// model that forwards. Explicit configuration, like the soft-landing
    /// map — Decoyrail has no built-in opinions, and a request whose model
    /// is absent, unmapped, or unidentifiable forwards unmodified. Ignored
    /// on every other action.
    #[serde(default)]
    pub route: BTreeMap<String, String>,
}

/// Does an `allow_secrets` list cover this secret (by name or provider label)?
pub fn lists_secret(allow_secrets: &[String], secret: &Secret) -> bool {
    allow_secrets.iter().any(|entry| {
        entry == &secret.name
            || entry
                .strip_prefix("provider:")
                .is_some_and(|label| secret.provider.as_deref() == Some(label))
    })
}

impl Rule {
    fn matches(&self, host: &str, path: &str, method: &str) -> bool {
        let host_ok = self.hosts.iter().any(|g| glob_match(g, host));
        let method_ok =
            self.methods.is_empty() || self.methods.iter().any(|m| m.eq_ignore_ascii_case(method));
        let path_ok =
            self.path_prefixes.is_empty() || self.path_prefixes.iter().any(|p| path.starts_with(p));
        host_ok && method_ok && path_ok
    }
}

/// What a DLP detector hit does to the request carrying it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpMode {
    /// Detector disabled.
    Off,
    /// Forward the request, record an alert audit event.
    Warn,
    /// Deny the request with a machine-readable error naming the detector.
    Block,
    /// Replace the matched value with a typed placeholder and forward.
    Mask,
}

impl DlpMode {
    pub fn name(self) -> &'static str {
        match self {
            DlpMode::Off => "off",
            DlpMode::Warn => "warn",
            DlpMode::Block => "block",
            DlpMode::Mask => "mask",
        }
    }
}

/// Sensitive-data filtering: which structured detectors run on outbound
/// requests and what a hit does. Independent of the destination rules — a
/// blocking detector hit overrides a policy allow, same precedence as the
/// tripwire (fail closed).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DlpConfig {
    pub pan: DlpMode,
    pub ssn: DlpMode,
    pub iban: DlpMode,
    pub aba: DlpMode,
    pub email: DlpMode,
    /// Extra allowlisted values (compared ignoring case and separators), for
    /// org-specific fixtures beyond the built-in test-value allowlists.
    pub allow: Vec<String>,
    /// Debug mode: every request with a DLP hit is dumped in full (headers and
    /// body, with vaulted real secrets scrubbed back out) to a private file
    /// under the state dir, and the audit note carries the file path. The
    /// audit log itself still gets fingerprints only. Meant to be switched on
    /// to diagnose a block and switched back off.
    pub debug: bool,
}

impl Default for DlpConfig {
    fn default() -> Self {
        // Warn-first launch posture: the detectors are new, so a hit is
        // recorded (visible in `decoyrail log -t`) but nothing breaks out of
        // the box. Users upgrade detectors to block once their own traffic
        // shows the alerts are real. Email stays off entirely because agents
        // ship commit-author emails constantly.
        Self {
            pan: DlpMode::Warn,
            ssn: DlpMode::Warn,
            iban: DlpMode::Warn,
            aba: DlpMode::Warn,
            email: DlpMode::Off,
            allow: Vec::new(),
            debug: false,
        }
    }
}

/// Prompt-cache layer knobs (plan 004 phases 2-3). Every field is off or a
/// safe default, and every active behavior is additionally gated on a Pro
/// license at its entry point — so an unlicensed or unconfigured proxy runs
/// the free, observe-only doctor exactly as before. Mirrors `[cache]` in the
/// policy file and hot-reloads like the rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Splice `cache_control` markers into requests whose prefix demonstrably
    /// repeats but carries none (phase 2).
    pub repair: bool,
    /// Pre-warm a warm cache with a proxy-initiated request during idle so it
    /// survives a long local operation (phase 3).
    pub keep_alive: bool,
    /// Idle seconds before a keep-alive fires. Default sits just under the 5m
    /// provider TTL so the cache is refreshed before it lapses.
    pub keep_alive_secs: u64,
    /// Cap on proxy-initiated pre-warms per prefix per session; a real request
    /// resets the count. Bounds proxy-attributed spend.
    pub keep_alive_max: u32,
    /// Serialize concurrent requests that share a cacheable prefix so one
    /// writes the cache and the rest read it (phase 3).
    pub serialize_fanout: bool,
    /// How long a serialized sibling waits for the leader's first response
    /// byte before proceeding anyway, so a stalled leader can't wedge them.
    pub fanout_timeout_ms: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            repair: false,
            keep_alive: false,
            keep_alive_secs: 240,
            keep_alive_max: 6,
            serialize_fanout: false,
            fanout_timeout_ms: 2000,
        }
    }
}

/// Budget soft-landing (plan 003): the band between a configurable share of
/// the monthly budget and the hard limit. Inside it, requests naming a model
/// on the left of `map` are rewritten to the cheaper model on the right; at
/// 100% the kill switch still stops everything, unchanged. Off by default
/// (no threshold, no map), Pro-gated at its entry point in the pipeline, and
/// hot-reloaded like the rest of the policy. Mirrors `[soft_landing]` in the
/// policy file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SoftLandingConfig {
    /// Percent of the monthly budget where downgrades begin. 0 disables.
    pub threshold_pct: f64,
    /// Explicit downgrade map, requested model to cheaper model. The map is
    /// the customer's opinion of "equivalent"; Decoyrail has none built in,
    /// and a model with no entry forwards untouched.
    pub map: BTreeMap<String, String>,
}

impl SoftLandingConfig {
    /// Configured on: a positive threshold and at least one mapping.
    pub fn enabled(&self) -> bool {
        self.threshold_pct > 0.0 && !self.map.is_empty()
    }
}

/// What a spend-tripwire trip does to subsequent LLM traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TripwireMode {
    /// Deny LLM-bound requests until `decoyrail trip clear` (the default).
    Block,
    /// Record the trip and keep forwarding: visibility before enforcement.
    Alert,
    /// No detection at all.
    Off,
}

/// Spend tripwire (plan 002): mechanical runaway detection — the same
/// request repeated many times in a window, or a spend rate far above the
/// session's own baseline. On by default with conservative thresholds; a
/// safety feature, so it ships in the free tier and no license gates it.
/// Mirrors `[spend_tripwire]` in the policy file, hot-reloaded like the rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SpendTripwireConfig {
    pub mode: TripwireMode,
    /// Identical requests inside the window that trip. 0 disables repeat
    /// detection. The default is generous to polling patterns: fifteen
    /// byte-identical LLM calls in five minutes is a loop, not a retry.
    pub repeats: u32,
    /// Sliding window, seconds, shared by both detectors.
    pub window_secs: u64,
    /// A window's spend rate must exceed the session baseline by this factor
    /// to trip. 0 disables rate detection.
    pub rate_multiplier: f64,
    /// And exceed this many dollars inside the window, so a spiky-but-cheap
    /// burst over a near-zero baseline never trips.
    pub rate_floor_usd: f64,
}

impl Default for SpendTripwireConfig {
    fn default() -> Self {
        Self {
            mode: TripwireMode::Block,
            repeats: 15,
            window_secs: 300,
            rate_multiplier: 10.0,
            rate_floor_usd: 5.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub default_action: Action,
    #[serde(default = "default_escalate_fallback")]
    pub escalate_fallback: Action,
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub dlp: DlpConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub soft_landing: SoftLandingConfig,
    #[serde(default)]
    pub spend_tripwire: SpendTripwireConfig,
}

fn default_escalate_fallback() -> Action {
    Action::Deny
}

/// The concrete decision for a request after rule evaluation.
#[derive(Debug, Clone)]
pub struct Decision {
    pub action: Action,
    pub rule: String,
    pub escalated: bool,
    /// The winning rule's `allow_secrets`. Whether a listed secret is swapped
    /// or merely spared the tripwire depends on `action`.
    pub allow_secrets: Vec<String>,
    /// The winning rule's model map (route rules only; empty otherwise).
    pub route: BTreeMap<String, String>,
}

impl Decision {
    /// The winning rule releases this secret: swap decoy for real (transport
    /// and location checks still apply). Only allow — and route, which is
    /// allow plus a model rewrite — releases; a warn rule forwards, but its
    /// listed secrets stay decoys.
    pub fn releases(&self, secret: &Secret) -> bool {
        matches!(self.action, Action::Allow | Action::Route)
            && lists_secret(&self.allow_secrets, secret)
    }

    /// The winning rule expects this secret here even though it is not
    /// released (blocked, or forwarded under warn): no swap, but no
    /// honeytoken alarm either.
    pub fn expects(&self, secret: &Secret) -> bool {
        lists_secret(&self.allow_secrets, secret)
    }
}

/// Why a trusted policy load was refused. The two arms tell different
/// stories downstream: `Untrusted` is a tamper event (alarm prominence),
/// `Other` is the ordinary broken-file path (parse failure, unreadable
/// state). Both fail closed.
#[derive(Debug)]
pub enum LoadError {
    /// The file was changed outside Decoyrail, has no integrity record, or
    /// is missing while its record exists. Carries the full instructive
    /// message for humans.
    Untrusted(String),
    Other(anyhow::Error),
}

impl LoadError {
    pub fn into_anyhow(self) -> anyhow::Error {
        match self {
            LoadError::Untrusted(msg) => anyhow::anyhow!(msg),
            LoadError::Other(e) => e,
        }
    }
}

/// Read the policy text, materializing the shipped default (through the
/// recorded write path, so it is born trusted) on a genuinely fresh home. A
/// missing file whose integrity record exists is not fresh: a deleted
/// policy is an edit, and re-materializing over it would silently re-bless.
fn read_or_materialize() -> Result<String, LoadError> {
    let inner = || -> Result<std::path::PathBuf> {
        config::ensure_home()?;
        config::policy_path()
    };
    let path = inner().map_err(LoadError::Other)?;
    if !path.exists() {
        let sig_exists = config::policy_sig_path()
            .map(|p| p.exists())
            .map_err(LoadError::Other)?;
        if sig_exists {
            return Err(LoadError::Untrusted(format!(
                "{} is missing but its integrity record exists; a deleted policy is an \
                 edit. Restore the file (last backup: {}), or start over with \
                 `decoyrail policy reset`.",
                path.display(),
                config::policy_backup_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "policy.toml.bak".into()),
            )));
        }
        crate::integrity::install(DEFAULT_POLICY_TOML, "default policy")
            .map_err(LoadError::Other)?;
    }
    std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))
        .map_err(LoadError::Other)
}

impl Policy {
    /// Parse-only load for CLI read paths (`policy ls`, `policy test`,
    /// `vault ls`): these report on the file, including an untrusted one,
    /// and never release a secret. The proxy loads via [`Self::load_trusted`].
    pub fn load_or_default() -> Result<Self> {
        let text = read_or_materialize().map_err(LoadError::into_anyhow)?;
        let policy: Policy = toml::from_str(&text).context("parsing policy.toml")?;
        Ok(policy)
    }

    /// The proxy's load: only a policy Decoyrail wrote or blessed for this
    /// home. Verification is silent and applies in every home; anything
    /// unverifiable is [`LoadError::Untrusted`], which callers surface with
    /// alarm prominence and fail closed on.
    pub fn load_trusted() -> Result<Self, LoadError> {
        let text = read_or_materialize()?;
        match crate::integrity::verify(&text) {
            Ok(crate::integrity::Verdict::Trusted) => toml::from_str(&text)
                .context("parsing policy.toml")
                .map_err(LoadError::Other),
            Ok(v) => Err(LoadError::Untrusted(crate::integrity::untrusted_message(v))),
            Err(e) => Err(LoadError::Other(e)),
        }
    }

    pub fn evaluate(&self, host: &str, path: &str, method: &str) -> Decision {
        for rule in &self.rules {
            if rule.matches(host, path, method) {
                return self.resolve(
                    rule.action,
                    rule.name.clone(),
                    rule.allow_secrets.clone(),
                    rule.route.clone(),
                );
            }
        }
        self.resolve(
            self.default_action,
            "default".into(),
            Vec::new(),
            BTreeMap::new(),
        )
    }

    fn resolve(
        &self,
        action: Action,
        rule: String,
        allow_secrets: Vec<String>,
        route: BTreeMap<String, String>,
    ) -> Decision {
        match action {
            Action::Escalate => Decision {
                // A hand-edited fallback of "escalate" would otherwise resolve
                // to an action the pipeline forwards; fail closed instead. A
                // fallback of "route" resolves like allow — the escalated
                // rule has no map, so nothing ever rewrites through it.
                action: match self.escalate_fallback {
                    Action::Escalate => Action::Deny,
                    other => other,
                },
                rule,
                escalated: true,
                allow_secrets,
                route,
            },
            other => Decision {
                action: other,
                rule,
                escalated: false,
                allow_secrets,
                route,
            },
        }
    }

    /// Rules that can release this secret (allow and route rules listing
    /// it), for `vault ls` and the `decoyrail run` startup report.
    pub fn releasing_rules(&self, secret: &Secret) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|r| {
                matches!(r.action, Action::Allow | Action::Route)
                    && lists_secret(&r.allow_secrets, secret)
            })
            .collect()
    }

    /// Non-blocking sanity warnings about `allow_secrets` declarations:
    /// entries that can't match anything, and releasing rules a broader
    /// earlier rule shadows completely. `known` is the vault's secrets (the
    /// session vault doesn't exist at lint time; provider labels cover it).
    pub fn lint(&self, known: &[Secret]) -> Vec<String> {
        let mut warnings = Vec::new();
        for rule in &self.rules {
            for entry in &rule.allow_secrets {
                if let Some(label) = entry.strip_prefix("provider:") {
                    if !PROVIDER_LABELS.contains(&label) {
                        warnings.push(format!(
                            "rule '{}': unknown provider label '{entry}' (known: {})",
                            rule.name,
                            PROVIDER_LABELS.join(", ")
                        ));
                    }
                } else if !known.is_empty() && !known.iter().any(|s| &s.name == entry) {
                    warnings.push(format!(
                        "rule '{}': no vault secret named '{entry}'",
                        rule.name
                    ));
                }
            }
        }
        // Shadow check: a releasing rule below an unconstrained rule whose
        // hosts cover all of its hosts can never win, so it never releases.
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.allow_secrets.is_empty() {
                continue;
            }
            let shadowed_by = self.rules[..i].iter().find(|earlier| {
                earlier.path_prefixes.is_empty()
                    && earlier.methods.is_empty()
                    && rule
                        .hosts
                        .iter()
                        .all(|h| earlier.hosts.iter().any(|e| glob_covers(e, h)))
            });
            if let Some(earlier) = shadowed_by {
                warnings.push(format!(
                    "rule '{}' can never win: rule '{}' above it matches every \
                     request it matches, so its allow_secrets never apply",
                    rule.name, earlier.name
                ));
            }
        }
        warnings
    }

    /// Non-blocking sanity warnings about route rules (plan 006): a route
    /// rule whose map is empty never rewrites (it is just an allow; say so),
    /// and a map targeting a model the pricing table doesn't price is likely
    /// a typo the provider will reject — the same flag 003 raises on a
    /// soft-landing target. Split from [`Self::lint`] because only these
    /// warnings need the pricing table.
    pub fn lint_routes(&self, pricing: &crate::pricing::Pricing) -> Vec<String> {
        let mut warnings = Vec::new();
        for rule in self.rules.iter().filter(|r| r.action == Action::Route) {
            if rule.route.is_empty() {
                warnings.push(format!(
                    "rule '{}': action is route but the route map is empty, so it \
                     behaves exactly like allow and never rewrites",
                    rule.name
                ));
            }
            for to in rule.route.values() {
                if !pricing.knows_model(to) {
                    warnings.push(format!(
                        "rule '{}': route target model '{to}' is not in the pricing \
                         table (typo? requests forward as configured either way)",
                        rule.name
                    ));
                }
            }
        }
        warnings
    }
}

/// Does the `outer` host glob match every host the `inner` glob matches?
fn glob_covers(outer: &str, inner: &str) -> bool {
    let outer = outer.to_ascii_lowercase();
    let inner = inner.to_ascii_lowercase();
    if outer == "*" || outer == inner {
        return true;
    }
    if let Some(suffix) = outer.strip_prefix("*.") {
        let bare = inner.strip_prefix("*.").unwrap_or(&inner);
        return bare == suffix || bare.ends_with(&format!(".{suffix}"));
    }
    false
}

/// Safe defaults for a Claude Code / Codex CLI rollout: allow the AI provider
/// APIs and the toolchain endpoints agents legitimately need; deny everything
/// else so exfiltration destinations are blocked by default.
pub const DEFAULT_POLICY_TOML: &str = r#"# Decoyrail default policy: "Claude Code safe defaults"
# Rules are evaluated top-to-bottom; first match wins.
#
# allow_secrets lists the secrets expected at destinations a rule matches:
# vault entry names, or provider labels like "provider:github" (which cover
# auto-decoyed session secrets and vault entries with a recognized format).
# On an allow rule the decoy is swapped for the real value; on a deny or
# escalate rule the request blocks without raising the honeytoken alarm.
#
# Actions: allow | deny | warn | route | escalate. "warn" forwards like allow
# but records a distinct warn event and never releases a secret; set it as the
# default (or run `decoyrail run --watch`) to tune the policy against real
# traffic without blocking the agent first. "route" is allow plus a model
# rewrite per the rule's explicit map (Pro; see the example near the end).
default_action = "deny"
escalate_fallback = "deny"

# Claude Code's telemetry/event-logging endpoint. Not needed for the agent to
# work, and it ships conversation-adjacent metadata off the machine. First-match
# -wins: this carve-out sits above the broad anthropic allow. The credential is
# expected here (the client sends it on every call), so deny quietly.
[[rule]]
name = "anthropic-logging"
hosts = ["api.anthropic.com"]
path_prefixes = ["/api/event_logging"]
action = "deny"
allow_secrets = ["provider:anthropic"]

[[rule]]
name = "anthropic"
hosts = ["api.anthropic.com"]
action = "allow"
allow_secrets = ["provider:anthropic"]

# Anthropic's telemetry host: reachable, but no credential belongs there.
[[rule]]
name = "anthropic-statsig"
hosts = ["statsig.anthropic.com"]
action = "allow"

# Claude Code subscription auth refreshes its OAuth token on the console
# host. Scoped to the oauth paths; the rest of the console stays denied.
[[rule]]
name = "anthropic-oauth"
hosts = ["console.anthropic.com"]
path_prefixes = ["/v1/oauth"]
action = "allow"

[[rule]]
name = "openai"
hosts = ["api.openai.com"]
action = "allow"
allow_secrets = ["provider:openai"]

# api.github.com is needed for normal agent work (repos, issues, PRs), but its
# Gist API is a one-POST exfiltration channel. First-match-wins: this carve-out
# sits above the broad allow, mirroring the gist.github.com rules below. The
# token is expected on every API call, so block without the alarm.
[[rule]]
name = "github-gist-api"
hosts = ["api.github.com"]
path_prefixes = ["/gists"]
action = "escalate"
allow_secrets = ["provider:github"]

[[rule]]
name = "github"
hosts = ["github.com", "api.github.com", "codeload.github.com", "*.githubusercontent.com"]
action = "allow"
allow_secrets = ["provider:github"]

[[rule]]
name = "npm-registry"
hosts = ["registry.npmjs.org"]
action = "allow"
allow_secrets = ["provider:npm"]

[[rule]]
name = "package-registries"
hosts = [
  "pypi.org",
  "*.pythonhosted.org",
  "crates.io",
  "static.crates.io",
]
action = "allow"

# Example of a destination worth a second look rather than a blanket allow.
[[rule]]
name = "pastebins"
hosts = ["pastebin.com", "*.ngrok.io", "*.ngrok-free.app"]
action = "escalate"

# Path-scoped rule: allow reading gists, but escalate anything else on the
# host. Rules are first-match, so this read allowance precedes the catch-all.
[[rule]]
name = "gist-read"
hosts = ["gist.github.com"]
methods = ["GET", "HEAD"]
action = "allow"
allow_secrets = ["provider:github"]

[[rule]]
name = "gist-other"
hosts = ["gist.github.com"]
action = "escalate"
allow_secrets = ["provider:github"]

# Sensitive-data filtering. These detectors scan every outbound request,
# whatever the destination, and a "block" hit wins over any allow rule above.
# Modes: block (reject with an error naming the detector), mask (replace the
# value with a placeholder and forward), warn (forward but record an alert),
# off. Detectors start in warn mode: watch `decoyrail log -t` for dlp alerts,
# then tighten with `decoyrail dlp set <detector> block`.
[dlp]
pan = "warn"     # payment card numbers (Luhn-checked; common test cards pass)
ssn = "warn"     # US Social Security numbers in dashed form
iban = "warn"    # international bank account numbers (mod-97 checked)
aba = "warn"     # US bank routing numbers (checksum + prefix checked)
email = "off"    # email addresses; off because commits and packages carry them
# allow = ["4111 1111 1111 1111"]  # extra allowlisted fixture values
# debug = true   # dump each hit's full payload (secrets scrubbed) for inspection

# Prompt-cache layer (Pro). Diagnosis (`decoyrail cache`) is always on and
# free; the settings below are active management and take effect only with a
# Pro license. All default off, so an unlicensed proxy is observe-only.
# [cache]
# repair = true             # inject cache markers where a repeating prefix has none
# keep_alive = true         # pre-warm a warm cache during idle (proxy-initiated, metered)
# keep_alive_secs = 240     # idle seconds before a pre-warm fires (just under the 5m TTL)
# keep_alive_max = 6        # cap pre-warms per prefix per session
# serialize_fanout = true   # let one of N parallel requests write the cache, the rest read it
# fanout_timeout_ms = 2000  # sibling wait cap so a stalled leader can't wedge them

# Model router (Pro). A rule with action = "route" allows exactly like
# "allow" (secrets still release via allow_secrets) and rewrites the requested
# model per its explicit map; deny/tripwire/DLP/budget outrank it as they
# outrank an allow. Every rewrite is audited (action: route) and marked on the
# response (x-decoyrail-route); a model with no map entry forwards untouched.
# [[rule]]
# name = "anthropic-cheap-tier"
# hosts = ["api.anthropic.com"]
# action = "route"
# allow_secrets = ["provider:anthropic"]
# route = { "claude-opus-4" = "claude-sonnet-5" }

# Budget soft-landing (Pro). Past threshold_pct of the monthly budget (set via
# `decoyrail budget`), requests naming a model on the left are rewritten to
# the cheaper model on the right; at 100% the kill switch still stops
# everything. Every downgrade is audited, marked on the response
# (x-decoyrail-downgrade), and invalidates the provider prompt cache (caches
# are model-scoped). Off by default.
# [soft_landing]
# threshold_pct = 80
# map = { "claude-opus-4" = "claude-sonnet-5" }

# Spend tripwire (free). Catches runaway loops in minutes: the same request
# repeated `repeats` times inside the window, or a spend rate far above the
# session's own baseline, blocks LLM-bound traffic (non-LLM egress keeps
# flowing) until `decoyrail trip clear`. On by default with the settings
# below; uncomment to tune, or set mode = "alert" (record, don't block) or
# "off".
# [spend_tripwire]
# mode = "block"
# repeats = 15
# window_secs = 300
# rate_multiplier = 10.0
# rate_floor_usd = 5.0
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        toml::from_str(DEFAULT_POLICY_TOML).unwrap()
    }

    #[test]
    fn allows_anthropic_denies_unknown() {
        let p = policy();
        assert_eq!(
            p.evaluate("api.anthropic.com", "/v1/messages", "POST")
                .action,
            Action::Allow
        );
        assert_eq!(
            p.evaluate("evil.example.com", "/", "POST").action,
            Action::Deny
        );
    }

    #[test]
    fn anthropic_event_logging_denied_before_broad_allow() {
        let p = policy();
        let d = p.evaluate("api.anthropic.com", "/api/event_logging", "POST");
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.rule, "anthropic-logging");
    }

    #[test]
    fn anthropic_oauth_refresh_allowed_console_otherwise_denied() {
        let p = policy();
        // Subscription auth: token refresh must ride the scoped allow.
        assert_eq!(
            p.evaluate("console.anthropic.com", "/v1/oauth/token", "POST")
                .action,
            Action::Allow
        );
        // Anything else on the console falls through to default deny.
        assert_eq!(
            p.evaluate("console.anthropic.com", "/v1/organizations", "GET")
                .action,
            Action::Deny
        );
    }

    #[test]
    fn wildcard_host_rule() {
        let p = policy();
        assert_eq!(
            p.evaluate("raw.githubusercontent.com", "/foo", "GET")
                .action,
            Action::Allow
        );
    }

    #[test]
    fn escalate_falls_back_to_deny_without_judge() {
        let p = policy();
        let d = p.evaluate("pastebin.com", "/", "POST");
        assert_eq!(d.action, Action::Deny);
        assert!(d.escalated);
    }

    #[test]
    fn path_and_method_scoped_rules() {
        // A rule constrained by path_prefixes only matches that sub-path.
        let p: Policy = toml::from_str(
            r#"
default_action = "deny"
[[rule]]
name = "api-read"
hosts = ["api.example.com"]
methods = ["GET"]
path_prefixes = ["/v1/read"]
action = "allow"
"#,
        )
        .unwrap();
        assert_eq!(
            p.evaluate("api.example.com", "/v1/read/x", "GET").action,
            Action::Allow
        );
        // Wrong path → falls through to default deny.
        assert_eq!(
            p.evaluate("api.example.com", "/v1/write", "GET").action,
            Action::Deny
        );
        // Wrong method → falls through to default deny.
        assert_eq!(
            p.evaluate("api.example.com", "/v1/read/x", "POST").action,
            Action::Deny
        );
    }

    #[test]
    fn gist_api_carved_out_of_github_allow() {
        let p = policy();
        // Creating a gist through the REST API must not ride the broad
        // api.github.com allow — it escalates (deny until the judge ships).
        let d = p.evaluate("api.github.com", "/gists", "POST");
        assert!(d.escalated);
        assert_eq!(d.action, Action::Deny);
        // Ordinary API traffic on the same host stays allowed.
        assert_eq!(
            p.evaluate("api.github.com", "/repos/acme/app/pulls", "POST")
                .action,
            Action::Allow
        );
    }

    #[test]
    fn gist_read_allowed_write_escalated() {
        let p = policy();
        assert_eq!(
            p.evaluate("gist.github.com", "/user/abc", "GET").action,
            Action::Allow
        );
        // POST to a gist is not the read rule → escalate → deny fallback.
        let d = p.evaluate("gist.github.com", "/", "POST");
        assert!(d.escalated);
        assert_eq!(d.action, Action::Deny);
    }

    fn secret(name: &str, provider: Option<&str>) -> Secret {
        Secret {
            name: name.into(),
            real: "real".into(),
            decoy: "decoy".into(),
            env: None,
            location: crate::vault::Location::Any,
            provider: provider.map(str::to_string),
        }
    }

    #[test]
    fn winning_allow_rule_releases_listed_secrets() {
        let p: Policy = toml::from_str(
            r#"
default_action = "deny"
[[rule]]
name = "aws"
hosts = ["*.amazonaws.com"]
action = "allow"
allow_secrets = ["aws", "provider:github"]
"#,
        )
        .unwrap();
        let d = p.evaluate("s3.amazonaws.com", "/bucket", "PUT");
        assert!(d.releases(&secret("aws", None)));
        assert!(d.releases(&secret("env:GITHUB_TOKEN", Some("github"))));
        assert!(!d.releases(&secret("other", None)));
        // Default deny elsewhere: nothing released, nothing expected.
        let d = p.evaluate("evil.example.com", "/", "POST");
        assert!(!d.releases(&secret("aws", None)));
        assert!(!d.expects(&secret("aws", None)));
    }

    #[test]
    fn listed_secret_on_blocking_rule_is_expected_not_released() {
        let p: Policy = toml::from_str(
            r#"
default_action = "deny"
[[rule]]
name = "telemetry"
hosts = ["api.example.com"]
path_prefixes = ["/telemetry"]
action = "deny"
allow_secrets = ["svc"]
[[rule]]
name = "api"
hosts = ["api.example.com"]
action = "allow"
allow_secrets = ["svc"]
"#,
        )
        .unwrap();
        let d = p.evaluate("api.example.com", "/telemetry/batch", "POST");
        assert_eq!(d.action, Action::Deny);
        assert!(!d.releases(&secret("svc", None)), "deny rule must not swap");
        assert!(d.expects(&secret("svc", None)), "but no honeytoken alarm");
        let d = p.evaluate("api.example.com", "/v1/x", "POST");
        assert!(d.releases(&secret("svc", None)));
    }

    #[test]
    fn credential_free_carve_out_above_releasing_rule() {
        // A scoped allow without allow_secrets above a broad allow with it:
        // reachable, but the secret is neither released nor expected there.
        let p: Policy = toml::from_str(
            r#"
default_action = "deny"
[[rule]]
name = "public-reads"
hosts = ["api.example.com"]
path_prefixes = ["/public"]
action = "allow"
[[rule]]
name = "api"
hosts = ["api.example.com"]
action = "allow"
allow_secrets = ["svc"]
"#,
        )
        .unwrap();
        let d = p.evaluate("api.example.com", "/public/data", "GET");
        assert_eq!(d.action, Action::Allow);
        assert!(!d.releases(&secret("svc", None)));
        assert!(!d.expects(&secret("svc", None)));
    }

    #[test]
    fn lint_flags_unknown_names_labels_and_shadowed_rules() {
        let p: Policy = toml::from_str(
            r#"
default_action = "deny"
[[rule]]
name = "broad"
hosts = ["*.example.com"]
action = "allow"
[[rule]]
name = "shadowed"
hosts = ["api.example.com"]
action = "allow"
allow_secrets = ["ghost", "provider:nope"]
"#,
        )
        .unwrap();
        let warnings = p.lint(&[secret("svc", None)]);
        assert!(
            warnings.iter().any(|w| w.contains("'ghost'")),
            "{warnings:?}"
        );
        assert!(
            warnings.iter().any(|w| w.contains("provider:nope")),
            "{warnings:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("'shadowed'") && w.contains("'broad'")),
            "{warnings:?}"
        );
        // The shipped default policy lints clean against an empty vault.
        assert!(policy().lint(&[]).is_empty());
    }

    #[test]
    fn glob_cover_semantics() {
        assert!(glob_covers("*", "anything.example.com"));
        assert!(glob_covers("*.example.com", "api.example.com"));
        assert!(glob_covers("*.example.com", "*.sub.example.com"));
        assert!(glob_covers("*.example.com", "example.com"));
        assert!(!glob_covers("*.example.com", "example.org"));
        assert!(!glob_covers("api.example.com", "*.example.com"));
    }

    #[test]
    fn dlp_defaults_when_section_absent() {
        // Policies written before the [dlp] section existed keep parsing, and
        // land on the warn-first defaults: visible, never breaking.
        let p: Policy = toml::from_str("default_action = \"deny\"").unwrap();
        assert_eq!(p.dlp.pan, DlpMode::Warn);
        assert_eq!(p.dlp.ssn, DlpMode::Warn);
        assert_eq!(p.dlp.iban, DlpMode::Warn);
        assert_eq!(p.dlp.aba, DlpMode::Warn);
        assert_eq!(p.dlp.email, DlpMode::Off);
        assert!(p.dlp.allow.is_empty());
        assert!(!p.dlp.debug);
    }

    #[test]
    fn dlp_section_parses_modes_and_allowlist() {
        let p: Policy = toml::from_str(
            r#"
default_action = "deny"
[dlp]
pan = "mask"
ssn = "warn"
email = "block"
allow = ["4111 1111 1111 1111"]
debug = true
"#,
        )
        .unwrap();
        assert_eq!(p.dlp.pan, DlpMode::Mask);
        assert_eq!(p.dlp.ssn, DlpMode::Warn);
        assert_eq!(p.dlp.email, DlpMode::Block);
        // Unspecified detectors keep their defaults.
        assert_eq!(p.dlp.iban, DlpMode::Warn);
        assert_eq!(p.dlp.allow, vec!["4111 1111 1111 1111".to_string()]);
        assert!(p.dlp.debug);
    }

    #[test]
    fn default_policy_toml_carries_dlp_defaults() {
        let p = policy();
        assert_eq!(p.dlp.pan, DlpMode::Warn);
        assert_eq!(p.dlp.email, DlpMode::Off);
    }

    #[test]
    fn cache_config_defaults_off_and_parses_overrides() {
        // Absent section: the observe-only defaults, everything active off.
        let p: Policy = toml::from_str("default_action = \"deny\"").unwrap();
        assert!(!p.cache.repair);
        assert!(!p.cache.keep_alive);
        assert!(!p.cache.serialize_fanout);
        assert_eq!(p.cache.keep_alive_secs, 240);
        assert_eq!(p.cache.keep_alive_max, 6);
        assert_eq!(p.cache.fanout_timeout_ms, 2000);

        let p: Policy = toml::from_str(
            "default_action = \"deny\"\n[cache]\nrepair = true\nkeep_alive = true\n\
             keep_alive_secs = 5\nserialize_fanout = true\n",
        )
        .unwrap();
        assert!(p.cache.repair);
        assert!(p.cache.keep_alive);
        assert!(p.cache.serialize_fanout);
        assert_eq!(p.cache.keep_alive_secs, 5);
        // Unspecified knobs keep their defaults.
        assert_eq!(p.cache.keep_alive_max, 6);
    }

    #[test]
    fn shipped_default_policy_is_observe_only() {
        let p = policy();
        assert!(!p.cache.repair);
        assert!(!p.cache.keep_alive);
        assert!(!p.cache.serialize_fanout);
        assert!(!p.soft_landing.enabled());
    }

    #[test]
    fn soft_landing_defaults_off_and_parses_overrides() {
        // Absent section (including every policy written before it existed):
        // off, nothing rewrites.
        let p: Policy = toml::from_str("default_action = \"deny\"").unwrap();
        assert!(!p.soft_landing.enabled());
        assert_eq!(p.soft_landing.threshold_pct, 0.0);
        assert!(p.soft_landing.map.is_empty());

        let p: Policy = toml::from_str(
            "default_action = \"deny\"\n[soft_landing]\nthreshold_pct = 80\n\
             map = { \"claude-opus-4\" = \"claude-sonnet-5\", \"gpt-5\" = \"gpt-5-mini\" }\n",
        )
        .unwrap();
        assert!(p.soft_landing.enabled());
        assert_eq!(p.soft_landing.threshold_pct, 80.0);
        assert_eq!(p.soft_landing.map["claude-opus-4"], "claude-sonnet-5");
        assert_eq!(p.soft_landing.map["gpt-5"], "gpt-5-mini");

        // A threshold without a map (or a map without a threshold) stays off:
        // both halves are explicit opt-ins.
        let p: Policy =
            toml::from_str("default_action = \"deny\"\n[soft_landing]\nthreshold_pct = 80\n")
                .unwrap();
        assert!(!p.soft_landing.enabled());
        let p: Policy =
            toml::from_str("default_action = \"deny\"\n[soft_landing]\nmap = { \"a\" = \"b\" }\n")
                .unwrap();
        assert!(!p.soft_landing.enabled());
    }

    #[test]
    fn spend_tripwire_defaults_on_and_parses_overrides() {
        // Absent section (including every policy written before it existed):
        // the conservative defaults, in block mode. A safety feature defaults
        // on, unlike the paid conveniences above.
        let p: Policy = toml::from_str("default_action = \"deny\"").unwrap();
        assert_eq!(p.spend_tripwire.mode, TripwireMode::Block);
        assert_eq!(p.spend_tripwire.repeats, 15);
        assert_eq!(p.spend_tripwire.window_secs, 300);
        assert_eq!(p.spend_tripwire.rate_multiplier, 10.0);
        assert_eq!(p.spend_tripwire.rate_floor_usd, 5.0);

        // A partial table overrides just what it names.
        let p: Policy = toml::from_str(
            "default_action = \"deny\"\n[spend_tripwire]\nmode = \"alert\"\nrepeats = 30\n",
        )
        .unwrap();
        assert_eq!(p.spend_tripwire.mode, TripwireMode::Alert);
        assert_eq!(p.spend_tripwire.repeats, 30);
        assert_eq!(
            p.spend_tripwire.window_secs, 300,
            "unnamed fields keep defaults"
        );

        let p: Policy =
            toml::from_str("default_action = \"deny\"\n[spend_tripwire]\nmode = \"off\"\n")
                .unwrap();
        assert_eq!(p.spend_tripwire.mode, TripwireMode::Off);

        // The shipped default policy parses with the commented table intact.
        let p: Policy = toml::from_str(DEFAULT_POLICY_TOML).unwrap();
        assert_eq!(p.spend_tripwire.mode, TripwireMode::Block);
    }

    #[test]
    fn load_trusted_only_loads_what_decoyrail_wrote() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        // Fresh home: the materialized default is born trusted.
        assert!(Policy::load_trusted().is_ok());

        // One appended byte: untrusted, with the cure named.
        let path = crate::config::policy_path().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, format!("{text}#")).unwrap();
        let err = Policy::load_trusted().unwrap_err();
        assert!(matches!(err, LoadError::Untrusted(_)), "{err:?}");
        let msg = err.into_anyhow().to_string();
        assert!(msg.contains("policy sign"), "{msg}");
        // CLI read paths still parse the untrusted file (they report on it,
        // and `policy ls` says it is untrusted; they release nothing).
        assert!(Policy::load_or_default().is_ok());

        // Byte-identical restore: trusted again, no blessing needed.
        std::fs::write(&path, &text).unwrap();
        assert!(Policy::load_trusted().is_ok());

        // Record deleted, file untouched: absence of proof is absence of
        // trust, never a cue to re-bless silently.
        std::fs::remove_file(crate::config::policy_sig_path().unwrap()).unwrap();
        assert!(matches!(
            Policy::load_trusted(),
            Err(LoadError::Untrusted(_))
        ));
    }

    #[test]
    fn deleted_policy_with_record_is_an_edit() {
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        assert!(Policy::load_trusted().is_ok());
        std::fs::remove_file(crate::config::policy_path().unwrap()).unwrap();

        // Neither load may re-materialize a default over the evidence.
        let err = Policy::load_trusted().unwrap_err();
        assert!(matches!(err, LoadError::Untrusted(_)), "{err:?}");
        assert!(err.into_anyhow().to_string().contains("policy reset"));
        assert!(Policy::load_or_default().is_err());
        assert!(!crate::config::policy_path().unwrap().exists());
    }

    /// An unreadable record is the ordinary broken-file error (`Other`), not
    /// the tamper story: nothing claims an edit happened, the load just
    /// cannot prove anything either way and fails closed with the cause.
    #[cfg(unix)]
    #[test]
    fn unreadable_record_is_other_not_tamper() {
        use std::os::unix::fs::PermissionsExt;
        let _g = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        assert!(Policy::load_trusted().is_ok());
        let sig = crate::config::policy_sig_path().unwrap();
        std::fs::set_permissions(&sig, std::fs::Permissions::from_mode(0o000)).unwrap();
        let err = Policy::load_trusted().unwrap_err();
        assert!(matches!(err, LoadError::Other(_)), "{err:?}");
        assert!(err.into_anyhow().to_string().contains("reading"));
        std::fs::set_permissions(&sig, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Policy::load_trusted().is_ok());
    }

    #[test]
    fn warn_parses_everywhere_an_action_is_accepted() {
        assert_eq!(Action::parse("warn").unwrap(), Action::Warn);
        assert_eq!(Action::parse("WARN").unwrap(), Action::Warn);
        assert_eq!(Action::Warn.as_str(), "warn");
        let p: Policy = toml::from_str(
            r#"
default_action = "warn"
escalate_fallback = "warn"
[[rule]]
name = "watched"
hosts = ["api.example.com"]
action = "warn"
"#,
        )
        .unwrap();
        assert_eq!(p.default_action, Action::Warn);
        assert_eq!(p.escalate_fallback, Action::Warn);
        assert_eq!(p.rules[0].action, Action::Warn);
    }

    #[test]
    fn warn_default_forwards_unmatched_named_rules_still_win() {
        let p: Policy = toml::from_str(
            r#"
default_action = "warn"
[[rule]]
name = "blocked"
hosts = ["evil.example.com"]
action = "deny"
[[rule]]
name = "second-look"
hosts = ["pastebin.example.com"]
action = "escalate"
"#,
        )
        .unwrap();
        let d = p.evaluate("unknown.example.com", "/", "POST");
        assert_eq!(d.action, Action::Warn);
        assert_eq!(d.rule, "default");
        // Named deny and escalate rules keep winning over the warn default.
        assert_eq!(
            p.evaluate("evil.example.com", "/", "POST").action,
            Action::Deny
        );
        let d = p.evaluate("pastebin.example.com", "/", "POST");
        assert!(d.escalated);
        assert_eq!(d.action, Action::Deny);
    }

    #[test]
    fn warn_never_releases_but_expects_listed_secrets() {
        let p: Policy = toml::from_str(
            r#"
default_action = "deny"
[[rule]]
name = "watched"
hosts = ["api.example.com"]
action = "warn"
allow_secrets = ["svc"]
"#,
        )
        .unwrap();
        let d = p.evaluate("api.example.com", "/v1/x", "POST");
        assert_eq!(d.action, Action::Warn);
        assert!(!d.releases(&secret("svc", None)), "warn must never swap");
        assert!(d.expects(&secret("svc", None)), "but no honeytoken alarm");
        assert!(!d.expects(&secret("other", None)));
    }

    #[test]
    fn route_parses_carries_map_and_releases_like_allow() {
        assert_eq!(Action::parse("route").unwrap(), Action::Route);
        assert_eq!(Action::parse("ROUTE").unwrap(), Action::Route);
        assert_eq!(Action::Route.as_str(), "route");
        let p: Policy = toml::from_str(
            r#"
default_action = "deny"
[[rule]]
name = "routed"
hosts = ["api.example.com"]
action = "route"
allow_secrets = ["svc"]
route = { "claude-opus-4" = "claude-sonnet-5" }
"#,
        )
        .unwrap();
        let d = p.evaluate("api.example.com", "/v1/x", "POST");
        assert_eq!(d.action, Action::Route);
        assert_eq!(d.rule, "routed");
        // The winning rule's map rides the decision for the pipeline.
        assert_eq!(d.route["claude-opus-4"], "claude-sonnet-5");
        // Policy-wise a route rule is an allow: it releases and expects its
        // listed secrets exactly the same way.
        assert!(d.releases(&secret("svc", None)));
        assert!(d.expects(&secret("svc", None)));
        assert!(!d.releases(&secret("other", None)));
        assert_eq!(p.releasing_rules(&secret("svc", None)).len(), 1);
        // A non-route decision carries no map.
        let d = p.evaluate("evil.example.com", "/", "POST");
        assert!(d.route.is_empty());
    }

    #[test]
    fn deny_above_route_wins_and_route_map_defaults_empty() {
        // First-match-wins gives deny/escalate precedence over a route rule
        // with no new machinery, exactly as over an allow.
        let p: Policy = toml::from_str(
            r#"
default_action = "deny"
[[rule]]
name = "blocked"
hosts = ["api.example.com"]
path_prefixes = ["/blocked"]
action = "deny"
[[rule]]
name = "routed"
hosts = ["api.example.com"]
action = "route"
route = { "claude-opus-4" = "claude-sonnet-5" }
"#,
        )
        .unwrap();
        let d = p.evaluate("api.example.com", "/blocked/x", "POST");
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.rule, "blocked");
        assert_eq!(
            p.evaluate("api.example.com", "/v1/x", "POST").action,
            Action::Route
        );
        // A rule without the key parses with an empty map (every policy
        // written before plan 006 keeps loading).
        let p: Policy = toml::from_str(
            "default_action = \"deny\"\n[[rule]]\nname = \"r\"\n\
             hosts = [\"x.example.com\"]\naction = \"route\"\n",
        )
        .unwrap();
        assert!(p.rules[0].route.is_empty());
    }

    #[test]
    fn lint_routes_flags_empty_maps_and_unpriced_targets() {
        let pricing = crate::pricing::Pricing::default();
        let p: Policy = toml::from_str(
            r#"
default_action = "deny"
[[rule]]
name = "empty-map"
hosts = ["a.example.com"]
action = "route"
[[rule]]
name = "typo"
hosts = ["b.example.com"]
action = "route"
route = { "claude-opus-4" = "claude-sonet-5" }
[[rule]]
name = "fine"
hosts = ["c.example.com"]
action = "route"
route = { "claude-opus-4" = "claude-sonnet-5" }
[[rule]]
name = "not-a-route"
hosts = ["d.example.com"]
action = "allow"
"#,
        )
        .unwrap();
        let warnings = p.lint_routes(&pricing);
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("'empty-map'") && w.contains("empty")),
            "{warnings:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("'typo'") && w.contains("claude-sonet-5")),
            "{warnings:?}"
        );
        // The shipped default (no route rules) lints route-clean.
        assert!(policy().lint_routes(&pricing).is_empty());
    }

    #[test]
    fn escalate_resolves_through_warn_fallback() {
        let p: Policy = toml::from_str(
            r#"
default_action = "deny"
escalate_fallback = "warn"
[[rule]]
name = "second-look"
hosts = ["pastebin.example.com"]
action = "escalate"
"#,
        )
        .unwrap();
        let d = p.evaluate("pastebin.example.com", "/", "POST");
        assert_eq!(d.action, Action::Warn);
        assert!(d.escalated, "the event still records the escalation");
    }

    #[test]
    fn escalate_fallback_of_escalate_fails_closed() {
        // A hand-edited fallback of "escalate" must not resolve to an action
        // the pipeline would forward.
        let p: Policy = toml::from_str(
            r#"
default_action = "deny"
escalate_fallback = "escalate"
[[rule]]
name = "loop"
hosts = ["api.example.com"]
action = "escalate"
"#,
        )
        .unwrap();
        let d = p.evaluate("api.example.com", "/", "POST");
        assert_eq!(d.action, Action::Deny);
        assert!(d.escalated);
    }

    #[test]
    fn path_scoped_deny_beats_broader_allow() {
        // First-match-wins: a path-scoped deny placed above a whole-host allow
        // carves that sub-path out of the allowance.
        let p: Policy = toml::from_str(
            r#"
default_action = "deny"

[[rule]]
name = "no-event-logging"
hosts = ["api.anthropic.com"]
path_prefixes = ["/api/event_logging/"]
action = "deny"

[[rule]]
name = "anthropic"
hosts = ["api.anthropic.com"]
action = "allow"
"#,
        )
        .unwrap();
        assert_eq!(
            p.evaluate("api.anthropic.com", "/api/event_logging/v2/batch", "POST")
                .action,
            Action::Deny
        );
        assert_eq!(
            p.evaluate("api.anthropic.com", "/v1/messages", "POST")
                .action,
            Action::Allow
        );
    }
}
