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
//! secret's decoy blocks quietly with the request instead of sounding the
//! honeytoken alarm (the agent's own credential riding a denied telemetry
//! call is not an exfil signal). A decoy the winning rule does not expect is
//! always a tripwire.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config;
use crate::vault::{glob_match, Secret, PROVIDER_LABELS};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
    /// Defer to judge/human. Resolves to `escalate_fallback` until v0.5.
    Escalate,
}

impl Action {
    /// The lowercase spelling used in policy.toml and the CLI.
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Escalate => "escalate",
        }
    }

    /// Parse an action from CLI/user input (case-insensitive).
    pub fn parse(s: &str) -> Result<Action> {
        match s.to_ascii_lowercase().as_str() {
            "allow" => Ok(Action::Allow),
            "deny" => Ok(Action::Deny),
            "escalate" => Ok(Action::Escalate),
            other => Err(anyhow::anyhow!(
                "unknown action '{other}' (use allow|deny|escalate)"
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
    /// the real value) only when the rule resolves to allow.
    #[serde(default)]
    pub allow_secrets: Vec<String>,
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
}

impl Decision {
    /// The winning rule releases this secret: swap decoy for real (transport
    /// and location checks still apply).
    pub fn releases(&self, secret: &Secret) -> bool {
        self.action == Action::Allow && lists_secret(&self.allow_secrets, secret)
    }

    /// The winning rule expects this secret here even though the request is
    /// blocked: no swap, but no honeytoken alarm either.
    pub fn expects(&self, secret: &Secret) -> bool {
        lists_secret(&self.allow_secrets, secret)
    }
}

impl Policy {
    pub fn load_or_default() -> Result<Self> {
        config::ensure_home()?;
        let path = config::policy_path()?;
        if !path.exists() {
            std::fs::write(&path, DEFAULT_POLICY_TOML)?;
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let policy: Policy = toml::from_str(&text).context("parsing policy.toml")?;
        Ok(policy)
    }

    pub fn evaluate(&self, host: &str, path: &str, method: &str) -> Decision {
        for rule in &self.rules {
            if rule.matches(host, path, method) {
                return self.resolve(rule.action, rule.name.clone(), rule.allow_secrets.clone());
            }
        }
        self.resolve(self.default_action, "default".into(), Vec::new())
    }

    fn resolve(&self, action: Action, rule: String, allow_secrets: Vec<String>) -> Decision {
        match action {
            Action::Escalate => Decision {
                action: self.escalate_fallback,
                rule,
                escalated: true,
                allow_secrets,
            },
            other => Decision {
                action: other,
                rule,
                escalated: false,
                allow_secrets,
            },
        }
    }

    /// Rules that can release this secret (allow rules listing it), for
    /// `vault ls` and the `decoyrail run` startup report.
    pub fn releasing_rules(&self, secret: &Secret) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|r| r.action == Action::Allow && lists_secret(&r.allow_secrets, secret))
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
