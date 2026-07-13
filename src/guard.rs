//! Session vault: auto-decoy sensitive values from the terminal environment
//! for `decoyrail run`.
//!
//! Vault entries protect the secrets the user explicitly added; everything
//! else in the shell environment (provider keys, CI tokens, DB passwords)
//! would otherwise pass into the agent as-is. `decoyrail run` scans the
//! environment it inherited, replaces anything sensitive-looking with a
//! deterministic decoy, and registers the pair in an in-memory session vault
//! so the proxy swaps (recognized provider formats, at rules that release
//! their `provider:<label>`) or tripwires (everything else) exactly as for
//! persistent entries. Session secrets never touch disk and die with the run.

use crate::vault::{infer_provider, make_decoy, Location, Secret, Vault};

/// Env-var name fragments that mark a variable as credential-shaped
/// (substring match on the uppercased name).
const NAME_FRAGMENTS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "APIKEY",
    "API_KEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
];

/// Name markers that only match as a whole `_`-separated segment: a substring
/// match on AUTH would catch GIT_AUTHOR_NAME and SSH_AUTH_SOCK.
const NAME_SEGMENTS: &[&str] = &["AUTH"];

/// Value prefixes that are recognizably credentials but map to no provider
/// label (tripwire-only). Recognized provider formats are labeled by
/// `vault::infer_provider`, and the policy decides which hosts release each
/// label (the shipped default releases them at that provider's API).
const SHAPE_ONLY: &[&str] = &["AKIA", "AIza", "glsa_", "dop_v1_", "pypi-"];

fn name_sensitive(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    if NAME_FRAGMENTS.iter().any(|f| upper.contains(f)) {
        return true;
    }
    NAME_SEGMENTS
        .iter()
        .any(|seg| upper.split('_').any(|part| part == *seg))
}

fn value_sensitive(value: &str) -> bool {
    if infer_provider(value).is_some() || SHAPE_ONLY.iter().any(|p| value.starts_with(p)) {
        return true;
    }
    // PEM private key material.
    if value.contains("-----BEGIN") && value.contains("PRIVATE KEY") {
        return true;
    }
    // Connection string with inline credentials (scheme://user:pass@host).
    connection_string_with_password(value)
}

/// `scheme://user:password@host` — the same shape `make_decoy` special-cases.
fn connection_string_with_password(value: &str) -> bool {
    let Some((_, rest)) = value.split_once("://") else {
        return false;
    };
    let Some((userinfo, _)) = rest.split_once('@') else {
        return false;
    };
    userinfo.contains(':')
}

/// Values that are clearly not secrets even under a sensitive name:
/// filesystem paths (SSH_AUTH_SOCK, *_TOKEN_FILE) and short flag-like values.
fn value_exempt(value: &str) -> bool {
    value.len() < 8 || value.starts_with('/') || value.starts_with("./") || value.starts_with('~')
}

/// Scan an environment for sensitive-looking variables and build session
/// secrets for them. Skips variables named in `pass`, variables a vault entry
/// already injects (`--env`), and values the vault already knows (as a real
/// value or as a decoy — e.g. a nested `decoyrail run`).
pub fn detect_env(
    env: impl Iterator<Item = (String, String)>,
    vault: &Vault,
    pass: &[String],
) -> Vec<Secret> {
    let mut out: Vec<Secret> = Vec::new();
    for (name, value) in env {
        if pass.contains(&name) {
            continue;
        }
        if value_exempt(&value) {
            continue;
        }
        if !(name_sensitive(&name) || value_sensitive(&value)) {
            continue;
        }
        if vault
            .secrets
            .iter()
            .any(|s| s.env.as_deref() == Some(name.as_str()))
        {
            continue; // the vault entry's decoy takes over this variable
        }
        if vault
            .secrets
            .iter()
            .any(|s| s.real == value || s.decoy == value)
        {
            continue; // already vaulted under another variable, or already a decoy
        }
        let entry_name = format!("env:{name}");
        let decoy = make_decoy(&entry_name, &value);
        // A recognized provider format gets its label so the policy's
        // `provider:<label>` rules release it; anything else is a pure
        // tripwire until a rule names it.
        let provider = infer_provider(&value).map(str::to_string);
        out.push(Secret {
            name: entry_name,
            real: value.clone(),
            decoy,
            env: Some(name),
            location: Location::Any,
            provider,
        });
    }
    // std::env::vars order is arbitrary; sort so output and audit are stable.
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_vault() -> Vault {
        Vault::default()
    }

    fn detect_one(name: &str, value: &str) -> Vec<Secret> {
        detect_env(
            vec![(name.to_string(), value.to_string())].into_iter(),
            &empty_vault(),
            &[],
        )
    }

    #[test]
    fn sensitive_names_are_detected() {
        for name in [
            "GITHUB_TOKEN",
            "MY_SECRET",
            "DB_PASSWORD",
            "STRIPE_API_KEY",
            "NPM_AUTH",
            "SERVICE_CREDENTIALS",
        ] {
            let got = detect_one(name, "hunter2-longer-value");
            assert_eq!(got.len(), 1, "{name} should be detected");
            assert_eq!(got[0].env.as_deref(), Some(name));
            assert_ne!(got[0].decoy, got[0].real);
        }
    }

    #[test]
    fn author_and_socket_vars_are_not_false_positives() {
        assert!(detect_one("GIT_AUTHOR_EMAIL", "long@example.com").is_empty());
        assert!(detect_one("GIT_AUTHOR_NAME", "Long Example").is_empty());
        // Path value exempts even a segment-matching name.
        assert!(detect_one("SSH_AUTH_SOCK", "/private/tmp/agent.sock").is_empty());
        assert!(detect_one("API_TOKEN_FILE", "/run/secrets/token").is_empty());
    }

    #[test]
    fn short_and_flag_values_are_skipped() {
        assert!(detect_one("DEBUG_AUTH", "1").is_empty());
        assert!(detect_one("USE_TOKEN", "true").is_empty());
    }

    #[test]
    fn value_shape_detected_under_any_name() {
        let got = detect_one("WHATEVER", "sk-ant-api03-abcdefgh");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].provider.as_deref(), Some("anthropic"));

        let got = detect_one("SOMETHING", "postgres://app:s3cr3tpass@db.internal:5432/x");
        assert_eq!(got.len(), 1);
        assert!(got[0].provider.is_none(), "conn string is tripwire-only");
    }

    #[test]
    fn provider_labels_and_tripwire_only() {
        let got = detect_one("GITHUB_TOKEN", "ghp_abcdefghijklmnop");
        assert_eq!(got[0].provider.as_deref(), Some("github"));

        // AWS signs with the secret; no provider label, no swap destination.
        let got = detect_one("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG");
        assert!(got[0].provider.is_none());
        let got = detect_one("X", "AKIAIOSFODNN7EXAMPLE");
        assert!(got[0].provider.is_none());
    }

    #[test]
    fn pass_list_and_vault_coverage_skip() {
        let mut vault = empty_vault();
        vault.secrets.push(Secret {
            name: "anthropic".into(),
            real: "sk-ant-real-value-xyz".into(),
            decoy: "sk-ant-decoy-value-xyz".into(),
            env: Some("ANTHROPIC_API_KEY".into()),
            location: Location::Any,
            provider: Some("anthropic".into()),
        });
        let env = vec![
            // --pass-env exemption
            ("GITHUB_TOKEN".to_string(), "ghp_abcdefghijklm".to_string()),
            // vault entry already owns this env var
            (
                "ANTHROPIC_API_KEY".to_string(),
                "sk-ant-whatever-value".to_string(),
            ),
            // value already vaulted under a different name
            (
                "COPY_OF_KEY".to_string(),
                "sk-ant-real-value-xyz".to_string(),
            ),
            // value is an existing decoy (nested decoyrail run)
            (
                "NESTED_TOKEN".to_string(),
                "sk-ant-decoy-value-xyz".to_string(),
            ),
        ];
        let got = detect_env(env.into_iter(), &vault, &["GITHUB_TOKEN".to_string()]);
        assert!(got.is_empty(), "all four must be skipped, got {got:?}");
    }

    #[test]
    fn decoys_are_deterministic_across_runs() {
        let a = detect_one("GITHUB_TOKEN", "ghp_abcdefghijklmnop");
        let b = detect_one("GITHUB_TOKEN", "ghp_abcdefghijklmnop");
        assert_eq!(a[0].decoy, b[0].decoy);
    }
}
