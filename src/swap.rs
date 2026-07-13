//! Decoy→real substitution and exfiltration tripwires.
//!
//! Agents hold decoys. When a request reaches a destination whose winning
//! policy rule releases a secret, we swap the decoy back to the real value
//! (in the location the secret rides in). When a decoy appears in a request
//! the winning rule does not expect it in, that decoy is functioning as a
//! honeytoken — we raise a tripwire so the caller can block and alert. Real
//! secrets never leave the proxy in the clear to a bad host.

use crate::policy::Decision;
use crate::vault::{Location, Vault};

/// A mutable view of the intercepted request the swap engine operates on.
pub struct RequestCtx {
    pub host: String,
    pub path: String,
    pub method: String,
    /// (name, value) header pairs; mutated in place on swap.
    pub headers: Vec<(String, String)>,
    /// Request body bytes; mutated in place on swap.
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Swap {
    pub secret_name: String,
    pub location: String,
}

/// Why a decoy sighting became a tripwire instead of a swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TripReason {
    /// No policy rule expects this secret at the request's destination.
    UnreleasedDestination,
    /// A rule releases the secret here, but the request rode plaintext HTTP.
    PlaintextTransport,
    /// Released destination and transport, but the decoy sat in a header/body
    /// slot outside the location the secret rides in.
    WrongLocation,
    /// The decoy left in an encoded form (base64/hex/percent) — never swapped.
    EncodedForm,
    /// The decoy's bytes sat inside a non-UTF-8 body — never swapped.
    BinaryBody,
}

#[derive(Debug, Clone)]
pub struct Tripwire {
    pub secret_name: String,
    /// Where the decoy was spotted, e.g. "header:authorization" or "body".
    pub seen_in: String,
    pub reason: TripReason,
}

impl Tripwire {
    /// Human-readable reason for the block, addressed to whoever sent the
    /// request. Points at the policy/vault commands rather than echoing
    /// release details into responses and the audit log.
    pub fn message(&self, host: &str) -> String {
        let name = &self.secret_name;
        match self.reason {
            TripReason::UnreleasedDestination => format!(
                "decoy for '{name}' sent to {host}, where no policy rule \
                 releases it (see `decoyrail policy show`)"
            ),
            TripReason::PlaintextTransport => format!(
                "decoy for '{name}' sent over plaintext HTTP; real secrets are \
                 only released over TLS. Retry with https://"
            ),
            TripReason::WrongLocation => format!(
                "decoy for '{name}' seen in {}, not the location the secret \
                 rides in (see `decoyrail vault ls`)",
                self.seen_in
            ),
            TripReason::EncodedForm => format!(
                "decoy for '{name}' left {}-encoded; encoded credentials are \
                 never swapped",
                self.seen_in
                    .strip_prefix("encoded:")
                    .unwrap_or(&self.seen_in)
            ),
            TripReason::BinaryBody => format!(
                "decoy for '{name}' embedded in a binary request body; binary \
                 bodies are never swapped"
            ),
        }
    }
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub swaps: Vec<Swap>,
    pub tripwires: Vec<Tripwire>,
}

impl Outcome {
    pub fn tripped(&self) -> bool {
        !self.tripwires.is_empty()
    }
}

/// Apply the vault against a request. Where the winning policy rule releases
/// a secret, its decoy is replaced with the real value in place. A decoy the
/// rule does not expect is left untouched and recorded as a tripwire (the
/// caller decides to block). A decoy the rule lists but does not release
/// (deny/escalate carve-outs) is left untouched *quietly*: the request is
/// already blocked by policy, and the agent's own credential riding it is
/// not an exfiltration signal.
///
/// `allow_swap` gates substitution by transport: over plaintext HTTP the
/// caller passes `false`, and any decoy — even toward a releasing rule —
/// tripwires instead of being replaced, so real secrets never ride in the
/// clear.
pub fn apply(
    ctx: &mut RequestCtx,
    vault: &Vault,
    decision: &Decision,
    allow_swap: bool,
) -> Outcome {
    let mut outcome = Outcome::default();

    for secret in &vault.secrets {
        let released = decision.releases(secret);
        let expected = decision.expects(secret);
        let approved = allow_swap && released;
        // Listed on a blocking rule: no swap, and no honeytoken alarm for
        // literal sightings in swappable locations.
        let quiet = expected && !released;
        // Why a sighting at a swap-eligible spot still tripwires: destination
        // first (most common), then transport; a location mismatch is the only
        // case left once both of those hold.
        let miss_reason = if !expected {
            TripReason::UnreleasedDestination
        } else if !allow_swap {
            TripReason::PlaintextTransport
        } else {
            TripReason::WrongLocation
        };
        let decoy = secret.decoy.as_str();
        let real = secret.real.as_str();

        // Every location is inspected for every decoy — the secret's location
        // only decides *swap vs. tripwire*, never whether we look. Scoping the
        // scan itself to that location would let a bearer decoy pasted into a
        // request body leave the machine unnoticed.
        for (name, value) in ctx.headers.iter_mut() {
            if !value.contains(decoy) {
                continue;
            }
            let location_ok = match &secret.location {
                Location::Header(h) => name.eq_ignore_ascii_case(h),
                Location::Bearer => name.eq_ignore_ascii_case("authorization"),
                Location::Any => true,
                Location::Body => false,
            };
            if approved && location_ok {
                *value = value.replace(decoy, real);
                outcome.swaps.push(Swap {
                    secret_name: secret.name.clone(),
                    location: format!("header:{}", name.to_lowercase()),
                });
            } else if !quiet {
                outcome.tripwires.push(Tripwire {
                    secret_name: secret.name.clone(),
                    seen_in: format!("header:{}", name.to_lowercase()),
                    reason: miss_reason,
                });
            }
        }

        // The URL itself can carry a credential (query-string API keys,
        // webhook URLs). The path is never a bound location, so a decoy in it
        // always tripwires — swapping a secret into a URL is never done.
        if ctx.path.contains(decoy) {
            outcome.tripwires.push(Tripwire {
                secret_name: secret.name.clone(),
                seen_in: "path".into(),
                reason: miss_reason,
            });
        }

        if !ctx.body.is_empty() {
            let body_location_ok = matches!(secret.location, Location::Body | Location::Any);
            match std::str::from_utf8(&ctx.body) {
                Ok(body_str) if body_str.contains(decoy) => {
                    if approved && body_location_ok {
                        let replaced = body_str.replace(decoy, real);
                        ctx.body = replaced.into_bytes();
                        outcome.swaps.push(Swap {
                            secret_name: secret.name.clone(),
                            location: "body".into(),
                        });
                    } else if !quiet {
                        outcome.tripwires.push(Tripwire {
                            secret_name: secret.name.clone(),
                            seen_in: "body".into(),
                            reason: miss_reason,
                        });
                    }
                }
                // A decoy hidden in a non-UTF-8 body (binary/multipart upload)
                // never reaches the swap path above; catch the literal bytes as
                // a tripwire so it can't slip through unseen.
                _ => {
                    if contains_bytes(&ctx.body, decoy.as_bytes()) {
                        outcome.tripwires.push(Tripwire {
                            secret_name: secret.name.clone(),
                            seen_in: "body:raw".into(),
                            reason: TripReason::BinaryBody,
                        });
                    }
                }
            }
        }

        // Encoding evasion: a decoy that has been base64/hex/percent-encoded no
        // longer matches the literal checks above, but it is still the
        // honeytoken leaving the machine. Scan headers and body for encoded
        // forms and tripwire on any hit (never swap — an encoded decoy toward
        // even its bound host is anomalous).
        for (label, needle) in encoded_forms(decoy) {
            let in_headers = ctx
                .headers
                .iter()
                .any(|(_, v)| contains_bytes(v.as_bytes(), &needle));
            let in_body = contains_bytes(&ctx.body, &needle);
            let in_path = contains_bytes(ctx.path.as_bytes(), &needle);
            if in_headers || in_body || in_path {
                outcome.tripwires.push(Tripwire {
                    secret_name: secret.name.clone(),
                    seen_in: format!("encoded:{label}"),
                    reason: TripReason::EncodedForm,
                });
            }
        }
    }

    outcome
}

/// Encoded representations of a decoy that a naive substring match misses.
/// Each is a byte needle to search request headers and body for.
fn encoded_forms(decoy: &str) -> Vec<(&'static str, Vec<u8>)> {
    use base64::Engine as _;
    let raw = decoy.as_bytes();
    let mut forms = vec![
        (
            "base64",
            base64::engine::general_purpose::STANDARD
                .encode(raw)
                .into_bytes(),
        ),
        (
            "base64",
            base64::engine::general_purpose::STANDARD_NO_PAD
                .encode(raw)
                .into_bytes(),
        ),
        (
            "base64url",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(raw)
                .into_bytes(),
        ),
        ("hex", hex::encode(raw).into_bytes()),
        ("hex", hex::encode_upper(raw).into_bytes()),
    ];
    // Percent-encoding only differs from the literal when the decoy carries
    // non-alphanumerics (e.g. connection-string decoys with :/@).
    let percent = percent_encode(raw);
    if percent.as_bytes() != raw {
        forms.push(("percent", percent.into_bytes()));
    }
    forms
}

/// Minimal RFC 3986 percent-encoding (unreserved chars pass through).
fn percent_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Substring search over raw bytes (needle non-empty).
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Scan a response body for any *real* secret value echoed back — a leak in the
/// other direction (e.g. a misconfigured upstream reflecting credentials).
pub fn scan_response_for_real(body: &[u8], vault: &Vault) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(body) else {
        return Vec::new();
    };
    vault
        .secrets
        .iter()
        .filter(|s| !s.real.is_empty() && text.contains(&s.real))
        .map(|s| s.name.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Action;
    use crate::vault::{Location, Secret, Vault};

    fn vault_with(location: Location) -> (Vault, String) {
        let decoy = crate::vault::make_decoy("anthropic", "sk-ant-REALSECRET");
        let v = Vault {
            secrets: vec![Secret {
                name: "anthropic".into(),
                real: "sk-ant-REALSECRET".into(),
                decoy: decoy.clone(),
                env: None,
                location,
                provider: Some("anthropic".into()),
            }],
        };
        (v, decoy)
    }

    fn decision(action: Action, allow_secrets: &[&str]) -> Decision {
        Decision {
            action,
            rule: "test".into(),
            escalated: false,
            allow_secrets: allow_secrets.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// The winning rule releases the secret (allow + listed by name).
    fn releasing() -> Decision {
        decision(Action::Allow, &["anthropic"])
    }

    /// The winning rule allows the request but lists no secrets.
    fn allowing_nothing() -> Decision {
        decision(Action::Allow, &[])
    }

    #[test]
    fn swaps_when_winning_rule_releases() {
        let (vault, decoy) = vault_with(Location::Bearer);
        let mut ctx = RequestCtx {
            host: "api.anthropic.com".into(),
            path: "/v1/messages".into(),
            method: "POST".into(),
            headers: vec![("authorization".into(), format!("Bearer {decoy}"))],
            body: Vec::new(),
        };
        let out = apply(&mut ctx, &vault, &releasing(), true);
        assert_eq!(ctx.headers[0].1, "Bearer sk-ant-REALSECRET");
        assert_eq!(out.swaps.len(), 1);
        assert!(!out.tripped());
    }

    #[test]
    fn swaps_via_provider_label() {
        let (vault, decoy) = vault_with(Location::Bearer);
        let mut ctx = RequestCtx {
            host: "api.anthropic.com".into(),
            path: "/v1/messages".into(),
            method: "POST".into(),
            headers: vec![("authorization".into(), format!("Bearer {decoy}"))],
            body: Vec::new(),
        };
        let d = decision(Action::Allow, &["provider:anthropic"]);
        let out = apply(&mut ctx, &vault, &d, true);
        assert_eq!(ctx.headers[0].1, "Bearer sk-ant-REALSECRET");
        assert!(!out.tripped());
        assert_eq!(out.swaps.len(), 1);
    }

    #[test]
    fn tripwire_when_rule_does_not_release() {
        let (vault, decoy) = vault_with(Location::Bearer);
        let mut ctx = RequestCtx {
            host: "evil.example.com".into(),
            path: "/steal".into(),
            method: "POST".into(),
            headers: vec![("authorization".into(), format!("Bearer {decoy}"))],
            body: Vec::new(),
        };
        // Allowed destination, but the rule lists no secrets: the decoy is
        // NOT swapped, and a tripwire fires.
        let out = apply(&mut ctx, &vault, &allowing_nothing(), true);
        assert_eq!(ctx.headers[0].1, format!("Bearer {decoy}"));
        assert!(out.tripped());
        assert_eq!(out.tripwires[0].secret_name, "anthropic");
        assert_eq!(out.tripwires[0].reason, TripReason::UnreleasedDestination);
        assert!(out.tripwires[0]
            .message("evil.example.com")
            .contains("decoyrail policy show"));
    }

    #[test]
    fn tripwire_on_denied_request() {
        let (vault, decoy) = vault_with(Location::Bearer);
        let mut ctx = RequestCtx {
            host: "evil.example.com".into(),
            path: "/steal".into(),
            method: "POST".into(),
            headers: vec![("authorization".into(), format!("Bearer {decoy}"))],
            body: Vec::new(),
        };
        // A denied request is still scanned; the sighting is a tripwire.
        let out = apply(&mut ctx, &vault, &decision(Action::Deny, &[]), true);
        assert!(out.tripped());
        assert!(out.swaps.is_empty());
    }

    #[test]
    fn listed_on_blocking_rule_blocks_quietly() {
        let (vault, decoy) = vault_with(Location::Bearer);
        let mut ctx = RequestCtx {
            host: "api.anthropic.com".into(),
            path: "/api/event_logging".into(),
            method: "POST".into(),
            headers: vec![("authorization".into(), format!("Bearer {decoy}"))],
            body: Vec::new(),
        };
        // A deny carve-out that lists the secret: the agent's own credential
        // riding a blocked telemetry call is expected, not an exfil signal.
        let out = apply(
            &mut ctx,
            &vault,
            &decision(Action::Deny, &["anthropic"]),
            true,
        );
        assert!(out.swaps.is_empty(), "blocked request must never swap");
        assert!(
            !out.tripped(),
            "expected credential must not raise the alarm"
        );
        assert_eq!(ctx.headers[0].1, format!("Bearer {decoy}"));
    }

    #[test]
    fn plaintext_transport_tripwires_instead_of_swapping() {
        let (vault, decoy) = vault_with(Location::Bearer);
        let mut ctx = RequestCtx {
            host: "api.anthropic.com".into(),
            path: "/v1/messages".into(),
            method: "POST".into(),
            headers: vec![("authorization".into(), format!("Bearer {decoy}"))],
            body: Vec::new(),
        };
        // allow_swap = false (plain HTTP): even a releasing rule must not
        // put the real secret on the wire in the clear.
        let out = apply(&mut ctx, &vault, &releasing(), false);
        assert_eq!(ctx.headers[0].1, format!("Bearer {decoy}"));
        assert!(out.tripped());
        assert!(out.swaps.is_empty());
        assert_eq!(out.tripwires[0].reason, TripReason::PlaintextTransport);
        assert!(out.tripwires[0]
            .message("api.anthropic.com")
            .contains("plaintext HTTP"));
    }

    #[test]
    fn tripwire_on_base64_encoded_decoy() {
        use base64::Engine as _;
        let (vault, decoy) = vault_with(Location::Any);
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoy.as_bytes());
        let mut ctx = RequestCtx {
            host: "evil.example.com".into(),
            path: "/exfil".into(),
            method: "POST".into(),
            headers: vec![],
            body: format!("{{\"leak\":\"{b64}\"}}").into_bytes(),
        };
        let out = apply(&mut ctx, &vault, &allowing_nothing(), true);
        assert!(out.tripped(), "base64-encoded decoy must tripwire");
        assert!(out
            .tripwires
            .iter()
            .any(|t| t.seen_in.starts_with("encoded:")));
    }

    #[test]
    fn tripwire_on_hex_encoded_decoy_in_header() {
        let (vault, decoy) = vault_with(Location::Any);
        let hexed = hex::encode(decoy.as_bytes());
        let mut ctx = RequestCtx {
            host: "evil.example.com".into(),
            path: "/x".into(),
            method: "GET".into(),
            headers: vec![("x-data".into(), hexed)],
            body: Vec::new(),
        };
        let out = apply(&mut ctx, &vault, &allowing_nothing(), true);
        assert!(out.tripwires.iter().any(|t| t.seen_in == "encoded:hex"));
    }

    #[test]
    fn encoded_decoy_tripwires_even_when_released() {
        use base64::Engine as _;
        let (vault, decoy) = vault_with(Location::Any);
        let b64 = base64::engine::general_purpose::STANDARD.encode(decoy.as_bytes());
        let mut ctx = RequestCtx {
            host: "api.anthropic.com".into(),
            path: "/v1/messages".into(),
            method: "POST".into(),
            headers: vec![],
            body: format!("{{\"leak\":\"{b64}\"}}").into_bytes(),
        };
        // An encoded decoy toward even a releasing rule is anomalous.
        let out = apply(&mut ctx, &vault, &releasing(), true);
        assert!(out.tripped());
        assert!(out.swaps.is_empty());
    }

    #[test]
    fn tripwire_on_literal_decoy_in_non_utf8_body() {
        let (vault, decoy) = vault_with(Location::Body);
        let mut body = vec![0xff, 0xfe, 0x00]; // invalid UTF-8 prefix
        body.extend_from_slice(decoy.as_bytes());
        body.push(0x80);
        let mut ctx = RequestCtx {
            host: "evil.example.com".into(),
            path: "/x".into(),
            method: "POST".into(),
            headers: vec![],
            body,
        };
        let out = apply(&mut ctx, &vault, &allowing_nothing(), true);
        assert!(out.tripwires.iter().any(|t| t.seen_in == "body:raw"));
    }

    #[test]
    fn bearer_decoy_in_body_tripwires_even_when_released() {
        let (vault, decoy) = vault_with(Location::Bearer);
        let mut ctx = RequestCtx {
            host: "api.anthropic.com".into(),
            path: "/v1/messages".into(),
            method: "POST".into(),
            headers: vec![],
            body: format!("{{\"leak\":\"{decoy}\"}}").into_bytes(),
        };
        let out = apply(&mut ctx, &vault, &releasing(), true);
        // The releasing rule is right but the location is wrong: never swap,
        // and never let the copy leave unnoticed.
        assert!(out.swaps.is_empty());
        assert!(out.tripwires.iter().any(|t| t.seen_in == "body"));
        assert!(String::from_utf8(ctx.body).unwrap().contains(&decoy));
    }

    #[test]
    fn body_decoy_in_header_tripwires() {
        let (vault, decoy) = vault_with(Location::Body);
        let mut ctx = RequestCtx {
            host: "api.example.com".into(),
            path: "/x".into(),
            method: "POST".into(),
            headers: vec![("x-exfil".into(), decoy.clone())],
            body: Vec::new(),
        };
        let out = apply(&mut ctx, &vault, &releasing(), true);
        assert!(out.swaps.is_empty());
        assert!(out.tripwires.iter().any(|t| t.seen_in == "header:x-exfil"));
        assert_eq!(ctx.headers[0].1, decoy);
    }

    #[test]
    fn wrong_header_tripwires_when_released() {
        let (vault, decoy) = vault_with(Location::Bearer);
        let mut ctx = RequestCtx {
            host: "api.anthropic.com".into(),
            path: "/v1/messages".into(),
            method: "POST".into(),
            headers: vec![("x-api-key".into(), decoy.clone())],
            body: Vec::new(),
        };
        let out = apply(&mut ctx, &vault, &releasing(), true);
        assert!(out.swaps.is_empty());
        assert!(out
            .tripwires
            .iter()
            .any(|t| t.seen_in == "header:x-api-key" && t.reason == TripReason::WrongLocation));
    }

    #[test]
    fn decoy_in_url_tripwires_and_is_never_swapped() {
        let (vault, decoy) = vault_with(Location::Any);
        // Even under a releasing rule with location `any`, a URL-borne decoy
        // is a tripwire: the path is not a swappable location.
        let mut ctx = RequestCtx {
            host: "api.anthropic.com".into(),
            path: format!("/v1/thing?key={decoy}"),
            method: "GET".into(),
            headers: vec![],
            body: Vec::new(),
        };
        let out = apply(&mut ctx, &vault, &releasing(), true);
        assert!(out.swaps.is_empty());
        assert!(out.tripwires.iter().any(|t| t.seen_in == "path"));
        assert!(ctx.path.contains(&decoy), "path must be left untouched");

        // Percent-encoded in the query string is caught by the encoded scan.
        let mut ctx = RequestCtx {
            host: "evil.example.com".into(),
            path: format!("/x?d={}", percent_encode(decoy.as_bytes())),
            method: "GET".into(),
            headers: vec![],
            body: Vec::new(),
        };
        let out = apply(&mut ctx, &vault, &allowing_nothing(), true);
        assert!(out.tripped());
    }

    #[test]
    fn swaps_in_body() {
        let (vault, decoy) = vault_with(Location::Body);
        let mut ctx = RequestCtx {
            host: "api.example.com".into(),
            path: "/x".into(),
            method: "POST".into(),
            headers: vec![],
            body: format!("{{\"token\":\"{decoy}\"}}").into_bytes(),
        };
        apply(&mut ctx, &vault, &releasing(), true);
        assert_eq!(
            String::from_utf8(ctx.body).unwrap(),
            "{\"token\":\"sk-ant-REALSECRET\"}"
        );
    }
}
