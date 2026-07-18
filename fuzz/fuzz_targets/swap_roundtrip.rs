#![no_main]
//! Fuzz the decoy<->real swap engine with the core security invariant as an
//! assert: a real secret appears in the outbound request only when the
//! winning decision is allow (or route, which releases identically),
//! releases it, AND the transport is TLS.
//! Everything else (deny, warn, no release, plaintext) must leave the bytes
//! free of every real value, whatever the surrounding input looks like.

use libfuzzer_sys::fuzz_target;

use decoyrail::policy::{Action, Decision};
use decoyrail::swap::{self, RequestCtx};
use decoyrail::vault::{make_decoy, Location, Secret, Vault};

#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    body: Vec<u8>,
    header_name: String,
    header_value: String,
    splice_at: u16,
    release: bool,
    tls: bool,
    /// Winning action, modulo the actions the pipeline can hand the swap
    /// engine (escalate resolves before the swap runs).
    action: u8,
}

fn secret(name: &str, real: &str, location: Location) -> Secret {
    Secret {
        name: name.into(),
        real: real.into(),
        decoy: make_decoy(name, real),
        env: None,
        location,
        provider: None,
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fuzz_target!(|input: Input| {
    let vault = Vault {
        secrets: vec![
            secret(
                "bearer",
                "real-bearer-0123456789abcdef0123",
                Location::Bearer,
            ),
            secret(
                "hdr",
                "real-hdr-fedcba9876543210aabb",
                Location::Header("x-api-key".into()),
            ),
            secret("body", "real-body-00112233445566778899", Location::Body),
            secret("any", "real-any-aabbccddeeff00112233", Location::Any),
        ],
    };

    // If the fuzzer synthesized a real value into its own input (the
    // constants above are discoverable via compare tracing), the invariant
    // below would fire on bytes the swap engine never placed. Skip those.
    for s in &vault.secrets {
        if contains(&input.body, s.real.as_bytes())
            || input.header_value.contains(&s.real)
            || input.header_name.contains(&s.real)
        {
            return;
        }
    }

    let action = match input.action % 4 {
        0 => Action::Allow,
        1 => Action::Deny,
        2 => Action::Warn,
        // Route is allow plus a model rewrite that runs before the swap and
        // never touches a credential: the release invariant must hold for it
        // exactly as for allow.
        _ => Action::Route,
    };
    let decision = Decision {
        action,
        rule: "fuzz".into(),
        escalated: false,
        allow_secrets: if input.release {
            vec!["bearer".into(), "hdr".into(), "body".into(), "any".into()]
        } else {
            Vec::new()
        },
        route: Default::default(),
    };

    // Splice every decoy (and one base64-encoded decoy, for the encoded-form
    // tripwire) into the fuzz body so the interesting paths run every
    // iteration instead of waiting for the fuzzer to guess a decoy.
    let mut body = input.body.clone();
    let at = (input.splice_at as usize) % (body.len() + 1);
    let mut spliced = Vec::new();
    for s in &vault.secrets {
        spliced.extend_from_slice(s.decoy.as_bytes());
        spliced.push(b' ');
    }
    {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&vault.secrets[3].decoy);
        spliced.extend_from_slice(b64.as_bytes());
    }
    body.splice(at..at, spliced);

    let mut ctx = RequestCtx {
        host: "fuzz.example".into(),
        path: "/v1/messages".into(),
        method: "POST".into(),
        headers: vec![
            (
                "authorization".into(),
                format!("Bearer {}", vault.secrets[0].decoy),
            ),
            ("x-api-key".into(), vault.secrets[1].decoy.clone()),
            (input.header_name, input.header_value),
        ],
        body,
    };

    let outcome = swap::apply(&mut ctx, &vault, &decision, input.tls);
    for t in &outcome.tripwires {
        let _ = t.message("fuzz.example");
    }

    // The invariant: without (release AND allow/route AND TLS), no real
    // value may exist anywhere in the request the proxy would forward. Warn
    // forwards like allow but sits on the unreleased side, always.
    let released =
        input.release && matches!(action, Action::Allow | Action::Route) && input.tls;
    if !released {
        for s in &vault.secrets {
            assert!(
                !contains(&ctx.body, s.real.as_bytes()),
                "real secret {:?} leaked into body without release+tls",
                s.name
            );
            for (name, value) in &ctx.headers {
                assert!(
                    !value.contains(&s.real) && !name.contains(&s.real),
                    "real secret {:?} leaked into headers without release+tls",
                    s.name
                );
            }
        }
    }

    // The response-echo scanner must be total over arbitrary bytes.
    let _ = swap::scan_response_for_real(&ctx.body, &vault);
});
