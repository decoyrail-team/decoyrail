#![no_main]
//! Fuzz the proxy's own byte-level surfaces: the request-head parse every
//! connection starts with (it feeds policy, cert minting, and audit), the
//! keep-alive body minimizer, the beta-header splice, and the byte-surgical
//! cache_control repair. Invariants: the head parse is total and always
//! yields a lowercase host; body rewrites emit valid JSON when given valid
//! JSON (a corrupted repair would silently break the client's request).

use libfuzzer_sys::fuzz_target;

use decoyrail::cache;
use decoyrail::proxy;

#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    head: Vec<u8>,
    json: Vec<u8>,
    ttl_1h: bool,
    token: String,
}

fuzz_target!(|input: Input| {
    let route = proxy::parse_head(&input.head);
    assert_eq!(
        route.host,
        route.host.to_ascii_lowercase(),
        "parse_head must normalize the host"
    );

    if let Some(out) = proxy::minimize_body(&input.json) {
        let v: serde_json::Value =
            serde_json::from_slice(&out).expect("minimize_body emitted invalid JSON");
        assert_eq!(v.get("max_tokens"), Some(&serde_json::json!(1)));
        assert!(v.get("stream").is_none());
    }

    if let Some(out) = cache::splice_marker(&input.json, input.ttl_1h) {
        if serde_json::from_slice::<serde_json::Value>(&input.json).is_ok() {
            serde_json::from_slice::<serde_json::Value>(&out)
                .expect("splice_marker corrupted a valid JSON body");
        }
    }

    // Idempotent per token: adding the same beta token twice must not grow
    // the header. Restrict to tokens the merge logic can round-trip (the
    // real caller only passes fixed identifiers).
    let token = input.token.trim();
    if !token.is_empty() && !token.contains(',') && token == input.token {
        let mut headers = vec![("anthropic-beta".to_string(), "existing-token".to_string())];
        proxy::add_beta_header(&mut headers, token);
        let once = headers.clone();
        proxy::add_beta_header(&mut headers, token);
        assert_eq!(headers, once, "add_beta_header is not idempotent");
    }
});
