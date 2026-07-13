//! End-to-end proxy tests against a local in-process TLS upstream.
//!
//! One test drives every security-critical path (swap, tripwire, policy deny,
//! redirect relay, non-443 port, body cap) through a single booted proxy — the
//! shared process-global `DECOYRAIL_HOME`/`DECOYRAIL_EXTRA_CA` env means scenarios
//! run sequentially rather than as parallel `#[test]` fns.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use decoyrail::engine::Engine;
use decoyrail::vault::{make_decoy, Location, Secret, Vault};

const REAL: &str = "REALSECRET-abc123-do-not-leak";

/// Concurrency the `/v1/fanout` endpoint has observed, for the fan-out
/// serialization scenario: with serialization on, requests sharing a prefix
/// never all reach the upstream at once.
static FANOUT_INFLIGHT: AtomicUsize = AtomicUsize::new(0);
static FANOUT_MAX: AtomicUsize = AtomicUsize::new(0);

/// Minimal HTTP upstream behavior, keyed by path.
async fn upstream_service(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let path = req.uri().path().to_string();
    match path.as_str() {
        // Echo the received x-secret header so the test can see what actually
        // reached the upstream (should be the REAL secret, never the decoy).
        "/echo" => {
            let seen = req
                .headers()
                .get("x-secret")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let body = format!("{{\"x_secret\":\"{seen}\"}}");
            Ok(Response::new(Full::new(Bytes::from(body))))
        }
        // Redirect off to another host: decoyrail must relay this, not follow it.
        "/redirect" => Ok(Response::builder()
            .status(StatusCode::FOUND)
            .header("location", "https://evil.invalid/stolen")
            .body(Full::new(Bytes::new()))
            .unwrap()),
        // Echo the received body verbatim, for the DLP mask/warn scenarios.
        "/echo-body" => {
            let body = req.into_body().collect().await.unwrap().to_bytes();
            Ok(Response::new(Full::new(body)))
        }
        // Sink for the body-cap test (never reached when body exceeds the cap).
        "/sink" => {
            let _ = req.into_body().collect().await;
            Ok(Response::new(Full::new(Bytes::from("ok"))))
        }
        // Anthropic-shaped Messages response with usage fields, for the
        // exact-token-metering test.
        "/v1/messages" => {
            let body = r#"{"id":"msg_1","model":"claude-sonnet-5-20250929",
                "content":[{"type":"text","text":"hi"}],
                "usage":{"input_tokens":1000,"output_tokens":200,
                         "cache_read_input_tokens":5000,
                         "cache_creation_input_tokens":100}}"#;
            Ok(Response::builder()
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(body)))
                .unwrap())
        }
        // Anthropic-shaped SSE stream: usage split across message_start
        // (input side) and message_delta (final output count).
        "/v1/messages-sse" => {
            let body = concat!(
                "event: message_start\n",
                "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-5-20250929\",\"usage\":{\"input_tokens\":200,\"output_tokens\":1,\"cache_read_input_tokens\":50}}}\n",
                "\n",
                "event: content_block_delta\n",
                "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n",
                "\n",
                "event: message_delta\n",
                "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":75}}\n",
                "\n",
            );
            Ok(Response::builder()
                .header("content-type", "text/event-stream")
                .body(Full::new(Bytes::from(body)))
                .unwrap())
        }
        // Records peak concurrency, then returns after a short delay. Used to
        // prove fan-out serialization: a serialized batch never peaks above
        // N-1 (leader alone, then the siblings), an unserialized one peaks at N.
        "/v1/fanout" => {
            let n = FANOUT_INFLIGHT.fetch_add(1, Ordering::SeqCst) + 1;
            FANOUT_MAX.fetch_max(n, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            FANOUT_INFLIGHT.fetch_sub(1, Ordering::SeqCst);
            Ok(Response::builder()
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(r#"{"ok":true}"#)))
                .unwrap())
        }
        // An SSE-shaped body served WITHOUT the text/event-stream content
        // type, the way some subscription backends stream (ChatGPT's Codex
        // endpoint). Exercises the buffered-body SSE usage fallback.
        "/v1/sse-mislabeled" => {
            let body = concat!(
                "event: message_start\n",
                "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-5-20250929\",\"usage\":{\"input_tokens\":123,\"output_tokens\":1}}}\n",
                "\n",
                "event: message_delta\n",
                "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":45}}\n",
            );
            Ok(Response::builder()
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(body)))
                .unwrap())
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))
            .unwrap()),
    }
}

/// Spawn a TLS upstream for `localhost`; returns (port, cert_pem) where the
/// self-signed cert doubles as the trust anchor for DECOYRAIL_EXTRA_CA.
async fn spawn_upstream() -> (u16, String) {
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "localhost");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into().unwrap()),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
    ];
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_pem = cert.pem();

    let chain = vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())];
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap();
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key_der)
        .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service_fn(upstream_service))
                    .await;
            });
        }
    });
    (port, cert_pem)
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_end_to_end() {
    decoyrail::proxy_test_install_crypto();

    let home = tempfile::tempdir().unwrap();
    std::env::set_var("DECOYRAIL_HOME", home.path());
    // Don't inherit a real HTTP(S)_PROXY from the CI/dev shell.
    for v in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "SSL_CERT_FILE",
    ] {
        std::env::remove_var(v);
    }

    let (up_port, up_cert_pem) = spawn_upstream().await;
    let extra_ca = home.path().join("upstream.pem");
    std::fs::write(&extra_ca, &up_cert_pem).unwrap();
    std::env::set_var("DECOYRAIL_EXTRA_CA", &extra_ca);

    // Policy: allow localhost and release the two swappable secrets there
    // (one vault entry by name, one session entry by name), default deny.
    // The honey secret is listed nowhere: seen toward localhost it tripwires.
    std::fs::write(
        home.path().join("policy.toml"),
        "default_action = \"deny\"\nescalate_fallback = \"deny\"\n\
         [[rule]]\nname = \"local\"\nhosts = [\"localhost\"]\naction = \"allow\"\n\
         allow_secrets = [\"svc\", \"env:LOCAL_TOKEN\"]\n",
    )
    .unwrap();

    // Pricing: treat the local upstream as an Anthropic-protocol host so the
    // exact-token-metering paths run against it.
    std::fs::write(
        home.path().join("pricing.json"),
        r#"{"hosts": {"localhost": "anthropic"}}"#,
    )
    .unwrap();

    // Vault: a secret the policy releases at localhost (swappable) and a
    // honey secret no rule lists (must tripwire if seen toward localhost).
    let mut vault = Vault::load_or_init().unwrap();
    let decoy = vault
        .add("svc", REAL, None, Location::Header("x-secret".into()))
        .unwrap();
    let honey_decoy = vault
        .add(
            "honey",
            "HONEY-should-never-swap",
            None,
            Location::Header("x-honey".into()),
        )
        .unwrap();

    // Session vault (what `decoyrail run` builds from the terminal env): one
    // secret detected by the guard (tripwire-only, no provider label) and one
    // the policy releases at localhost so its swap path can be exercised.
    let session_from_env = decoyrail::guard::detect_env(
        vec![(
            "CI_DEPLOY_TOKEN".to_string(),
            "session-tripwire-value-123".to_string(),
        )]
        .into_iter(),
        &vault,
        &[],
    );
    assert_eq!(session_from_env.len(), 1);
    let session_trip_decoy = session_from_env[0].decoy.clone();
    assert!(session_from_env[0].provider.is_none());

    const SESSION_REAL: &str = "SESSION-REAL-987654-do-not-leak";
    let session_decoy = make_decoy("env:LOCAL_TOKEN", SESSION_REAL);
    let mut session_secrets = session_from_env;
    session_secrets.push(Secret {
        name: "env:LOCAL_TOKEN".into(),
        real: SESSION_REAL.into(),
        decoy: session_decoy.clone(),
        env: Some("LOCAL_TOKEN".into()),
        location: Location::Any,
        provider: None,
    });

    // Install a signed Pro license before boot so the plan-004 phase 2/3
    // scenarios (repair, keep-alive, fan-out) clear their Pro gate. The
    // throwaway signing key is trusted via DECOYRAIL_LICENSE_EXTRA_KEY. This
    // changes no earlier scenario: every active cache behavior is additionally
    // gated on the `[cache]` policy config, which stays off until enabled below.
    {
        use decoyrail::license::{generate_keypair, sign_document, LicenseDoc};
        let (pkcs8, pub_hex) = generate_keypair().unwrap();
        std::env::set_var("DECOYRAIL_LICENSE_EXTRA_KEY", &pub_hex);
        let doc = LicenseDoc {
            licensee: "Test".into(),
            tier: "pro".into(),
            rank: None,
            seats: 1,
            issued: "2026-01-01".parse().unwrap(),
            expires: "2999-01-01".parse().unwrap(),
            grace_days: 14,
        };
        let text = sign_document(&doc, &pkcs8).unwrap();
        std::fs::write(home.path().join("license.toml"), text).unwrap();
    }

    let mut engine = Engine::boot().unwrap();
    engine.set_session_secrets(session_secrets);
    // Label the session the way `decoyrail run` does, so the stats scenario
    // at the end can check session attribution.
    engine
        .announce_session("test-agent --do-things")
        .await
        .unwrap();
    let ca_pem = std::fs::read(home.path().join("ca-cert.pem")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { decoyrail::proxy::serve_on(engine, listener).await });

    // Client trusts the Decoyrail CA and routes through the proxy.
    let decoyrail_ca = reqwest::Certificate::from_pem(&ca_pem).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(decoyrail_ca)
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_port}")).unwrap())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let base = format!("https://localhost:{up_port}");

    // 1. SWAP (and non-443 port forwarding): send the decoy; upstream must have
    //    received the REAL secret.
    let body = client
        .get(format!("{base}/echo"))
        .header("x-secret", &decoy)
        .send()
        .await
        .expect("swap request")
        .text()
        .await
        .unwrap();
    assert!(
        body.contains(REAL),
        "upstream should receive the real secret; got {body}"
    );
    assert!(!body.contains(&decoy), "decoy must not leak upstream");

    // 2. TRIPWIRE: honey decoy toward localhost (not its bound host) → blocked.
    let resp = client
        .get(format!("{base}/echo"))
        .header("x-honey", &honey_decoy)
        .send()
        .await
        .expect("tripwire request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "off-policy decoy must be blocked"
    );

    // 3. POLICY DENY: an unknown host is denied before any forwarding.
    let resp = client
        .get(format!("https://denied.invalid:{up_port}/echo"))
        .send()
        .await
        .expect("deny request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "unknown host must be denied"
    );

    // 4. REDIRECT: upstream 302 must be relayed, not followed (following would
    //    hit evil.invalid and fail; relaying returns the 302 as-is).
    let resp = client
        .get(format!("{base}/redirect"))
        .send()
        .await
        .expect("redirect request");
    assert_eq!(
        resp.status(),
        StatusCode::FOUND,
        "redirect must be relayed, not followed"
    );
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "https://evil.invalid/stolen"
    );

    // 5. BODY CAP: a request body over the cap is rejected with 413.
    let huge = vec![b'x'; 33 * 1024 * 1024];
    let resp = client
        .post(format!("{base}/sink"))
        .body(huge)
        .send()
        .await
        .expect("oversized request");
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "oversized body must be 413"
    );

    // 6. SESSION SWAP: a session-vault decoy bound to localhost is swapped for
    //    its real value exactly like a persistent vault entry.
    let body = client
        .get(format!("{base}/echo"))
        .header("x-secret", &session_decoy)
        .send()
        .await
        .expect("session swap request")
        .text()
        .await
        .unwrap();
    assert!(
        body.contains(SESSION_REAL),
        "upstream should receive the session real value; got {body}"
    );
    assert!(
        !body.contains(&session_decoy),
        "session decoy must not leak upstream"
    );

    // 7. SESSION TRIPWIRE: a guard-detected decoy with no bound destination is
    //    blocked toward any host.
    let resp = client
        .get(format!("{base}/echo"))
        .header("x-anything", &session_trip_decoy)
        .send()
        .await
        .expect("session tripwire request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "session decoy must tripwire"
    );

    // 8. URL TRIPWIRE: a decoy in the query string is caught even at the
    //    bound host (the path is never a swappable location).
    let resp = client
        .get(format!("{base}/echo?key={session_decoy}"))
        .send()
        .await
        .expect("url tripwire request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "URL-borne decoy must tripwire"
    );

    // 10. EXACT METERING (buffered): a Messages-shaped response's usage is
    //     parsed and priced per model; an x-api-key request is usage-billed.
    let req_body = r#"{"model":"claude-sonnet-5-20250929","messages":[]}"#;
    let resp = client
        .post(format!("{base}/v1/messages"))
        .header("x-api-key", "sk-ant-api03-test")
        .header("content-type", "application/json")
        .body(req_body)
        .send()
        .await
        .expect("metered request");
    assert_eq!(resp.status(), StatusCode::OK);
    let disk = decoyrail::meter::Meter::load().unwrap();
    let m = &disk.per_host["localhost"].models["claude-sonnet-5-20250929"];
    assert_eq!(m.requests, 1);
    assert_eq!(m.input_tokens, 1000);
    assert_eq!(m.output_tokens, 200);
    assert_eq!(m.cache_read_tokens, 5000);
    assert_eq!(m.cache_write_tokens, 100);
    // 1000*3 + 200*15 + 5000*0.3 + 100*3.75 per mtok
    assert!(
        (m.cost_usd - 0.007875).abs() < 1e-9,
        "cost was {}",
        m.cost_usd
    );

    // 11. SUBSCRIPTION BILLING: OAuth-style auth (Bearer, no x-api-key) is
    //     plan-covered — tokens tracked under a tagged key, cost zero.
    let resp = client
        .post(format!("{base}/v1/messages"))
        .header("authorization", "Bearer sk-ant-oat01-test")
        .header("content-type", "application/json")
        .body(req_body)
        .send()
        .await
        .expect("subscription request");
    assert_eq!(resp.status(), StatusCode::OK);
    let disk = decoyrail::meter::Meter::load().unwrap();
    let sub = &disk.per_host["localhost"].models["claude-sonnet-5-20250929 [subscription]"];
    assert_eq!(sub.input_tokens, 1000);
    assert_eq!(sub.cost_usd, 0.0);

    // 12. EXACT METERING (SSE): usage events are scanned out of the stream as
    //     it passes; the meter is updated asynchronously after the stream
    //     drains, so poll briefly.
    let text = client
        .post(format!("{base}/v1/messages-sse"))
        .header("x-api-key", "sk-ant-api03-test")
        .header("content-type", "application/json")
        .body(r#"{"model":"claude-sonnet-5-20250929","stream":true}"#)
        .send()
        .await
        .expect("sse request")
        .text()
        .await
        .unwrap();
    assert!(
        text.contains("message_delta"),
        "SSE body must pass through untouched; got {text}"
    );
    let mut sse_tokens = None;
    for _ in 0..40 {
        let disk = decoyrail::meter::Meter::load().unwrap();
        let m = disk.per_host["localhost"].models["claude-sonnet-5-20250929"].clone();
        // Scenario 10 recorded 200 output tokens; the SSE stream adds 75.
        if m.output_tokens == 275 {
            sse_tokens = Some(m);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let m = sse_tokens.expect("SSE usage must reach the meter");
    assert_eq!(m.requests, 2);
    assert_eq!(m.input_tokens, 1200);
    assert_eq!(m.cache_read_tokens, 5050);
    // Scenario 10's cost plus 200*3 + 75*15 + 50*0.3 per mtok.
    assert!(
        (m.cost_usd - (0.007875 + 0.00174)).abs() < 1e-9,
        "cost was {}",
        m.cost_usd
    );

    // 13. AUDIT CARRIES USAGE: the buffered allow event notes the parsed
    //     tokens inline; the SSE request gets a follow-up `usage` event
    //     (written asynchronously after the stream drains, so poll).
    let audit_path = home.path().join("audit.jsonl");
    let mut log = String::new();
    for _ in 0..40 {
        log = std::fs::read_to_string(&audit_path).unwrap();
        if log.contains("\"action\":\"usage\"") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        log.contains(
            "usage: claude-sonnet-5-20250929 in=1000 out=200 cache_read=5000 cache_write=100"
        ),
        "buffered allow event must carry the usage note"
    );
    assert!(
        log.contains("\"action\":\"usage\""),
        "SSE stream must append a usage event"
    );
    assert!(
        log.contains("usage: claude-sonnet-5-20250929 in=200 out=75 cache_read=50"),
        "usage event must carry the streamed token counts"
    );

    // 13.5. CACHE DOCTOR: two Messages requests whose prefix differs only by
    //       an injected timestamp in the system prompt. The doctor must name
    //       the divergent byte offset and the section it fell in, and its
    //       state file must never hold prompt content. (Spec 004 AC 1.)
    let cache_body = |ts: &str| {
        format!(
            "{{\"model\":\"claude-sonnet-5-20250929\",\
              \"system\":[{{\"type\":\"text\",\"text\":\"You are helpful. Now: {ts}\"}}],\
              \"messages\":[{{\"role\":\"user\",\"content\":\"hi\"}}]}}"
        )
    };
    for ts in ["2026-07-11T10:00:00", "2026-07-11T10:00:05"] {
        let resp = client
            .post(format!("{base}/v1/messages"))
            .header("x-api-key", "sk-ant-api03-test")
            .header("content-type", "application/json")
            .body(cache_body(ts))
            .send()
            .await
            .expect("cache doctor request");
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let stats = decoyrail::cache::CacheStats::load().unwrap();
    let s = &stats.per_key["localhost claude-sonnet-5-20250929"];
    assert!(s.requests >= 2, "doctor must observe Messages requests");
    assert_eq!(
        s.diverged, 1,
        "the timestamp change must count as divergence"
    );
    let div = s
        .last_divergence
        .as_ref()
        .expect("divergence must be recorded");
    assert_eq!(
        div.section, "system[0]",
        "the divergence must be located in the system block"
    );
    assert!(div.offset > 0, "offset must land inside the section");
    let raw_stats = std::fs::read_to_string(home.path().join("cache.json")).unwrap();
    assert!(
        !raw_stats.contains("You are helpful"),
        "cache.json must never hold prompt content"
    );

    // 14. AUDIT: the chain verifies and recorded the tripwire.
    assert!(
        decoyrail::audit::verify().is_ok(),
        "audit chain must verify"
    );

    // --- DLP scenarios. The policy above carries no [dlp] section, so the
    //     warn-first defaults apply. Mode changes are made by rewriting
    //     policy.toml and ride the hot-reload path, exactly like
    //     `decoyrail dlp set`.
    const PAN: &str = "4539148803436467"; // Luhn-valid Visa, not a test number
    let policy_rules = "default_action = \"deny\"\nescalate_fallback = \"deny\"\n\
         [[rule]]\nname = \"local\"\nhosts = [\"localhost\"]\naction = \"allow\"\n";
    // Force a distinct mtime per rewrite so hot-reload can't miss an edit that
    // lands within the filesystem's timestamp granularity.
    let set_dlp = |dlp: &str, bump: u64| {
        let path = home.path().join("policy.toml");
        std::fs::write(&path, format!("{policy_rules}[dlp]\n{dlp}\n")).unwrap();
        let f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(bump))
            .unwrap();
    };

    // 15. DLP DEFAULT (warn-first): with no [dlp] section, a real-shaped card
    //     number is forwarded untouched, but an alert with a fingerprint (and
    //     never the number) lands in the audit log.
    let echoed = client
        .post(format!("{base}/echo-body"))
        .header("content-type", "application/json")
        .body(format!("{{\"card_number\":\"{PAN}\"}}"))
        .send()
        .await
        .expect("dlp default request")
        .text()
        .await
        .unwrap();
    assert!(
        echoed.contains(PAN),
        "default warn mode must forward the body as-is"
    );
    let log = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        log.contains("dlp: warned pan@body") && log.contains("fp="),
        "default warn mode must record an alert with a fingerprint"
    );
    assert!(
        !log.contains(PAN),
        "the matched value must never reach the audit log"
    );

    // 16. DLP BLOCK: upgraded to block, the same card number is denied with a
    //     machine-readable error.
    set_dlp("pan = \"block\"", 2);
    let resp = client
        .post(format!("{base}/echo-body"))
        .header("content-type", "application/json")
        .body(format!("{{\"card_number\":\"{PAN}\"}}"))
        .send()
        .await
        .expect("dlp block request");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "PAN must be blocked");
    let err: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    assert_eq!(err["reason"], "dlp");
    assert_eq!(err["detectors"][0]["detector"], "pan");
    assert_eq!(err["detectors"][0]["location"], "body");
    assert!(err["detectors"][0]["offset"].is_number());
    let log = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        !log.contains(PAN),
        "the matched value must never reach the audit log"
    );
    assert!(
        log.contains("dlp: blocked pan@body"),
        "deny event must carry the detector and fingerprint"
    );

    // 17. DLP TEST-VALUE ALLOWLIST: the canonical test card sails through
    //     even in block mode.
    let resp = client
        .post(format!("{base}/echo-body"))
        .body(r#"{"card_number":"4242424242424242"}"#)
        .send()
        .await
        .expect("dlp allowlist request");
    assert_eq!(resp.status(), StatusCode::OK, "test card must pass");

    // 18. DLP MASK: the upstream receives the placeholder, never the number.
    set_dlp("pan = \"mask\"", 4);
    let echoed = client
        .post(format!("{base}/echo-body"))
        .body(format!("{{\"card\":\"{PAN}\",\"amount\":5}}"))
        .send()
        .await
        .expect("dlp mask request")
        .text()
        .await
        .unwrap();
    assert_eq!(echoed, "{\"card\":\"[decoyrail:masked:pan]\",\"amount\":5}");

    // 19. DLP ENCODED: a base64-wrapped card number is caught within the
    //     bounded decode scan.
    set_dlp("pan = \"block\"", 6);
    use base64::Engine as _;
    let blob = base64::engine::general_purpose::STANDARD.encode(format!("card={PAN}"));
    let resp = client
        .post(format!("{base}/echo-body"))
        .body(format!("{{\"blob\":\"{blob}\"}}"))
        .send()
        .await
        .expect("dlp encoded request");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let err: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    assert_eq!(err["detectors"][0]["detector"], "pan");
    assert_eq!(err["detectors"][0]["location"], "body:base64");

    // 20. DLP DEBUG: the blocked request's payload lands in a private dump
    //     file with the match marked, any swapped-in real secret is scrubbed
    //     back out, and the audit note names the file (but still never the
    //     value).
    {
        let path = home.path().join("policy.toml");
        std::fs::write(
            &path,
            format!(
                "{policy_rules}allow_secrets = [\"env:LOCAL_TOKEN\"]\n\
                 [dlp]\npan = \"block\"\ndebug = true\n"
            ),
        )
        .unwrap();
        let f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(8))
            .unwrap();
    }
    let resp = client
        .post(format!("{base}/echo-body"))
        .body(format!(
            "{{\"token\":\"{session_decoy}\",\"card\":\"{PAN}\"}}"
        ))
        .send()
        .await
        .expect("dlp debug request");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let dumps: Vec<_> = std::fs::read_dir(home.path().join("dlp-debug"))
        .expect("debug mode must create the dump dir")
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(dumps.len(), 1, "one dump per hit-carrying request");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&dumps[0]).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "dump files must be owner-only");
    }
    let dump = std::fs::read_to_string(&dumps[0]).unwrap();
    assert!(
        dump.contains(&format!(">>>{PAN}<<<")),
        "dump must mark what matched; got:\n{dump}"
    );
    assert!(
        !dump.contains(SESSION_REAL),
        "the real secret the swap placed must be scrubbed from the dump"
    );
    assert!(
        dump.contains("[decoyrail:scrubbed:env:LOCAL_TOKEN]"),
        "scrubbed secret must be named; got:\n{dump}"
    );
    let log = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        log.contains("payload="),
        "audit note must name the dump file"
    );
    assert!(
        !log.contains(PAN),
        "the audit log never holds the value, debug mode or not"
    );

    // 21. The audit chain still verifies across the DLP events.
    assert!(
        decoyrail::audit::verify().is_ok(),
        "audit chain must verify across DLP events"
    );

    // 22. STATS: the analytics view over everything this test just did.
    //     Requests so far: allows 1 (swap), 4 (redirect), 6 (session swap),
    //     10 (metered), 11 (subscription), 12 (SSE), 13.5 (two cache-doctor
    //     requests), 15 (dlp warn), 17 (allowlist), 18 (mask) = 11;
    //     denies 2/7/8 (tripwires), 3 (policy), 5 (body cap),
    //     16/19/20 (dlp) = 8.
    {
        use decoyrail::stats::{self, Window};
        let report = stats::query(&Window::All).unwrap();
        assert!(report.integrity.ok, "chain verified, stats must agree");
        let t = &report.totals;
        assert_eq!(t.requests, 19);
        assert_eq!(t.allows, 11);
        assert_eq!(t.denies.total, 8);
        assert_eq!(t.denies.tripwire, 3);
        assert_eq!(t.denies.dlp, 3);
        assert_eq!(t.denies.policy, 2);
        assert_eq!(t.denies.budget, 0);
        // 3 request-side tripwire denies, plus scenarios 1 and 6 echoing the
        // real secret back in the response (each records an echo alert).
        assert_eq!(t.tripwires, 5);
        assert_eq!(t.dlp_alerts, 2, "the warn and the mask");

        // Dollars match a hand-computed total from the stub's usage fields:
        // scenario 10 and 13.5's two cache-doctor requests hit the same
        // stub response (1000*3 + 200*15 + 5000*0.3 + 100*3.75 per mtok,
        // three times) plus scenario 12's stream (200*3 + 75*15 + 50*0.3
        // per mtok); the subscription request costs zero.
        assert!(
            (t.cost_usd - (3.0 * 0.007875 + 0.00174)).abs() < 1e-9,
            "cost was {}",
            t.cost_usd
        );

        // The streamed request was correlated back to its allow event: it
        // counts once, under its model, in every breakdown.
        let billed = report
            .by_model
            .iter()
            .find(|m| m.name == "claude-sonnet-5-20250929")
            .expect("billed model row");
        assert_eq!(
            billed.stats.requests, 4,
            "buffered + streamed + two cache-doctor requests, once each"
        );
        assert_eq!(billed.stats.tokens.input, 3200);
        assert_eq!(billed.stats.tokens.output, 675);
        assert_eq!(billed.stats.tokens.cache_read, 15050);
        let sub = report
            .by_model
            .iter()
            .find(|m| m.name == "claude-sonnet-5-20250929 [subscription]")
            .expect("subscription model row");
        assert_eq!(sub.stats.requests, 1);
        assert_eq!(sub.stats.cost_usd, 0.0);

        // Session attribution: one labeled session owns all the traffic.
        assert_eq!(report.by_session.len(), 1);
        let session = &report.by_session[0];
        assert_eq!(session.label, "test-agent --do-things");
        assert_eq!(session.stats.requests, 19);

        // Latency was measured for every completed request.
        let d = t.duration_ms.as_ref().expect("durations recorded");
        assert_eq!(d.measured, 19);

        // The JSON output is schema v1 and byte-identical across reruns.
        let first = stats::render_json(&report).unwrap();
        let second = stats::render_json(&stats::query(&Window::All).unwrap()).unwrap();
        assert_eq!(first, second, "same query twice must be byte-identical");
        let parsed: serde_json::Value = serde_json::from_str(&first).unwrap();
        assert_eq!(parsed["schema"], 1);
        assert!(parsed["integrity"]["ok"].as_bool().unwrap());
        assert!(parsed["totals"]["tokens"]["total"].is_u64());
        assert!(parsed["by_session"].is_array());
        assert!(parsed["by_model"].is_array());
        assert!(parsed["by_host"].is_array());
        assert!(parsed["by_day"].is_array());

        // The embeddable one-liner: exactly one line, three fields.
        let line = stats::render_line(&stats::query(&Window::Today).unwrap());
        assert_eq!(line.lines().count(), 1);
        assert!(
            line.contains("tok") && line.contains('$') && line.contains("alerts"),
            "one-line mode must carry tokens, dollars, alerts: {line}"
        );
    }

    // --- Plan 004 phases 2-3 (Pro). A Pro license is installed above; each
    //     behavior is additionally gated on its `[cache]` policy knob, toggled
    //     here through the same hot-reload path as `set_dlp`.
    let set_cache = |cache: &str, bump: u64| {
        let path = home.path().join("policy.toml");
        std::fs::write(&path, format!("{policy_rules}[cache]\n{cache}\n")).unwrap();
        let f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(bump))
            .unwrap();
    };
    let big_system = "You are a careful, precise coding assistant. ".repeat(150);

    // 23. CACHE REPAIR: a client sending no cache markers repeats a large,
    //     stable prefix. First sight is left untouched; from the second
    //     identical prefix on, Decoyrail splices an ephemeral marker in, with
    //     the text the model reads byte-identical. (Spec 004 AC 2.)
    set_cache("repair = true", 20);
    let repair_body = |msg: &str| {
        format!(
            "{{\"model\":\"claude-sonnet-5-20250929\",\
              \"system\":[{{\"type\":\"text\",\"text\":\"{big_system}\"}}],\
              \"messages\":[{{\"role\":\"user\",\"content\":\"{msg}\"}}]}}"
        )
    };
    let first = client
        .post(format!("{base}/echo-body"))
        .header("x-api-key", "sk-ant-api03-test")
        .header("content-type", "application/json")
        .body(repair_body("first"))
        .send()
        .await
        .expect("repair first request");
    assert!(
        first.headers().get("x-decoyrail-cache").is_none(),
        "first sight of a prefix is never repaired"
    );
    let first_json: serde_json::Value = serde_json::from_str(&first.text().await.unwrap()).unwrap();
    assert!(
        first_json["system"][0].get("cache_control").is_none(),
        "the first request reaches upstream unmarked"
    );

    let second = client
        .post(format!("{base}/echo-body"))
        .header("x-api-key", "sk-ant-api03-test")
        .header("content-type", "application/json")
        .body(repair_body("second"))
        .send()
        .await
        .expect("repair second request");
    assert_eq!(
        second.headers().get("x-decoyrail-cache").unwrap(),
        "repaired system[0]",
        "a repaired response says so in its headers"
    );
    let second_json: serde_json::Value =
        serde_json::from_str(&second.text().await.unwrap()).unwrap();
    assert_eq!(
        second_json["system"][0]["cache_control"]["type"], "ephemeral",
        "the injected marker reached the upstream"
    );
    assert_eq!(
        second_json["system"][0]["text"], first_json["system"][0]["text"],
        "the content the model reads is byte-identical to the client's"
    );
    let cstats = decoyrail::cache::CacheStats::load().unwrap();
    assert!(
        cstats.per_key["localhost claude-sonnet-5-20250929"].repaired >= 1,
        "the doctor recorded the injection"
    );

    // 24. FAN-OUT SERIALIZATION: four concurrent requests sharing one cacheable
    //     prefix are serialized so the upstream never sees all four at once,
    //     and none is wedged. (Spec 004: 1 write + N-1 reads.)
    set_cache("serialize_fanout = true\nfanout_timeout_ms = 5000", 22);
    FANOUT_MAX.store(0, Ordering::SeqCst);
    let fanout_body = format!(
        "{{\"model\":\"claude-sonnet-5-20250929\",\
          \"system\":[{{\"type\":\"text\",\"text\":\"{big_system}\"}}],\
          \"messages\":[{{\"role\":\"user\",\"content\":\"fan\"}}]}}"
    );
    let mut futs = Vec::new();
    for _ in 0..4 {
        let c = client.clone();
        let url = format!("{base}/v1/fanout");
        let b = fanout_body.clone();
        futs.push(tokio::spawn(async move {
            c.post(url)
                .header("x-api-key", "sk-ant-api03-test")
                .header("content-type", "application/json")
                .body(b)
                .send()
                .await
                .map(|r| r.status())
        }));
    }
    let mut ok = 0;
    for f in futs {
        if let Ok(Ok(StatusCode::OK)) = f.await {
            ok += 1;
        }
    }
    assert_eq!(ok, 4, "every serialized request still completes (no wedge)");
    assert!(
        FANOUT_MAX.load(Ordering::SeqCst) <= 3,
        "serialization held peak upstream concurrency below N; saw {}",
        FANOUT_MAX.load(Ordering::SeqCst)
    );

    // 25. KEEP-ALIVE: with a 1s idle window, a single real request leaves the
    //     proxy pre-warming the cache on its own, metered and audited as
    //     proxy-initiated spend. (Spec 004 AC 3.)
    set_cache(
        "keep_alive = true\nkeep_alive_secs = 1\nkeep_alive_max = 1",
        24,
    );
    let before = decoyrail::meter::Meter::load()
        .unwrap()
        .per_host
        .get("localhost")
        .map(|h| h.requests)
        .unwrap_or(0);
    let resp = client
        .post(format!("{base}/v1/messages"))
        .header("x-api-key", "sk-ant-api03-test")
        .header("content-type", "application/json")
        .body(r#"{"model":"claude-sonnet-5-20250929","messages":[{"role":"user","content":"warm me"}]}"#)
        .send()
        .await
        .expect("keep-alive seed request");
    assert_eq!(resp.status(), StatusCode::OK);
    let mut fired = false;
    for _ in 0..50 {
        let log = std::fs::read_to_string(&audit_path).unwrap();
        if log.contains("\"action\":\"keepalive\"") {
            fired = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        fired,
        "keep-alive must fire a proxy-initiated pre-warm during idle"
    );
    let log = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        log.contains("proxy-initiated pre-warm"),
        "the pre-warm identifies itself in the audit log"
    );
    let after = decoyrail::meter::Meter::load().unwrap().per_host["localhost"].requests;
    assert!(
        after > before + 1,
        "the pre-warm is metered on top of the real request ({before} -> {after})"
    );

    // 26. The audit chain still verifies across every phase 2-3 event.
    assert!(
        decoyrail::audit::verify().is_ok(),
        "audit chain must verify across cache repair and keep-alive events"
    );

    // 27. BUFFERED SSE USAGE FALLBACK: a provider backend that streams SSE
    //     without the text/event-stream content type (like ChatGPT's Codex
    //     endpoint, chatgpt.com/backend-api/codex/responses) still gets its
    //     token usage metered, instead of landing in "no provider usage".
    let before = decoyrail::meter::Meter::load().unwrap().per_host["localhost"].models
        ["claude-sonnet-5-20250929"]
        .input_tokens;
    let resp = client
        .post(format!("{base}/v1/sse-mislabeled"))
        .header("x-api-key", "sk-ant-api03-test")
        .header("content-type", "application/json")
        .body(r#"{"model":"claude-sonnet-5-20250929","messages":[]}"#)
        .send()
        .await
        .expect("mislabeled sse request");
    assert_eq!(resp.status(), StatusCode::OK);
    let m = decoyrail::meter::Meter::load().unwrap().per_host["localhost"].models
        ["claude-sonnet-5-20250929"]
        .clone();
    assert_eq!(
        m.input_tokens,
        before + 123,
        "usage must be parsed from a buffered body that is really SSE"
    );
}
