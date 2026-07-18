//! End-to-end model-router tests (plan 006) against a local TLS upstream
//! that echoes request bodies, so every assertion sees exactly the bytes the
//! proxy forwarded.
//!
//! One test drives the scenarios sequentially through a single booted proxy,
//! for the same reason as `proxy_integration` and `softland_integration`:
//! `DECOYRAIL_HOME` and the license trust hook are process-global env. This
//! file is its own test binary, so it runs in its own process and cannot
//! race those tests' env.

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
use decoyrail::vault::{Location, Secret};

/// The upstream echoes every request body verbatim, whatever the path: the
/// test's view of what actually left the proxy.
async fn upstream_service(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let body = req.into_body().collect().await.unwrap().to_bytes();
    Ok(Response::builder()
        .header("content-type", "application/json")
        .body(Full::new(body))
        .unwrap())
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

/// Push a file's mtime into the future so the per-request hot reload can't
/// miss an edit landing within the filesystem's timestamp granularity.
fn bump_mtime(path: &std::path::Path, secs: u64) {
    let f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(secs))
        .unwrap();
}

/// A policy with a deny carve-out above a path-scoped route rule above a
/// broad allow, so one host exercises deny-over-route, routed, and unrouted
/// traffic. The route map is a parameter so the unknown-target scenario can
/// hot-swap it.
fn policy_text(route_map: &str) -> String {
    format!(
        "default_action = \"deny\"\nescalate_fallback = \"deny\"\n\
         [[rule]]\nname = \"blocked\"\nhosts = [\"localhost\"]\n\
         path_prefixes = [\"/blocked\"]\naction = \"deny\"\n\
         [[rule]]\nname = \"cheap-tier\"\nhosts = [\"localhost\"]\n\
         path_prefixes = [\"/routed\"]\naction = \"route\"\n\
         route = {{ {route_map} }}\n\
         [[rule]]\nname = \"local\"\nhosts = [\"localhost\"]\naction = \"allow\"\n"
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn model_router_end_to_end() {
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

    decoyrail::policy_edit::write_policy(
        &policy_text("\"claude-opus-4\" = \"claude-sonnet-5\""),
        "test setup",
    )
    .unwrap();

    // Treat the local upstream as an Anthropic-protocol host so its requests
    // classify as LLM traffic with an identifiable model (and the cache
    // doctor observes them).
    std::fs::write(
        home.path().join("pricing.json"),
        r#"{"hosts": {"localhost": "anthropic"}}"#,
    )
    .unwrap();

    // A generous budget with some billable spend on the books, so the
    // over-budget scenario can trip the kill switch later just by lowering
    // the budget. localhost traffic estimates at $0, so the spend stays put.
    decoyrail::meter::save_budget(10.0).unwrap();
    let mut seed = decoyrail::meter::Meter::default();
    seed.roll_period(&decoyrail::util::current_period());
    seed.per_host
        .entry("api.anthropic.com".to_string())
        .or_default()
        .est_cost_usd = 0.85;
    seed.save().unwrap();

    // Throwaway license signing key, trusted via the env hook. The license
    // itself is installed mid-test: the no-Pro scenario runs first.
    let (pkcs8, pub_hex) = decoyrail::license::generate_keypair().unwrap();
    std::env::set_var("DECOYRAIL_LICENSE_EXTRA_KEY", &pub_hex);

    // A session secret whose decoy is never listed by the route rule: seeing
    // it there must tripwire exactly as it would on an allow rule.
    const DECOY: &str = "decoy-token-e2e-a1b2c3d4";
    let mut engine = Engine::boot().unwrap();
    engine.set_session_secrets(vec![Secret {
        name: "env:TEST_TOKEN".into(),
        real: "REAL-TOKEN-do-not-leak-424242".into(),
        decoy: DECOY.into(),
        env: Some("TEST_TOKEN".into()),
        location: Location::Any,
        provider: None,
    }]);
    let ca_pem = std::fs::read(home.path().join("ca-cert.pem")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { decoyrail::proxy::serve_on(engine, listener).await });

    let decoyrail_ca = reqwest::Certificate::from_pem(&ca_pem).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(decoyrail_ca)
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{proxy_port}")).unwrap())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let base = format!("https://localhost:{up_port}");
    let audit_path = home.path().join("audit.jsonl");
    let route_events = || {
        std::fs::read_to_string(&audit_path)
            .unwrap()
            .lines()
            .filter(|l| l.contains("\"action\":\"route\""))
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    // An Anthropic Messages shape with a stable system block, so the cache
    // doctor records a cacheable prefix for the model it sees.
    let system = "You are a careful, brief assistant. ".repeat(60);
    let body_opus = format!(
        r#"{{"model":"claude-opus-4","max_tokens":16,"system":"{system}","messages":[{{"role":"user","content":"hi"}}]}}"#
    );
    let post = |path: &'static str, body: String| {
        let client = client.clone();
        let base = base.clone();
        async move {
            client
                .post(format!("{base}{path}"))
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .expect("request through proxy")
        }
    };

    // 1. NO PRO LICENSE (AC e): the route rule still allows, but the free
    //    tier never rewrites — the body passes byte-identical, nothing marks
    //    the response, and no route event is written. This request also
    //    warms the doctor's state for claude-opus-4 on this host.
    let resp = post("/routed/messages", body_opus.clone()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get("x-decoyrail-route").is_none(),
        "no Pro license, no route marker"
    );
    assert_eq!(
        resp.text().await.unwrap(),
        body_opus,
        "without Pro the body must pass byte-identical"
    );
    assert!(route_events().is_empty(), "no route event without Pro");

    // Install a signed Pro license; the hot reload picks it up per request.
    {
        use decoyrail::license::{sign_document, LicenseDoc};
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

    // 2. ROUTED (AC a) WITH CACHE IMPACT (AC d): the forwarded body carries
    //    the mapped model, the response says so, and — because step 1 left a
    //    warm cacheable prefix for claude-opus-4 — the audit note prices the
    //    forfeited cache alongside the invalidation it always states.
    let resp = post("/routed/messages", body_opus.clone()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-decoyrail-route")
            .expect("route marker header"),
        "claude-opus-4 -> claude-sonnet-5"
    );
    assert_eq!(
        resp.text().await.unwrap(),
        body_opus.replace("claude-opus-4", "claude-sonnet-5"),
        "only the model value may change"
    );
    let events = route_events();
    let line = events.last().expect("a route audit event must be recorded");
    assert!(
        line.contains("\"rule\":\"cheap-tier\""),
        "the event names the winning rule: {line}"
    );
    assert!(
        line.contains("route: model claude-opus-4 -> claude-sonnet-5"),
        "the event names the mapping: {line}"
    );
    assert!(
        line.contains("prompt cache invalidated"),
        "the event must note the cache invalidation: {line}"
    );
    assert!(
        line.contains("forfeits a warm") && line.contains("re-bills at the full input rate"),
        "the event must price the forfeited warm cache: {line}"
    );
    assert!(
        !line.contains("not in the pricing table"),
        "a priced target model is not flagged: {line}"
    );

    // 3. ELSEWHERE THE ORIGINAL MODEL RIDES (AC a): the sibling allow rule on
    //    the same host forwards the requested model untouched.
    let resp = post("/other/messages", body_opus.clone()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("x-decoyrail-route").is_none());
    assert_eq!(
        resp.text().await.unwrap(),
        body_opus,
        "unrouted traffic keeps the requested model"
    );

    // 4. UNMAPPED OR ABSENT MODEL: nothing identifiable to the map, nothing
    //    guessed — the request forwards unmodified through the route rule.
    let body_haiku = body_opus.replace("claude-opus-4", "claude-haiku-4-5");
    let resp = post("/routed/messages", body_haiku.clone()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("x-decoyrail-route").is_none());
    assert_eq!(resp.text().await.unwrap(), body_haiku);
    let body_no_model = r#"{"messages":[{"role":"user","content":"hi"}]}"#.to_string();
    let resp = post("/routed/messages", body_no_model.clone()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("x-decoyrail-route").is_none());
    assert_eq!(resp.text().await.unwrap(), body_no_model);

    // 5. DENY ABOVE ROUTE WINS (AC b): first-match-wins gives the carve-out
    //    precedence, and no route event is written for a denied request.
    let before = route_events().len();
    let resp = post("/blocked/messages", body_opus.clone()).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "deny must win");
    assert_eq!(route_events().len(), before, "no route event on a deny");

    // 6. TRIPWIRE ON A ROUTE RULE (AC b): a decoy the rule does not list
    //    denies exactly as on an allow rule (the model-free body also means
    //    no rewrite and no route event).
    let resp = post(
        "/routed/messages",
        format!(r#"{{"data":"leak {DECOY} now"}}"#),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let text = resp.text().await.unwrap();
    assert!(
        text.contains("tripwire"),
        "deny attributed to the tripwire: {text}"
    );
    assert_eq!(route_events().len(), before, "no route event on a tripwire");

    // 7. OVER BUDGET (AC b): budget $0.50 puts the seeded spend at 170%; the
    //    kill switch denies before the router ever runs.
    decoyrail::meter::save_budget(0.5).unwrap();
    bump_mtime(&home.path().join("budget.json"), 2);
    let resp = post("/routed/messages", body_opus.clone()).await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "the kill switch must block exactly as before"
    );
    let text = resp.text().await.unwrap();
    assert!(
        text.contains("budget exhausted"),
        "the deny is attributed to the budget: {text}"
    );
    assert_eq!(route_events().len(), before, "no route event over budget");
    decoyrail::meter::save_budget(10.0).unwrap();
    bump_mtime(&home.path().join("budget.json"), 4);

    // 8. HOT RELOAD + UNKNOWN TARGET (AC f): a mid-session policy write
    //    swaps the map; the next request routes per the new map, and a
    //    target the pricing table doesn't know forwards as configured (the
    //    provider errors informatively) with the likely typo flagged.
    decoyrail::policy_edit::write_policy(
        &policy_text("\"claude-opus-4\" = \"totally-unknown-model\""),
        "test",
    )
    .unwrap();
    bump_mtime(&home.path().join("policy.toml"), 6);
    let resp = post("/routed/messages", body_opus.clone()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-decoyrail-route")
            .expect("route marker header"),
        "claude-opus-4 -> totally-unknown-model"
    );
    assert!(
        resp.text().await.unwrap().contains("totally-unknown-model"),
        "the configured target forwards as written"
    );
    let events = route_events();
    let line = events.last().unwrap();
    assert!(
        line.contains("totally-unknown-model") && line.contains("not in the pricing table"),
        "the unknown target must be logged as such: {line}"
    );

    // 9. THE AUDIT TRAIL RECONSTRUCTS EVERY REWRITE (AC c): exactly the two
    //    rewrites above were recorded, each naming rule + from -> to, the
    //    forwarded requests audit as plain allow events, and the
    //    tamper-evident chain verifies across the whole run (what
    //    `decoyrail log --verify` runs).
    assert_eq!(events.len(), 2, "one route event per rewritten request");
    assert!(events
        .iter()
        .all(|l| l.contains("\"rule\":\"cheap-tier\"")
            && l.contains("route: model claude-opus-4 -> ")));
    let log = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        log.lines()
            .any(|l| l.contains("\"action\":\"allow\"") && l.contains("\"rule\":\"cheap-tier\"")),
        "forwarded requests on a route rule audit as allow"
    );
    assert!(
        decoyrail::audit::verify().is_ok(),
        "audit chain must verify across route events"
    );
}
