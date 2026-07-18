//! End-to-end budget soft-landing tests (plan 003) against a local TLS
//! upstream that echoes request bodies, so every assertion sees exactly the
//! bytes the proxy forwarded.
//!
//! One test drives the scenarios sequentially through a single booted proxy,
//! for the same reason as `proxy_integration`: `DECOYRAIL_HOME` and the
//! license trust hook are process-global env. This file is its own test
//! binary, so it runs in its own process and cannot race that test's env.

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

#[tokio::test(flavor = "multi_thread")]
async fn budget_soft_landing_end_to_end() {
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

    // Policy: allow localhost; soft-landing at 80% with an explicit map.
    let base_policy = "default_action = \"deny\"\nescalate_fallback = \"deny\"\n\
         [[rule]]\nname = \"local\"\nhosts = [\"localhost\"]\naction = \"allow\"\n";
    decoyrail::policy_edit::write_policy(
        &format!(
            "{base_policy}[soft_landing]\nthreshold_pct = 80\n\
             map = {{ \"claude-opus-4\" = \"claude-sonnet-5\" }}\n"
        ),
        "test setup",
    )
    .unwrap();

    // Treat the local upstream as an Anthropic-protocol host so its requests
    // classify as LLM traffic with an identifiable model.
    std::fs::write(
        home.path().join("pricing.json"),
        r#"{"hosts": {"localhost": "anthropic"}}"#,
    )
    .unwrap();

    // Budget $1.00 with $0.85 of billable spend already on the books: 85% of
    // budget, inside the 80% band, under the hard limit. The spend sits on a
    // host the byte estimator prices, and localhost traffic estimates at $0,
    // so the fraction stays put while the scenarios run.
    decoyrail::meter::save_budget(1.0).unwrap();
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

    let engine = Engine::boot().unwrap();
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
    let body_opus =
        r#"{"model":"claude-opus-4","max_tokens":16,"messages":[{"role":"user","content":"hi"}]}"#;

    // 1. NO PRO LICENSE: spend is in the band, but the free tier never
    //    rewrites — the body passes byte-identical, nothing marks the
    //    response, and today's behavior (nothing until the kill switch) holds.
    let resp = client
        .post(format!("{base}/echo-body"))
        .header("content-type", "application/json")
        .body(body_opus)
        .send()
        .await
        .expect("no-license request");
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get("x-decoyrail-downgrade").is_none(),
        "no Pro license, no downgrade marker"
    );
    assert_eq!(
        resp.text().await.unwrap(),
        body_opus,
        "without Pro the body must pass byte-identical"
    );
    let log = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        !log.contains("\"action\":\"downgrade\""),
        "no downgrade event without Pro"
    );

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

    // 2. IN THE BAND (Pro): the forwarded body carries the mapped model, the
    //    response says so, and the audit event notes the cache invalidation.
    let resp = client
        .post(format!("{base}/echo-body"))
        .header("content-type", "application/json")
        .body(body_opus)
        .send()
        .await
        .expect("in-band request");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-decoyrail-downgrade")
            .expect("downgrade marker header"),
        "claude-opus-4 -> claude-sonnet-5"
    );
    let echoed = resp.text().await.unwrap();
    assert_eq!(
        echoed,
        body_opus.replace("claude-opus-4", "claude-sonnet-5"),
        "only the model value may change"
    );
    let log = std::fs::read_to_string(&audit_path).unwrap();
    let line = log
        .lines()
        .find(|l| l.contains("\"action\":\"downgrade\""))
        .expect("a downgrade audit event must be recorded");
    assert!(
        line.contains("budget soft-landing: model claude-opus-4 -> claude-sonnet-5"),
        "the event names the mapping: {line}"
    );
    assert!(
        line.contains("at 85% of budget"),
        "the event says why: {line}"
    );
    assert!(
        line.contains("prompt cache invalidated"),
        "the event must note the cache invalidation: {line}"
    );
    assert!(
        !line.contains("not in the pricing table"),
        "a priced target model is not flagged: {line}"
    );

    // 3. UNDER THE THRESHOLD: raising the budget to $2 puts the same spend
    //    at ~42%; the body passes byte-identical again.
    decoyrail::meter::save_budget(2.0).unwrap();
    bump_mtime(&home.path().join("budget.json"), 2);
    let resp = client
        .post(format!("{base}/echo-body"))
        .header("content-type", "application/json")
        .body(body_opus)
        .send()
        .await
        .expect("under-threshold request");
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers().get("x-decoyrail-downgrade").is_none(),
        "under the threshold nothing is marked"
    );
    assert_eq!(
        resp.text().await.unwrap(),
        body_opus,
        "under the threshold the body must pass byte-identical"
    );

    // 4. HARD LIMIT UNCHANGED: budget $0.50 puts spend at 170%; the kill
    //    switch denies exactly as today — no downgrade sneaks in front of it.
    decoyrail::meter::save_budget(0.5).unwrap();
    bump_mtime(&home.path().join("budget.json"), 4);
    let resp = client
        .post(format!("{base}/echo-body"))
        .header("content-type", "application/json")
        .body(body_opus)
        .send()
        .await
        .expect("over-budget request");
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

    // 5. UNKNOWN TARGET MODEL: a map naming a model the pricing table doesn't
    //    know forwards as configured (the provider errors informatively) and
    //    the audit note flags the likely typo.
    decoyrail::meter::save_budget(1.0).unwrap();
    bump_mtime(&home.path().join("budget.json"), 6);
    decoyrail::policy_edit::write_policy(
        &format!(
            "{base_policy}[soft_landing]\nthreshold_pct = 80\n\
             map = {{ \"claude-opus-4\" = \"totally-unknown-model\" }}\n"
        ),
        "test",
    )
    .unwrap();
    bump_mtime(&home.path().join("policy.toml"), 6);
    let resp = client
        .post(format!("{base}/echo-body"))
        .header("content-type", "application/json")
        .body(body_opus)
        .send()
        .await
        .expect("unknown-target request");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("x-decoyrail-downgrade")
            .expect("downgrade marker header"),
        "claude-opus-4 -> totally-unknown-model"
    );
    assert!(
        resp.text().await.unwrap().contains("totally-unknown-model"),
        "the configured target forwards as written"
    );
    let log = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        log.lines().any(|l| l.contains("\"action\":\"downgrade\"")
            && l.contains("totally-unknown-model")
            && l.contains("not in the pricing table")),
        "the unknown target must be logged as such"
    );

    // 6. MODEL ABSENT: nothing identifiable, nothing guessed — the request
    //    passes through unchanged even inside the band.
    let body_no_model = r#"{"messages":[{"role":"user","content":"hi"}]}"#;
    let resp = client
        .post(format!("{base}/echo-body"))
        .header("content-type", "application/json")
        .body(body_no_model)
        .send()
        .await
        .expect("model-absent request");
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get("x-decoyrail-downgrade").is_none());
    assert_eq!(resp.text().await.unwrap(), body_no_model);

    // 7. Every downgrade event chains cleanly: the tamper-evident log
    //    verifies across the whole run (what `decoyrail log --verify` runs).
    assert!(
        decoyrail::audit::verify().is_ok(),
        "audit chain must verify across downgrade events"
    );
}
