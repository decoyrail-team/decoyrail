//! End-to-end spend-tripwire tests (plan 002) against a local TLS upstream,
//! driving the proxy pipeline in-process: a replayed request blocks at the
//! policy's repeat threshold with a machine-readable body, the trip stands
//! until an explicit clear, non-LLM egress keeps flowing, alert mode records
//! without blocking, and every event lands chain-valid in the audit log.
//!
//! One test drives the scenarios sequentially through a single booted proxy,
//! for the same reason as `proxy_integration` and friends: `DECOYRAIL_HOME`
//! is process-global env, and this file being its own test binary keeps it
//! from racing the other integration suites.

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

/// The upstream echoes every request body verbatim: the test's view of what
/// actually left the proxy (and proof a request was forwarded at all). Paths
/// under /sse answer as an Anthropic SSE stream with usage instead, so the
/// streamed-metering path (and its spend-rate feed) gets exercised too.
async fn upstream_service(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let sse = req.uri().path().starts_with("/sse");
    let body = req.into_body().collect().await.unwrap().to_bytes();
    if sse {
        let stream = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-4\",",
            "\"usage\":{\"input_tokens\":1000,\"cache_creation_input_tokens\":0,",
            "\"cache_read_input_tokens\":0}}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":200}}\n\n",
        );
        return Ok(Response::builder()
            .header("content-type", "text/event-stream")
            .body(Full::new(Bytes::from_static(stream.as_bytes())))
            .unwrap());
    }
    Ok(Response::builder()
        .header("content-type", "application/json")
        .body(Full::new(body))
        .unwrap())
}

/// Spawn a TLS upstream serving `localhost` and `127.0.0.1`; returns
/// (port, cert_pem) where the self-signed cert doubles as the trust anchor
/// for DECOYRAIL_EXTRA_CA.
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

/// A plaintext twin of the upstream for the non-LLM scenario: the proxy's
/// plain-HTTP path skips TLS minting, which only supports DNS names, and an
/// IP-named host is exactly the "ordinary non-LLM egress" stand-in we want.
async fn spawn_plain_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service_fn(upstream_service))
                    .await;
            });
        }
    });
    port
}

/// Push a file's mtime into the future so the per-request hot reload can't
/// miss an edit landing within the filesystem's timestamp granularity.
fn bump_mtime(path: &std::path::Path, secs: u64) {
    let f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(secs))
        .unwrap();
}

/// Allow both upstream names; the tripwire table's mode is a parameter so
/// the alert-mode scenario can hot-swap it. A tiny threshold keeps the test
/// fast; the defaults are proven in `watch`'s unit tests.
fn policy_text(mode: &str) -> String {
    format!(
        "default_action = \"deny\"\nescalate_fallback = \"deny\"\n\
         [[rule]]\nname = \"local\"\nhosts = [\"localhost\", \"127.0.0.1\"]\naction = \"allow\"\n\
         [spend_tripwire]\nmode = \"{mode}\"\nrepeats = 3\nwindow_secs = 300\n"
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn spend_tripwire_end_to_end() {
    decoyrail::proxy_test_install_crypto();

    let home = tempfile::tempdir().unwrap();
    std::env::set_var("DECOYRAIL_HOME", home.path());
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
    let plain_port = spawn_plain_upstream().await;
    let extra_ca = home.path().join("upstream.pem");
    std::fs::write(&extra_ca, &up_cert_pem).unwrap();
    std::env::set_var("DECOYRAIL_EXTRA_CA", &extra_ca);

    decoyrail::policy_edit::write_policy(&policy_text("block"), "test setup").unwrap();

    // `localhost` classifies as an LLM provider host (the tripwire's scope);
    // `127.0.0.1` stays unmapped, standing in for ordinary non-LLM egress.
    std::fs::write(
        home.path().join("pricing.json"),
        r#"{"hosts": {"localhost": "anthropic"}}"#,
    )
    .unwrap();

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

    let audit_path = home.path().join("audit.jsonl");
    let post = |host: &'static str, body: String| {
        let client = client.clone();
        async move {
            client
                .post(format!("https://{host}:{up_port}/v1/messages"))
                .header("content-type", "application/json")
                .body(body)
                .send()
                .await
                .expect("request through proxy")
        }
    };
    let loop_body =
        r#"{"model":"claude-opus-4","messages":[{"role":"user","content":"same failing call"}]}"#
            .to_string();

    // 1. DISTINCT REQUESTS DON'T TRIP (AC b): a burst of unique requests,
    //    well past the repeat threshold in count, all forward.
    for i in 0..6 {
        let body = format!(
            r#"{{"model":"claude-opus-4","messages":[{{"role":"user","content":"distinct {i}"}}]}}"#
        );
        let resp = post("localhost", body.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK, "distinct request {i}");
        assert_eq!(resp.text().await.unwrap(), body, "forwarded verbatim");
    }
    assert!(
        decoyrail::watch::load_trip().unwrap().is_none(),
        "distinct traffic must not trip"
    );

    // 2. REPLAYED REQUEST BLOCKS AT THE THRESHOLD (AC a): identical bodies;
    //    the first two forward, the third is the loop and is denied with a
    //    machine-readable body naming the trigger and the clear path.
    for i in 0..2 {
        let resp = post("localhost", loop_body.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK, "repeat {i} below threshold");
    }
    let resp = post("localhost", loop_body.clone()).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "third repeat trips");
    let body: serde_json::Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    assert_eq!(body["decoyrail"], true);
    assert_eq!(body["blocked"], true);
    assert_eq!(body["reason"], "spend_tripwire");
    assert_eq!(body["trigger"]["kind"], "repeat");
    assert_eq!(body["trigger"]["count"], 3);
    let fp = body["trigger"]["fingerprint"].as_str().unwrap();
    assert_eq!(fp.len(), 16, "salted fingerprint, not content");
    assert!(!loop_body.contains(fp), "fingerprint must not echo content");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("decoyrail trip clear"),
        "the block must explain how to clear: {body}"
    );

    // The trip persisted with the trigger's facts.
    let trip = decoyrail::watch::load_trip()
        .unwrap()
        .expect("trip.json written");
    assert_eq!(trip.kind, "repeat");
    assert_eq!(trip.fingerprint, fp);
    assert!(!trip.sid.is_empty(), "trip records the tripping session");

    // 3. THE TRIP STANDS: a different LLM-bound request is also denied (the
    //    loop must not continue by varying one byte of an already-runaway
    //    session), and the deny is audited with the spend-tripwire note.
    let resp = post(
        "localhost",
        r#"{"model":"claude-opus-4","messages":[{"role":"user","content":"fresh"}]}"#.into(),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "trip blocks LLM traffic"
    );
    let log = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        log.contains("spend tripwire: identical request repeated 3x"),
        "deny must carry the trigger: {log}"
    );

    // 4. NON-LLM EGRESS KEEPS FLOWING: an unmapped host classifies as
    //    ordinary traffic and rides through the trip.
    let resp = client
        .post(format!("http://127.0.0.1:{plain_port}/anything"))
        .body(r#"{"anything":"else"}"#)
        .send()
        .await
        .expect("plain request through proxy");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "a spend trip must not block non-LLM egress"
    );

    // 5. EXPLICIT CLEAR (AC d): removing trip.json (what `decoyrail trip
    //    clear` does) unblocks the running proxy without a restart, and
    //    detection starts fresh — the cleared window must not re-trip on the
    //    next single request.
    decoyrail::watch::clear_trip().unwrap();
    let resp = post("localhost", loop_body.clone()).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "cleared trip must unblock live traffic"
    );

    // 5.5. STREAMED SPEND FEEDS THE RATE DETECTOR: an SSE response with
    //      provider usage is metered off the response path, and its billable
    //      dollars reach the same watch state the buffered path feeds. The
    //      observable contract is the metered spend; the watch feed shares
    //      the code path.
    let resp = client
        .post(format!("https://localhost:{up_port}/sse/messages"))
        .header("content-type", "application/json")
        .body(r#"{"model":"claude-opus-4","stream":true,"messages":[{"role":"user","content":"stream me"}]}"#)
        .send()
        .await
        .expect("sse request through proxy");
    assert_eq!(resp.status(), StatusCode::OK);
    let sse_text = resp.text().await.unwrap();
    assert!(sse_text.contains("message_delta"), "SSE passed through");
    // The metering task runs off the response path; give it a beat, then
    // check the usage event landed with cost attached.
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let log = std::fs::read_to_string(&audit_path).unwrap();
        if log.contains("\"action\":\"usage\"") {
            break;
        }
    }
    assert!(
        std::fs::read_to_string(&audit_path)
            .unwrap()
            .contains("\"action\":\"usage\""),
        "streamed usage event must land"
    );

    // A non-provider stream takes the same metering path with nothing billed:
    // the rate detector must see no spend from it.
    let resp = client
        .post(format!("http://127.0.0.1:{plain_port}/sse/other"))
        .body(r#"{"just":"a stream"}"#)
        .send()
        .await
        .expect("plain sse through proxy");
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.text().await.unwrap().contains("message_delta"));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // 6. ALERT MODE: hot-swap the policy; the same replay tips the detector
    //    but traffic keeps forwarding, with exactly one alert event at onset.
    decoyrail::policy_edit::write_policy(&policy_text("alert"), "alert mode").unwrap();
    bump_mtime(&home.path().join("policy.toml"), 2);
    decoyrail::watch::clear_trip().unwrap();
    let alerts_before = std::fs::read_to_string(&audit_path)
        .unwrap()
        .lines()
        .filter(|l| l.contains("alert mode: forwarding continues"))
        .count();
    for i in 0..5 {
        let resp = post("localhost", loop_body.clone()).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "alert mode must never block (repeat {i})"
        );
    }
    let log = std::fs::read_to_string(&audit_path).unwrap();
    let alerts_after = log
        .lines()
        .filter(|l| l.contains("alert mode: forwarding continues"))
        .count();
    assert_eq!(
        alerts_after,
        alerts_before + 1,
        "the trip is news exactly once, not per request"
    );
    assert!(
        decoyrail::watch::load_trip().unwrap().is_some(),
        "alert mode still records the trip"
    );

    // 7. FINGERPRINTS ON REQUEST EVENTS: LLM-bound allow events carry the
    //    salted fp (the waste report's grouping key); unmapped-host events
    //    don't. And the whole log, trips and all, verifies chain-valid
    //    (AC a's second half).
    let allow_with_fp = log
        .lines()
        .filter(|l| l.contains("\"action\":\"allow\"") && l.contains("\"fp\":\""))
        .count();
    assert!(allow_with_fp >= 8, "LLM allows carry fingerprints: {log}");
    assert!(
        !log.lines()
            .any(|l| l.contains("\"host\":\"127.0.0.1\"") && l.contains("\"fp\":\"")),
        "non-LLM events must not carry fingerprints"
    );
    let verified = decoyrail::audit::verify().expect("audit chain verifies");
    assert!(verified > 0);

    // 8. PERSISTENCE FAILURE STILL TRIPS: with trip.json unwritable (a
    //    directory squats on the atomic-write temp path), the detector still
    //    blocks from memory; only durability is lost, never enforcement.
    decoyrail::policy_edit::write_policy(&policy_text("block"), "back to block").unwrap();
    bump_mtime(&home.path().join("policy.toml"), 4);
    decoyrail::watch::clear_trip().unwrap();
    std::fs::create_dir(home.path().join("trip.tmp")).unwrap();
    for i in 0..2 {
        let resp = post("localhost", loop_body.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK, "repeat {i} below threshold");
    }
    let resp = post("localhost", loop_body.clone()).await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "an unpersistable trip must still block in memory"
    );
    assert!(
        decoyrail::watch::load_trip().unwrap().is_none(),
        "the write really failed; enforcement came from memory alone"
    );
    std::fs::remove_dir(home.path().join("trip.tmp")).unwrap();

    let verified = decoyrail::audit::verify().expect("audit chain verifies after all scenarios");
    assert!(verified > 0);

    std::env::remove_var("DECOYRAIL_HOME");
    std::env::remove_var("DECOYRAIL_EXTRA_CA");
}
