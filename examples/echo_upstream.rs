//! A tiny local TLS upstream for the e2e script — replaces the dependency on
//! httpbin.org (flaky, rate-limited, and it meant sending test "secrets" to a
//! third party). Serves `localhost` with a self-signed cert.
//!
//! Usage: echo_upstream <port> <cert_out.pem>
//!   Writes its self-signed cert PEM to <cert_out.pem> (point DECOYRAIL_EXTRA_CA
//!   at it so Decoyrail trusts this upstream), then serves:
//!     GET /headers       → JSON echo of received request headers
//!     POST /v1/messages  → Anthropic-shaped stub reply with a usage block,
//!                          echoing the requested model (for the demo tapes
//!                          and anything that needs priceable traffic)
//!     any other          → 200 "ok"

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

async fn handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    if req.uri().path() == "/headers" {
        let mut map = serde_json::Map::new();
        for (name, value) in req.headers() {
            if let Ok(v) = value.to_str() {
                map.insert(
                    name.as_str().to_string(),
                    serde_json::Value::String(v.to_string()),
                );
            }
        }
        let body = serde_json::json!({ "headers": map }).to_string();
        Ok(Response::new(Full::new(Bytes::from(body))))
    } else if req.uri().path() == "/v1/messages" {
        // Stand-in for an LLM API: echo the requested model and report a
        // plausible coding-agent usage so the metering side has something
        // real to parse and price. Deterministic on purpose.
        let body = match req.into_body().collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => Bytes::new(),
        };
        let model = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| Some(v.get("model")?.as_str()?.to_string()))
            .unwrap_or_else(|| "claude-sonnet-5".to_string());
        let reply = serde_json::json!({
            "id": "msg_stub",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [{ "type": "text", "text": "ok" }],
            "stop_reason": "end_turn",
            "usage": { "input_tokens": 52_413, "output_tokens": 387 }
        })
        .to_string();
        Ok(Response::builder()
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(reply)))
            .expect("static response parts"))
    } else {
        Ok(Response::new(Full::new(Bytes::from("ok"))))
    }
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut args = std::env::args().skip(1);
    let port: u16 = args.next().expect("port").parse().expect("port number");
    let cert_out = args.next().expect("cert output path");

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
    std::fs::write(&cert_out, cert.pem()).unwrap();

    let chain = vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())];
    let key_der = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap();
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key_der)
        .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(cfg));

    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    eprintln!("echo_upstream listening on 127.0.0.1:{port}");
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
                .serve_connection(TokioIo::new(tls), service_fn(handle))
                .await;
        });
    }
}
