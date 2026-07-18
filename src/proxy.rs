//! The MITM proxy: the trusted boundary where decoys become real secrets for
//! approved destinations and tripwires fire for everything else.
//!
//! Flow per connection:
//!   1. Read the `CONNECT host:port` line from the client.
//!   2. Reply 200, then TLS-terminate using a leaf cert minted for `host`.
//!   3. Serve HTTP/1.1 over the decrypted stream; each request runs the
//!      pipeline (policy → budget → swap/tripwire → DLP → forward/deny →
//!      audit).
//!   4. Forward approved requests upstream over real TLS and stream the
//!      response back. Event-streams (SSE) pass through untouched for low
//!      latency; bounded JSON responses are scanned for real-secret echoes.

use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::audit::Entry;
use crate::engine::Engine;
use crate::policy::Action;
use crate::swap::{self, RequestCtx};

type ResBody = BoxBody<Bytes, std::io::Error>;

/// Buffered JSON responses larger than this are streamed without scanning.
const SCAN_CAP: usize = 1 << 20; // 1 MiB

/// Request bodies are buffered for swap/tripwire inspection; beyond this cap
/// the request is rejected outright (413) rather than forwarded uninspected —
/// forwarding would bypass the tripwire, and buffering unboundedly lets one
/// runaway client OOM the proxy (and with it, all egress control).
const REQ_BODY_CAP: usize = 32 << 20; // 32 MiB

pub async fn serve(engine: Engine, addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("decoyrail proxy listening on {}", listener.local_addr()?);
    serve_on(engine, listener).await;
    Ok(())
}

/// Accept loop over an already-bound listener (used by `decoyrail run`, which needs
/// the ephemeral port before spawning the child).
pub async fn serve_on(engine: Engine, listener: TcpListener) {
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        let engine = engine.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(engine, stream).await {
                // Connection-level errors are common (clients hang up); stay quiet
                // unless debugging.
                if std::env::var("DECOYRAIL_DEBUG").is_ok() {
                    eprintln!("conn error: {e:#}");
                }
            }
        });
    }
}

/// Routing fields parsed from a raw request head: the request line's method
/// and target, plus the target read as a CONNECT `host:port`. Public (with
/// `parse_head`) so the exact parse the proxy trusts for policy, cert
/// minting, and audit can be unit-tested and fuzzed.
#[derive(Debug)]
pub struct HeadRoute {
    pub method: String,
    pub target: String,
    /// Hostnames are case-insensitive; normalized once here so policy rules,
    /// secret release, and audit entries all see one canonical form.
    pub host: String,
    /// The tunnel port is preserved so non-443 upstreams (e.g. :8443 APIs)
    /// reach the right place; an absent or malformed port defaults to 443.
    pub port: u16,
}

/// Parse the routing fields out of a raw request head (the bytes up to
/// CRLFCRLF). Total: any input yields a route; empty fields mean the head
/// carried no request line.
pub fn parse_head(head: &[u8]) -> HeadRoute {
    let head_text = String::from_utf8_lossy(head);
    let first_line = head_text.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let (host, port) = match target.rsplit_once(':') {
        Some((h, p)) => (h.to_ascii_lowercase(), p.parse::<u16>().unwrap_or(443)),
        None => (target.to_ascii_lowercase(), 443),
    };
    HeadRoute {
        method,
        target,
        host,
        port,
    }
}

async fn handle_conn(engine: Engine, mut stream: TcpStream) -> Result<()> {
    let head = read_request_head(&mut stream).await?;
    let route = parse_head(&head);

    if !route.method.eq_ignore_ascii_case("CONNECT") {
        // Plaintext HTTP arrives as absolute-form requests; replay the head we
        // consumed for routing and run the same pipeline (without TLS).
        return serve_plain_http(engine, head, stream).await;
    }

    let (host, port) = (route.host, route.port);

    // Acknowledge the tunnel, then take over TLS ourselves.
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let (chain, key) = engine.ca.leaf_for(&host)?;
    let mut server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    server_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let tls = acceptor.accept(stream).await?;

    let host_for_service = host.clone();
    let engine_for_service = engine.clone();
    let service = service_fn(move |req: Request<Incoming>| {
        let engine = engine_for_service.clone();
        let host = host_for_service.clone();
        async move { Ok::<_, Infallible>(pipeline(engine, host, port, true, req).await) }
    });

    http1::Builder::new()
        .serve_connection(TokioIo::new(tls), service)
        .await
        .map_err(|e| anyhow!("serving TLS connection: {e}"))?;
    Ok(())
}

/// Serve absolute-form plaintext HTTP proxy requests over an accepted socket.
/// Each request names its own destination, so host/port derive per request.
async fn serve_plain_http(engine: Engine, head: Vec<u8>, stream: TcpStream) -> Result<()> {
    let service = service_fn(move |req: Request<Incoming>| {
        let engine = engine.clone();
        async move {
            let Some(host) = req.uri().host().map(|h| h.to_ascii_lowercase()) else {
                return Ok::<_, Infallible>(deny_response(
                    StatusCode::BAD_REQUEST,
                    "decoyrail: expected an absolute-form proxy request",
                ));
            };
            let port = req.uri().port_u16().unwrap_or(80);
            Ok(pipeline(engine, host, port, false, req).await)
        }
    });

    http1::Builder::new()
        .serve_connection(TokioIo::new(Rewind::new(head, stream)), service)
        .await
        .map_err(|e| anyhow!("serving plaintext connection: {e}"))?;
    Ok(())
}

/// The per-request control pipeline. Never panics — always yields a response.
async fn pipeline(
    engine: Engine,
    host: String,
    port: u16,
    tls: bool,
    req: Request<Incoming>,
) -> Response<ResBody> {
    match pipeline_inner(&engine, &host, port, tls, req).await {
        Ok(resp) => resp,
        Err(e) => deny_response(
            StatusCode::BAD_GATEWAY,
            &format!("decoyrail: upstream error: {e:#}"),
        ),
    }
}

async fn pipeline_inner(
    engine: &Engine,
    host: &str,
    port: u16,
    tls: bool,
    req: Request<Incoming>,
) -> Result<Response<ResBody>> {
    let started = std::time::Instant::now();
    let method = req.method().to_string();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.to_string())
        .unwrap_or_else(|| "/".into());

    // Collect request headers into an owned, mutable form for swapping.
    let mut headers: Vec<(String, String)> = Vec::new();
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            headers.push((name.as_str().to_string(), v.to_string()));
        }
    }

    // Pick up vault/policy/budget edits made since the proxy started.
    engine.refresh().await;

    // 1. Policy decision on destination (and the DLP detector modes plus the
    //    prompt-cache, soft-landing, and spend-tripwire knobs, read under the
    //    same lock so one request sees one consistent policy).
    let (decision, dlp_cfg, cache_cfg, soft_cfg, trip_cfg) = {
        let policy = engine.policy.read().await;
        (
            policy.evaluate(host, &path, &method),
            policy.dlp.clone(),
            policy.cache.clone(),
            policy.soft_landing.clone(),
            policy.spend_tripwire.clone(),
        )
    };

    // 2. Budget kill switch (global: merged spend from all sessions plus
    //    ours), and the spend fraction the soft-landing band check reads.
    let (over_budget, budget_pct) = {
        let mut meter = engine.meter.lock().await;
        let now = crate::util::current_period();
        (meter.over_budget(&now), meter.budget_used_pct(&now))
    };

    // 3. Buffer the request body (prompts are small; enables body swap),
    //    bounded so a runaway client can't exhaust proxy memory.
    let mut body_bytes = match http_body_util::Limited::new(req.into_body(), REQ_BODY_CAP)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(e) if e.is::<http_body_util::LengthLimitError>() => {
            audit(
                engine,
                Entry {
                    host: host.into(),
                    path,
                    method,
                    action: "deny".into(),
                    rule: decision.rule,
                    escalated: decision.escalated,
                    status: 413,
                    note: format!("request body exceeds {REQ_BODY_CAP} byte inspection cap"),
                    dur_ms: Some(started.elapsed().as_millis() as u64),
                    ..Default::default()
                },
            )
            .await;
            return Ok(deny_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "decoyrail: request body exceeds the inspection cap",
            ));
        }
        Err(e) => return Err(anyhow!("reading request body: {e}")),
    };

    // 3.35. Spend tripwire (plan 002): identify LLM-bound requests by a
    //       salted fingerprint of destination + method + pre-swap body (the
    //       bytes as the agent sent them, before any rewrite below can vary
    //       them) and run the runaway detectors — the same request repeated
    //       past the policy's threshold inside its window, or a spend rate
    //       far above the session's own baseline. A trip persists to
    //       trip.json until `decoyrail trip clear` (a restart is not a
    //       clear), and in block mode denies LLM-bound traffic below with
    //       the same precedence family as the budget kill switch; non-LLM
    //       egress keeps flowing either way. Alert mode records the onset
    //       and keeps forwarding. This is a free-tier safety verb: no
    //       license read anywhere near it.
    let provider = engine.pricing.read().await.provider_for_host(host);
    let fp = provider
        .is_some()
        .then(|| crate::watch::fingerprint(&engine.dlp_salt, host, &path, &method, &body_bytes));
    let mut spend_trip: Option<crate::watch::Trip> = None;
    let mut trip_onset = false;
    if let Some(fp) = &fp {
        let mut watch = engine.watch.lock().await;
        if let Some(t) = watch.tripped() {
            spend_trip = Some(t.clone());
        } else if let Some(sig) = watch.observe(&trip_cfg, crate::util::now_unix(), fp) {
            let trip = sig.to_trip(
                trip_cfg.window_secs,
                crate::util::now_rfc3339(),
                engine.session_id.clone(),
            );
            watch.set_tripped(Some(trip.clone()));
            // Persist so the trip outlives this process and reaches the
            // other sessions sharing this home. A failed write still trips
            // this session (the in-memory state above), just not durably.
            if let Err(e) = crate::watch::save_trip(&trip) {
                eprintln!("decoyrail: warning: could not persist spend trip: {e:#}");
            }
            spend_trip = Some(trip);
            trip_onset = true;
        }
    }
    let spend_block = spend_trip.is_some() && trip_cfg.mode == crate::policy::TripwireMode::Block;
    if trip_onset && !spend_block {
        // Alert mode: the trip is news exactly once, not per request; the
        // traffic keeps forwarding below.
        let trip = spend_trip.as_ref().expect("onset implies a trip");
        audit(
            engine,
            Entry {
                host: host.into(),
                path: path.clone(),
                method: method.clone(),
                action: "alert".into(),
                rule: decision.rule.clone(),
                note: format!(
                    "spend tripwire: {} (alert mode: forwarding continues; \
                     clear with `decoyrail trip clear`)",
                    trip.reason
                ),
                fp: fp.clone(),
                ..Default::default()
            },
        )
        .await;
    }

    // 3.4. Budget soft-landing (plan 003, Pro + policy opt-in): in the band
    //      between the policy's threshold and the hard limit, rewrite the
    //      requested model to the cheaper one the downgrade map names. Runs
    //      before the doctor, the accounting parse, and the swap, so every
    //      later step sees exactly the body that forwards; at 100% the kill
    //      switch below still denies, unchanged. The tier read gates only
    //      this paid convenience, never a security verb — with no Pro
    //      license, no configured table, or no mapped model, the bytes pass
    //      through untouched and only the hard limit remains. Subscription
    //      traffic never feeds the band: `budget_used_pct` counts billable
    //      dollars only. The downgrade is never silent: an audit event here,
    //      a response header below.
    let mut downgrade_header: Option<String> = None;
    if soft_cfg.enabled()
        && provider.is_some()
        && !over_budget
        && !spend_block
        && matches!(
            decision.action,
            Action::Allow | Action::Warn | Action::Route
        )
        && budget_pct.is_some_and(|pct| pct >= soft_cfg.threshold_pct)
        && engine.tier().await >= crate::license::Tier::Pro
    {
        if let Some(rw) = crate::softland::rewrite_model(&body_bytes, &soft_cfg.map) {
            body_bytes = rw.body;
            let pct = budget_pct.unwrap_or(0.0);
            // A model rewrite invalidates the provider's prompt cache (caches
            // are model-scoped), so the note says so and the cost math stays
            // honest. A target model the pricing table doesn't know forwards
            // as configured (the provider errors informatively) but is
            // flagged: it is likely a typo in the map.
            let mut note = format!(
                "budget soft-landing: model {} -> {} at {pct:.0}% of budget; \
                 provider prompt cache invalidated (caches are model-scoped)",
                rw.from, rw.to
            );
            if !engine.pricing.read().await.knows_model(&rw.to) {
                note.push_str("; target model not in the pricing table");
            }
            downgrade_header = Some(format!("{} -> {}", rw.from, rw.to));
            audit(
                engine,
                Entry {
                    host: host.into(),
                    path: path.clone(),
                    method: method.clone(),
                    action: "downgrade".into(),
                    rule: decision.rule.clone(),
                    note,
                    ..Default::default()
                },
            )
            .await;
        }
    }

    // 3.45. Model router (plan 006, Pro + a winning `route` rule): rewrite
    //       the requested model per the rule's explicit map. Runs after the
    //       soft-landing step, so in the budget band the map applies to the
    //       model actually about to forward (both rewrites audit
    //       independently), and before the doctor, the accounting parse, and
    //       the swap, so every later step sees the body that forwards.
    //       Security verbs outrank it exactly as they outrank an allow: a
    //       deny rule never reaches here, the over-budget kill switch is
    //       checked before the rewrite, and a tripwire or DLP block below
    //       still denies. The tier read gates only the paid rewrite, never
    //       reachability — without Pro the rule still allows and the bytes
    //       ride through untouched. A rule with no map, or a request whose
    //       model is absent, unmapped, or unidentifiable, forwards
    //       unmodified: never an error, never a guess. The rewrite is never
    //       silent: a `route` audit event here (pricing any warm prompt
    //       cache it forfeits — caches are model-scoped — from the doctor's
    //       state for the original model), a response header below.
    let mut route_header: Option<String> = None;
    if let (Action::Route, Some(prov)) = (decision.action, provider) {
        if !over_budget && !spend_block && engine.tier().await >= crate::license::Tier::Pro {
            if let Some(rw) = crate::softland::rewrite_model(&body_bytes, &decision.route) {
                body_bytes = rw.body;
                let mut note = format!(
                    "route: model {} -> {}; provider prompt cache invalidated \
                     (caches are model-scoped)",
                    rw.from, rw.to
                );
                // Cache-aware routing: when the doctor knows a warm cacheable
                // prefix for the original model on this host, the note prices
                // what the rewrite forfeits — that prefix re-bills at the
                // full input rate instead of the cache-read rate.
                let warm = engine.cache.lock().await.warm_prefix_bytes(
                    host,
                    &rw.from,
                    crate::util::now_unix(),
                );
                if let Some(bytes) = warm {
                    let rate = engine.pricing.read().await.rate_for(prov, Some(&rw.from));
                    let waste = crate::cache::repairable_waste_usd(bytes, &rate);
                    note.push_str(&format!(
                        "; forfeits a warm {bytes}-byte cached prefix for {} \
                         (~${waste:.4} re-bills at the full input rate)",
                        rw.from
                    ));
                }
                // A target the pricing table doesn't know forwards as
                // configured (the provider errors informatively) but is
                // flagged: it is likely a typo in the map.
                if !engine.pricing.read().await.knows_model(&rw.to) {
                    note.push_str("; target model not in the pricing table");
                }
                route_header = Some(format!("{} -> {}", rw.from, rw.to));
                audit(
                    engine,
                    Entry {
                        host: host.into(),
                        path: path.clone(),
                        method: method.clone(),
                        action: "route".into(),
                        rule: decision.rule.clone(),
                        note,
                        ..Default::default()
                    },
                )
                .await;
            }
        }
    }

    // 3.5. Prompt-cache doctor (observe-only, plan 004): diagnose cache
    //      hygiene on the pre-swap body, so nothing the doctor keeps ever
    //      derives from a real secret. Anthropic protocol only (OpenAI's
    //      cache is automatic, no request-side markers to check), and only
    //      for requests policy is letting through: a denied request never
    //      reaches the provider, so it can't affect the provider's cache.
    //      Tripwire/DLP overrides below aren't known yet; both are rare on a
    //      provider-bound request and cost one noisy comparison, not a
    //      mutation. The parsed model is reused by the accounting step.
    let cache_active = provider == Some(crate::pricing::Provider::Anthropic)
        && matches!(decision.action, Action::Allow | Action::Route)
        && !over_budget
        && !spend_block;
    // Cache repair and active management are Pro conveniences; the tier read
    // never gates a security verb (SPEC invariant), only these paid features.
    let pro = cache_active
        && (cache_cfg.repair || cache_cfg.keep_alive || cache_cfg.serialize_fanout)
        && engine.tier().await >= crate::license::Tier::Pro;
    // Response header noting any repair, and the pre-swap request template a
    // keep-alive would replay (captured after any marker splice, before the
    // swap, so it carries markers but only decoys).
    let mut cache_header: Option<String> = None;
    let mut keepalive_template: Option<crate::cache::KeepAliveTemplate> = None;
    let doctor_model = if cache_active {
        let obs = {
            let mut doctor = engine.cache.lock().await;
            doctor.observe(host, &body_bytes, crate::util::now_unix())
        };
        if let Some(obs) = &obs {
            // Repair (phase 2, Pro + `[cache] repair`): the doctor flagged a
            // stable repeating prefix carrying no marker of its own; splice one
            // in, byte-surgically, on the pre-swap body.
            if pro && cache_cfg.repair {
                if let Some(plan) = &obs.repair {
                    if let Some(spliced) = crate::cache::splice_marker(&body_bytes, plan.ttl_1h) {
                        body_bytes = spliced;
                        if plan.ttl_1h {
                            add_beta_header(&mut headers, "extended-cache-ttl-2025-04-11");
                        }
                        engine.cache.lock().await.note_repaired(host, &obs.model);
                        let ttl = if plan.ttl_1h { " 1h" } else { "" };
                        cache_header = Some(format!("repaired {}", plan.section));
                        audit(
                            engine,
                            Entry {
                                host: host.into(),
                                path: path.clone(),
                                method: method.clone(),
                                action: "cache".into(),
                                rule: decision.rule.clone(),
                                note: format!("injected ephemeral{ttl} marker in {}", plan.section),
                                ..Default::default()
                            },
                        )
                        .await;
                    }
                }
            }
            // Keep-alive (phase 3): stash the request to replay during idle.
            // Captured here so it carries any repair marker but no real secret.
            // TLS-only: a pre-warm places real secrets, which never ride
            // plaintext (swap won't release them there anyway).
            if pro && cache_cfg.keep_alive && tls {
                keepalive_template = Some(crate::cache::KeepAliveTemplate {
                    method: method.clone(),
                    path: path.clone(),
                    port,
                    headers: headers.clone(),
                    body: body_bytes.clone(),
                });
            }
        }
        if let Err(e) = engine
            .cache
            .lock()
            .await
            .flush(&crate::util::current_period())
        {
            eprintln!("decoyrail: cache stats flush failed: {e:#}");
        }
        obs.map(|o| o.model)
    } else {
        None
    };

    // Fan-out serialization key (phase 3): computed from the pre-swap prefix,
    // before the body is consumed by the swap below. Same-prefix concurrent
    // requests share this key and serialize at the gate.
    let fanout_key = if pro && cache_cfg.serialize_fanout {
        doctor_model
            .as_deref()
            .and_then(|m| crate::cache::cacheable_key(host, m, &body_bytes))
    } else {
        None
    };

    // 4. Swap decoys → real for approved destinations; detect tripwires.
    let mut ctx = RequestCtx {
        host: host.to_string(),
        path: path.clone(),
        method: method.clone(),
        headers,
        body: body_bytes,
    };
    // The winning policy rule carries which secrets it releases; the swap
    // engine turns that into swap vs tripwire per decoy sighting. Real
    // secrets are only ever placed into TLS requests; a decoy riding a
    // plaintext request tripwires even toward a releasing rule (fail closed
    // rather than transmit a credential in the clear).
    let outcome = {
        let vault = engine.vault.read().await;
        let mut outcome = swap::apply(&mut ctx, &vault, &decision, tls);
        // Session secrets (auto-decoyed env vars) get the same treatment;
        // decoys never collide across the two vaults, so applying in sequence
        // composes.
        let session = swap::apply(&mut ctx, &engine.session, &decision, tls);
        outcome.swaps.extend(session.swaps);
        outcome.tripwires.extend(session.tripwires);
        outcome
    };

    // 4.5. Request-side DLP on the post-swap view — exactly the bytes that
    //      would leave. Mask-mode hits rewrite the body in place here; a
    //      blocking hit is resolved below with tripwire precedence.
    let dlp = crate::detect::apply(&mut ctx, &dlp_cfg, &engine.dlp_salt);

    // 4.6. Debug mode: preserve what DLP scanned in a private dump file the
    //      audit note can point at, with any real secret the swap placed
    //      scrubbed back out first. A failed dump is reported on stderr and
    //      the request proceeds to its verdict regardless.
    let dump_note = if dlp_cfg.debug && !dlp.hits.is_empty() {
        let vault = engine.vault.read().await;
        match write_dlp_dump(&ctx, &dlp, &vault, &engine.session) {
            Ok(p) => format!(" payload={}", p.display()),
            Err(e) => {
                eprintln!("decoyrail: dlp debug dump failed: {e:#}");
                String::new()
            }
        }
    } else {
        String::new()
    };

    // 5. Final action. A tripwire, a DLP block, or a blown budget overrides
    //    policy → deny, and critically we have NOT forwarded any real secret.
    //    These overrides take the same precedence over warn as over allow; a
    //    warn that survives them forwards below exactly like an allow (the
    //    swap released nothing, so only decoys ride it) and is audited as a
    //    distinct `warn` event.
    let (final_action, note) = if outcome.tripped() {
        let mut msg = format!("tripwire: {}", outcome.tripwires[0].message(host));
        if outcome.tripwires.len() > 1 {
            msg.push_str(&format!(" (+{} more)", outcome.tripwires.len() - 1));
        }
        (Action::Deny, msg)
    } else if dlp.has_blocking() {
        (Action::Deny, format!("dlp: {}{dump_note}", dlp.summary()))
    } else if over_budget {
        (Action::Deny, "budget exhausted".to_string())
    } else if spend_block {
        let trip = spend_trip.as_ref().expect("spend_block implies a trip");
        (
            Action::Deny,
            format!(
                "spend tripwire: {} (clear with `decoyrail trip clear`)",
                trip.reason
            ),
        )
    } else if decision.action == Action::Route {
        // A route rule forwards and audits exactly like allow; the rewrite
        // (when one happened) already wrote its own `route` event above.
        (Action::Allow, String::new())
    } else {
        (decision.action, String::new())
    };

    let swap_names: Vec<String> = outcome
        .swaps
        .iter()
        .map(|s| format!("{}@{}", s.secret_name, s.location))
        .collect();
    let trip_names: Vec<String> = outcome
        .tripwires
        .iter()
        .map(|t| format!("{}@{}", t.secret_name, t.seen_in))
        .collect();

    if final_action == Action::Deny {
        audit(
            engine,
            Entry {
                host: host.into(),
                path,
                method,
                action: "deny".into(),
                rule: decision.rule,
                escalated: decision.escalated,
                swaps: swap_names,
                tripwires: trip_names,
                status: 403,
                note: note.clone(),
                dur_ms: Some(started.elapsed().as_millis() as u64),
                bytes_up: ctx.body.len() as u64,
                fp,
                ..Default::default()
            },
        )
        .await;
        // A DLP block gets a machine-readable body naming each detector and
        // offset, so a coding agent can fix its own request and retry.
        if !outcome.tripped() && dlp.has_blocking() {
            return Ok(dlp_deny_response(&dlp));
        }
        // A spend-tripwire block explains its trigger the same way, so an
        // agent stuck in the loop can read why and break out of it.
        if !outcome.tripped() && !over_budget && spend_block {
            return Ok(trip_deny_response(
                spend_trip.as_ref().expect("spend_block implies a trip"),
            ));
        }
        return Ok(deny_response(
            StatusCode::FORBIDDEN,
            &format!(
                "decoyrail blocked this request: {}",
                if note.is_empty() {
                    "denied by policy"
                } else {
                    &note
                }
            ),
        ));
    }

    // DLP warn/mask hits on a request that is going forward are recorded
    // before it leaves (the mask already rewrote the body above).
    if dlp.has_advisory() || dlp.truncated {
        audit(
            engine,
            Entry {
                host: host.into(),
                path: path.clone(),
                method: method.clone(),
                action: "alert".into(),
                rule: decision.rule.clone(),
                note: format!("dlp: {}{dump_note}", dlp.summary()),
                ..Default::default()
            },
        )
        .await;
    }

    // LLM-aware accounting: the provider was resolved above (step 3.5); here
    // the model the request names (the doctor already parsed it when it ran;
    // the swap never touches the model field, so that parse is reusable) and
    // whether its tokens are billed per use or covered by a flat
    // subscription (e.g. Claude-plan OAuth).
    let (model, billing) = {
        let pricing = engine.pricing.read().await;
        match provider {
            Some(p) => (
                doctor_model.or_else(|| crate::pricing::parse_model(&ctx.body)),
                pricing.billing_for(p, host, &ctx.headers),
            ),
            None => (None, crate::pricing::Billing::Usage),
        }
    };

    // 6. Forward upstream, honoring the tunneled scheme and port.
    let (scheme, default_port) = if tls { ("https", 443) } else { ("http", 80) };
    let url = if port == default_port {
        format!("{scheme}://{host}{path}")
    } else {
        format!("{scheme}://{host}:{port}{path}")
    };
    let mut upstream = engine.http.request(
        reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
        &url,
    );
    for (name, value) in &ctx.headers {
        if is_hop_by_hop(name) || name.eq_ignore_ascii_case("host") {
            continue;
        }
        // LLM responses must arrive uncompressed so the usage fields (and the
        // secret-echo scan) are readable: drop the client's Accept-Encoding
        // for provider hosts and upstream sends identity.
        if provider.is_some() && name.eq_ignore_ascii_case("accept-encoding") {
            continue;
        }
        upstream = upstream.header(name, value);
    }
    let bytes_up = ctx.body.len() as u64;
    if !ctx.body.is_empty() {
        upstream = upstream.body(ctx.body);
    }

    // Fan-out serialization (phase 3): the first request for a shared prefix
    // forwards immediately and writes the cache; siblings wait here for its
    // first response byte (bounded by fanout_timeout_ms), then read the warm
    // cache. The guard releases siblings on drop, so an error can't wedge them.
    let fanout_guard = fanout_key.map(|k| engine.fanout.enter(k));
    if let Some(g) = &fanout_guard {
        if !g.is_leader() {
            g.wait_for_leader(std::time::Duration::from_millis(
                cache_cfg.fanout_timeout_ms,
            ))
            .await;
        }
    }

    let resp = upstream.send().await?;
    if let Some(g) = &fanout_guard {
        if g.is_leader() {
            g.leader_ready();
        }
    }
    let status = resp.status();
    let is_event_stream = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.contains("text/event-stream"))
        .unwrap_or(false);

    // Preserve upstream response headers (minus hop-by-hop).
    let mut builder = Response::builder().status(status.as_u16());
    for (name, value) in resp.headers() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_bytes());
    }
    // Surface any cache repair on the response, so a mutation is never silent
    // (SPEC invariant): the client sees exactly what the proxy changed.
    if let Some(h) = &cache_header {
        builder = builder.header("x-decoyrail-cache", h.as_str());
    }
    // Same rule for a soft-landing downgrade (plan 003): degraded traffic
    // announces itself, so silent quality loss can't erode trust.
    if let Some(h) = &downgrade_header {
        builder = builder.header("x-decoyrail-downgrade", h.as_str());
    }
    // And for a routed model (plan 006): the rewrite is never silent.
    if let Some(h) = &route_header {
        builder = builder.header("x-decoyrail-route", h.as_str());
    }

    // SSE streams pass through untouched (latency-critical). Every other
    // response is buffered up to SCAN_CAP and scanned for echoed real secrets —
    // including chunked responses with no Content-Length, which previously
    // slipped through unscanned. A body that exceeds the cap is streamed: the
    // buffered prefix is scanned, then chained with the remainder.
    let mut stream = resp.bytes_stream();
    let mut prefix: Vec<Bytes> = Vec::new();
    let mut buffered_len: usize = 0;
    let mut overflowed = false;

    if !is_event_stream {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            buffered_len += chunk.len();
            prefix.push(chunk);
            if buffered_len > SCAN_CAP {
                overflowed = true;
                break;
            }
        }
    }

    let streamed = is_event_stream || overflowed;
    // Lets the streamed follow-up `usage` event name the allow event it
    // completes: the allow event's seq isn't known until it is written, after
    // the body (and the MeteredStream inside it) is already built.
    let req_seq_cell: Arc<std::sync::OnceLock<u64>> = Arc::new(std::sync::OnceLock::new());
    let (body, bytes_down_now, usage): (ResBody, u64, Option<crate::pricing::TokenUsage>) =
        if streamed {
            // Streamed. Scan whatever prefix we did buffer, then meter the total
            // as it drains (SSE responses are exactly the traffic budgets care
            // about). For LLM event streams, an incremental scanner extracts the
            // provider's usage events as the bytes pass — no buffering, no delay.
            if !prefix.is_empty() {
                let joined: Vec<u8> = prefix.iter().flat_map(|b| b.iter().copied()).collect();
                scan_and_alert(
                    engine,
                    &joined,
                    host,
                    &path,
                    &method,
                    &decision,
                    &swap_names,
                    status.as_u16(),
                )
                .await;
            }
            let prefix_stream = futures_util::stream::iter(prefix.into_iter().map(Ok));
            let rest = MeteredStream {
                inner: prefix_stream.chain(stream),
                engine: engine.clone(),
                host: host.to_string(),
                counted: 0,
                recorded: false,
                bytes_up,
                // Scan any provider stream for usage, not only those labeled
                // text/event-stream: some backends stream SSE under a
                // different content type (e.g. ChatGPT's Codex endpoint). This
                // is the streamed branch (SSE or oversized), so a body that
                // isn't SSE simply yields no usage and falls back to bytes.
                scanner: provider.map(crate::pricing::SseUsageScanner::new),
                provider,
                model: model.clone(),
                billing,
                path: path.clone(),
                method: method.clone(),
                started,
                req_seq: req_seq_cell.clone(),
            };
            let framed = rest.map(|chunk| chunk.map(Frame::data).map_err(std::io::Error::other));
            // Traffic counted now; downstream bytes and cost fold in on drain.
            (BodyExt::boxed(StreamBody::new(framed)), 0, None)
        } else {
            // Fully buffered: exact byte count, scan, one-shot body — and for
            // LLM hosts, the provider-reported token usage straight from JSON.
            let bytes = Bytes::from(prefix.concat());
            scan_and_alert(
                engine,
                &bytes,
                host,
                &path,
                &method,
                &decision,
                &swap_names,
                status.as_u16(),
            )
            .await;
            let n = bytes.len() as u64;
            // Prefer a single-JSON usage object; fall back to scanning the
            // body as SSE, for provider backends that stream `data:` events
            // without the text/event-stream content type (e.g. Codex).
            let usage = provider.and_then(|p| {
                crate::pricing::parse_usage_json(p, &bytes)
                    .or_else(|| crate::pricing::scan_usage_sse(p, &bytes))
            });
            (Full::new(bytes).map_err(|e| match e {}).boxed(), n, usage)
        };

    // Meter + audit the allowed request. Buffered LLM responses are costed
    // here from parsed usage (zero when subscription-billed); buffered
    // responses without usage get the byte estimate; streamed bodies defer
    // both the downstream size and the cost to MeteredStream's completion.
    let usage_note;
    let usage_rec;
    let billed_usd;
    {
        let token_record = match (provider, usage) {
            (Some(p), Some(u)) => {
                let rate = engine.pricing.read().await.rate_for(p, model.as_deref());
                let (cost, ref_cost) = crate::pricing::split_cost(billing, &u, &rate);
                Some((
                    crate::pricing::model_key(model.as_deref(), billing),
                    u,
                    cost,
                    ref_cost,
                ))
            }
            _ => None,
        };
        let now = crate::util::current_period();
        let mut meter = engine.meter.lock().await;
        meter.record_traffic(&now, host, bytes_up, bytes_down_now);
        match &token_record {
            Some((key, u, cost, ref_cost)) => {
                meter.record_tokens(&now, host, key, u, *cost, *ref_cost)
            }
            None if !streamed => meter.add_estimated(&now, host, bytes_up + bytes_down_now),
            None => {}
        }
        let _ = meter.flush(&now);
        // The allow event carries the usage when it was parsed synchronously;
        // streamed responses get a follow-up `usage` event from MeteredStream
        // instead, once the counts are known.
        usage_note = token_record
            .as_ref()
            .map(|(key, u, _, _)| usage_note_for(key, u))
            .unwrap_or_default();
        billed_usd = token_record
            .as_ref()
            .map(|(_, _, cost, _)| *cost)
            .unwrap_or(0.0);
        usage_rec =
            token_record.map(|(key, u, cost, ref_cost)| usage_rec_for(&key, &u, cost, ref_cost));
    }
    // Feed the spend-rate detector (plan 002) with the billable dollars this
    // request just metered, outside the meter lock.
    if billed_usd > 0.0 {
        engine
            .watch
            .lock()
            .await
            .observe_cost(crate::util::now_unix(), billed_usd);
    }
    let recorded = audit(
        engine,
        Entry {
            host: host.into(),
            path,
            method,
            // "allow", or "warn" for a forwarded-with-alert resolution (the
            // deny branch returned above; escalate never leaves resolution).
            action: final_action.as_str().into(),
            rule: decision.rule,
            escalated: decision.escalated,
            swaps: swap_names,
            tripwires: Vec::new(),
            status: status.as_u16(),
            note: usage_note,
            // Streamed responses defer duration to the follow-up `usage`
            // event (full drain time), so no request is measured twice.
            dur_ms: (!streamed).then(|| started.elapsed().as_millis() as u64),
            bytes_up,
            bytes_down: bytes_down_now,
            usage: usage_rec,
            fp,
            ..Default::default()
        },
    )
    .await;
    // Fail closed: an allowed request whose audit event could not be written
    // does not get its response delivered. The request already went upstream
    // (status/bytes were needed for the event), but withholding the response
    // stops an unaudited session from progressing silently.
    match recorded {
        Some(seq) => {
            let _ = req_seq_cell.set(seq);
        }
        None => {
            return Ok(deny_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "decoyrail: audit log unavailable; failing closed",
            ));
        }
    }

    // Keep-alive (phase 3): now that the request forwarded, arm/refresh the
    // pre-warm for its prefix. The first arm for a (host, model) starts a
    // watcher task that fires during idle; a real request resets the budget.
    if let (Some(template), Some(model)) = (keepalive_template, model.as_ref()) {
        let key = format!("{host} {model}");
        let spawn = engine.keepalive.lock().await.arm(
            key.clone(),
            template,
            cache_cfg.keep_alive_max,
            crate::util::now_unix(),
        );
        if spawn {
            spawn_keepalive_watcher(
                engine.clone(),
                host.to_string(),
                model.clone(),
                key,
                cache_cfg.keep_alive_secs,
            );
        }
    }

    Ok(builder.body(body).unwrap_or_else(|_| {
        deny_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "decoyrail: response build failed",
        )
    }))
}

/// The structured twin of `usage_note_for`: what analytics consumes.
fn usage_rec_for(
    model_key: &str,
    u: &crate::pricing::TokenUsage,
    cost_usd: f64,
    ref_cost_usd: f64,
) -> crate::audit::UsageRec {
    crate::audit::UsageRec {
        model: model_key.to_string(),
        input: u.input,
        output: u.output,
        cache_read: u.cache_read,
        cache_write: u.cache_write,
        cost_usd,
        ref_cost_usd,
    }
}

/// Render parsed token usage for an audit note: greppable key=value counts,
/// zero cache fields omitted.
fn usage_note_for(model_key: &str, u: &crate::pricing::TokenUsage) -> String {
    let mut note = format!("usage: {model_key} in={} out={}", u.input, u.output);
    if u.cache_read > 0 {
        note.push_str(&format!(" cache_read={}", u.cache_read));
    }
    if u.cache_write > 0 {
        note.push_str(&format!(" cache_write={}", u.cache_write));
    }
    note
}

/// Scan a (possibly partial) response body for echoed real secrets and, if any
/// are found, record an `alert` audit event.
#[allow(clippy::too_many_arguments)]
async fn scan_and_alert(
    engine: &Engine,
    bytes: &[u8],
    host: &str,
    path: &str,
    method: &str,
    decision: &crate::policy::Decision,
    swap_names: &[String],
    status: u16,
) {
    let leaked = {
        let vault = engine.vault.read().await;
        let mut leaked = swap::scan_response_for_real(bytes, &vault);
        leaked.extend(swap::scan_response_for_real(bytes, &engine.session));
        leaked
    };
    if leaked.is_empty() {
        return;
    }
    audit(
        engine,
        Entry {
            host: host.into(),
            path: path.into(),
            method: method.into(),
            action: "alert".into(),
            rule: decision.rule.clone(),
            swaps: swap_names.to_vec(),
            tripwires: leaked.iter().map(|n| format!("{n}@response")).collect(),
            status,
            note: "real secret echoed in response".into(),
            ..Default::default()
        },
    )
    .await;
}

/// Wraps a response byte stream, tallying bytes (and, for LLM event streams,
/// scanning for the provider's usage events) as they flow, then folding both
/// into the meter when the stream ends or is dropped (covering client
/// disconnects). This is how streamed/SSE responses get metered — neither the
/// size nor the token counts are known when the request is first recorded.
struct MeteredStream<S> {
    inner: S,
    engine: Engine,
    host: String,
    counted: u64,
    recorded: bool,
    /// Request upload size, for the byte-estimate fallback when the stream
    /// carried no parseable usage.
    bytes_up: u64,
    scanner: Option<crate::pricing::SseUsageScanner>,
    provider: Option<crate::pricing::Provider>,
    model: Option<String>,
    billing: crate::pricing::Billing,
    /// Request path/method, so the follow-up `usage` audit event written when
    /// the stream drains can say which request the tokens belong to.
    path: String,
    method: String,
    /// Request start time; the follow-up event carries the full-drain
    /// duration (the allow event deliberately omits it for streamed bodies).
    started: std::time::Instant,
    /// Seq of the allow event, set once that event is written; the follow-up
    /// event references it so analytics counts the request exactly once.
    req_seq: Arc<std::sync::OnceLock<u64>>,
}

impl<S> MeteredStream<S> {
    fn record(&mut self) {
        if self.recorded {
            return;
        }
        self.recorded = true;
        let engine = self.engine.clone();
        let host = std::mem::take(&mut self.host);
        let counted = self.counted;
        let bytes_up = self.bytes_up;
        let scanner = self.scanner.take();
        let provider = self.provider;
        let model = self.model.take();
        let billing = self.billing;
        let path = std::mem::take(&mut self.path);
        let method = std::mem::take(&mut self.method);
        let dur_ms = self.started.elapsed().as_millis() as u64;
        let req_seq = self.req_seq.get().copied();
        // Best-effort, off the response path: fold downstream bytes and cost
        // (exact tokens when the stream reported them, estimate otherwise)
        // into the meter, then note the usage in the audit log. The stream is
        // already delivered by now, so none of this adds latency.
        tokio::spawn(async move {
            let token_record = match (provider, scanner.and_then(|s| s.finish())) {
                (Some(p), Some(u)) => {
                    let rate = engine.pricing.read().await.rate_for(p, model.as_deref());
                    let (cost, ref_cost) = crate::pricing::split_cost(billing, &u, &rate);
                    Some((
                        crate::pricing::model_key(model.as_deref(), billing),
                        u,
                        cost,
                        ref_cost,
                    ))
                }
                _ => None,
            };
            let now = crate::util::current_period();
            {
                let mut meter = engine.meter.lock().await;
                meter.add_downstream_bytes(&now, &host, counted);
                match &token_record {
                    Some((key, u, cost, ref_cost)) => {
                        meter.record_tokens(&now, &host, key, u, *cost, *ref_cost)
                    }
                    None => meter.add_estimated(&now, &host, bytes_up + counted),
                }
                let _ = meter.flush(&now);
            }
            // Streamed spend reaches the rate detector (plan 002) here, once
            // the counts exist — the same feed buffered responses get inline.
            let billed_usd = token_record
                .as_ref()
                .map(|(_, _, cost, _)| *cost)
                .unwrap_or(0.0);
            if billed_usd > 0.0 {
                engine
                    .watch
                    .lock()
                    .await
                    .observe_cost(crate::util::now_unix(), billed_usd);
            }
            // The allow event was written when the stream started, before the
            // token counts (and final size/duration) existed; this companion
            // event carries them, written for every streamed response so byte
            // and latency analytics don't lose non-LLM streams.
            let _ = audit(
                &engine,
                Entry {
                    host,
                    path,
                    method,
                    action: "usage".into(),
                    note: token_record
                        .as_ref()
                        .map(|(key, u, _, _)| usage_note_for(key, u))
                        .unwrap_or_default(),
                    dur_ms: Some(dur_ms),
                    bytes_down: counted,
                    usage: token_record
                        .map(|(key, u, cost, ref_cost)| usage_rec_for(&key, &u, cost, ref_cost)),
                    req_seq,
                    ..Default::default()
                },
            )
            .await;
        });
    }
}

impl<S> futures_util::Stream for MeteredStream<S>
where
    S: futures_util::Stream<Item = reqwest::Result<Bytes>> + Unpin,
{
    type Item = reqwest::Result<Bytes>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match std::pin::Pin::new(&mut self.inner).poll_next(cx) {
            std::task::Poll::Ready(Some(Ok(chunk))) => {
                self.counted += chunk.len() as u64;
                if let Some(s) = self.scanner.as_mut() {
                    s.feed(&chunk);
                }
                std::task::Poll::Ready(Some(Ok(chunk)))
            }
            std::task::Poll::Ready(Some(Err(e))) => std::task::Poll::Ready(Some(Err(e))),
            std::task::Poll::Ready(None) => {
                self.record();
                std::task::Poll::Ready(None)
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl<S> Drop for MeteredStream<S> {
    fn drop(&mut self) {
        self.record();
    }
}

/// Append an audit event, stamped with this process's session id. A failed
/// append (disk full, permissions, lock) is printed to stderr and reported to
/// the caller: deny paths are already blocking, but the allow path fails
/// closed on `None` — traffic must not flow unrecorded. On success, returns
/// the event's seq so a follow-up event can reference it.
async fn audit(engine: &Engine, mut entry: Entry) -> Option<u64> {
    entry.sid = engine.session_id.clone();
    let ts = crate::util::now_rfc3339();
    let mut auditor = engine.auditor.lock().await;
    match auditor.append(entry, ts) {
        Ok(ev) => Some(ev.seq),
        Err(e) => {
            eprintln!("decoyrail: audit append failed: {e:#}");
            None
        }
    }
}

/// Write the full request a DLP hit rode in to an owner-only file under the
/// state dir, so `[dlp] debug = true` can answer "what actually matched?".
/// The dump is the post-swap view — the exact bytes DLP scanned — except any
/// real secret the swap engine placed (device or session vault) is scrubbed
/// back to a named placeholder before anything touches disk. The audit log
/// itself never carries payload content, only this file's path.
fn write_dlp_dump(
    ctx: &RequestCtx,
    dlp: &crate::detect::DlpOutcome,
    vault: &crate::vault::Vault,
    session: &crate::vault::Vault,
) -> Result<std::path::PathBuf> {
    use std::fmt::Write as _;
    let ts = crate::util::now_rfc3339();
    let mut text = String::new();
    let _ = writeln!(text, "# decoyrail dlp debug dump  {ts}");
    let _ = writeln!(text, "# {} {}{}", ctx.method, ctx.host, ctx.path);
    let _ = writeln!(text, "# hits:");
    for h in &dlp.hits {
        let _ = writeln!(
            text,
            "#   {} {}@{} off={} fp={}",
            h.mode.name(),
            h.detector,
            h.seen_in,
            h.offset,
            h.fingerprint
        );
        if let Some(c) = &h.context {
            let _ = writeln!(text, "#     {c}");
        }
    }
    if dlp.truncated {
        let _ = writeln!(
            text,
            "# encoded-scan bound reached; later hits may be missing"
        );
    }
    text.push('\n');
    for (name, value) in &ctx.headers {
        let _ = writeln!(text, "{name}: {value}");
    }
    text.push('\n');
    text.push_str(&String::from_utf8_lossy(&ctx.body));

    for s in vault.secrets.iter().chain(session.secrets.iter()) {
        if !s.real.is_empty() && text.contains(&s.real) {
            text = text.replace(&s.real, &format!("[decoyrail:scrubbed:{}]", s.name));
        }
    }

    let dir = crate::config::dlp_debug_dir()?;
    std::fs::create_dir_all(&dir)?;
    // Timestamp digits plus a process-wide sequence keep names unique and
    // sortable even for hits landing within one clock tick.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let stamp: String = ts.chars().filter(char::is_ascii_digit).collect();
    let host: String = ctx
        .host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let path = dir.join(format!("{stamp}-{seq:04}-{host}.txt"));
    crate::config::write_private(&path, text.as_bytes())?;
    Ok(path)
}

/// 403 for a DLP block: names each detector and where it hit (never the
/// value), plus the remediation hint, machine-readable.
fn dlp_deny_response(dlp: &crate::detect::DlpOutcome) -> Response<ResBody> {
    let detectors: Vec<_> = dlp
        .blocking()
        .map(|h| {
            serde_json::json!({
                "detector": h.detector,
                "location": h.seen_in,
                "offset": h.offset,
            })
        })
        .collect();
    let body = serde_json::json!({
        "decoyrail": true,
        "blocked": true,
        "reason": "dlp",
        "detectors": detectors,
        "message": "decoyrail blocked this request: sensitive data detected. \
                    Remove the flagged value and retry, or change the mode \
                    with `decoyrail dlp set <detector> <mode>`.",
    })
    .to_string();
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
        .expect("static dlp deny response is always valid")
}

/// The spend tripwire's block body: machine-readable, naming the trigger and
/// counts and how to clear, so a coding agent stuck in the loop can read why
/// its requests stopped and break out on its own.
fn trip_deny_response(trip: &crate::watch::Trip) -> Response<ResBody> {
    let body = serde_json::json!({
        "decoyrail": true,
        "blocked": true,
        "reason": "spend_tripwire",
        "trigger": {
            "kind": trip.kind,
            "fingerprint": trip.fingerprint,
            "count": trip.count,
            "window_secs": trip.window_secs,
        },
        "message": format!(
            "decoyrail blocked this request: spend tripwire ({}). Stop repeating \
             this request; a human can clear the trip with `decoyrail trip clear`.",
            trip.reason
        ),
    })
    .to_string();
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
        .expect("static trip deny response is always valid")
}

fn deny_response(status: StatusCode, msg: &str) -> Response<ResBody> {
    let body =
        serde_json::json!({ "decoyrail": true, "blocked": true, "message": msg }).to_string();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed())
        .expect("static deny response is always valid")
}

/// Read HTTP request head (up to CRLFCRLF). Bounded to avoid unbounded
/// buffering. Returns raw bytes so non-CONNECT requests can be replayed into
/// hyper via `Rewind`.
async fn read_request_head(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err(anyhow!("request head too large"));
        }
    }
    Ok(buf)
}

/// An I/O adapter that replays already-consumed bytes (the request head peeked
/// for routing) before delegating to the underlying stream.
struct Rewind<T> {
    prefix: Vec<u8>,
    pos: usize,
    inner: T,
}

impl<T> Rewind<T> {
    fn new(prefix: Vec<u8>, inner: T) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Rewind<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = std::cmp::min(buf.remaining(), self.prefix.len() - self.pos);
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Rewind<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Add a token to the `anthropic-beta` request header (needed for the 1h
/// cache TTL), merging with any value the client already set rather than
/// clobbering it. Public for fuzzing (it splices client-controlled header
/// values).
pub fn add_beta_header(headers: &mut Vec<(String, String)>, token: &str) {
    if let Some((_, v)) = headers
        .iter_mut()
        .find(|(n, _)| n.eq_ignore_ascii_case("anthropic-beta"))
    {
        if !v.split(',').any(|t| t.trim() == token) {
            v.push(',');
            v.push_str(token);
        }
        return;
    }
    headers.push(("anthropic-beta".into(), token.into()));
}

/// Rewrite a stored request into a zero-output pre-warm: `max_tokens = 1` and
/// no streaming, so replaying it costs a cache read plus one token instead of
/// a full generation. Re-serialization is fine here — this is a
/// proxy-originated request, not the client's bytes, and the provider caches
/// on content tokens, not JSON key order. Public for fuzzing (it rewrites
/// client-shaped JSON).
pub fn minimize_body(body: &[u8]) -> Option<Vec<u8>> {
    let mut v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let obj = v.as_object_mut()?;
    obj.insert("max_tokens".into(), serde_json::json!(1));
    obj.remove("stream");
    serde_json::to_vec(&v).ok()
}

/// One long-lived watcher per (host, model): wakes every idle interval and, if
/// the cache has gone idle with pre-warm budget left, fires a keep-alive. Dies
/// with the process (session-local).
fn spawn_keepalive_watcher(
    engine: Engine,
    host: String,
    model: String,
    key: String,
    idle_secs: u64,
) {
    let interval = idle_secs.max(1);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            let due = engine
                .keepalive
                .lock()
                .await
                .due(&key, idle_secs, crate::util::now_unix());
            if let Some(template) = due {
                keepalive_fire(&engine, &host, &model, &template).await;
            }
        }
    });
}

/// Replay a stored request as a pre-warm: re-evaluate policy, re-run the swap
/// (so real secrets are placed under the same release rules as any forwarded
/// request), forward over TLS, then meter and audit it as proxy-initiated
/// spend. Best-effort — any failure just skips this refresh.
async fn keepalive_fire(
    engine: &Engine,
    host: &str,
    model: &str,
    tmpl: &crate::cache::KeepAliveTemplate,
) {
    let Some(body) = minimize_body(&tmpl.body) else {
        return;
    };
    let (decision, trip_mode) = {
        let policy = engine.policy.read().await;
        (
            policy.evaluate(host, &tmpl.path, &tmpl.method),
            policy.spend_tripwire.mode,
        )
    };
    // A route rule allows (the template body already carries whatever model
    // the pipeline forwarded), so a pre-warm rides it like any allow.
    if !matches!(decision.action, Action::Allow | Action::Route) {
        return;
    }
    // A standing spend trip (plan 002) stops proxy-initiated spend too: the
    // quiet recurring cost of a pre-warm is exactly what a tripped session
    // must not keep accruing while its own requests are blocked.
    if trip_mode == crate::policy::TripwireMode::Block
        && engine.watch.lock().await.tripped().is_some()
    {
        return;
    }
    let mut ctx = RequestCtx {
        host: host.to_string(),
        path: tmpl.path.clone(),
        method: tmpl.method.clone(),
        headers: tmpl.headers.clone(),
        body,
    };
    let outcome = {
        let vault = engine.vault.read().await;
        let mut o = swap::apply(&mut ctx, &vault, &decision, true);
        let s = swap::apply(&mut ctx, &engine.session, &decision, true);
        o.swaps.extend(s.swaps);
        o.tripwires.extend(s.tripwires);
        o
    };
    // A pre-warm that would trip its own wire is a misconfiguration; never send
    // it (fail closed exactly like the request path).
    if outcome.tripped() {
        return;
    }

    let url = if tmpl.port == 443 {
        format!("https://{host}{}", tmpl.path)
    } else {
        format!("https://{host}:{}{}", tmpl.port, tmpl.path)
    };
    let mut up = engine.http.request(
        reqwest::Method::from_bytes(tmpl.method.as_bytes()).unwrap_or(reqwest::Method::POST),
        &url,
    );
    for (name, value) in &ctx.headers {
        if is_hop_by_hop(name)
            || name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("accept-encoding")
        {
            continue;
        }
        up = up.header(name, value);
    }
    let bytes_up = ctx.body.len() as u64;
    up = up.body(ctx.body);

    let started = std::time::Instant::now();
    let Ok(resp) = up.send().await else {
        return;
    };
    let status = resp.status();
    let Ok(bytes) = resp.bytes().await else {
        return;
    };
    let bytes_down = bytes.len() as u64;

    // Price the pre-warm before touching the meter, so the pricing read never
    // nests inside the meter lock.
    let (provider, billing, rate) = {
        let pricing = engine.pricing.read().await;
        let provider = pricing.provider_for_host(host);
        let billing = provider
            .map(|p| pricing.billing_for(p, host, &ctx.headers))
            .unwrap_or(crate::pricing::Billing::Usage);
        let rate = provider.map(|p| pricing.rate_for(p, Some(model)));
        (provider, billing, rate)
    };
    let usage = provider.and_then(|p| crate::pricing::parse_usage_json(p, &bytes));
    let token_record = match (usage, rate) {
        (Some(u), Some(rate)) => {
            let (cost, ref_cost) = crate::pricing::split_cost(billing, &u, &rate);
            Some((
                crate::pricing::model_key(Some(model), billing),
                u,
                cost,
                ref_cost,
            ))
        }
        _ => None,
    };

    let now = crate::util::current_period();
    {
        let mut meter = engine.meter.lock().await;
        meter.record_traffic(&now, host, bytes_up, bytes_down);
        match &token_record {
            Some((key, u, cost, ref_cost)) => {
                meter.record_tokens(&now, host, key, u, *cost, *ref_cost)
            }
            None => meter.add_estimated(&now, host, bytes_up + bytes_down),
        }
        let _ = meter.flush(&now);
    }
    let note = match &token_record {
        Some((key, u, _, _)) => format!("proxy-initiated pre-warm; {}", usage_note_for(key, u)),
        None => "proxy-initiated pre-warm".to_string(),
    };
    audit(
        engine,
        Entry {
            host: host.into(),
            path: tmpl.path.clone(),
            method: tmpl.method.clone(),
            action: "keepalive".into(),
            rule: decision.rule.clone(),
            swaps: outcome
                .swaps
                .iter()
                .map(|s| format!("{}@{}", s.secret_name, s.location))
                .collect(),
            status: status.as_u16(),
            note,
            dur_ms: Some(started.elapsed().as_millis() as u64),
            bytes_up,
            bytes_down,
            usage: token_record
                .map(|(key, u, cost, ref_cost)| usage_rec_for(&key, &u, cost, ref_cost)),
            ..Default::default()
        },
    )
    .await;
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "content-length"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // env_guard's std MutexGuard is held across awaits on purpose: it
    // serializes the process-global DECOYRAIL_HOME for the whole test.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn keepalive_fire_respects_a_standing_spend_trip() {
        let _g = crate::util::env_guard();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", tmp.path());
        crate::policy_edit::write_policy(
            "default_action = \"deny\"\n\
             [[rule]]\nname = \"local\"\nhosts = [\"localhost\"]\naction = \"allow\"\n",
            "test",
        )
        .unwrap();

        let engine = Engine::boot().unwrap();
        let trip = crate::watch::Signal::Repeat {
            fingerprint: "aabbccdd11223344".into(),
            count: 3,
        }
        .to_trip(300, crate::util::now_rfc3339(), "sid".into());
        engine.watch.lock().await.set_tripped(Some(trip));

        // Port 1 is unreachable on purpose: the trip check must return
        // before anything is sent, so nothing here needs a network.
        let tmpl = crate::cache::KeepAliveTemplate {
            method: "POST".into(),
            path: "/v1/messages".into(),
            port: 1,
            headers: Vec::new(),
            body: br#"{"model":"m","messages":[]}"#.to_vec(),
        };
        keepalive_fire(&engine, "localhost", "m", &tmpl).await;
        let log = std::fs::read_to_string(crate::config::audit_path().unwrap()).unwrap_or_default();
        assert!(
            !log.contains("\"action\":\"keepalive\""),
            "a tripped session must not pre-warm: {log}"
        );
        std::env::remove_var("DECOYRAIL_HOME");
    }

    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn keepalive_fire_respects_a_denying_policy() {
        let _g = crate::util::env_guard();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", tmp.path());
        crate::policy_edit::write_policy("default_action = \"deny\"\n", "test").unwrap();

        let engine = Engine::boot().unwrap();
        // Port 1 is unreachable on purpose: the deny must return before
        // anything is sent, so nothing here needs a network.
        let tmpl = crate::cache::KeepAliveTemplate {
            method: "POST".into(),
            path: "/v1/messages".into(),
            port: 1,
            headers: Vec::new(),
            body: br#"{"model":"m","messages":[]}"#.to_vec(),
        };
        keepalive_fire(&engine, "api.example.com", "m", &tmpl).await;
        let log = std::fs::read_to_string(crate::config::audit_path().unwrap()).unwrap_or_default();
        assert!(
            !log.contains("\"action\":\"keepalive\""),
            "a denied destination must not pre-warm: {log}"
        );
        std::env::remove_var("DECOYRAIL_HOME");
    }

    #[test]
    fn parse_head_normalizes_connect_target() {
        let r = parse_head(b"CONNECT Api.Example.COM:8443 HTTP/1.1\r\n\r\n");
        assert_eq!(r.method, "CONNECT");
        assert_eq!(r.host, "api.example.com");
        assert_eq!(r.port, 8443);
    }

    #[test]
    fn parse_head_defaults_missing_or_bad_port() {
        let r = parse_head(b"CONNECT example.com HTTP/1.1\r\n\r\n");
        assert_eq!((r.host.as_str(), r.port), ("example.com", 443));
        let r = parse_head(b"CONNECT example.com:notaport HTTP/1.1\r\n\r\n");
        assert_eq!((r.host.as_str(), r.port), ("example.com", 443));
    }

    #[test]
    fn parse_head_is_total_on_garbage() {
        let r = parse_head(b"\xff\xfe\x00");
        assert_eq!(r.method, "\u{fffd}\u{fffd}\u{0}");
        let r = parse_head(b"");
        assert_eq!(r.method, "");
        assert_eq!(r.port, 443);
    }

    #[test]
    fn minimize_body_caps_output_and_drops_stream() {
        let out = minimize_body(br#"{"model":"m","stream":true,"max_tokens":4096,"messages":[]}"#)
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["max_tokens"], 1);
        assert!(v.get("stream").is_none());
        assert!(minimize_body(b"[1,2,3]").is_none());
        assert!(minimize_body(b"not json").is_none());
    }

    #[test]
    fn add_beta_header_merges_and_dedups() {
        let mut headers = vec![("anthropic-beta".to_string(), "existing".to_string())];
        add_beta_header(&mut headers, "new-token");
        assert_eq!(headers[0].1, "existing,new-token");
        add_beta_header(&mut headers, "new-token");
        assert_eq!(headers[0].1, "existing,new-token");
        let mut none = Vec::new();
        add_beta_header(&mut none, "tok");
        assert_eq!(
            none,
            vec![("anthropic-beta".to_string(), "tok".to_string())]
        );
    }
}
