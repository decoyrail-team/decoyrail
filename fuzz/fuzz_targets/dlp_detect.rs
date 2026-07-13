#![no_main]
//! Fuzz the request-side DLP detectors (PAN/SSN/IBAN/ABA/email) across every
//! mode combination. The detectors run on raw client bytes before anything is
//! forwarded, so they must be total: no panic, no unbounded work, and the
//! summary/rendering paths must hold for whatever they matched. A second pass
//! over the (possibly mask-rewritten) request exercises convergence.

use libfuzzer_sys::fuzz_target;

use decoyrail::detect;
use decoyrail::policy::{DlpConfig, DlpMode};
use decoyrail::swap::RequestCtx;

#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    modes: [u8; 5],
    header_value: String,
    body: Vec<u8>,
}

fn mode(b: u8) -> DlpMode {
    match b % 4 {
        0 => DlpMode::Off,
        1 => DlpMode::Warn,
        2 => DlpMode::Block,
        _ => DlpMode::Mask,
    }
}

fuzz_target!(|input: Input| {
    let cfg = DlpConfig {
        pan: mode(input.modes[0]),
        ssn: mode(input.modes[1]),
        iban: mode(input.modes[2]),
        aba: mode(input.modes[3]),
        email: mode(input.modes[4]),
        allow: Vec::new(),
        debug: false,
    };
    let salt = [0u8; 32];
    let mut ctx = RequestCtx {
        host: "fuzz.example".into(),
        path: "/".into(),
        method: "POST".into(),
        headers: vec![("x-fuzz".into(), input.header_value)],
        body: input.body,
    };

    let out = detect::apply(&mut ctx, &cfg, &salt);
    let _ = out.summary();
    let _ = out.has_blocking();
    let _ = out.has_advisory();
    for h in out.blocking() {
        // The audit path renders these; fingerprints must never carry the
        // matched value (they are fixed-size hex), and rendering must hold.
        assert!(h.fingerprint.len() <= 64);
    }

    // Re-applying to the rewritten request must also be total (mask mode
    // rewrites the body in place; the proxy never does this twice, but the
    // rewritten bytes are exactly what leaves the machine).
    let _ = detect::apply(&mut ctx, &cfg, &salt);
});
