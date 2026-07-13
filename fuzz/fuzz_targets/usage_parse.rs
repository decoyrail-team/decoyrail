#![no_main]
//! Fuzz the provider usage/model parsers that run on upstream-controlled
//! response bytes, with a differential assert: feeding the incremental SSE
//! scanner the same bytes in arbitrary chunk splits must yield exactly the
//! usage a whole-body scan yields. Chunk boundaries are picked by the network,
//! so any divergence is a metering bug an upstream could trigger at will.

use libfuzzer_sys::fuzz_target;

use decoyrail::pricing::{self, Provider, SseUsageScanner};

#[derive(arbitrary::Arbitrary, Debug)]
struct Input {
    anthropic: bool,
    cuts: Vec<u8>,
    body: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let provider = if input.anthropic {
        Provider::Anthropic
    } else {
        Provider::OpenAi
    };

    let _ = pricing::parse_model(&input.body);
    let _ = pricing::parse_usage_json(provider, &input.body);

    let whole = pricing::scan_usage_sse(provider, &input.body);

    let mut scanner = SseUsageScanner::new(provider);
    let mut pos = 0;
    for &cut in &input.cuts {
        let end = (pos + cut as usize).min(input.body.len());
        scanner.feed(&input.body[pos..end]);
        pos = end;
    }
    scanner.feed(&input.body[pos..]);
    assert_eq!(
        scanner.finish(),
        whole,
        "SSE usage scan diverged between chunked and whole-body feeding"
    );
});
