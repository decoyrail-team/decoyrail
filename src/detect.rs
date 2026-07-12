//! Request-side DLP detectors: structured sensitive data (payment cards,
//! SSNs, bank identifiers, emails) that must not ride an outbound request to
//! any destination — including ones policy allows.
//!
//! Precision over recall by design: every detector is checksum- or
//! structure-validated (Luhn, mod-97, ABA checksum, SSN validity rules) and
//! ships an allowlist of well-known test values so a developer's fixtures
//! don't trip the filter. Matched values are never logged or persisted: a hit
//! carries the detector type, position, and a salted fingerprint only. The
//! one exception is opt-in debug mode (`[dlp] debug`), where a hit also
//! carries a context snippet destined for a private payload dump file, still
//! never the audit log.
//!
//! Encoded evasion (base64/hex/percent) is scanned one decode level deep
//! within a bounded budget; hitting the bound is reported to the caller so
//! audit events can state it.

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::config;
use crate::policy::{DlpConfig, DlpMode};
use crate::swap::RequestCtx;

/// Fingerprint length in hex chars (64 bits of a salted SHA-256).
const FP_LEN: usize = 16;
/// Shortest base64 run worth decoding (a 13-digit PAN encodes to 18+ chars).
const MIN_B64_RUN: usize = 20;
/// Shortest hex run worth decoding (13 bytes → 26 chars).
const MIN_HEX_RUN: usize = 26;
/// Total decoded bytes examined per request across all encoded windows. Huge
/// bodies get a bounded scan; the caller is told when the bound was hit.
const DECODE_BUDGET: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detector {
    Pan,
    Ssn,
    Iban,
    Aba,
    Email,
}

impl Detector {
    pub const ALL: [Detector; 5] = [
        Detector::Pan,
        Detector::Ssn,
        Detector::Iban,
        Detector::Aba,
        Detector::Email,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Detector::Pan => "pan",
            Detector::Ssn => "ssn",
            Detector::Iban => "iban",
            Detector::Aba => "aba",
            Detector::Email => "email",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Detector::Pan => "payment card numbers (Luhn + network prefix)",
            Detector::Ssn => "US Social Security numbers (dashed form)",
            Detector::Iban => "international bank account numbers (mod-97)",
            Detector::Aba => "US bank routing numbers (checksum + prefix)",
            Detector::Email => "email addresses",
        }
    }
}

/// The configured mode for a detector.
pub fn mode_for(cfg: &DlpConfig, d: Detector) -> DlpMode {
    match d {
        Detector::Pan => cfg.pan,
        Detector::Ssn => cfg.ssn,
        Detector::Iban => cfg.iban,
        Detector::Aba => cfg.aba,
        Detector::Email => cfg.email,
    }
}

/// One detector hit. Carries where it was seen and a salted fingerprint —
/// never the matched value.
#[derive(Debug, Clone)]
pub struct Hit {
    pub detector: &'static str,
    /// "body", "path", "header:<name>", or "<loc>:<encoding>" for hits found
    /// inside a decoded window.
    pub seen_in: String,
    /// Byte offset of the match (for encoded hits: of the encoded run).
    pub offset: usize,
    pub fingerprint: String,
    /// The resolved mode. A mask-mode hit anywhere the body rewrite can't
    /// reach (path, headers, encoded forms) fails closed to `Block`.
    pub mode: DlpMode,
    /// Debug mode only: the matched value with surrounding text from the
    /// (possibly decoded) view it was found in, for the payload dump. Never
    /// set outside debug mode and never part of `summary()`, so the audit log
    /// stays fingerprint-only.
    pub context: Option<String>,
}

#[derive(Debug, Default)]
pub struct DlpOutcome {
    pub hits: Vec<Hit>,
    /// The encoded-form scan hit its decode budget; stated in audit events.
    pub truncated: bool,
}

impl DlpOutcome {
    pub fn has_blocking(&self) -> bool {
        self.hits.iter().any(|h| h.mode == DlpMode::Block)
    }

    pub fn has_advisory(&self) -> bool {
        self.hits
            .iter()
            .any(|h| matches!(h.mode, DlpMode::Warn | DlpMode::Mask))
    }

    pub fn blocking(&self) -> impl Iterator<Item = &Hit> {
        self.hits.iter().filter(|h| h.mode == DlpMode::Block)
    }

    /// One line for the audit note: every hit with its verb, fingerprint-only.
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = self
            .hits
            .iter()
            .map(|h| {
                let verb = match h.mode {
                    DlpMode::Block => "blocked",
                    DlpMode::Mask => "masked",
                    DlpMode::Warn => "warned",
                    DlpMode::Off => "off",
                };
                format!(
                    "{verb} {}@{} off={} fp={}",
                    h.detector, h.seen_in, h.offset, h.fingerprint
                )
            })
            .collect();
        if self.truncated {
            parts.push("encoded-scan bound reached".into());
        }
        parts.join(", ")
    }
}

/// Load (or create on first use) the local fingerprint salt. Local-only and
/// never exported, so fingerprints in the audit log can be correlated on this
/// machine but not reversed or matched across machines.
pub fn load_or_create_salt() -> Result<[u8; 32]> {
    config::ensure_home()?;
    let path = config::dlp_salt_path()?;
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            let mut salt = [0u8; 32];
            salt.copy_from_slice(&bytes);
            return Ok(salt);
        }
    }
    let mut salt = [0u8; 32];
    use rand::RngCore as _;
    rand::thread_rng().fill_bytes(&mut salt);
    config::write_private(&path, &salt)?;
    Ok(salt)
}

fn fingerprint(salt: &[u8], normalized: &str) -> String {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(normalized.as_bytes());
    hex::encode(h.finalize())[..FP_LEN].to_string()
}

/// Run the configured detectors over a request and enforce mask mode.
///
/// Runs on the same post-swap view that gets forwarded: decoy values have
/// already been replaced (a numeric decoy must not trip the detectors), and a
/// mask rewrite here is exactly what leaves the machine. Non-UTF-8 bodies are
/// not text-scanned; the decoy tripwire still covers vaulted bytes there.
pub fn apply(ctx: &mut RequestCtx, cfg: &DlpConfig, salt: &[u8]) -> DlpOutcome {
    let mut out = DlpOutcome::default();
    if Detector::ALL
        .iter()
        .all(|&d| mode_for(cfg, d) == DlpMode::Off)
    {
        return out;
    }
    let allow: Vec<String> = cfg.allow.iter().map(|s| normalize_allow(s)).collect();
    let mut budget = DECODE_BUDGET;

    // Path and headers: detectable but not maskable — rewriting a URL or a
    // header value changes request semantics in ways we can't verify, so a
    // mask-mode hit there fails closed to block.
    let push = |out: &mut DlpOutcome,
                span: &Span,
                text: &str,
                seen_in: String,
                offset: usize,
                maskable: bool| {
        let mut mode = mode_for(cfg, span.det);
        if mode == DlpMode::Mask && !maskable {
            mode = DlpMode::Block;
        }
        out.hits.push(Hit {
            detector: span.det.name(),
            seen_in,
            offset,
            fingerprint: fingerprint(salt, &span.norm),
            mode,
            context: cfg.debug.then(|| context_snippet(text, span)),
        });
    };

    for span in scan_text(&ctx.path, cfg, &allow) {
        push(&mut out, &span, &ctx.path, "path".into(), span.start, false);
    }
    for (label, offset, decoded, spans) in
        scan_encoded(&ctx.path, cfg, &allow, &mut budget, &mut out)
    {
        for span in spans {
            push(
                &mut out,
                &span,
                &decoded,
                format!("path:{label}"),
                offset,
                false,
            );
        }
    }

    for (name, value) in &ctx.headers {
        let loc = format!("header:{}", name.to_ascii_lowercase());
        for span in scan_text(value, cfg, &allow) {
            push(&mut out, &span, value, loc.clone(), span.start, false);
        }
        for (label, offset, decoded, spans) in
            scan_encoded(value, cfg, &allow, &mut budget, &mut out)
        {
            for span in spans {
                push(
                    &mut out,
                    &span,
                    &decoded,
                    format!("{loc}:{label}"),
                    offset,
                    false,
                );
            }
        }
    }

    let Ok(body) = std::str::from_utf8(&ctx.body) else {
        return out;
    };
    let body = body.to_string();
    let spans = scan_text(&body, cfg, &allow);
    let mut mask_spans: Vec<(usize, usize, Detector)> = Vec::new();
    for span in &spans {
        push(&mut out, span, &body, "body".into(), span.start, true);
        if mode_for(cfg, span.det) == DlpMode::Mask {
            mask_spans.push((span.start, span.end, span.det));
        }
    }
    for (label, offset, decoded, spans) in scan_encoded(&body, cfg, &allow, &mut budget, &mut out) {
        for span in spans {
            // Masking inside an encoded blob would corrupt it; fail closed.
            push(
                &mut out,
                &span,
                &decoded,
                format!("body:{label}"),
                offset,
                false,
            );
        }
    }
    if !mask_spans.is_empty() {
        // Spans are non-overlapping and sorted; replace back-to-front so
        // earlier offsets stay valid.
        let mut rebuilt = body;
        for &(start, end, det) in mask_spans.iter().rev() {
            rebuilt.replace_range(start..end, &format!("[decoyrail:masked:{}]", det.name()));
        }
        ctx.body = rebuilt.into_bytes();
    }
    out
}

/// A match inside one piece of text. `norm` is the canonical value (digits
/// only / compact IBAN / lowercased email) used for allowlisting and
/// fingerprinting, so encoded and separator-styled forms of the same value
/// fingerprint identically.
struct Span {
    det: Detector,
    start: usize,
    end: usize,
    norm: String,
}

/// The matched value marked `>>>like this<<<` with up to `CTX` chars of the
/// surrounding text either side, control characters made printable. Debug
/// mode only; goes to the payload dump, never the audit log.
fn context_snippet(text: &str, span: &Span) -> String {
    const CTX: usize = 40;
    let mut start = span.start.saturating_sub(CTX);
    while !text.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = (span.end + CTX).min(text.len());
    while !text.is_char_boundary(end) {
        end += 1;
    }
    let clean = |s: &str| -> String {
        s.chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect()
    };
    format!(
        "{}{}>>>{}<<<{}{}",
        if start > 0 { "..." } else { "" },
        clean(&text[start..span.start]),
        clean(&text[span.start..span.end]),
        clean(&text[span.end..end]),
        if end < text.len() { "..." } else { "" },
    )
}

fn scan_text(text: &str, cfg: &DlpConfig, allow: &[String]) -> Vec<Span> {
    let mut spans = Vec::new();
    let pan_on = cfg.pan != DlpMode::Off;
    let aba_on = cfg.aba != DlpMode::Off;
    if pan_on || aba_on {
        scan_digit_runs(text, pan_on, aba_on, allow, &mut spans);
    }
    if cfg.ssn != DlpMode::Off {
        scan_ssn(text, allow, &mut spans);
    }
    if cfg.iban != DlpMode::Off {
        scan_iban(text, allow, &mut spans);
    }
    if cfg.email != DlpMode::Off {
        scan_email(text, allow, &mut spans);
    }
    // Drop overlaps (e.g. a digit run inside a larger match), keeping the
    // earliest-starting, longest span.
    spans.sort_by_key(|s| (s.start, std::cmp::Reverse(s.end)));
    let mut out: Vec<Span> = Vec::new();
    for s in spans {
        if out.last().map(|p| s.start >= p.end).unwrap_or(true) {
            out.push(s);
        }
    }
    out
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// Case- and separator-insensitive canonical form for allowlist comparison.
fn normalize_allow(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase()
}

fn allowed(builtin: &[&str], allow: &[String], norm: &str) -> bool {
    let n = normalize_allow(norm);
    builtin.contains(&n.as_str()) || allow.contains(&n)
}

/// Widely published test card numbers (payment-provider docs, fixtures).
const PAN_TEST_NUMBERS: &[&str] = &[
    "4111111111111111",
    "4012888888881881",
    "4222222222222",
    "4242424242424242",
    "4000056655665556",
    "4917610000000000",
    "5555555555554444",
    "5200828282828210",
    "5105105105105100",
    "2223003122003222",
    "378282246310005",
    "371449635398431",
    "6011111111111117",
    "6011000990139424",
    "3056930009020004",
    "36227206271667",
    "3566002020360505",
    "6200000000000005",
];

const SSN_TEST_NUMBERS: &[&str] = &["078051120", "219099999", "457555462"];

/// Example IBANs from bank and payment-provider documentation.
const IBAN_TEST_NUMBERS: &[&str] = &[
    "GB82WEST12345698765432",
    "DE89370400440532013000",
    "GB33BUKB20201555555555",
    "FR1420041010050500013M02606",
    "NL91ABNA0417164300",
];

/// Test routing numbers from payment-provider documentation.
const ABA_TEST_NUMBERS: &[&str] = &["110000000", "021000021", "011401533"];

/// Walk maximal runs of digits with optional uniform space/dash separators,
/// feeding the PAN and ABA detectors. A run glued to a word character, '-',
/// '_' or '.' is an identifier or decimal, not a standalone number: skipped
/// outright, which is what keeps UUIDs, timestamps and version strings quiet.
fn scan_digit_runs(
    text: &str,
    pan_on: bool,
    aba_on: bool,
    allow: &[String],
    spans: &mut Vec<Span>,
) {
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        if i > 0 && (is_word(b[i - 1]) || matches!(b[i - 1], b'-' | b'_' | b'.')) {
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            continue;
        }
        let start = i;
        let mut digits: Vec<u8> = Vec::new();
        let mut sep = 0u8;
        let mut mixed_sep = false;
        let mut last_sep = false;
        let mut end = i;
        let mut j = i;
        while j < b.len() {
            let c = b[j];
            if c.is_ascii_digit() {
                digits.push(c - b'0');
                end = j + 1;
                last_sep = false;
                j += 1;
            } else if (c == b' ' || c == b'-')
                && !last_sep
                && j + 1 < b.len()
                && b[j + 1].is_ascii_digit()
            {
                if sep == 0 {
                    sep = c;
                } else if sep != c {
                    mixed_sep = true;
                }
                last_sep = true;
                j += 1;
            } else {
                break;
            }
        }
        // A run glued to a trailing word character is part of an identifier.
        let bounded = end >= b.len() || !(is_word(b[end]) || b[end] == b'_');
        if bounded {
            let norm: String = digits.iter().map(|d| (d + b'0') as char).collect();
            if pan_on
                && (13..=19).contains(&digits.len())
                && !mixed_sep
                && card_network(&digits).is_some()
                && luhn(&digits)
                && !allowed(PAN_TEST_NUMBERS, allow, &norm)
            {
                spans.push(Span {
                    det: Detector::Pan,
                    start,
                    end,
                    norm,
                });
            } else if aba_on
                && digits.len() == 9
                && sep == 0
                && aba_valid(&digits)
                && !allowed(ABA_TEST_NUMBERS, allow, &norm)
            {
                spans.push(Span {
                    det: Detector::Aba,
                    start,
                    end,
                    norm,
                });
            }
        }
        i = j.max(i + 1);
    }
}

/// Major card network by issuer prefix and length. Random Luhn-valid digit
/// runs pass Luhn 10% of the time; requiring a real IIN range is what makes
/// the PAN detector precise enough to run in block mode.
fn card_network(d: &[u8]) -> Option<&'static str> {
    let n = d.len();
    let p = |k: usize| -> u32 { d.iter().take(k).fold(0u32, |a, &x| a * 10 + x as u32) };
    let (p1, p2, p3, p4) = (p(1), p(2), p(3), p(4));
    if p1 == 4 && matches!(n, 13 | 16 | 19) {
        Some("visa")
    } else if ((51..=55).contains(&p2) || (2221..=2720).contains(&p4)) && n == 16 {
        Some("mastercard")
    } else if matches!(p2, 34 | 37) && n == 15 {
        Some("amex")
    } else if (p4 == 6011 || (644..=649).contains(&p3) || p2 == 65) && (16..=19).contains(&n) {
        Some("discover")
    } else if (3528..=3589).contains(&p4) && (16..=19).contains(&n) {
        Some("jcb")
    } else if ((300..=305).contains(&p3) || matches!(p2, 36 | 38 | 39)) && (14..=19).contains(&n) {
        Some("diners")
    } else {
        None
    }
}

fn luhn(d: &[u8]) -> bool {
    let mut sum = 0u32;
    for (i, &x) in d.iter().rev().enumerate() {
        let mut v = x as u32;
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

fn aba_valid(d: &[u8]) -> bool {
    if d.len() != 9 {
        return false;
    }
    let s = 3 * (d[0] + d[3] + d[6]) as u32
        + 7 * (d[1] + d[4] + d[7]) as u32
        + (d[2] + d[5] + d[8]) as u32;
    // s == 0 means all zeros, which trivially "passes" the checksum.
    let prefix = d[0] * 10 + d[1];
    s != 0 && s.is_multiple_of(10) && matches!(prefix, 0..=12 | 21..=32 | 61..=72 | 80)
}

/// US SSNs in the dashed form only (bare 9-digit runs are far too common in
/// ordinary traffic to match precisely; those need the judge).
fn scan_ssn(text: &str, allow: &[String], spans: &mut Vec<Span>) {
    let b = text.as_bytes();
    let n = b.len();
    let mut i = 0;
    while i + 11 <= n {
        if !b[i].is_ascii_digit() {
            i += 1;
            continue;
        }
        if i > 0 && (is_word(b[i - 1]) || matches!(b[i - 1], b'-' | b'_' | b'.')) {
            i += 1;
            continue;
        }
        let shaped = b[i..i + 3].iter().all(u8::is_ascii_digit)
            && b[i + 3] == b'-'
            && b[i + 4..i + 6].iter().all(u8::is_ascii_digit)
            && b[i + 6] == b'-'
            && b[i + 7..i + 11].iter().all(u8::is_ascii_digit);
        if !shaped || (i + 11 < n && (is_word(b[i + 11]) || matches!(b[i + 11], b'-' | b'_'))) {
            i += 1;
            continue;
        }
        let num = |r: std::ops::Range<usize>| -> u32 {
            b[r].iter().fold(0u32, |a, &c| a * 10 + (c - b'0') as u32)
        };
        let (area, group, serial) = (num(i..i + 3), num(i + 4..i + 6), num(i + 7..i + 11));
        if area == 0 || area == 666 || area >= 900 || group == 0 || serial == 0 {
            i += 1;
            continue;
        }
        let norm: String = text[i..i + 11]
            .chars()
            .filter(char::is_ascii_digit)
            .collect();
        if !allowed(SSN_TEST_NUMBERS, allow, &norm) {
            spans.push(Span {
                det: Detector::Ssn,
                start: i,
                end: i + 11,
                norm,
            });
        }
        i += 11;
    }
}

/// IBAN country-code → total length, for the countries that show up in
/// developer traffic. Unknown country codes never match (precision).
const IBAN_LEN: &[(&str, usize)] = &[
    ("AD", 24),
    ("AE", 23),
    ("AT", 20),
    ("BE", 16),
    ("BG", 22),
    ("CH", 21),
    ("CY", 28),
    ("CZ", 24),
    ("DE", 22),
    ("DK", 18),
    ("EE", 20),
    ("ES", 24),
    ("FI", 18),
    ("FR", 27),
    ("GB", 22),
    ("GR", 27),
    ("HR", 21),
    ("HU", 28),
    ("IE", 22),
    ("IT", 27),
    ("LI", 21),
    ("LT", 20),
    ("LU", 20),
    ("LV", 21),
    ("MC", 27),
    ("MT", 31),
    ("NL", 18),
    ("NO", 15),
    ("PL", 28),
    ("PT", 25),
    ("RO", 24),
    ("SA", 24),
    ("SE", 24),
    ("SI", 19),
    ("SK", 24),
    ("TR", 26),
];

fn scan_iban(text: &str, allow: &[String], spans: &mut Vec<Span>) {
    let b = text.as_bytes();
    let mut i = 0;
    while i + 4 <= b.len() {
        let shaped = b[i].is_ascii_uppercase()
            && b[i + 1].is_ascii_uppercase()
            && b[i + 2].is_ascii_digit()
            && b[i + 3].is_ascii_digit()
            && (i == 0 || !is_word(b[i - 1]));
        if !shaped {
            i += 1;
            continue;
        }
        let Some(&(_, expected)) = IBAN_LEN
            .iter()
            .find(|(cc, _)| cc.as_bytes() == &b[i..i + 2])
        else {
            i += 1;
            continue;
        };
        // Consume the run (uppercase alnum, print-style single spaces allowed)
        // and require it to be exactly one IBAN: partial matches inside longer
        // tokens are rejected.
        let mut compact = String::new();
        let mut last_space = false;
        let mut end = i;
        let mut j = i;
        while j < b.len() {
            let c = b[j];
            if c.is_ascii_uppercase() || c.is_ascii_digit() {
                compact.push(c as char);
                end = j + 1;
                last_space = false;
                j += 1;
            } else if c == b' '
                && !last_space
                && j + 1 < b.len()
                && (b[j + 1].is_ascii_uppercase() || b[j + 1].is_ascii_digit())
            {
                last_space = true;
                j += 1;
            } else {
                break;
            }
        }
        let bounded = end >= b.len() || !is_word(b[end]);
        if bounded
            && compact.len() == expected
            && iban_mod97(&compact) == 1
            && !allowed(IBAN_TEST_NUMBERS, allow, &compact)
        {
            spans.push(Span {
                det: Detector::Iban,
                start: i,
                end,
                norm: compact,
            });
        }
        i = end.max(i + 1);
    }
}

/// ISO 13616 check: move the first four chars to the end, map letters to
/// 10..35, and the whole number must be ≡ 1 mod 97. Computed streaming.
fn iban_mod97(compact: &str) -> u32 {
    let b = compact.as_bytes();
    let mut rem: u32 = 0;
    for &c in b[4..].iter().chain(&b[..4]) {
        let v = if c.is_ascii_digit() {
            (c - b'0') as u32
        } else {
            (c - b'A') as u32 + 10
        };
        rem = if v < 10 {
            (rem * 10 + v) % 97
        } else {
            (rem * 100 + v) % 97
        };
    }
    rem
}

fn scan_email(text: &str, allow: &[String], spans: &mut Vec<Span>) {
    let b = text.as_bytes();
    let is_local = |c: u8| is_word(c) || matches!(c, b'.' | b'_' | b'%' | b'+' | b'-');
    let is_domain = |c: u8| is_word(c) || matches!(c, b'.' | b'-');
    for (k, _) in text.bytes().enumerate().filter(|&(_, c)| c == b'@') {
        let mut s = k;
        while s > 0 && is_local(b[s - 1]) {
            s -= 1;
        }
        if s == k {
            continue;
        }
        let mut e = k + 1;
        while e < b.len() && is_domain(b[e]) {
            e += 1;
        }
        while e > k + 1 && matches!(b[e - 1], b'.' | b'-') {
            e -= 1;
        }
        let domain = &text[k + 1..e];
        let mut labels = domain.split('.');
        let tld = labels.next_back().unwrap_or("");
        let valid = domain.contains('.')
            && tld.len() >= 2
            && tld.bytes().all(|c| c.is_ascii_alphabetic())
            && domain.split('.').all(|l| !l.is_empty());
        if !valid {
            continue;
        }
        let norm = text[s..e].to_ascii_lowercase();
        if !allowed(&[], allow, &norm) {
            spans.push(Span {
                det: Detector::Email,
                start: s,
                end: e,
                norm,
            });
        }
    }
}

/// Scan encoded windows: base64/base64url and hex runs decoded one level, and
/// a percent-decoded view of the whole text. Bounded by the shared decode
/// budget; hitting it sets `truncated` on the outcome. Each finding carries
/// the decoded text its spans index into, so debug mode can show context.
fn scan_encoded(
    text: &str,
    cfg: &DlpConfig,
    allow: &[String],
    budget: &mut usize,
    out: &mut DlpOutcome,
) -> Vec<(&'static str, usize, String, Vec<Span>)> {
    use base64::Engine as _;
    let mut found = Vec::new();
    let charge = |budget: &mut usize, n: usize, out: &mut DlpOutcome| -> bool {
        if *budget < n {
            out.truncated = true;
            false
        } else {
            *budget -= n;
            true
        }
    };

    if text.contains('%') {
        if let Some(decoded) = percent_decode(text) {
            if decoded != text && charge(budget, decoded.len(), out) {
                let spans = scan_text(&decoded, cfg, allow);
                if !spans.is_empty() {
                    found.push(("percent", 0, decoded, spans));
                }
            }
        }
    }

    let b = text.as_bytes();
    let is_run_char = |c: u8| is_word(c) || matches!(c, b'+' | b'/' | b'_' | b'-' | b'=');
    let mut i = 0;
    while i < b.len() {
        if !is_run_char(b[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && is_run_char(b[i]) {
            i += 1;
        }
        let run = &text[start..i];
        if run.len() >= MIN_HEX_RUN
            && run.len().is_multiple_of(2)
            && run.bytes().all(|c| c.is_ascii_hexdigit())
            && charge(budget, run.len() / 2, out)
        {
            if let Ok(decoded) = hex::decode(run) {
                if let Ok(txt) = String::from_utf8(decoded) {
                    let spans = scan_text(&txt, cfg, allow);
                    if !spans.is_empty() {
                        found.push(("hex", start, txt, spans));
                        continue;
                    }
                }
            }
        }
        let trimmed = run.trim_end_matches('=');
        if run.len() >= MIN_B64_RUN && trimmed.len() % 4 != 1 {
            for engine in [
                &base64::engine::general_purpose::STANDARD_NO_PAD,
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            ] {
                let Ok(decoded) = engine.decode(trimmed) else {
                    continue;
                };
                if !charge(budget, decoded.len(), out) {
                    break;
                }
                if let Ok(txt) = String::from_utf8(decoded) {
                    let spans = scan_text(&txt, cfg, allow);
                    if !spans.is_empty() {
                        found.push(("base64", start, txt, spans));
                    }
                }
                break;
            }
        }
    }
    found
}

/// Decode %XX sequences; None if the result isn't valid UTF-8.
fn percent_decode(text: &str) -> Option<String> {
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex_val(b[i + 1]), hex_val(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).ok()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    const SALT: [u8; 32] = [7u8; 32];
    // Luhn-valid, real IIN ranges, not in any test-number allowlist.
    const PAN: &str = "4539148803436467";

    fn cfg_all(mode: DlpMode) -> DlpConfig {
        DlpConfig {
            pan: mode,
            ssn: mode,
            iban: mode,
            aba: mode,
            email: mode,
            allow: Vec::new(),
            debug: false,
        }
    }

    fn ctx(body: &str) -> RequestCtx {
        RequestCtx {
            host: "api.example.com".into(),
            path: "/x".into(),
            method: "POST".into(),
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn scan(body: &str) -> DlpOutcome {
        apply(&mut ctx(body), &cfg_all(DlpMode::Block), &SALT)
    }

    #[test]
    fn luhn_valid_pan_blocks() {
        let out = scan(&format!("{{\"card\":\"{PAN}\"}}"));
        assert_eq!(out.hits.len(), 1);
        let h = &out.hits[0];
        assert_eq!(h.detector, "pan");
        assert_eq!(h.seen_in, "body");
        assert_eq!(h.mode, DlpMode::Block);
        assert!(out.has_blocking());
    }

    #[test]
    fn test_card_numbers_pass() {
        for pan in ["4242424242424242", "4111 1111 1111 1111", "378282246310005"] {
            let out = scan(&format!("pay with {pan} thanks"));
            assert!(out.hits.is_empty(), "test number {pan} must be allowlisted");
        }
    }

    #[test]
    fn separated_pan_hits_with_same_fingerprint() {
        let plain = scan(&format!("n={PAN};"));
        let dashed = scan("n=4539-1488-0343-6467;");
        let spaced = scan("n=4539 1488 0343 6467;");
        assert_eq!(plain.hits.len(), 1);
        assert_eq!(dashed.hits.len(), 1);
        assert_eq!(spaced.hits.len(), 1);
        assert_eq!(plain.hits[0].fingerprint, dashed.hits[0].fingerprint);
        assert_eq!(plain.hits[0].fingerprint, spaced.hits[0].fingerprint);
    }

    #[test]
    fn longer_digit_runs_and_identifiers_pass() {
        // A valid PAN embedded in a longer run, glued to a word, glued to an
        // id prefix, or after a decimal point is not a standalone card number.
        for body in [
            format!("{{\"id\":1{PAN}}}"),
            format!("{{\"id\":\"x{PAN}\"}}"),
            format!("{{\"id\":\"order_{PAN}\"}}"),
            format!("{{\"v\":0.{PAN}}}"),
            format!("{{\"id\":\"{PAN}b\"}}"),
        ] {
            let out = scan(&body);
            assert!(out.hits.is_empty(), "no hit expected in {body}");
        }
    }

    #[test]
    fn luhn_valid_without_network_prefix_passes() {
        // Luhn-valid but no real issuer range: precision gate keeps it quiet.
        let out = scan("{\"n\":\"1111111111111117\"}");
        assert!(out.hits.is_empty());
    }

    #[test]
    fn ssn_dashed_valid_blocks_invalid_pass() {
        assert_eq!(scan("ssn: 545-55-5463").hits[0].detector, "ssn");
        for bad in [
            "666-12-3456", // area 666 never issued
            "957-12-3456", // area 900+ never issued
            "545-00-3456", // group 00 invalid
            "545-55-0000", // serial 0000 invalid
            "078-05-1120", // canonical test SSN
            "545555463",   // bare digits: dashed form only
        ] {
            assert!(scan(&format!("ssn: {bad}")).hits.is_empty(), "{bad}");
        }
    }

    #[test]
    fn iban_valid_blocks_examples_pass() {
        let compact = scan("acct DE40100100100000012345 ok");
        assert_eq!(compact.hits[0].detector, "iban");
        let spaced = scan("acct DE40 1001 0010 0000 0123 45 ok");
        assert_eq!(spaced.hits[0].detector, "iban");
        assert_eq!(compact.hits[0].fingerprint, spaced.hits[0].fingerprint);
        for pass in [
            "DE89370400440532013000",  // documentation example
            "DE41100100100000012345",  // bad check digits
            "XX82WEST12345698765432",  // unknown country
            "DE401001001000000123456", // wrong length for DE
        ] {
            assert!(scan(&format!("acct {pass} ok")).hits.is_empty(), "{pass}");
        }
    }

    #[test]
    fn aba_valid_blocks_test_values_pass() {
        assert_eq!(scan("routing: 060000008").hits[0].detector, "aba");
        for pass in ["110000000", "021000021", "123456789", "000000000"] {
            assert!(scan(&format!("routing: {pass}")).hits.is_empty(), "{pass}");
        }
    }

    #[test]
    fn email_off_by_default_warn_when_enabled() {
        let mut cfg = cfg_all(DlpMode::Off);
        cfg.email = DlpMode::Warn;
        let out = apply(&mut ctx("contact: dev@example.com"), &cfg, &SALT);
        assert_eq!(out.hits.len(), 1);
        assert_eq!(out.hits[0].detector, "email");
        assert_eq!(out.hits[0].mode, DlpMode::Warn);
        assert!(!out.has_blocking());
        assert!(out.has_advisory());
        // And nothing else fires while every other detector is off.
        let out = apply(&mut ctx(PAN), &cfg, &SALT);
        assert!(out.hits.is_empty());
    }

    #[test]
    fn base64_encoded_pan_caught() {
        let blob = base64::engine::general_purpose::STANDARD.encode(format!("card={PAN}"));
        let out = scan(&format!("{{\"blob\":\"{blob}\"}}"));
        assert_eq!(out.hits.len(), 1);
        assert_eq!(out.hits[0].detector, "pan");
        assert_eq!(out.hits[0].seen_in, "body:base64");
    }

    #[test]
    fn hex_encoded_pan_caught() {
        let blob = hex::encode(format!("card={PAN}"));
        let out = scan(&format!("{{\"blob\":\"{blob}\"}}"));
        assert_eq!(out.hits[0].seen_in, "body:hex");
    }

    #[test]
    fn percent_encoded_pan_caught() {
        let out = scan("card=4539%2D1488%2D0343%2D6467");
        assert!(out
            .hits
            .iter()
            .any(|h| h.detector == "pan" && h.seen_in == "body:percent"));
    }

    #[test]
    fn mask_rewrites_body_and_preserves_the_rest() {
        let mut cfg = cfg_all(DlpMode::Off);
        cfg.pan = DlpMode::Mask;
        let mut c = ctx(&format!("{{\"card\":\"{PAN}\",\"amount\":5}}"));
        let out = apply(&mut c, &cfg, &SALT);
        assert_eq!(out.hits[0].mode, DlpMode::Mask);
        assert!(!out.has_blocking());
        let body = String::from_utf8(c.body).unwrap();
        assert_eq!(body, "{\"card\":\"[decoyrail:masked:pan]\",\"amount\":5}");
    }

    #[test]
    fn mask_outside_plain_body_fails_closed_to_block() {
        let mut cfg = cfg_all(DlpMode::Off);
        cfg.pan = DlpMode::Mask;
        // Header hit: not maskable.
        let mut c = ctx("");
        c.headers.push(("x-card".into(), PAN.into()));
        let out = apply(&mut c, &cfg, &SALT);
        assert_eq!(out.hits[0].mode, DlpMode::Block);
        assert_eq!(c.headers[0].1, PAN, "header left untouched");
        // Encoded body hit: not maskable either.
        let blob = base64::engine::general_purpose::STANDARD.encode(format!("card={PAN}"));
        let mut c = ctx(&format!("{{\"blob\":\"{blob}\"}}"));
        let before = c.body.clone();
        let out = apply(&mut c, &cfg, &SALT);
        assert_eq!(out.hits[0].mode, DlpMode::Block);
        assert_eq!(c.body, before, "encoded body left untouched");
    }

    #[test]
    fn pan_in_path_and_header_detected() {
        let mut c = ctx("");
        c.path = format!("/pay?card={PAN}");
        c.headers.push(("x-meta".into(), format!("n {PAN} n")));
        let out = apply(&mut c, &cfg_all(DlpMode::Block), &SALT);
        assert!(out.hits.iter().any(|h| h.seen_in == "path"));
        assert!(out.hits.iter().any(|h| h.seen_in == "header:x-meta"));
    }

    #[test]
    fn user_allowlist_matches_ignoring_separators() {
        let mut cfg = cfg_all(DlpMode::Block);
        cfg.allow = vec!["4539 1488 0343 6467".into()];
        let out = apply(&mut ctx(&format!("card {PAN}")), &cfg, &SALT);
        assert!(out.hits.is_empty());
    }

    #[test]
    fn all_off_scans_nothing() {
        let out = apply(
            &mut ctx(&format!("card {PAN}")),
            &cfg_all(DlpMode::Off),
            &SALT,
        );
        assert!(out.hits.is_empty());
    }

    #[test]
    fn summary_carries_fingerprint_never_the_value() {
        let out = scan(&format!("card {PAN}"));
        let s = out.summary();
        assert!(s.contains("blocked pan@body"));
        assert!(s.contains("fp="));
        assert!(!s.contains(PAN));
    }

    #[test]
    fn debug_off_captures_no_context() {
        let out = scan(&format!("card {PAN}"));
        assert!(out.hits[0].context.is_none());
    }

    #[test]
    fn debug_captures_context_but_summary_stays_clean() {
        let mut cfg = cfg_all(DlpMode::Block);
        cfg.debug = true;
        let out = apply(&mut ctx(&format!("{{\"card\":\"{PAN}\"}}")), &cfg, &SALT);
        let c = out.hits[0].context.as_deref().unwrap();
        assert!(c.contains(&format!(">>>{PAN}<<<")), "got {c}");
        assert!(c.contains("card"), "surrounding text included; got {c}");
        // The audit-log summary is unchanged by debug mode.
        assert!(!out.summary().contains(PAN));
    }

    #[test]
    fn debug_context_for_encoded_hit_shows_decoded_text() {
        let blob = base64::engine::general_purpose::STANDARD.encode(format!("card={PAN} end"));
        let mut cfg = cfg_all(DlpMode::Block);
        cfg.debug = true;
        let out = apply(&mut ctx(&format!("{{\"blob\":\"{blob}\"}}")), &cfg, &SALT);
        assert_eq!(out.hits[0].seen_in, "body:base64");
        let c = out.hits[0].context.as_deref().unwrap();
        assert!(
            c.contains(&format!("card=>>>{PAN}<<< end")),
            "context must come from the decoded view; got {c}"
        );
    }
}
