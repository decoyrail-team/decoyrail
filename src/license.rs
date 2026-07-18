//! Offline license: a signed file unlocks the paid tiers (Pro/Team/Enterprise).
//!
//! The invariant that shapes everything here: **licensing fails open to Free,
//! never closed.** An invalid, expired, or missing license can only ever mean
//! "run the free tier", which contains every security feature. No code path in
//! this module may block traffic or weaken enforcement, and the request
//! pipeline's security verbs never consult it.
//!
//! The file is TOML: a `[license]` table (licensee, tier, seats, dates)
//! followed by a `[signature]` table holding an Ed25519 signature over the
//! exact bytes that precede it. Verification is offline against public keys
//! embedded in the binary — no network call, ever, so licensing works
//! air-gapped by construction. Signing happens only in the private issuing
//! tool, which is not part of this repository.
//!
//! `DECOYRAIL_LICENSE_EXTRA_KEY` (hex Ed25519 public key) adds one extra
//! verification key. It exists for tests and evaluation setups; it is not a
//! security hole because a license only gates paid conveniences, and gating
//! is a speed bump by design in a source-available core.

use anyhow::{anyhow, Context, Result};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

use crate::config;

/// Verification keys baked into release builds (hex Ed25519 public keys).
/// A list (not one key) so a future release can rotate keys while honoring
/// already-issued licenses until their expiry. The private halves never touch
/// this repository; signing lives in the private issuing tool.
const RELEASE_KEYS_HEX: &[&str] = &[
    // Production key 1, minted 2026-07-18.
    "9dfcb03ae6bb4813c9843ab80971c1af9e3f5c94cd75404be64ac6c7ee524459",
];

/// The tiers the binary knows, lowest to highest. Free is the no-license
/// state and is never encoded in a license file we issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Free,
    Pro,
    Team,
    Enterprise,
}

impl std::fmt::Display for Tier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Tier::Free => "free",
            Tier::Pro => "pro",
            Tier::Team => "team",
            Tier::Enterprise => "enterprise",
        })
    }
}

/// The signed payload. `tier` stays a string so an old binary can read a
/// license naming a tier it predates; `rank` orders unknown names against the
/// known ladder (pro=1, team=2, enterprise=3) for that case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseDoc {
    pub licensee: String,
    pub tier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<u32>,
    pub seats: u32,
    pub issued: NaiveDate,
    pub expires: NaiveDate,
    #[serde(default = "default_grace_days")]
    pub grace_days: u32,
}

fn default_grace_days() -> u32 {
    14
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    /// Issued in the future (clock skew, pre-provisioned file). Features stay
    /// unlocked — never brick on time — but status warns.
    NotYetValid,
    Valid,
    /// Past expiry but inside the grace window: everything keeps working,
    /// status and the log warn.
    Grace {
        days_left: i64,
    },
    /// Past grace: the effective tier is Free.
    Expired,
}

#[derive(Serialize, Deserialize)]
struct FileDoc {
    license: LicenseDoc,
    signature: SigBlock,
}

#[derive(Serialize, Deserialize)]
struct SigBlock {
    algorithm: String,
    /// Base64 Ed25519 signature over the file bytes preceding `[signature]`.
    value: String,
}

const SIG_MARKER: &str = "\n[signature]";

/// The verification keys this process trusts: the embedded release keys plus
/// the optional `DECOYRAIL_LICENSE_EXTRA_KEY` (see module docs).
pub fn trust_keys() -> Vec<Vec<u8>> {
    let mut keys = Vec::new();
    for h in RELEASE_KEYS_HEX {
        match hex::decode(h) {
            Ok(k) => keys.push(k),
            // A malformed embedded key is a build defect; dropping it
            // silently would surface as a bare "does not verify" for every
            // customer, so say what actually happened.
            Err(_) => eprintln!(
                "decoyrail: warning: an embedded license verification key is not valid hex (build defect)"
            ),
        }
    }
    if let Ok(v) = std::env::var("DECOYRAIL_LICENSE_EXTRA_KEY") {
        match hex::decode(v.trim()) {
            Ok(k) => keys.push(k),
            Err(_) => eprintln!(
                "decoyrail: warning: DECOYRAIL_LICENSE_EXTRA_KEY is not valid hex; ignoring it"
            ),
        }
    }
    keys
}

/// Parse a license file and verify its signature against `keys`. Returns the
/// signed document; any failure is an error naming why (the caller decides
/// what "invalid" means — for the engine it means the Free tier).
pub fn parse_and_verify(text: &str, keys: &[Vec<u8>]) -> Result<LicenseDoc> {
    // Line-ending tolerance: mail clients, editors, and copy-paste turn LF
    // into CRLF in transit. Signing and verification both hash the
    // LF-normalized bytes, so a CRLF round-trip of a genuine license stays
    // valid while any content edit still breaks the signature.
    let text = text.replace("\r\n", "\n");
    let idx = text
        .find(SIG_MARKER)
        .ok_or_else(|| anyhow!("no [signature] section"))?;
    // The signed bytes are everything before the [signature] header,
    // including the newline that precedes it. Any edit to the payload —
    // whitespace included — breaks the signature, which is the point.
    let payload = &text.as_bytes()[..idx + 1];
    let doc: FileDoc = toml::from_str(&text).context("parsing license file")?;
    if doc.signature.algorithm != "ed25519" {
        return Err(anyhow!(
            "unsupported signature algorithm '{}'",
            doc.signature.algorithm
        ));
    }
    use base64::Engine as _;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(doc.signature.value.trim())
        .context("decoding signature")?;
    if keys.is_empty() {
        return Err(anyhow!(
            "this build embeds no license verification keys yet; \
             licenses are issued starting at launch"
        ));
    }
    let verified = keys.iter().any(|k| {
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, k)
            .verify(payload, &sig)
            .is_ok()
    });
    if !verified {
        return Err(anyhow!("signature does not verify against any trusted key"));
    }
    Ok(doc.license)
}

/// Where the license's validity stands relative to `today` (local clock; a
/// wrong clock can only warn or downgrade to Free, never block traffic).
pub fn evaluate(doc: &LicenseDoc, today: NaiveDate) -> Validity {
    if today < doc.issued {
        return Validity::NotYetValid;
    }
    if today <= doc.expires {
        return Validity::Valid;
    }
    // checked_add: this runs on the request path via engine.refresh(), so a
    // signed-but-absurd grace_days must saturate (grace forever), never
    // panic. Licensing may not take traffic down under any input.
    let grace_end = doc
        .expires
        .checked_add_signed(chrono::Duration::days(i64::from(doc.grace_days)))
        .unwrap_or(NaiveDate::MAX);
    if today <= grace_end {
        Validity::Grace {
            days_left: (grace_end - today).num_days(),
        }
    } else {
        Validity::Expired
    }
}

/// Map the document's tier string onto the ladder this binary knows. Unknown
/// names (a newer product tier) fall back to `rank` — the highest known tier
/// at or below it — and to Pro when unranked: the license is signed by us, so
/// generosity here is bounded by what we ourselves issued.
pub fn tier_of(doc: &LicenseDoc) -> Tier {
    match doc.tier.to_ascii_lowercase().as_str() {
        "free" => Tier::Free,
        "pro" => Tier::Pro,
        "team" => Tier::Team,
        "enterprise" => Tier::Enterprise,
        _ => match doc.rank {
            Some(0) => Tier::Free,
            Some(1) => Tier::Pro,
            Some(2) => Tier::Team,
            Some(_) => Tier::Enterprise,
            None => Tier::Pro,
        },
    }
}

/// The tier in force at `today`: the licensed tier, or Free past grace.
pub fn effective_tier(doc: &LicenseDoc, today: NaiveDate) -> Tier {
    match evaluate(doc, today) {
        Validity::Expired => Tier::Free,
        _ => tier_of(doc),
    }
}

/// The tier in force right now for an optional installed license. The one
/// shared definition that boot, hot-reload crossing checks, and gating all
/// use, so they can never disagree.
pub fn current_tier(doc: Option<&LicenseDoc>) -> Tier {
    doc.map(|d| effective_tier(d, chrono::Utc::now().date_naive()))
        .unwrap_or(Tier::Free)
}

/// Load and verify the installed license, if any. `Ok(None)` means no file
/// (the defined Free state); `Err` means a file exists but is unreadable or
/// fails verification — callers treat that as Free too, loudly.
pub fn load_installed() -> Result<Option<LicenseDoc>> {
    let path = config::license_path()?;
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    parse_and_verify(&text, &trust_keys()).map(Some)
}

/// Render a license document as the signed file: payload, then a `[signature]`
/// section. `pkcs8` is an Ed25519 keypair. This is a library primitive (the
/// private issuing tool and tests call it); the binary itself never signs.
pub fn sign_document(doc: &LicenseDoc, pkcs8: &[u8]) -> Result<String> {
    #[derive(Serialize)]
    struct Payload<'a> {
        license: &'a LicenseDoc,
    }
    // Sign the exact bytes that will precede "[signature]" in the file —
    // including the blank separator line — since verification hashes
    // everything up to and including the newline before the marker.
    let payload = format!(
        "{}\n",
        toml::to_string(&Payload { license: doc }).context("serializing license")?
    );
    let keypair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8)
        .map_err(|_| anyhow!("bad Ed25519 keypair"))?;
    let sig = keypair.sign(payload.as_bytes());
    use base64::Engine as _;
    let value = base64::engine::general_purpose::STANDARD.encode(sig.as_ref());
    Ok(format!(
        "{payload}[signature]\nalgorithm = \"ed25519\"\nvalue = \"{value}\"\n"
    ))
}

/// Generate a fresh Ed25519 keypair: (PKCS#8 private, hex public). For the
/// issuing tool and tests.
pub fn generate_keypair() -> Result<(Vec<u8>, String)> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| anyhow!("generating Ed25519 keypair"))?;
    let keypair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| anyhow!("re-reading generated keypair"))?;
    use ring::signature::KeyPair as _;
    Ok((
        pkcs8.as_ref().to_vec(),
        hex::encode(keypair.public_key().as_ref()),
    ))
}

/// One-line human summary of a validity state, for `license status` and the
/// spend status output.
pub fn describe_validity(v: Validity) -> String {
    match v {
        Validity::NotYetValid => {
            "not yet valid (issued in the future; check this machine's clock)".to_string()
        }
        Validity::Valid => "valid".to_string(),
        Validity::Grace { days_left } => {
            format!("expired; in the grace window ({days_left} day(s) left, then the free tier)")
        }
        Validity::Expired => "expired past grace; running the free tier".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(tier: &str, issued: &str, expires: &str) -> LicenseDoc {
        LicenseDoc {
            licensee: "Acme Corp".into(),
            tier: tier.into(),
            rank: None,
            seats: 25,
            issued: issued.parse().unwrap(),
            expires: expires.parse().unwrap(),
            grace_days: 14,
        }
    }

    fn d(s: &str) -> NaiveDate {
        s.parse().unwrap()
    }

    #[test]
    fn embedded_release_keys_are_valid_and_trusted() {
        let _g = crate::util::env_guard();
        std::env::remove_var("DECOYRAIL_LICENSE_EXTRA_KEY");
        // A release must be able to verify a sold license: at least one
        // embedded key, every one a well-formed 32-byte Ed25519 public key,
        // and trust_keys() must carry them all.
        assert!(!RELEASE_KEYS_HEX.is_empty());
        let keys = trust_keys();
        assert_eq!(keys.len(), RELEASE_KEYS_HEX.len());
        for h in RELEASE_KEYS_HEX {
            let k = hex::decode(h).unwrap();
            assert_eq!(k.len(), 32);
            assert!(keys.contains(&k));
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (pkcs8, pub_hex) = generate_keypair().unwrap();
        let text = sign_document(&doc("team", "2026-01-01", "2027-01-01"), &pkcs8).unwrap();
        let keys = vec![hex::decode(&pub_hex).unwrap()];
        let parsed = parse_and_verify(&text, &keys).unwrap();
        assert_eq!(parsed.licensee, "Acme Corp");
        assert_eq!(tier_of(&parsed), Tier::Team);
        assert_eq!(parsed.seats, 25);
    }

    #[test]
    fn tampered_payload_rejected() {
        let (pkcs8, pub_hex) = generate_keypair().unwrap();
        let text = sign_document(&doc("pro", "2026-01-01", "2027-01-01"), &pkcs8).unwrap();
        let keys = vec![hex::decode(&pub_hex).unwrap()];
        let tampered = text.replace("\"pro\"", "\"enterprise\"");
        assert!(parse_and_verify(&tampered, &keys).is_err());
        // Even a whitespace edit to the payload breaks the signature.
        let tampered = text.replacen("seats = 25", "seats =  25", 1);
        assert!(parse_and_verify(&tampered, &keys).is_err());
    }

    #[test]
    fn wrong_key_and_no_keys_rejected() {
        let (pkcs8, _) = generate_keypair().unwrap();
        let (_, other_pub) = generate_keypair().unwrap();
        let text = sign_document(&doc("pro", "2026-01-01", "2027-01-01"), &pkcs8).unwrap();
        let wrong = vec![hex::decode(&other_pub).unwrap()];
        assert!(parse_and_verify(&text, &wrong).is_err());
        assert!(parse_and_verify(&text, &[]).is_err());
    }

    #[test]
    fn missing_signature_section_rejected() {
        assert!(parse_and_verify("[license]\nlicensee = \"x\"\n", &[]).is_err());
    }

    #[test]
    fn crlf_converted_license_still_verifies() {
        let (pkcs8, pub_hex) = generate_keypair().unwrap();
        let text = sign_document(&doc("pro", "2026-01-01", "2027-01-01"), &pkcs8).unwrap();
        let keys = vec![hex::decode(&pub_hex).unwrap()];
        // A mail client or editor turning LF into CRLF must not invalidate a
        // genuine license.
        let crlf = text.replace('\n', "\r\n");
        assert_eq!(
            parse_and_verify(&crlf, &keys).unwrap().licensee,
            "Acme Corp"
        );
    }

    #[test]
    fn absurd_grace_days_never_panics() {
        // grace_days huge enough to overflow the date type: evaluate runs on
        // the request path, so it must saturate, not panic.
        let mut l = doc("pro", "2026-01-01", "2026-06-01");
        l.grace_days = u32::MAX;
        assert_eq!(
            evaluate(&l, d("2027-01-01")),
            Validity::Grace {
                days_left: (NaiveDate::MAX - d("2027-01-01")).num_days()
            }
        );
        assert_eq!(effective_tier(&l, d("2027-01-01")), Tier::Pro);
    }

    #[test]
    fn validity_windows() {
        let l = doc("pro", "2026-01-01", "2026-12-31"); // grace_days = 14
        assert_eq!(evaluate(&l, d("2025-12-31")), Validity::NotYetValid);
        assert_eq!(evaluate(&l, d("2026-01-01")), Validity::Valid);
        assert_eq!(evaluate(&l, d("2026-12-31")), Validity::Valid);
        assert_eq!(
            evaluate(&l, d("2027-01-01")),
            Validity::Grace { days_left: 13 }
        );
        assert_eq!(
            evaluate(&l, d("2027-01-14")),
            Validity::Grace { days_left: 0 }
        );
        assert_eq!(evaluate(&l, d("2027-01-15")), Validity::Expired);
    }

    #[test]
    fn effective_tier_fails_open_to_free() {
        let l = doc("enterprise", "2026-01-01", "2026-06-01");
        assert_eq!(effective_tier(&l, d("2026-03-01")), Tier::Enterprise);
        // Grace keeps the paid tier; past grace drops to Free, never blocks.
        assert_eq!(effective_tier(&l, d("2026-06-10")), Tier::Enterprise);
        assert_eq!(effective_tier(&l, d("2026-07-01")), Tier::Free);
        // Not-yet-valid warns but stays unlocked (never brick on time).
        assert_eq!(effective_tier(&l, d("2025-12-01")), Tier::Enterprise);
    }

    #[test]
    fn unknown_tier_maps_by_rank() {
        let mut l = doc("pro-plus", "2026-01-01", "2027-01-01");
        assert_eq!(tier_of(&l), Tier::Pro); // unranked unknown: lowest paid
        l.rank = Some(2);
        assert_eq!(tier_of(&l), Tier::Team);
        l.rank = Some(9);
        assert_eq!(tier_of(&l), Tier::Enterprise);
        l.rank = Some(0);
        assert_eq!(tier_of(&l), Tier::Free);
    }

    #[test]
    fn tier_ordering() {
        assert!(Tier::Free < Tier::Pro);
        assert!(Tier::Pro < Tier::Team);
        assert!(Tier::Team < Tier::Enterprise);
    }

    #[test]
    fn load_installed_none_when_missing_and_roundtrips() {
        let _g = crate::util::env_guard();
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", tmp.path());
        assert!(load_installed().unwrap().is_none());

        let (pkcs8, pub_hex) = generate_keypair().unwrap();
        std::env::set_var("DECOYRAIL_LICENSE_EXTRA_KEY", &pub_hex);
        let text = sign_document(&doc("team", "2026-01-01", "2027-01-01"), &pkcs8).unwrap();
        config::ensure_home().unwrap();
        std::fs::write(config::license_path().unwrap(), &text).unwrap();
        let loaded = load_installed().unwrap().unwrap();
        assert_eq!(tier_of(&loaded), Tier::Team);

        // A corrupted installed file is an error (callers treat it as Free).
        std::fs::write(
            config::license_path().unwrap(),
            text.replace("Acme", "Evil"),
        )
        .unwrap();
        assert!(load_installed().is_err());

        std::env::remove_var("DECOYRAIL_LICENSE_EXTRA_KEY");
        std::env::remove_var("DECOYRAIL_HOME");
    }
}
