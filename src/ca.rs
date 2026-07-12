//! Decoyrail's per-device certificate authority.
//!
//! On first use we generate a long-lived root CA and persist it to `~/.decoyrail`.
//! For every host the proxy intercepts we mint a short-lived leaf certificate
//! signed by that root, so TLS clients that trust the Decoyrail CA (installed via
//! `decoyrail ca install` or an MDM profile) accept the interception transparently.

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use std::collections::HashMap;
use std::sync::Mutex;
use time::{Duration, OffsetDateTime};

use crate::config;

/// Leaf certs are short-lived: some TLS stacks reject server certs whose
/// validity exceeds ~398 days, and rcgen's default window (1975–4096) trips
/// exactly that. 397 days stays under the limit with margin.
const LEAF_VALID_DAYS: i64 = 397;
/// The CA is long-lived (it must outlast the leaves it signs); 10 years.
const CA_VALID_DAYS: i64 = 3650;
/// Backdate `not_before` to tolerate modest client/server clock skew.
const CLOCK_SKEW: Duration = Duration::hours(1);

/// The signing root: keeps the CA cert + key in memory, and a cache of minted
/// leaf certs keyed by host so repeat connections are cheap.
pub struct CertAuthority {
    ca_cert: Certificate,
    ca_key: KeyPair,
    ca_cert_pem: String,
    leaf_cache: Mutex<
        HashMap<
            String,
            (
                Vec<rustls::pki_types::CertificateDer<'static>>,
                rustls::pki_types::PrivateKeyDer<'static>,
            ),
        >,
    >,
}

impl CertAuthority {
    /// Load the persisted CA, generating and saving one on first run.
    pub fn load_or_create() -> Result<Self> {
        config::ensure_home()?;
        let cert_path = config::ca_cert_path()?;
        let key_path = config::ca_key_path()?;

        if !cert_path.exists() || !key_path.exists() {
            generate_root()?;
        }

        // Installs that predate key-permission hardening left ca-key.pem
        // world-readable — with it, any local user can mint certificates this
        // device trusts. Tighten on sight and say so.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&key_path) {
                let mut perms = meta.permissions();
                if perms.mode() & 0o077 != 0 {
                    eprintln!(
                        "decoyrail: warning: {} was readable by other users; restricting to 0600",
                        key_path.display()
                    );
                    perms.set_mode(0o600);
                    let _ = std::fs::set_permissions(&key_path, perms);
                }
            }
        }

        let ca_cert_pem = std::fs::read_to_string(&cert_path)
            .with_context(|| format!("reading CA cert {}", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(&key_path)
            .with_context(|| format!("reading CA key {}", key_path.display()))?;

        let ca_key = KeyPair::from_pem(&key_pem).context("parsing CA key")?;
        // Reconstruct the issuer cert from the persisted PEM. It shares the
        // subject DN and (via ca_key) the key pair of the installed root, so
        // leaves it signs validate against the trusted CA on the client.
        let params =
            CertificateParams::from_ca_cert_pem(&ca_cert_pem).context("parsing CA cert params")?;
        let ca_cert = params
            .self_signed(&ca_key)
            .context("re-materializing CA issuer cert")?;

        Ok(Self {
            ca_cert,
            ca_key,
            ca_cert_pem,
            leaf_cache: Mutex::new(HashMap::new()),
        })
    }

    /// PEM of the trusted root — used by CLI export and (future) the menubar UI.
    #[allow(dead_code)]
    pub fn root_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Return a rustls cert chain + key for `host`, minting and caching on miss.
    pub fn leaf_for(
        &self,
        host: &str,
    ) -> Result<(
        Vec<rustls::pki_types::CertificateDer<'static>>,
        rustls::pki_types::PrivateKeyDer<'static>,
    )> {
        if let Some(hit) = self.leaf_cache.lock().unwrap().get(host) {
            return Ok((hit.0.clone(), hit.1.clone_key()));
        }

        let mut leaf = CertificateParams::new(vec![host.to_string()])?;
        leaf.is_ca = IsCa::NoCa;
        let now = OffsetDateTime::now_utc();
        leaf.not_before = now - CLOCK_SKEW;
        leaf.not_after = now + Duration::days(LEAF_VALID_DAYS);
        leaf.distinguished_name = {
            let mut dn = DistinguishedName::new();
            dn.push(DnType::CommonName, host);
            dn
        };
        leaf.subject_alt_names = vec![SanType::DnsName(host.try_into()?)];

        let leaf_key = KeyPair::generate()?;
        let leaf_cert = leaf
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .context("signing leaf cert")?;

        let chain = vec![
            rustls::pki_types::CertificateDer::from(leaf_cert.der().to_vec()),
            rustls::pki_types::CertificateDer::from(self.ca_cert.der().to_vec()),
        ];
        let key = rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der())
            .map_err(|e| anyhow::anyhow!("leaf key: {e}"))?;

        self.leaf_cache
            .lock()
            .unwrap()
            .insert(host.to_string(), (chain.clone(), key.clone_key()));
        Ok((chain, key))
    }
}

/// SHA-1 fingerprint (uppercase hex) of the persisted root cert's DER: the
/// identity `security delete-certificate -Z` keys on. Returns `None` when no
/// CA has been generated; uninstall must never mint a root just to delete it.
pub fn root_sha1_fingerprint() -> Result<Option<String>> {
    let cert_path = config::ca_cert_path()?;
    if !cert_path.exists() {
        return Ok(None);
    }
    let pem = std::fs::read_to_string(&cert_path)
        .with_context(|| format!("reading CA cert {}", cert_path.display()))?;
    let der = pem_body_to_der(&pem)?;
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &der);
    Ok(Some(hex::encode_upper(digest.as_ref())))
}

/// Decode the base64 body of a single-certificate PEM file.
fn pem_body_to_der(pem: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .context("decoding CA cert PEM body")
}

/// Generate a fresh root CA and persist cert + key PEM to `~/.decoyrail`.
fn generate_root() -> Result<()> {
    let mut params = CertificateParams::new(Vec::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Decoyrail Device CA");
    dn.push(DnType::OrganizationName, "Decoyrail");
    params.distinguished_name = dn;

    let now = OffsetDateTime::now_utc();
    params.not_before = now - CLOCK_SKEW;
    params.not_after = now + Duration::days(CA_VALID_DAYS);

    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;

    // The cert is public by design (clients install it); the key must never be.
    std::fs::write(config::ca_cert_path()?, cert.pem())?;
    config::write_private(&config::ca_key_path()?, key.serialize_pem().as_bytes())?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    #[test]
    fn root_fingerprint_absent_then_stable_and_matches_openssl() {
        let _guard = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DECOYRAIL_HOME", dir.path());

        // No CA yet: must report absence, not mint one.
        assert_eq!(super::root_sha1_fingerprint().unwrap(), None);
        assert!(!crate::config::ca_cert_path().unwrap().exists());

        super::CertAuthority::load_or_create().unwrap();
        let fp = super::root_sha1_fingerprint().unwrap().unwrap();
        assert_eq!(fp.len(), 40);
        assert!(fp
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()));
        assert_eq!(super::root_sha1_fingerprint().unwrap().unwrap(), fp);

        // Cross-check the digest against an independent implementation; this
        // hash is what `security delete-certificate -Z` keys on, so a mismatch
        // means uninstall deletes nothing.
        if let Ok(out) = std::process::Command::new("openssl")
            .args(["x509", "-noout", "-fingerprint", "-sha1", "-in"])
            .arg(crate::config::ca_cert_path().unwrap())
            .output()
        {
            if out.status.success() {
                let openssl = String::from_utf8_lossy(&out.stdout)
                    .split('=')
                    .nth(1)
                    .unwrap()
                    .trim()
                    .replace(':', "");
                assert_eq!(fp, openssl);
            }
        }
    }

    #[test]
    fn fresh_state_dir_and_ca_key_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = crate::util::env_guard();
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("state");
        std::env::set_var("DECOYRAIL_HOME", &home);

        super::CertAuthority::load_or_create().unwrap();

        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        // The key mints certs this device trusts; the dir holds it plus the
        // vault. Neither may be visible to other users, whatever the umask.
        assert_eq!(mode(&home), 0o700, "state dir must be user-only");
        assert_eq!(
            mode(&crate::config::ca_key_path().unwrap()),
            0o600,
            "CA private key must be user-only"
        );
    }
}
