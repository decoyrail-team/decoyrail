//! Decoyrail library surface.
//!
//! The `decoyrail` binary is a thin CLI over these modules; exposing them as a
//! library also lets integration tests in `tests/` drive the proxy pipeline
//! in-process against a local upstream.

pub mod audit;
pub mod ca;
pub mod cache;
pub mod config;
pub mod detect;
pub mod engine;
pub mod guard;
pub mod keyring;
pub mod license;
pub mod meter;
pub mod policy;
pub mod policy_edit;
pub mod pricing;
pub mod proxy;
pub mod stats;
pub mod swap;
pub mod util;
pub mod vault;

/// Install the process-wide rustls crypto provider. Exposed for integration
/// tests, which need it before standing up any TLS server or client.
pub fn proxy_test_install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
