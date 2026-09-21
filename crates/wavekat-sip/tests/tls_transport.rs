//! SIP over TLS against a loopback rustls server, under `TlsPolicy::Pinned`.
//!
//! Nothing here touches the process environment, so these run concurrently.
//! The `SystemRoots` test must trust a private CA via `SSL_CERT_FILE` and so
//! lives alone in `tls_system_roots.rs` — see that file for why.

#![cfg(feature = "tls")]

mod common;

use common::{account, chain, connect_endpoint, tls_listener};
use rcgen::{CertificateParams, DnType, KeyPair};
use wavekat_sip::{untrusted_certificate, CertFailure, TlsPolicy};

#[tokio::test]
async fn a_pinned_self_signed_certificate_connects() {
    let mut params = CertificateParams::new(vec!["pbx.local".to_string()]).expect("params");
    params.distinguished_name.push(DnType::CommonName, "pbx");
    let key = KeyPair::generate().expect("key");
    let cert = params.self_signed(&key).expect("cert");
    let der = cert.der().to_vec();
    let sha256: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&der).into();

    let (addr, _h) = tls_listener(der, key.serialize_der()).await;
    let acct = account("127.0.0.1", addr.port(), TlsPolicy::Pinned { sha256 });
    assert!(connect_endpoint(&acct).await.is_ok());
}

/// Pinning trusts one certificate, not a category of them: a chain that would
/// otherwise validate is still refused when it is not the pinned one.
#[tokio::test]
async fn a_wrong_pin_is_refused_despite_a_valid_chain() {
    let (_ca, leaf, key) = chain(&["sip.example.com"]);
    let (addr, _h) = tls_listener(leaf, key).await;
    let acct = account(
        "127.0.0.1",
        addr.port(),
        TlsPolicy::Pinned { sha256: [0u8; 32] },
    );

    let err = match connect_endpoint(&acct).await {
        Err(e) => e,
        Ok(_) => panic!("must not connect"),
    };
    let u = untrusted_certificate(err.as_ref()).expect("reports the certificate");
    assert_eq!(u.reason, CertFailure::PinMismatch);
    assert_eq!(u.fingerprint_hex().len(), 64, "reports what it saw");
}
