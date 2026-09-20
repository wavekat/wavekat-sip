//! TLS setup for the stream transport: policy → `rustls::ClientConfig`, the
//! handshake, and the failure mapping.
//!
//! The only module in the crate that names rustls. Everything above it sees a
//! [`SipStream`](super::stream::SipStream) and does not know whether bytes are
//! encrypted.

use std::io;
use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::account::TlsPolicy;
use crate::tls_error::{CertFailure, UntrustedCertificate};

/// SHA-256 of a certificate's DER encoding — the fingerprint a consumer pins.
fn sha256(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

/// The process-wide crypto provider, installed on first use.
fn provider() -> Arc<CryptoProvider> {
    if let Some(p) = CryptoProvider::get_default() {
        return p.clone();
    }
    // Racing callers are fine: whoever loses simply reads the winner's value.
    let _ = rustls::crypto::ring::default_provider().install_default();
    CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
}

/// Translate a rustls failure into what we tell the consumer.
fn cert_failure(err: &rustls::Error) -> CertFailure {
    match err {
        rustls::Error::InvalidCertificate(c) => match c {
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                CertFailure::Expired
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                CertFailure::NotYetValid
            }
            CertificateError::NotValidForNameContext { presented, .. } => {
                CertFailure::NameMismatch {
                    presented: presented.clone(),
                }
            }
            CertificateError::NotValidForName => CertFailure::NameMismatch {
                presented: Vec::new(),
            },
            CertificateError::UnknownIssuer => CertFailure::UnknownIssuer,
            CertificateError::BadEncoding => CertFailure::Malformed,
            // What `PinnedVerifier` returns on a mismatch; nothing else in this
            // crate's configuration produces it.
            CertificateError::ApplicationVerificationFailure => CertFailure::PinMismatch,
            other => CertFailure::Other(other.to_string()),
        },
        other => CertFailure::Other(other.to_string()),
    }
}

/// Accept exactly one certificate, by fingerprint.
///
/// Chain, expiry and name are all ignored on purpose: under
/// [`TlsPolicy::Pinned`] the fingerprint *is* the identity. That is what makes
/// it usable for the self-signed on-premise server it exists to serve, and it
/// stays narrow — it trusts one certificate, not every certificate.
#[derive(Debug)]
struct PinnedVerifier {
    sha256: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl PinnedVerifier {
    fn new(sha256: [u8; 32], provider: Arc<CryptoProvider>) -> Self {
        Self { sha256, provider }
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if sha256(end_entity.as_ref()) == self.sha256 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Where [`RecordingVerifier`] stashes the leaf fingerprint it last saw, so
/// [`connect`] can read it back after a handshake failure.
type FingerprintSlot = Arc<Mutex<Option<[u8; 32]>>>;

/// Wrap a verifier so the leaf's fingerprint is available after a failure.
///
/// A verifier can only return a `rustls::Error`, and the platform verifier is
/// opaque to us, so there is no other way to tell the consumer *which*
/// certificate was refused — which is exactly what a pinning prompt needs.
#[derive(Debug)]
struct RecordingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    seen: FingerprintSlot,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut slot) = self.seen.lock() {
            *slot = Some(sha256(end_entity.as_ref()));
        }
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Build the client config for `policy`, plus the slot its verifier records the
/// leaf fingerprint into.
fn config_with_recorder(policy: &TlsPolicy) -> io::Result<(rustls::ClientConfig, FingerprintSlot)> {
    let provider = provider();
    let inner: Arc<dyn ServerCertVerifier> = match policy {
        TlsPolicy::SystemRoots => Arc::new(
            rustls_platform_verifier::Verifier::new(provider.clone())
                .map_err(|e| io::Error::other(format!("platform trust store unavailable: {e}")))?,
        ),
        TlsPolicy::Pinned { sha256 } => Arc::new(PinnedVerifier::new(*sha256, provider.clone())),
    };

    let seen = Arc::new(Mutex::new(None));
    let recording = Arc::new(RecordingVerifier {
        inner,
        seen: seen.clone(),
    });

    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("no usable TLS protocol versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(recording)
        .with_no_client_auth();

    Ok((config, seen))
}

/// Build the client config for `policy`.
fn client_config(policy: &TlsPolicy) -> io::Result<rustls::ClientConfig> {
    config_with_recorder(policy).map(|(c, _)| c)
}

/// Perform the TLS handshake on an established TCP connection.
///
/// `server_name` is the **account's SIP domain**, never the host an SRV lookup
/// returned — RFC 5922 §7.1. It is both the name verified and the SNI sent. If
/// the SRV target were verified instead, whoever can answer the DNS query would
/// also choose which name the certificate has to match, and could point it at a
/// host whose certificate they legitimately hold.
pub(crate) async fn connect(
    tcp: TcpStream,
    server_name: &str,
    policy: &TlsPolicy,
) -> io::Result<TlsStream<TcpStream>> {
    let (config, seen) = config_with_recorder(policy)?;
    let name = ServerName::try_from(server_name.to_string()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{server_name}` is not a valid TLS server name"),
        )
    })?;

    TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .map_err(|e| {
            // A TLS error wraps the rustls error as its source; anything that
            // reached the verifier has a fingerprint recorded for it.
            let rustls_err = e
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>());
            let fingerprint = seen.lock().ok().and_then(|s| *s);
            match (rustls_err, fingerprint) {
                (Some(re), Some(sha256)) => io::Error::new(
                    io::ErrorKind::InvalidData,
                    UntrustedCertificate {
                        sha256,
                        reason: cert_failure(re),
                    },
                ),
                _ => e,
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        date_time_ymd, BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair,
    };

    /// A self-signed CA, and a leaf it signs for `names`.
    fn chain(names: &[&str]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "wavekat test ca");
        let ca_key = KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let owned: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let leaf_params = CertificateParams::new(owned).expect("leaf params");
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf cert");

        (
            ca_cert.der().to_vec(),
            leaf.der().to_vec(),
            leaf_key.serialize_der(),
        )
    }

    /// A self-signed leaf with an explicit validity window, for the
    /// expired / not-yet-valid cases.
    fn self_signed_valid(name: &str, from: (i32, u8, u8), to: (i32, u8, u8)) -> (Vec<u8>, Vec<u8>) {
        let mut params = CertificateParams::new(vec![name.to_string()]).expect("params");
        params.not_before = date_time_ymd(from.0, from.1, from.2);
        params.not_after = date_time_ymd(to.0, to.1, to.2);
        let key = KeyPair::generate().expect("key");
        let cert = params.self_signed(&key).expect("cert");
        (cert.der().to_vec(), key.serialize_der())
    }

    #[test]
    fn fingerprints_the_leaf_der() {
        let (_ca, leaf, _key) = chain(&["sip.example.com"]);
        let a = sha256(&leaf);
        let b = sha256(&leaf);
        assert_eq!(a, b, "the digest is stable");
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn maps_expiry_to_its_own_failure() {
        let err = rustls::Error::InvalidCertificate(rustls::CertificateError::Expired);
        assert_eq!(cert_failure(&err), CertFailure::Expired);
    }

    #[test]
    fn maps_not_yet_valid_to_its_own_failure() {
        let err = rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidYet);
        assert_eq!(cert_failure(&err), CertFailure::NotYetValid);
    }

    #[test]
    fn maps_unknown_issuer_to_its_own_failure() {
        let err = rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        assert_eq!(cert_failure(&err), CertFailure::UnknownIssuer);
    }

    #[test]
    fn maps_bad_encoding_to_malformed() {
        let err = rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding);
        assert_eq!(cert_failure(&err), CertFailure::Malformed);
    }

    /// rustls hands us the names the certificate presented, so reporting them
    /// costs no certificate parser of our own.
    #[test]
    fn name_mismatch_carries_the_presented_names() {
        let err =
            rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForNameContext {
                expected: rustls::pki_types::ServerName::try_from("sip.example.com")
                    .expect("name")
                    .to_owned(),
                presented: vec!["edge-3.example.net".to_string()],
            });
        assert_eq!(
            cert_failure(&err),
            CertFailure::NameMismatch {
                presented: vec!["edge-3.example.net".to_string()]
            }
        );
    }

    #[test]
    fn pin_mismatch_has_its_own_failure() {
        let err = rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        );
        assert_eq!(cert_failure(&err), CertFailure::PinMismatch);
    }

    #[test]
    fn a_non_certificate_failure_is_not_reported_as_one() {
        let err = rustls::Error::NoCertificatesPresented;
        assert!(matches!(cert_failure(&err), CertFailure::Other(_)));
    }

    #[test]
    fn both_policies_build_a_usable_client_config() {
        assert!(client_config(&TlsPolicy::SystemRoots).is_ok());
        assert!(client_config(&TlsPolicy::Pinned { sha256: [7u8; 32] }).is_ok());
    }

    #[test]
    fn a_pinned_verifier_accepts_only_its_own_fingerprint() {
        let (_ca, leaf, _key) = chain(&["sip.example.com"]);
        let der = rustls::pki_types::CertificateDer::from(leaf.clone());
        let name = rustls::pki_types::ServerName::try_from("sip.example.com").expect("name");
        let now = rustls::pki_types::UnixTime::now();

        let right = PinnedVerifier::new(sha256(&leaf), provider());
        assert!(right.verify_server_cert(&der, &[], &name, &[], now).is_ok());

        let wrong = PinnedVerifier::new([0u8; 32], provider());
        assert!(wrong
            .verify_server_cert(&der, &[], &name, &[], now)
            .is_err());
    }

    /// Pinning trusts one certificate, not a chain: an expired self-signed cert
    /// whose fingerprint matches is still the certificate the operator pinned.
    #[test]
    fn a_pinned_verifier_ignores_chain_and_expiry() {
        let (leaf, _key) = self_signed_valid("pbx.local", (2020, 1, 1), (2021, 1, 1));
        let der = rustls::pki_types::CertificateDer::from(leaf.clone());
        let name =
            rustls::pki_types::ServerName::try_from("totally-different.example").expect("name");
        let v = PinnedVerifier::new(sha256(&leaf), provider());
        assert!(v
            .verify_server_cert(&der, &[], &name, &[], rustls::pki_types::UnixTime::now())
            .is_ok());
    }

    /// The recorder is the only way `connect` can attach a fingerprint to a
    /// refused certificate's error, so it must capture it even when the
    /// wrapped verifier goes on to reject the certificate.
    #[test]
    fn recording_verifier_captures_the_fingerprint_even_on_rejection() {
        let (_ca, leaf, _key) = chain(&["sip.example.com"]);
        let der = rustls::pki_types::CertificateDer::from(leaf.clone());
        let name = rustls::pki_types::ServerName::try_from("sip.example.com").expect("name");
        let now = rustls::pki_types::UnixTime::now();

        // A pinned verifier for a different fingerprint always rejects, but
        // the wrapper should still have recorded what it actually saw.
        let inner: Arc<dyn ServerCertVerifier> =
            Arc::new(PinnedVerifier::new([0u8; 32], provider()));
        let seen = Arc::new(Mutex::new(None));
        let recording = RecordingVerifier {
            inner,
            seen: seen.clone(),
        };

        let result = recording.verify_server_cert(&der, &[], &name, &[], now);
        assert!(result.is_err(), "the wrapped verifier still rejects");
        assert_eq!(
            *seen.lock().expect("lock"),
            Some(sha256(&leaf)),
            "the fingerprint of the certificate actually presented was recorded"
        );
    }
}
