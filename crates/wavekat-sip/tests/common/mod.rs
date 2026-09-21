//! Helpers shared by the TLS integration test binaries.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use wavekat_sip::{SipAccount, TlsPolicy, Transport};

/// A CA (PEM-encoded, so `tls_system_roots.rs` can stand it up as a trusted
/// root via `SSL_CERT_FILE`) and a leaf it signs for `names`. A name that
/// parses as an IP address (e.g. `"127.0.0.1"`) becomes an IP SAN rather than
/// a DNS SAN — `rcgen::CertificateParams::new`'s own behavior, not something
/// this helper adds.
///
/// Every call's CA gets a distinct subject. Verifiers find a leaf's issuer by
/// name, so two CAs sharing one would let a trusted CA be tried against a leaf
/// it never signed — reporting `BadSignature` where an unrelated CA should
/// simply be an `UnknownIssuer`.
pub fn chain(names: &[&str]) -> (String, Vec<u8>, Vec<u8>) {
    static NEXT_CA: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT_CA.fetch_add(1, Ordering::Relaxed);

    let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, format!("wavekat test ca {n}"));
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let owned: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    let leaf_params = CertificateParams::new(owned).expect("leaf params");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).expect("leaf");

    (ca_cert.pem(), leaf.der().to_vec(), leaf_key.serialize_der())
}

/// A TLS listener that answers one connection, on an OS-assigned port.
pub async fn tls_listener(
    leaf: Vec<u8>,
    key: Vec<u8>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf)],
            PrivateKeyDer::try_from(key).expect("key"),
        )
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        if let Ok((sock, _)) = listener.accept().await {
            // Drive the handshake; the client's assertion is about whether it
            // completed, so the SIP exchange itself is not needed here.
            let _ = acceptor.accept(sock).await;
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    });
    (addr, handle)
}

pub fn account(server: &str, port: u16, policy: TlsPolicy) -> SipAccount {
    SipAccount {
        display_name: "Test".to_string(),
        username: "1001".to_string(),
        password: "secret".to_string(),
        domain: "sip.example.com".to_string(),
        auth_username: None,
        server: Some(server.to_string()),
        port: Some(port),
        transport: Transport::Tls,
        tls_policy: policy,
    }
}

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Attempt a connection, with a timeout so a hung handshake fails the test
/// rather than the suite.
pub async fn connect_endpoint(
    acct: &SipAccount,
) -> Result<Arc<wavekat_sip::SipEndpoint>, BoxError> {
    let cancel = tokio_util::sync::CancellationToken::new();
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        wavekat_sip::SipEndpoint::new(acct, cancel.clone()),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err("timed out establishing the endpoint".into()),
    }
}
