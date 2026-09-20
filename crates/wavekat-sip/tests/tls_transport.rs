//! SIP over TLS against a loopback rustls server.

#![cfg(feature = "tls")]

use std::net::SocketAddr;
use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use wavekat_sip::{untrusted_certificate, CertFailure, SipAccount, TlsPolicy, Transport};

/// A CA (PEM-encoded — `verifies_the_sip_domain_not_the_resolved_target`
/// stands it up as a trusted root via `SSL_CERT_FILE`) and a leaf it signs
/// for `names`.
fn chain(names: &[&str]) -> (String, Vec<u8>, Vec<u8>) {
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
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).expect("leaf");

    (ca_cert.pem(), leaf.der().to_vec(), leaf_key.serialize_der())
}

/// A TLS listener that answers one connection, on an OS-assigned port.
async fn tls_listener(leaf: Vec<u8>, key: Vec<u8>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
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

fn account(server: &str, port: u16, policy: TlsPolicy) -> SipAccount {
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

/// Serializes every test below that reads or writes `SSL_CERT_FILE`.
///
/// `TlsPolicy::SystemRoots` goes through the platform verifier's
/// native-certs loader, which reads `SSL_CERT_FILE` off the process
/// environment (`std::env::var_os`) on Unix. `std::env::set_var` racing a
/// concurrent read on another thread is unsound, and `cargo test` runs each
/// test function on its own thread — so every test that can reach that read
/// (any `SystemRoots` connection attempt) or that write (only the RFC 5922
/// regression test) takes this lock first.
static CERT_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Write `pem` to a fresh, process-unique temp file and return its path.
fn write_temp_ca_pem(pem: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "wavekat-sip-test-ca-{}-{nanos}.pem",
        std::process::id()
    ));
    std::fs::write(&path, pem).expect("write temp CA file");
    path
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Attempt a connection, with a timeout so a hung handshake fails the test
/// rather than the suite.
async fn connect_endpoint(
    acct: &SipAccount,
) -> Result<std::sync::Arc<wavekat_sip::SipEndpoint>, BoxError> {
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

/// The RFC 5922 §7.1 regression test.
///
/// The certificate is valid for the SRV target and *not* for the SIP domain.
/// If the implementation verified the resolved host, this would connect — which
/// is exactly the failure that leaves a connection looking secure while whoever
/// answers the DNS query chooses the identity.
#[tokio::test]
async fn verifies_the_sip_domain_not_the_resolved_target() {
    let (ca_pem, leaf, key) = chain(&["edge-3.example.net"]);
    let (addr, _h) = tls_listener(leaf, key).await;
    // domain is sip.example.com; we connect to 127.0.0.1 standing in for the
    // SRV target the certificate *is* valid for.
    let acct = account("127.0.0.1", addr.port(), TlsPolicy::SystemRoots);

    // `TlsPolicy::SystemRoots` verifies against the platform's real trust
    // store, which rightly does not trust a certificate this test just
    // generated. Left alone, the handshake fails on the untrusted issuer
    // before ever reaching the name check this test exists to exercise — so
    // the test stands its own CA up as an *additional* trusted root for the
    // duration of the connection attempt, via `SSL_CERT_FILE` (the same
    // input the platform verifier's native-certs loader already reads on
    // Unix). That makes the chain trusted and lets the real assertion — the
    // account's domain, not the SRV target, is what gets checked — run on
    // its own, rather than being pre-empted by an unrelated trust failure.
    let guard = CERT_ENV_LOCK.lock().expect("lock");
    let ca_path = write_temp_ca_pem(&ca_pem);
    let prev_cert_file = std::env::var_os("SSL_CERT_FILE");
    // Safety: serialized by `CERT_ENV_LOCK` against every other test in this
    // binary that reads or writes `SSL_CERT_FILE`.
    unsafe { std::env::set_var("SSL_CERT_FILE", &ca_path) };

    let result = connect_endpoint(&acct).await;

    // Safety: see above.
    unsafe {
        match &prev_cert_file {
            Some(v) => std::env::set_var("SSL_CERT_FILE", v),
            None => std::env::remove_var("SSL_CERT_FILE"),
        }
    }
    let _ = std::fs::remove_file(&ca_path);
    drop(guard);

    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("must not connect"),
    };
    let u = untrusted_certificate(err.as_ref()).expect("reports the certificate");
    assert!(
        matches!(u.reason, CertFailure::NameMismatch { .. }),
        "expected a name mismatch, got {:?}",
        u.reason
    );
}

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

#[tokio::test]
async fn an_untrusted_chain_is_refused_and_reports_its_fingerprint() {
    let (_ca, leaf, key) = chain(&["sip.example.com"]);
    let (addr, _h) = tls_listener(leaf, key).await;
    let acct = account("127.0.0.1", addr.port(), TlsPolicy::SystemRoots);

    // Shares `CERT_ENV_LOCK` with the RFC 5922 regression test above: both
    // reach the platform verifier's native-certs loader, which reads
    // `SSL_CERT_FILE` off the process environment, and that read must not
    // race that test's write of it.
    let guard = CERT_ENV_LOCK.lock().expect("lock");
    let result = connect_endpoint(&acct).await;
    drop(guard);

    let err = match result {
        Err(e) => e,
        Ok(_) => panic!("must not connect"),
    };
    let u = untrusted_certificate(err.as_ref()).expect("reports the certificate");
    assert!(matches!(
        u.reason,
        CertFailure::UnknownIssuer | CertFailure::NameMismatch { .. }
    ));
    assert_ne!(u.sha256, [0u8; 32]);
}
