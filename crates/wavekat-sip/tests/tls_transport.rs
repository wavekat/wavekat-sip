//! SIP over TLS against a loopback rustls server.

#![cfg(feature = "tls")]

use std::net::SocketAddr;
use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use wavekat_sip::{untrusted_certificate, CertFailure, SipAccount, TlsPolicy, Transport};

/// A CA (PEM-encoded — `system_roots_checks_the_domain_and_rejects_untrusted_chains`
/// stands it up as a trusted root via `SSL_CERT_FILE`) and a leaf it signs
/// for `names`. A name that parses as an IP address (e.g. `"127.0.0.1"`)
/// becomes an IP SAN rather than a DNS SAN — `rcgen::CertificateParams::new`'s
/// own behavior, not something this helper adds.
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

/// Guards the one test function below that mutates `SSL_CERT_FILE`.
///
/// Kept even though only that one function touches the environment now, so a
/// second test added later that also needs to override the trust store is
/// forced to coordinate through it rather than quietly racing it.
///
/// It is not a complete fix for `std::env::set_var`'s actual soundness
/// requirement — see `TrustedCaOverride`'s doc for the residual this does
/// not close.
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

/// Points `SSL_CERT_FILE` at a temp file holding `pem` — standing that CA up
/// as a trusted root for the platform verifier's native-certs loader — for
/// as long as this guard lives. Restores the previous value (or clears it)
/// and deletes the temp file on drop, including on an unwind, so a panic
/// between `install` and the end of the test cannot leave the environment or
/// a stray temp file behind for the next test to trip over.
///
/// # What the surrounding `CERT_ENV_LOCK` does and does not make sound
///
/// `std::env::set_var`'s actual requirement is that no *other thread* call
/// `getenv` for *any* variable while this mutates the environment — not just
/// for `SSL_CERT_FILE`. `CERT_ENV_LOCK` excludes every other test in this
/// binary that itself touches `SSL_CERT_FILE` (currently none — this is the
/// only place that does). It does **not** exclude the `Pinned`-policy tests
/// below, which run concurrently on their own threads: their own
/// `SipEndpoint::new` calls (DNS resolution, tokio, tracing) may call
/// `getenv` for an unrelated variable while this guard is live, and nothing
/// here prevents that. That residual is accepted rather than hidden: the
/// mutation window is exactly one TLS handshake attempt, and if the
/// underlying native-certs lookup ever stops honouring `SSL_CERT_FILE`, the
/// chain simply goes untrusted and the test using this guard fails loudly
/// with `UnknownIssuer` — it does not pass for the wrong reason.
struct TrustedCaOverride {
    prev: Option<std::ffi::OsString>,
    path: std::path::PathBuf,
}

impl TrustedCaOverride {
    fn install(pem: &str) -> Self {
        let path = write_temp_ca_pem(pem);
        let prev = std::env::var_os("SSL_CERT_FILE");
        // Safety: see this type's doc for what `CERT_ENV_LOCK` does and does
        // not exclude.
        unsafe { std::env::set_var("SSL_CERT_FILE", &path) };
        Self { prev, path }
    }
}

impl Drop for TrustedCaOverride {
    fn drop(&mut self) {
        // Safety: see this type's doc.
        unsafe {
            match &self.prev {
                Some(v) => std::env::set_var("SSL_CERT_FILE", v),
                None => std::env::remove_var("SSL_CERT_FILE"),
            }
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// `TlsPolicy::SystemRoots` end to end: the RFC 5922 §7.3 domain check (the
/// property this whole feature exists for), and an untrusted chain being
/// refused with its fingerprint reported. One function, not two, so this is
/// the only place in the binary that ever touches `SSL_CERT_FILE` — see
/// `TrustedCaOverride`'s doc for what holding `CERT_ENV_LOCK` here does and
/// does not make sound.
///
/// Unix-only: the trusted-root setup in the first case below rides
/// `SSL_CERT_FILE`, which is specific to the native-certs loader
/// `rustls-platform-verifier` uses on Unix. On another OS the certificate
/// would stay untrusted and this would fail with `UnknownIssuer` instead of
/// `NameMismatch`, for reasons that have nothing to do with the code under
/// test — skipped there rather than left to produce a confusing result.
#[cfg(unix)]
#[tokio::test]
async fn system_roots_checks_the_domain_and_rejects_untrusted_chains() {
    let _lock = CERT_ENV_LOCK.lock().expect("lock");

    // --- RFC 5922 §7.3: the account's domain is what gets verified, never
    // the resolved target. ---
    //
    // The leaf's only SAN is an IP SAN for 127.0.0.1 — the address the
    // socket actually dials, i.e. exactly the identity a *wrong*
    // implementation (one that verified the resolved target instead of the
    // account's domain) would find and accept. The account's domain is
    // sip.example.com, which this certificate was never issued for. So the
    // right implementation gets a `NameMismatch`; a wrong one completes the
    // handshake, and the `Ok(_) => panic!` arm below is what catches that —
    // this is what makes the test discriminate between the two, not just
    // assert that *some* failure happened. (Verified directly: see the fix
    // report for the command that points `stack::tls::connect`'s
    // `server_name` at the resolved target instead of `account.domain` and
    // confirms this test then fails at that `panic!`, not at the
    // `CertFailure` assertion.)
    {
        let (ca_pem, leaf, key) = chain(&["127.0.0.1"]);
        let (addr, _h) = tls_listener(leaf, key).await;
        let acct = account("127.0.0.1", addr.port(), TlsPolicy::SystemRoots);
        let _trust = TrustedCaOverride::install(&ca_pem);

        let err = match connect_endpoint(&acct).await {
            Err(e) => e,
            Ok(_) => panic!(
                "must not connect: an identity valid for the resolved target \
                 was accepted in place of the account's domain"
            ),
        };
        let u = untrusted_certificate(err.as_ref()).expect("reports the certificate");
        assert!(
            matches!(u.reason, CertFailure::NameMismatch { .. }),
            "expected a name mismatch, got {:?}",
            u.reason
        );
    }

    // --- An untrusted chain is refused too, and reports the fingerprint it
    // actually saw. No override here: the `TrustedCaOverride` above already
    // dropped at the end of its block, so this runs against whatever the
    // platform verifier finds on its own. ---
    {
        let (_ca, leaf, key) = chain(&["sip.example.com"]);
        let (addr, _h) = tls_listener(leaf, key).await;
        let acct = account("127.0.0.1", addr.port(), TlsPolicy::SystemRoots);

        let err = match connect_endpoint(&acct).await {
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
