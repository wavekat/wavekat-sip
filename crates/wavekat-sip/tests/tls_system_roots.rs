//! `TlsPolicy::SystemRoots` against a private CA installed via `SSL_CERT_FILE`.
//!
//! A binary of its own, holding exactly one test, because trusting the CA means
//! mutating the process environment. `std::env::set_var` is only sound while
//! no other thread reads the environment — for *any* variable. Sharing a
//! binary with other tests breaks that: their endpoints resolve DNS and start
//! runtimes on sibling threads, and under glibc a `getenv` racing `setenv` can
//! read freed memory. Here the variable is set before the runtime exists, in
//! the binary's only test, so there is no other thread to race.
//!
//! Unix-only: `SSL_CERT_FILE` is specific to the native-certs loader
//! `rustls-platform-verifier` uses on Unix. On another OS the certificate
//! would stay untrusted and this would fail with `UnknownIssuer` instead of
//! `NameMismatch`, for reasons that have nothing to do with the code under
//! test.

#![cfg(all(feature = "tls", unix))]

mod common;

use common::{account, chain, connect_endpoint, tls_listener};
use wavekat_sip::{untrusted_certificate, CertFailure, TlsPolicy};

/// Deletes the temp CA file on drop, including on an unwind.
struct TempFile(std::path::PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Write `pem` to a fresh, process-unique temp file.
fn write_temp_ca_pem(pem: &str) -> TempFile {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "wavekat-sip-test-ca-{}-{nanos}.pem",
        std::process::id()
    ));
    std::fs::write(&path, pem).expect("write temp CA file");
    TempFile(path)
}

/// The RFC 5922 §7.3 domain check (the property this whole feature exists
/// for), and an untrusted chain being refused with its fingerprint reported.
///
/// A plain `#[test]` that builds its own runtime rather than `#[tokio::test]`,
/// so the ordering this binary depends on is visible: environment first, then
/// the runtime and every thread that comes with it.
#[test]
fn system_roots_checks_the_domain_and_rejects_untrusted_chains() {
    // The CA for the first case below. The second case generates its own,
    // which this never trusts — so setting the variable once for the whole
    // test leaves that case untrusted, as it needs to be.
    let (ca_pem, leaf, key) = chain(&["127.0.0.1"]);
    let ca_file = write_temp_ca_pem(&ca_pem);

    // Safety: this is the only test in this binary, and it runs before the
    // tokio runtime below is built, so no other thread exists to call
    // `getenv` while the environment is being written. See the module doc.
    unsafe { std::env::set_var("SSL_CERT_FILE", &ca_file.0) };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");

    rt.block_on(async {
        // --- RFC 5922 §7.3: the account's domain is what gets verified,
        // never the resolved target. ---
        //
        // The leaf's only SAN is an IP SAN for 127.0.0.1 — the address the
        // socket actually dials, i.e. exactly the identity a *wrong*
        // implementation (one that verified the resolved target instead of
        // the account's domain) would find and accept. The account's domain
        // is sip.example.com, which this certificate was never issued for. So
        // the right implementation gets a `NameMismatch`; a wrong one
        // completes the handshake, and the `Ok(_) => panic!` arm below is
        // what catches that — this is what makes the test discriminate
        // between the two, not just assert that *some* failure happened.
        //
        // The CA *is* trusted here: were `SSL_CERT_FILE` not honoured, this
        // would fail with `UnknownIssuer`, so the test cannot pass for the
        // wrong reason.
        {
            let (addr, _h) = tls_listener(leaf, key).await;
            let acct = account("127.0.0.1", addr.port(), TlsPolicy::SystemRoots);

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

        // --- An untrusted chain is refused too, and reports the fingerprint
        // it actually saw. Its CA is not the one `SSL_CERT_FILE` names, and
        // `chain` gives every CA a distinct subject, so the verifier finds no
        // issuer for it at all. ---
        {
            let (_ca, leaf, key) = chain(&["sip.example.com"]);
            let (addr, _h) = tls_listener(leaf, key).await;
            let acct = account("127.0.0.1", addr.port(), TlsPolicy::SystemRoots);

            let err = match connect_endpoint(&acct).await {
                Err(e) => e,
                Ok(_) => panic!("must not connect"),
            };
            let u = untrusted_certificate(err.as_ref()).expect("reports the certificate");
            assert_eq!(u.reason, CertFailure::UnknownIssuer);
            assert_ne!(u.sha256, [0u8; 32]);
        }
    });
}
