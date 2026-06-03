//! Regression test for the registrar's handling of a *permanent* REGISTER
//! rejection.
//!
//! Before the fix, [`Registrar::register`] looped on every non-200 final
//! response — including `403 Forbidden`, `401 Unauthorized` (bad password),
//! and other rejections a retry can never satisfy — re-sending every 10s
//! forever. The caller's `register().await` never returned, so a misconfigured
//! account was pinned in "connecting" and the user never learned why.
//!
//! This test stands up a fake SIP server that answers every REGISTER with
//! `403 Forbidden` and asserts `register()` *returns the error* promptly
//! instead of hanging. Before the fix it would never resolve and the test's
//! timeout would fire.

use std::sync::Arc;
use std::time::Duration;

use rsip::{SipMessage, StatusCode};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use wavekat_sip::{Registrar, SipAccount, SipEndpoint, Transport};

/// An account whose SIP server points at `127.0.0.1:<port>` — the fake
/// server we stand up below.
fn account(server_port: u16) -> SipAccount {
    SipAccount {
        display_name: "Test".to_string(),
        username: "1001".to_string(),
        password: "secret".to_string(),
        domain: "127.0.0.1".to_string(),
        auth_username: None,
        server: Some("127.0.0.1".to_string()),
        port: Some(server_port),
        transport: Transport::Udp,
    }
}

/// Build a `403 Forbidden` response for `req`, echoing the headers the
/// client transaction matches a response against (Via carries the branch;
/// From/To/Call-ID/CSeq complete the match).
fn forbidden_for(req: &rsip::Request) -> rsip::Response {
    let mut headers = rsip::Headers::default();
    for h in req.headers.iter() {
        match h {
            rsip::Header::Via(_)
            | rsip::Header::From(_)
            | rsip::Header::To(_)
            | rsip::Header::CallId(_)
            | rsip::Header::CSeq(_) => headers.push(h.clone()),
            _ => {}
        }
    }
    headers.push(rsip::Header::ContentLength(
        rsip::headers::ContentLength::from(0u32),
    ));
    rsip::Response {
        status_code: StatusCode::Forbidden,
        version: rsip::Version::V2,
        headers,
        body: Vec::new(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn register_returns_on_permanent_rejection() {
    // Fake SIP server: answer every datagram that parses as a REGISTER with
    // 403 Forbidden, echoing the transaction-matching headers.
    let server = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind fake server");
    let server_addr = server.local_addr().expect("server addr");
    let server = Arc::new(server);

    let responder = server.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            let (n, src) = match responder.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            if let Ok(SipMessage::Request(req)) = SipMessage::try_from(&buf[..n]) {
                if req.method == rsip::Method::Register {
                    let resp = forbidden_for(&req);
                    let _ = responder.send_to(resp.to_string().as_bytes(), src).await;
                }
            }
        }
    });

    let cancel = CancellationToken::new();
    let acct = account(server_addr.port());
    let (endpoint, _incoming) = SipEndpoint::new(&acct, cancel.clone())
        .await
        .expect("bind local endpoint");
    let endpoint = Arc::new(endpoint);
    let registrar =
        Registrar::new(acct, endpoint.clone(), cancel.clone(), 60, 50).expect("build registrar");

    // The crux: register() must return — not spin on the 10s retry loop.
    let outcome = timeout(Duration::from_secs(5), registrar.register()).await;

    endpoint.shutdown();
    cancel.cancel();

    let result =
        outcome.expect("register() should return on a permanent rejection, not hang on retries");
    let err = result.expect_err("a 403 Forbidden REGISTER must surface as an error");
    assert!(
        err.to_string().contains("403"),
        "the surfaced error should name the rejecting status, got: {err}"
    );

    // The failure should also be visible in diagnostics for the UI panel.
    let diag = registrar.diagnostics();
    assert_eq!(diag.last_status, Some(403));
    assert_eq!(diag.failure_count, 1);
    assert!(diag.last_success_at.is_none());
}
