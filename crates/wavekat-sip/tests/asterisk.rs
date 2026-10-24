//! End-to-end tests against a real Asterisk.
//!
//! Every other integration test here talks to a SIP peer we wrote, so it only
//! proves we agree with ourselves. These talk to Asterisk 22 (PJSIP), a
//! registrar people actually run, and check what our own peers can't tell us:
//! that it accepts our REGISTER on each transport, answers our calls, routes
//! an inbound call back down the TCP connection we opened, and how it treats
//! a keepalive ping.
//!
//! They need the test server, so they are `#[ignore]`d. Run them with:
//!
//! ```sh
//! make e2e-asterisk
//! ```
//!
//! which starts Asterisk in Docker with `e2e/asterisk/*.conf`, runs this file
//! one test at a time, and stops it again. To point them at a server you
//! started yourself, set `WAVEKAT_E2E_SIP_HOST` / `WAVEKAT_E2E_SIP_PORT`, and
//! `WAVEKAT_E2E_ASTERISK_CONTAINER` for the restart test.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use wavekat_sip::re_exports::Uri;
use wavekat_sip::{AudioCodec, Caller, Registrar, SipAccount, SipEndpoint, TlsPolicy, Transport};

fn host() -> String {
    std::env::var("WAVEKAT_E2E_SIP_HOST").unwrap_or_else(|_| "127.0.0.1".into())
}

fn port() -> u16 {
    std::env::var("WAVEKAT_E2E_SIP_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5060)
}

/// One of the two accounts in `e2e/asterisk/pjsip.conf`.
fn account(user: &str, password: &str, transport: Transport) -> SipAccount {
    SipAccount {
        display_name: user.into(),
        username: user.into(),
        password: password.into(),
        domain: host(),
        auth_username: None,
        server: Some(host()),
        port: Some(port()),
        transport,
        tls_policy: TlsPolicy::default(),
    }
}

fn alice(transport: Transport) -> SipAccount {
    account("alice", "alice-e2e", transport)
}

fn bob(transport: Transport) -> SipAccount {
    account("bob", "bob-e2e", transport)
}

/// An endpoint plus a registrar for `account`, signed in.
async fn signed_in(account: SipAccount) -> (Arc<SipEndpoint>, Registrar, CancellationToken) {
    let cancel = CancellationToken::new();
    let endpoint = SipEndpoint::new(&account, cancel.clone())
        .await
        .expect("endpoint binds");
    let registrar =
        Registrar::new(account, endpoint.clone(), cancel.clone(), 120, 60).expect("registrar");
    timeout(Duration::from_secs(10), registrar.register())
        .await
        .expect("REGISTER answered within 10 s")
        .expect("Asterisk accepts the sign-in");
    (endpoint, registrar, cancel)
}

/// Sign in, check Asterisk said 200, and sign out again.
async fn assert_registers(transport: Transport) {
    let (_endpoint, registrar, cancel) = signed_in(alice(transport)).await;
    let diag = registrar.diagnostics().await;
    assert_eq!(diag.last_status, Some(200), "{diag:?}");
    assert!(diag.negotiated_expires.is_some(), "{diag:?}");
    registrar.unregister().await;
    cancel.cancel();
}

#[tokio::test]
#[ignore = "needs the Asterisk test server: make e2e-asterisk"]
async fn registers_over_udp() {
    assert_registers(Transport::Udp).await;
}

#[tokio::test]
#[ignore = "needs the Asterisk test server: make e2e-asterisk"]
async fn registers_over_tcp() {
    assert_registers(Transport::Tcp).await;
}

#[tokio::test]
#[ignore = "needs the Asterisk test server: make e2e-asterisk"]
async fn a_wrong_password_is_refused() {
    let account = account("alice", "not-the-password", Transport::Udp);
    let cancel = CancellationToken::new();
    let endpoint = SipEndpoint::new(&account, cancel.clone())
        .await
        .expect("endpoint binds");
    let registrar = Registrar::new(account, endpoint, cancel.clone(), 120, 60).expect("registrar");
    let err = timeout(Duration::from_secs(10), registrar.register())
        .await
        .expect("REGISTER answered within 10 s")
        .expect_err("Asterisk refuses a wrong password");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("401") || msg.contains("403") || msg.contains("auth"),
        "a refusal, not a timeout: {msg}"
    );
    cancel.cancel();
}

/// Dial the echo extension over `transport`, check the answer, hang up.
async fn assert_echo_call(transport: Transport) {
    let account = bob(transport);
    let (endpoint, registrar, cancel) = signed_in(account.clone()).await;
    let caller = Caller::new(account, endpoint);
    let target: Uri = format!("sip:600@{}", host()).as_str().try_into().unwrap();

    let mut call = timeout(Duration::from_secs(10), caller.dial(target))
        .await
        .expect("dial completes within 10 s")
        .expect("Asterisk answers the echo extension");
    // Asterisk is set to G.711 only, so of our offer it takes PCMU.
    assert_eq!(
        call.remote_media.codec,
        Some(AudioCodec::Pcmu),
        "{:?}",
        call.remote_media
    );
    assert!(call.remote_media.port > 0);

    timeout(Duration::from_secs(10), call.hangup())
        .await
        .expect("hangup completes within 10 s")
        .expect("Asterisk accepts the BYE");
    registrar.unregister().await;
    cancel.cancel();
}

#[tokio::test]
#[ignore = "needs the Asterisk test server: make e2e-asterisk"]
async fn an_echo_call_connects_and_hangs_up_over_udp() {
    assert_echo_call(Transport::Udp).await;
}

#[tokio::test]
#[ignore = "needs the Asterisk test server: make e2e-asterisk"]
async fn an_echo_call_connects_and_hangs_up_over_tcp() {
    assert_echo_call(Transport::Tcp).await;
}

#[tokio::test]
#[ignore = "needs the Asterisk test server: make e2e-asterisk"]
async fn an_inbound_call_arrives_down_the_tcp_connection() {
    // The reason a TCP line works behind NAT at all: the registrar sends the
    // INVITE back down the connection the line opened. Alice signs in over
    // TCP; Bob calls her through Asterisk; the call has to reach her there.
    let (alice_ep, alice_reg, alice_cancel) = signed_in(alice(Transport::Tcp)).await;
    let bob_account = bob(Transport::Udp);
    let (bob_ep, bob_reg, bob_cancel) = signed_in(bob_account.clone()).await;

    let answering = tokio::spawn({
        let alice_ep = alice_ep.clone();
        async move {
            let incoming = timeout(Duration::from_secs(10), alice_ep.next_incoming_call())
                .await
                .expect("the INVITE reaches alice")
                .expect("alice's endpoint is still up");
            incoming.accept().await.expect("alice answers")
        }
    });

    let caller = Caller::new(bob_account, bob_ep);
    let target: Uri = format!("sip:alice@{}", host()).as_str().try_into().unwrap();
    let mut call = timeout(Duration::from_secs(15), caller.dial(target))
        .await
        .expect("dial completes within 15 s")
        .expect("alice's answer reaches bob");
    let alice_call = answering.await.expect("answering task");

    // Bob hangs up; Asterisk passes the BYE down alice's TCP connection.
    timeout(Duration::from_secs(10), call.hangup())
        .await
        .expect("hangup completes within 10 s")
        .expect("Asterisk accepts the BYE");
    timeout(Duration::from_secs(10), alice_call.terminated().cancelled())
        .await
        .expect("alice hears the hang-up");

    bob_reg.unregister().await;
    alice_reg.unregister().await;
    bob_cancel.cancel();
    alice_cancel.cancel();
}

#[tokio::test]
#[ignore = "needs the Asterisk test server: make e2e-asterisk"]
async fn asterisk_does_not_answer_keepalive_pings() {
    // RFC 5626 §3.5.1 lets a server answer a double-CRLF ping with a CRLF
    // pong. Asterisk's PJSIP stack doesn't. The stream keepalive relies on
    // this being fine: a server that has never ponged is never judged by its
    // silence (docs/23-stream-keepalive.md). If Asterisk starts ponging,
    // this test fails, and that rule starts applying to Asterisk too.
    use tokio::io::AsyncWriteExt;
    let mut sock = tokio::net::TcpStream::connect((host(), port()))
        .await
        .expect("connect");
    sock.write_all(b"\r\n\r\n").await.expect("ping");
    let mut buf = [0u8; 64];
    match timeout(Duration::from_secs(3), sock.read(&mut buf)).await {
        Err(_) => {} // silence: no pong, connection still open
        Ok(Ok(0)) => panic!("Asterisk closed the connection on a ping"),
        Ok(Ok(n)) => panic!("Asterisk answered the ping: {:?}", &buf[..n]),
        Ok(Err(e)) => panic!("read failed: {e}"),
    }
}

#[tokio::test]
#[ignore = "needs the Asterisk test server: make e2e-asterisk"]
async fn restarting_asterisk_ends_a_tcp_endpoint() {
    // What a consumer rebuilds on: when the registrar restarts, the TCP
    // connection closes and the endpoint stops, so `next_incoming_call`
    // returns `None` straight away instead of the line going quietly deaf.
    let container = std::env::var("WAVEKAT_E2E_ASTERISK_CONTAINER")
        .unwrap_or_else(|_| "wavekat-sip-asterisk".into());
    let (endpoint, _registrar, cancel) = signed_in(alice(Transport::Tcp)).await;

    let ended = tokio::spawn({
        let endpoint = endpoint.clone();
        async move { endpoint.next_incoming_call().await.is_none() }
    });

    let status = tokio::process::Command::new("docker")
        .args(["restart", "--timeout", "1", &container])
        .status()
        .await
        .expect("run docker restart");
    assert!(status.success(), "docker restart {container}");

    let stopped = timeout(Duration::from_secs(20), ended)
        .await
        .expect("the endpoint notices the restart within 20 s")
        .expect("watch task");
    assert!(stopped, "next_incoming_call() returned a call, not None");
    cancel.cancel();

    // Leave Asterisk usable for whatever runs next: wait until it says it
    // has booted, then sign in once over TCP. Not over UDP: datagrams sent
    // while the container is down can leave Docker's port mapping pointing
    // at the old container, and UDP to it then goes nowhere for a while.
    // Until Asterisk is running inside the container, asking it fails
    // rather than waits, so ask again until it answers.
    let boot_deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let booted = tokio::process::Command::new("docker")
            .args([
                "exec",
                &container,
                "asterisk",
                "-rx",
                "core waitfullybooted",
            ])
            .output()
            .await
            .expect("run docker exec");
        if booted.status.success() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < boot_deadline,
            "Asterisk didn't boot again within 60 s"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let account = alice(Transport::Tcp);
        let probe_cancel = CancellationToken::new();
        let back = async {
            let ep = SipEndpoint::new(&account, probe_cancel.clone())
                .await
                .ok()?;
            let reg = Registrar::new(account.clone(), ep, probe_cancel.clone(), 120, 60).ok()?;
            timeout(Duration::from_secs(3), reg.register())
                .await
                .ok()?
                .ok()?;
            reg.unregister().await;
            Some(())
        }
        .await;
        probe_cancel.cancel();
        if back.is_some() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Asterisk booted but doesn't take a sign-in"
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
