//! Registering and refreshing against a picky registrar, over loopback.
//!
//! Two RFC 3261 §10 requirements a real provider exercises and a LAN PBX does
//! not: a `423 Interval Too Brief` + `Min-Expires` must be answered with a
//! retry at the lifetime the registrar asked for (§10.2.8) rather than needing
//! a human to edit the account's `expires`, and every REGISTER sharing a
//! `Call-ID` must carry a higher `CSeq` than the last one sent (§10.2) —
//! including the extra one a digest retry puts on the wire.
//!
//! The fake registrar runs over TCP so every REGISTER of an attempt arrives in
//! order on a single connection.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use wavekat_sip::{Registrar, SipAccount, SipEndpoint, TlsPolicy, Transport};

/// The floor our fake registrar insists on — an hour, where the account asks
/// for a minute.
const MIN_EXPIRES: u32 = 3600;

fn account(port: u16) -> SipAccount {
    SipAccount {
        display_name: "Test".into(),
        username: "1001".into(),
        password: "secret".into(),
        domain: "127.0.0.1".into(),
        auth_username: None,
        server: Some("127.0.0.1".into()),
        port: Some(port),
        transport: Transport::Tcp,
        tls_policy: TlsPolicy::default(),
    }
}

/// Read one framed message (headers only; a REGISTER has no body).
async fn read_message(sock: &mut tokio::net::TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = sock.read(&mut chunk).await.expect("read");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

/// Echo back the headers a response must mirror, plus a `To` tag.
fn response_for(register: &str, status_line: &str, extra: &str) -> String {
    let header = |name: &str| -> String {
        register
            .lines()
            .find(|l| {
                l.to_ascii_lowercase()
                    .starts_with(&name.to_ascii_lowercase())
            })
            .unwrap_or_default()
            .trim_end()
            .to_string()
    };
    format!(
        "{}\r\n{}\r\n{}\r\n{};tag=server\r\n{}\r\n{}\r\n{}Content-Length: 0\r\n\r\n",
        status_line,
        header("Via:"),
        header("From:"),
        header("To:"),
        header("Call-ID:"),
        header("CSeq:"),
        extra,
    )
}

/// Pull the `Expires` value off a REGISTER we captured.
fn expires_of(register: &str) -> Option<u32> {
    register
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("expires:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse().ok())
}

#[tokio::test]
async fn a_423_is_retried_at_the_registrars_minimum() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let (seen_tx, seen_rx) = oneshot::channel::<Vec<String>>();

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");

        // First REGISTER: refuse it and name the lifetime we want.
        let first = read_message(&mut sock).await;
        let too_brief = response_for(
            &first,
            "SIP/2.0 423 Interval Too Brief",
            &format!("Min-Expires: {MIN_EXPIRES}\r\n"),
        );
        sock.write_all(too_brief.as_bytes())
            .await
            .expect("write 423");

        // Second REGISTER: accept it, granting exactly what we demanded.
        let second = read_message(&mut sock).await;
        let ok = response_for(
            &second,
            "SIP/2.0 200 OK",
            &format!("Expires: {MIN_EXPIRES}\r\n"),
        );
        sock.write_all(ok.as_bytes()).await.expect("write 200");

        let _ = seen_tx.send(vec![first, second]);
        // Hold the connection open past the assertions.
        tokio::time::sleep(Duration::from_secs(3)).await;
    });

    let cancel = CancellationToken::new();
    let endpoint = SipEndpoint::new(&account(addr.port()), cancel.clone())
        .await
        .expect("binds a TCP endpoint");
    let registrar = Registrar::new(
        account(addr.port()),
        endpoint.clone(),
        cancel.clone(),
        60,
        50,
    )
    .expect("builds a registrar");

    let outcome = timeout(Duration::from_secs(5), registrar.register())
        .await
        .expect("register completes");
    assert!(
        outcome.is_ok(),
        "a 423 naming Min-Expires must still end registered: {outcome:?}"
    );

    let seen = timeout(Duration::from_secs(5), seen_rx)
        .await
        .expect("server saw both REGISTERs")
        .expect("channel");

    assert_eq!(
        expires_of(&seen[0]),
        Some(60),
        "the first REGISTER asks for the configured lifetime:\n{}",
        seen[0]
    );
    assert_eq!(
        expires_of(&seen[1]),
        Some(MIN_EXPIRES),
        "the retry must ask for the registrar's minimum:\n{}",
        seen[1]
    );

    let diag = registrar.diagnostics().await;
    assert_eq!(diag.last_status, Some(200));
    assert_eq!(diag.negotiated_expires, Some(MIN_EXPIRES));
    assert_eq!(
        diag.min_expires,
        Some(MIN_EXPIRES),
        "the learned floor is reported so a consumer can explain the bump"
    );
    assert_eq!(
        diag.configured_expires, 60,
        "the configured lifetime is reported unchanged"
    );

    endpoint.shutdown();
    cancel.cancel();
}

/// Learning the floor has to outlive the attempt that learned it: a refresh
/// must ask for the registrar's minimum outright, not spend another round trip
/// being told the same thing.
#[tokio::test]
async fn a_refresh_asks_for_the_learned_minimum_outright() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let (seen_tx, seen_rx) = oneshot::channel::<String>();

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");

        // Attempt 1: refuse, then accept the retry.
        let first = read_message(&mut sock).await;
        let too_brief = response_for(
            &first,
            "SIP/2.0 423 Interval Too Brief",
            &format!("Min-Expires: {MIN_EXPIRES}\r\n"),
        );
        sock.write_all(too_brief.as_bytes())
            .await
            .expect("write 423");
        let second = read_message(&mut sock).await;
        let ok = response_for(
            &second,
            "SIP/2.0 200 OK",
            &format!("Expires: {MIN_EXPIRES}\r\n"),
        );
        sock.write_all(ok.as_bytes()).await.expect("write 200");

        // Attempt 2 (the refresh): accept it, and report what it asked for.
        let third = read_message(&mut sock).await;
        let ok = response_for(
            &third,
            "SIP/2.0 200 OK",
            &format!("Expires: {MIN_EXPIRES}\r\n"),
        );
        sock.write_all(ok.as_bytes()).await.expect("write 200");
        let _ = seen_tx.send(third);
        tokio::time::sleep(Duration::from_secs(3)).await;
    });

    let cancel = CancellationToken::new();
    let endpoint = SipEndpoint::new(&account(addr.port()), cancel.clone())
        .await
        .expect("binds a TCP endpoint");
    let registrar = Registrar::new(
        account(addr.port()),
        endpoint.clone(),
        cancel.clone(),
        60,
        50,
    )
    .expect("builds a registrar");

    for attempt in 1..=2 {
        let outcome = timeout(Duration::from_secs(5), registrar.register())
            .await
            .expect("register completes");
        assert!(outcome.is_ok(), "attempt {attempt} registered: {outcome:?}");
    }

    let refresh = timeout(Duration::from_secs(5), seen_rx)
        .await
        .expect("server saw the refresh")
        .expect("channel");
    assert_eq!(
        expires_of(&refresh),
        Some(MIN_EXPIRES),
        "the refresh must ask for the learned minimum, not the configured 60:\n{refresh}"
    );

    endpoint.shutdown();
    cancel.cancel();
}

/// The shape a real provider produces: challenge first, *then* refuse the
/// lifetime. The retry has to be a whole fresh REGISTER — its own `CSeq`, its
/// own challenge answered from a fresh nonce — not the refused request replayed
/// with a bigger `Expires` and a stale `nc=1` a server may treat as a replay.
#[tokio::test]
async fn a_423_behind_a_digest_challenge_still_registers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let (seen_tx, seen_rx) = oneshot::channel::<Vec<String>>();

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let challenge = |register: &str, nonce: &str| {
            response_for(
                register,
                "SIP/2.0 401 Unauthorized",
                &format!(
                    "WWW-Authenticate: Digest realm=\"127.0.0.1\", nonce=\"{nonce}\", qop=\"auth\"\r\n"
                ),
            )
        };
        let mut seen = Vec::new();

        // Unauthenticated REGISTER → challenge.
        let first = read_message(&mut sock).await;
        sock.write_all(challenge(&first, "nonce-one").as_bytes())
            .await
            .expect("write 401");
        seen.push(first);

        // Authenticated REGISTER → the lifetime is too brief.
        let second = read_message(&mut sock).await;
        let too_brief = response_for(
            &second,
            "SIP/2.0 423 Interval Too Brief",
            &format!("Min-Expires: {MIN_EXPIRES}\r\n"),
        );
        sock.write_all(too_brief.as_bytes())
            .await
            .expect("write 423");
        seen.push(second);

        // The retry starts over: challenge it again with a *different* nonce,
        // which only a freshly computed digest can answer.
        let third = read_message(&mut sock).await;
        sock.write_all(challenge(&third, "nonce-two").as_bytes())
            .await
            .expect("write 401");
        seen.push(third);

        let fourth = read_message(&mut sock).await;
        let ok = response_for(
            &fourth,
            "SIP/2.0 200 OK",
            &format!("Expires: {MIN_EXPIRES}\r\n"),
        );
        sock.write_all(ok.as_bytes()).await.expect("write 200");
        seen.push(fourth);

        let _ = seen_tx.send(seen);
        tokio::time::sleep(Duration::from_secs(3)).await;
    });

    let cancel = CancellationToken::new();
    let endpoint = SipEndpoint::new(&account(addr.port()), cancel.clone())
        .await
        .expect("binds a TCP endpoint");
    let registrar = Registrar::new(
        account(addr.port()),
        endpoint.clone(),
        cancel.clone(),
        60,
        50,
    )
    .expect("builds a registrar");

    let outcome = timeout(Duration::from_secs(5), registrar.register())
        .await
        .expect("register completes");
    assert!(
        outcome.is_ok(),
        "a challenged 423 must still end registered: {outcome:?}"
    );

    let seen = timeout(Duration::from_secs(5), seen_rx)
        .await
        .expect("server saw all four REGISTERs")
        .expect("channel");

    assert_eq!(
        expires_of(&seen[1]),
        Some(60),
        "the refused attempt:\n{}",
        seen[1]
    );
    assert_eq!(
        expires_of(&seen[3]),
        Some(MIN_EXPIRES),
        "the accepted retry asks for the minimum:\n{}",
        seen[3]
    );
    assert!(
        seen[3].to_ascii_lowercase().contains("nonce=\"nonce-two\""),
        "the retry answers the second challenge, not the first:\n{}",
        seen[3]
    );

    let cseqs = cseqs_of(&seen);
    assert!(
        cseqs.windows(2).all(|w| w[0] < w[1]),
        "every REGISTER in one Call-ID needs a higher CSeq than the last: {cseqs:?}"
    );

    endpoint.shutdown();
    cancel.cancel();
}

/// Read every REGISTER's `CSeq` sequence number, in the order they arrived.
fn cseqs_of(registers: &[String]) -> Vec<u32> {
    registers
        .iter()
        .map(|m| {
            m.lines()
                .find(|l| l.to_ascii_lowercase().starts_with("cseq:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
                .expect("every REGISTER carries a CSeq")
        })
        .collect()
}

/// RFC 3261 §10.2: "The UA MUST increment the CSeq value by one for each
/// REGISTER request with the same Call-ID."
///
/// Regression test. Answering a digest challenge puts a *second* REGISTER on
/// the wire at the next sequence number, which the registration state has to
/// pick up — otherwise every refresh replays the number its predecessor's
/// authenticated REGISTER already used (`1, 2, 2, 3, …`), and a registrar that
/// enforces the ordering rejects it.
#[tokio::test]
async fn every_refresh_carries_a_higher_cseq_than_the_last_one_sent() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let (seen_tx, seen_rx) = oneshot::channel::<Vec<String>>();

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut seen = Vec::new();
        // Challenge each refresh, the way a provider does.
        for n in 0..2 {
            let unauth = read_message(&mut sock).await;
            let challenge = response_for(
                &unauth,
                "SIP/2.0 401 Unauthorized",
                &format!(
                    "WWW-Authenticate: Digest realm=\"127.0.0.1\", nonce=\"n{n}\", qop=\"auth\"\r\n"
                ),
            );
            sock.write_all(challenge.as_bytes())
                .await
                .expect("write 401");
            seen.push(unauth);

            let authed = read_message(&mut sock).await;
            let ok = response_for(&authed, "SIP/2.0 200 OK", "Expires: 60\r\n");
            sock.write_all(ok.as_bytes()).await.expect("write 200");
            seen.push(authed);
        }
        let _ = seen_tx.send(seen);
        tokio::time::sleep(Duration::from_secs(3)).await;
    });

    let cancel = CancellationToken::new();
    let endpoint = SipEndpoint::new(&account(addr.port()), cancel.clone())
        .await
        .expect("binds a TCP endpoint");
    let registrar = Registrar::new(
        account(addr.port()),
        endpoint.clone(),
        cancel.clone(),
        60,
        50,
    )
    .expect("builds a registrar");

    for attempt in 1..=2 {
        let outcome = registrar.register().await;
        assert!(outcome.is_ok(), "attempt {attempt} registered: {outcome:?}");
    }

    let seen = timeout(Duration::from_secs(5), seen_rx)
        .await
        .expect("server saw all four REGISTERs")
        .expect("channel");
    let cseqs = cseqs_of(&seen);
    assert!(
        cseqs.windows(2).all(|w| w[0] < w[1]),
        "CSeq must only ever climb within one Call-ID: {cseqs:?}"
    );

    endpoint.shutdown();
    cancel.cancel();
}
