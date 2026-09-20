//! End-to-end exercise of SIP over TCP against a loopback listener.
//!
//! A minimal server accepts one connection, reads a framed REGISTER, asserts
//! the headers name TCP, and answers `200 OK` on the same connection. This is
//! the integration counterpart to the in-crate framing and stream unit tests:
//! it drives the *public* surface exactly as a consumer would.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use wavekat_sip::re_exports::Uri;
use wavekat_sip::{Caller, Registrar, SipAccount, SipEndpoint, Transport};

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
    }
}

/// Read until the header terminator, so the assertions see a whole message.
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

/// Echo back the headers a 200 must mirror, plus a `To` tag.
fn ok_for(register: &str) -> String {
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
        "SIP/2.0 200 OK\r\n{}\r\n{}\r\n{};tag=server\r\n{}\r\n{}\r\nExpires: 60\r\nContent-Length: 0\r\n\r\n",
        header("Via:"),
        header("From:"),
        header("To:"),
        header("Call-ID:"),
        header("CSeq:"),
    )
}

#[tokio::test]
async fn registers_over_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let (seen_tx, seen_rx) = oneshot::channel::<String>();

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let register = read_message(&mut sock).await;
        sock.write_all(ok_for(&register).as_bytes())
            .await
            .expect("write 200");
        let _ = seen_tx.send(register);
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
    assert!(outcome.is_ok(), "REGISTER over TCP succeeded: {outcome:?}");

    let register = timeout(Duration::from_secs(5), seen_rx)
        .await
        .expect("server saw a REGISTER")
        .expect("channel");

    assert!(
        register.starts_with("REGISTER "),
        "server received a REGISTER:\n{register}"
    );
    assert!(
        register.contains("Via: SIP/2.0/TCP "),
        "Via must name TCP, not UDP:\n{register}"
    );
    assert!(
        register.to_ascii_lowercase().contains("transport=tcp"),
        "Contact must carry ;transport=tcp:\n{register}"
    );
    assert!(
        register.to_ascii_lowercase().contains("content-length:"),
        "stream framing requires Content-Length:\n{register}"
    );

    endpoint.shutdown();
    cancel.cancel();
}

/// An outbound INVITE must advertise TCP too.
///
/// Regression test: the `Via` transport is read back off the `Contact` we
/// build, and `Caller` built a bare `sip:user@addr` with no transport
/// parameter — so a REGISTER correctly said TCP while the INVITE on the same
/// connection claimed UDP. A stream peer happens to answer on the connection
/// anyway, which is exactly why this went unnoticed; a proxy that honours the
/// `Via` would send the response to a UDP socket that does not exist.
#[tokio::test]
async fn invite_over_tcp_advertises_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let (seen_tx, seen_rx) = oneshot::channel::<String>();

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let invite = read_message(&mut sock).await;
        // 486 Busy Here — enough to finish the transaction; we only care
        // about the request we were sent.
        let busy = ok_for(&invite).replace("SIP/2.0 200 OK", "SIP/2.0 486 Busy Here");
        sock.write_all(busy.as_bytes()).await.expect("write 486");
        let _ = seen_tx.send(invite);
        tokio::time::sleep(Duration::from_secs(3)).await;
    });

    let cancel = CancellationToken::new();
    let endpoint = SipEndpoint::new(&account(addr.port()), cancel.clone())
        .await
        .expect("binds a TCP endpoint");
    let caller = Caller::new(account(addr.port()), endpoint.clone());

    let target: Uri = format!("sip:601@127.0.0.1:{}", addr.port())
        .try_into()
        .expect("target uri");
    let _ = timeout(Duration::from_secs(5), caller.dial(target)).await;

    let invite = timeout(Duration::from_secs(5), seen_rx)
        .await
        .expect("server saw an INVITE")
        .expect("channel");

    assert!(
        invite.starts_with("INVITE "),
        "server received an INVITE:\n{invite}"
    );
    assert!(
        invite.contains("Via: SIP/2.0/TCP "),
        "INVITE Via must name TCP, not UDP:\n{invite}"
    );
    assert!(
        invite.to_ascii_lowercase().contains("transport=tcp"),
        "INVITE Contact must carry the transport, or in-dialog requests go to UDP:\n{invite}"
    );

    endpoint.shutdown();
    cancel.cancel();
}
