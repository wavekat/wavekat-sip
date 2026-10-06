//! Probing a registrar without signing in, over loopback TCP.
//!
//! `Registrar::probe` sends one REGISTER binding query (RFC 3261 §10.2.3): no
//! `Contact`, no credentials, and a `401` challenge reported instead of
//! answered. Over a single TCP connection we can see every request in order,
//! so this checks both what the query looks like on the wire and that a real
//! `register()` afterwards keeps the §10.2 `CSeq` sequence on the same
//! `Call-ID`.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use wavekat_sip::{RegisterProbe, Registrar, SipAccount, SipEndpoint, TlsPolicy, Transport};

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

fn header<'a>(msg: &'a str, name: &str) -> Option<&'a str> {
    msg.lines()
        .find(|l| {
            l.to_ascii_lowercase()
                .starts_with(&format!("{}:", name.to_ascii_lowercase()))
        })
        .map(|l| l.trim_end())
}

/// Echo back the headers a response must mirror, plus a `To` tag.
fn response_for(request: &str, status_line: &str, extra: &str) -> String {
    let h = |name: &str| header(request, name).unwrap_or_default().to_string();
    format!(
        "{}\r\n{}\r\n{}\r\n{};tag=server\r\n{}\r\n{}\r\n{}Content-Length: 0\r\n\r\n",
        status_line,
        h("Via"),
        h("From"),
        h("To"),
        h("Call-ID"),
        h("CSeq"),
        extra,
    )
}

fn cseq_of(msg: &str) -> u32 {
    header(msg, "CSeq")
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|n| n.parse().ok())
        .expect("CSeq number")
}

const CHALLENGE: &str =
    "WWW-Authenticate: Digest realm=\"127.0.0.1\", nonce=\"abc\", algorithm=MD5\r\n";

#[tokio::test]
async fn probe_reports_the_challenge_and_register_continues_the_sequence() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let (seen_tx, seen_rx) = oneshot::channel::<Vec<String>>();

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut seen = Vec::new();

        // The probe: challenge it. It must not be answered.
        let query = read_message(&mut sock).await;
        let challenge = response_for(&query, "SIP/2.0 401 Unauthorized", CHALLENGE);
        sock.write_all(challenge.as_bytes()).await.expect("write");
        seen.push(query);

        // The real register(): challenge, then accept the signed retry.
        let first = read_message(&mut sock).await;
        let challenge = response_for(&first, "SIP/2.0 401 Unauthorized", CHALLENGE);
        sock.write_all(challenge.as_bytes()).await.expect("write");
        let signed = read_message(&mut sock).await;
        let ok = response_for(&signed, "SIP/2.0 200 OK", "Expires: 60\r\n");
        sock.write_all(ok.as_bytes()).await.expect("write");
        seen.push(first);
        seen.push(signed);

        let _ = seen_tx.send(seen);
        tokio::time::sleep(Duration::from_secs(3)).await;
    });

    let cancel = CancellationToken::new();
    let endpoint = SipEndpoint::new(&account(addr.port()), cancel.clone())
        .await
        .expect("binds a TCP endpoint");
    let registrar = Registrar::new(account(addr.port()), endpoint, cancel.clone(), 60, 50)
        .expect("builds a registrar");

    let probe = timeout(Duration::from_secs(5), registrar.probe())
        .await
        .expect("probe completes")
        .expect("probe runs");
    assert_eq!(probe, RegisterProbe::Answered { status: 401 });

    // The probe is not a sign-in attempt: diagnostics are untouched.
    let diag = registrar.diagnostics().await;
    assert_eq!(diag.register_count, 0);
    assert_eq!(diag.failure_count, 0);
    assert_eq!(diag.last_status, None);

    timeout(Duration::from_secs(5), registrar.register())
        .await
        .expect("register completes")
        .expect("register succeeds");

    let seen = timeout(Duration::from_secs(5), seen_rx)
        .await
        .expect("server saw every request")
        .expect("channel");
    let (query, first, signed) = (&seen[0], &seen[1], &seen[2]);

    assert!(header(query, "Contact").is_none(), "{query}");
    assert!(header(query, "Expires").is_none(), "{query}");
    assert!(header(query, "Authorization").is_none(), "{query}");
    assert!(header(signed, "Authorization").is_some(), "{signed}");

    // One Call-ID throughout, and every request a higher CSeq (§10.2).
    assert_eq!(header(query, "Call-ID"), header(first, "Call-ID"));
    assert_eq!(header(first, "Call-ID"), header(signed, "Call-ID"));
    assert!(cseq_of(query) < cseq_of(first), "{query}\n{first}");
    assert!(cseq_of(first) < cseq_of(signed), "{first}\n{signed}");

    cancel.cancel();
}

#[tokio::test]
async fn probe_reports_a_refusal_as_answered() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let query = read_message(&mut sock).await;
        let refuse = response_for(&query, "SIP/2.0 403 Forbidden", "");
        sock.write_all(refuse.as_bytes()).await.expect("write");
        tokio::time::sleep(Duration::from_secs(3)).await;
    });

    let cancel = CancellationToken::new();
    let endpoint = SipEndpoint::new(&account(addr.port()), cancel.clone())
        .await
        .expect("binds a TCP endpoint");
    let registrar = Registrar::new(account(addr.port()), endpoint, cancel.clone(), 60, 50)
        .expect("builds a registrar");

    let probe = timeout(Duration::from_secs(5), registrar.probe())
        .await
        .expect("probe completes")
        .expect("probe runs");
    assert_eq!(probe, RegisterProbe::Answered { status: 403 });
    cancel.cancel();
}
