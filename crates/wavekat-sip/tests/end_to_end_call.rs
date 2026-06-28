//! End-to-end exercise of the public call API over loopback, on the in-house
//! engine (no external SIP stack). One endpoint dials another; the callee
//! accepts with an SDP answer; the caller confirms the negotiated media and
//! hangs up with a BYE that the callee's router auto-answers.
//!
//! This is the integration counterpart to the in-crate `stack::ua` loopback
//! tests: it drives the *public* surface (`SipEndpoint` / `Caller` /
//! `IncomingCall` / `Call`) exactly as a consumer would.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use wavekat_sip::re_exports::Uri;
use wavekat_sip::{build_sdp, Caller, DtmfDigit, SipAccount, SipEndpoint, Transport};

fn account(server: &str, port: u16) -> SipAccount {
    SipAccount {
        display_name: "Test".into(),
        username: "1001".into(),
        password: "secret".into(),
        domain: "127.0.0.1".into(),
        auth_username: None,
        server: Some(server.into()),
        port: Some(port),
        transport: Transport::Udp,
    }
}

/// A raw INVITE carrying a real G.711 SDP offer, from `peer` to `callee`. Set
/// `with_contact` for tests that go on to `accept()` — `Dialog::uas` needs the
/// `Contact` to learn the remote target; omit it when the call only ever rings.
/// The `Call-ID` is derived from `branch` so the matching `raw_cancel` shares it.
fn raw_invite(callee: SocketAddr, peer: SocketAddr, branch: &str, with_contact: bool) -> Vec<u8> {
    let sdp = String::from_utf8(build_sdp("127.0.0.1".parse().unwrap(), 40000)).unwrap();
    let contact = if with_contact {
        format!("Contact: <sip:caller@{peer}>\r\n")
    } else {
        String::new()
    };
    format!(
        "INVITE sip:1001@{callee} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {peer};branch={branch}\r\n\
         From: <sip:caller@127.0.0.1>;tag=caller\r\n\
         To: <sip:1001@127.0.0.1>\r\n\
         Call-ID: {branch}-call\r\n\
         CSeq: 1 INVITE\r\n\
         Max-Forwards: 70\r\n\
         {contact}\
         Content-Type: application/sdp\r\n\
         Content-Length: {len}\r\n\r\n{sdp}",
        len = sdp.len(),
    )
    .into_bytes()
}

/// A raw CANCEL sharing `branch` (and thus `Call-ID`) with the INVITE it
/// cancels — the §9.1 correlation the endpoint relies on to 487 the right
/// transaction.
fn raw_cancel(callee: SocketAddr, peer: SocketAddr, branch: &str) -> Vec<u8> {
    format!(
        "CANCEL sip:1001@{callee} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {peer};branch={branch}\r\n\
         From: <sip:caller@127.0.0.1>;tag=caller\r\n\
         To: <sip:1001@127.0.0.1>\r\n\
         Call-ID: {branch}-call\r\n\
         CSeq: 1 CANCEL\r\n\
         Max-Forwards: 70\r\n\
         Content-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dial_accept_hangup_over_loopback() {
    let cancel = CancellationToken::new();

    // Callee: server field is unused (it never dials out), but it must point
    // somewhere routable so the endpoint can pick a source IP.
    let callee_account = account("127.0.0.1", 5060);
    let callee = SipEndpoint::new(&callee_account, cancel.clone())
        .await
        .expect("bind callee");
    let callee_port = callee.local_addr().port();

    // Caller: its resolved server is the callee's bound address.
    let caller_account = account("127.0.0.1", callee_port);
    let caller_ep = SipEndpoint::new(&caller_account, cancel.clone())
        .await
        .expect("bind caller");

    // Callee accept loop: answer the first inbound call, then hold the Call so
    // the dialog stays alive for the caller's BYE.
    let callee_for_task = callee.clone();
    let accepted = tokio::spawn(async move {
        let incoming = callee_for_task
            .next_incoming_call()
            .await
            .expect("inbound call arrives");
        // The caller offered RTP; we should have parsed its media.
        assert!(incoming.remote_media.port > 0);
        let call = incoming.accept().await.expect("accept inbound call");
        // Keep the Call alive until the test drops the JoinHandle's output.
        call
    });

    // Place the call.
    let caller = Caller::new(caller_account, caller_ep.clone());
    let target: Uri = "sip:1001@127.0.0.1".try_into().unwrap();

    let mut call = timeout(Duration::from_secs(10), caller.dial(target))
        .await
        .expect("dial completes within 10s")
        .expect("call is answered");

    // The caller negotiated real remote media from the SDP answer.
    assert!(call.remote_media.port > 0);
    assert_eq!(call.remote_media.payload_type, 0); // PCMU

    // RFC 4028: the caller advertised Supported: timer + Session-Expires, the
    // callee echoed it, so the caller negotiated a timer and (peer refresher
    // unset → us) takes the refresher role.
    let caller_timer = call
        .session_timer()
        .expect("caller negotiated a session timer");
    assert_eq!(caller_timer.interval_secs, 1800);
    assert!(caller_timer.we_are_refresher, "caller should refresh");

    // The callee side finished accepting.
    let callee_call = timeout(Duration::from_secs(10), accepted)
        .await
        .expect("accept finishes within 10s")
        .expect("accept task did not panic");

    // The callee negotiated the same interval but, as the answerer of a timer
    // the caller supports, is the watchdog (peer/UAC refreshes).
    let callee_timer = callee_call
        .session_timer()
        .expect("callee negotiated a session timer");
    assert_eq!(callee_timer.interval_secs, 1800);
    assert!(
        !callee_timer.we_are_refresher,
        "callee should watch, not refresh"
    );

    // DTMF over SIP INFO: the press is sent in-dialog and the callee's router
    // auto-answers 200 OK, which classifies as accepted.
    let outcome = timeout(
        Duration::from_secs(10),
        call.send_dtmf_info(DtmfDigit::D5, 160),
    )
    .await
    .expect("INFO completes within 10s");
    assert!(outcome.is_accepted(), "INFO DTMF accepted, got {outcome:?}");

    // Hold then resume: each is an in-dialog re-INVITE the callee's router
    // auto-answers 200, so the local hold state flips on success.
    timeout(Duration::from_secs(10), call.set_hold(true))
        .await
        .expect("hold re-INVITE completes within 10s")
        .expect("hold accepted");
    assert!(call.is_held(), "call should be on hold");
    timeout(Duration::from_secs(10), call.set_hold(false))
        .await
        .expect("resume re-INVITE completes within 10s")
        .expect("resume accepted");
    assert!(!call.is_held(), "call should be resumed");

    // Hang up: BYE is sent and the callee's router auto-answers 200.
    timeout(Duration::from_secs(10), call.hangup())
        .await
        .expect("hangup completes within 10s")
        .expect("BYE acknowledged");

    cancel.cancel();
}

/// When a `Call` opts in via `inbound_requests`, the endpoint stops
/// auto-answering that dialog's re-INVITE / INFO and surfaces them instead — so
/// the *only* way the peer gets a 200 is the consumer answering. This drives
/// the callee-initiated direction: the callee sends INFO + a hold re-INVITE,
/// the caller's stream receives both and answers them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn opted_in_call_receives_inbound_in_dialog_requests() {
    use std::sync::{Arc, Mutex};
    use wavekat_sip::re_exports::Method;

    let cancel = CancellationToken::new();

    let callee_account = account("127.0.0.1", 5060);
    let callee = SipEndpoint::new(&callee_account, cancel.clone())
        .await
        .expect("bind callee");
    let callee_port = callee.local_addr().port();

    let caller_account = account("127.0.0.1", callee_port);
    let caller_ep = SipEndpoint::new(&caller_account, cancel.clone())
        .await
        .expect("bind caller");

    let callee_for_task = callee.clone();
    let accepted = tokio::spawn(async move {
        let incoming = callee_for_task
            .next_incoming_call()
            .await
            .expect("inbound call arrives");
        incoming.accept().await.expect("accept inbound call")
    });

    let caller = Caller::new(caller_account, caller_ep.clone());
    let target: Uri = "sip:1001@127.0.0.1".try_into().unwrap();
    let call = timeout(Duration::from_secs(10), caller.dial(target))
        .await
        .expect("dial completes within 10s")
        .expect("call is answered");

    let mut callee_call = timeout(Duration::from_secs(10), accepted)
        .await
        .expect("accept finishes within 10s")
        .expect("accept task did not panic");

    // Caller opts in and answers every inbound in-dialog request, recording the
    // methods it saw.
    let mut inbound = call.inbound_requests();
    let seen = Arc::new(Mutex::new(Vec::<Method>::new()));
    let seen_in_task = seen.clone();
    let responder = tokio::spawn(async move {
        while let Some(req) = inbound.recv().await {
            seen_in_task.lock().unwrap().push(*req.method());
            req.ok().await;
        }
    });

    // Callee sends INFO to the caller; it must be answered by the responder.
    let outcome = timeout(
        Duration::from_secs(10),
        callee_call.send_dtmf_info(DtmfDigit::D7, 120),
    )
    .await
    .expect("INFO completes within 10s");
    assert!(outcome.is_accepted(), "surfaced INFO answered: {outcome:?}");

    // Callee holds the caller via a re-INVITE; the responder answers that too.
    timeout(Duration::from_secs(10), callee_call.set_hold(true))
        .await
        .expect("hold re-INVITE completes within 10s")
        .expect("surfaced re-INVITE answered");

    let methods = seen.lock().unwrap().clone();
    assert!(
        methods.contains(&Method::Info),
        "caller's stream saw the INFO: {methods:?}"
    );
    assert!(
        methods.contains(&Method::Invite),
        "caller's stream saw the re-INVITE: {methods:?}"
    );

    responder.abort();
    cancel.cancel();
}

/// A remote `BYE` on an established call fires the callee's
/// [`Call::terminated`](wavekat_sip::Call::terminated) signal — the endpoint
/// auto-answers the BYE `200 OK` and notifies the owning `Call` so a consumer
/// can tear down audio and finalize a recording.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn remote_bye_fires_call_terminated() {
    let cancel = CancellationToken::new();

    let callee_account = account("127.0.0.1", 5060);
    let callee = SipEndpoint::new(&callee_account, cancel.clone())
        .await
        .expect("bind callee");
    let callee_port = callee.local_addr().port();

    let caller_account = account("127.0.0.1", callee_port);
    let caller_ep = SipEndpoint::new(&caller_account, cancel.clone())
        .await
        .expect("bind caller");

    let callee_for_task = callee.clone();
    let accepted = tokio::spawn(async move {
        let incoming = callee_for_task
            .next_incoming_call()
            .await
            .expect("inbound call arrives");
        incoming.accept().await.expect("accept inbound call")
    });

    let caller = Caller::new(caller_account, caller_ep.clone());
    let target: Uri = "sip:1001@127.0.0.1".try_into().unwrap();
    let mut call = timeout(Duration::from_secs(10), caller.dial(target))
        .await
        .expect("dial completes within 10s")
        .expect("call is answered");

    let callee_call = timeout(Duration::from_secs(10), accepted)
        .await
        .expect("accept finishes within 10s")
        .expect("accept task did not panic");

    // Before the BYE, the callee's termination signal is unfired.
    let term = callee_call.terminated();
    assert!(!term.is_cancelled(), "termination must not fire before BYE");

    // Caller hangs up: the callee's router auto-answers the BYE and fires the
    // termination signal.
    timeout(Duration::from_secs(10), call.hangup())
        .await
        .expect("hangup completes within 10s")
        .expect("BYE acknowledged");

    timeout(Duration::from_secs(10), term.cancelled())
        .await
        .expect("callee learns of the remote BYE via terminated()");

    cancel.cancel();
}

/// A `CANCEL` for a still-ringing inbound INVITE fires
/// [`IncomingCall::cancelled`](wavekat_sip::IncomingCall::cancelled) and `487`s
/// the INVITE — otherwise the call would ring forever. Driven with a raw UDP
/// peer because the public `Caller` only emits a CANCEL after a provisional,
/// which the bare endpoint doesn't send.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_cancel_fires_incoming_cancelled_and_487s_the_invite() {
    let cancel = CancellationToken::new();

    let callee_account = account("127.0.0.1", 5060);
    let callee = SipEndpoint::new(&callee_account, cancel.clone())
        .await
        .expect("bind callee");
    let callee_addr: SocketAddr = format!("127.0.0.1:{}", callee.local_addr().port())
        .parse()
        .unwrap();

    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let branch = "z9hG4bK-cancel-it";

    // The INVITE carries a real G.711 SDP offer so the endpoint surfaces it.
    peer.send_to(
        &raw_invite(callee_addr, peer_addr, branch, false),
        callee_addr,
    )
    .await
    .unwrap();

    let incoming = timeout(Duration::from_secs(10), callee.next_incoming_call())
        .await
        .expect("inbound INVITE arrives within 10s")
        .expect("inbound call");
    let cancelled = incoming.cancelled();
    assert!(!cancelled.is_cancelled(), "must not be cancelled yet");

    // The caller hangs up while ringing: a CANCEL sharing the INVITE's branch.
    peer.send_to(&raw_cancel(callee_addr, peer_addr, branch), callee_addr)
        .await
        .unwrap();

    // The pending call surfaces the cancellation.
    timeout(Duration::from_secs(10), cancelled.cancelled())
        .await
        .expect("CANCEL surfaces via IncomingCall::cancelled()");
    // `incoming` is intentionally never accepted — the caller hung up.
    drop(incoming);

    // And the peer sees both a 200 (to the CANCEL) and a 487 (to the INVITE),
    // so the INVITE transaction is torn down rather than ringing forever.
    let mut saw_200 = false;
    let mut saw_487 = false;
    let mut buf = [0u8; 4096];
    while !(saw_200 && saw_487) {
        let (n, _) = match timeout(Duration::from_secs(5), peer.recv_from(&mut buf)).await {
            Ok(res) => res.unwrap(),
            Err(_) => break,
        };
        let text = String::from_utf8_lossy(&buf[..n]);
        let first_line = text.lines().next().unwrap_or_default();
        if first_line.contains("200") {
            saw_200 = true;
        }
        if first_line.contains("487") {
            saw_487 = true;
        }
    }
    assert!(saw_200, "peer should receive 200 OK to its CANCEL");
    assert!(
        saw_487,
        "peer should receive 487 Request Terminated for the INVITE"
    );

    cancel.cancel();
}

/// A `CANCEL` that races in *after* the INVITE was accepted must not `487` the
/// now-established call, nor fire `cancelled()`: `accept` unregisters the pending
/// INVITE, so the late CANCEL is answered `200` and otherwise ignored. Guards the
/// unregister-on-decision contract — without it, a straggling CANCEL would tear
/// down a call the user already answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_after_accept_does_not_487_the_established_call() {
    let cancel = CancellationToken::new();

    let callee_account = account("127.0.0.1", 5060);
    let callee = SipEndpoint::new(&callee_account, cancel.clone())
        .await
        .expect("bind callee");
    let callee_addr: SocketAddr = format!("127.0.0.1:{}", callee.local_addr().port())
        .parse()
        .unwrap();

    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let branch = "z9hG4bK-late-cancel";

    // Ring, then accept — the INVITE needs a Contact so the dialog can form.
    peer.send_to(
        &raw_invite(callee_addr, peer_addr, branch, true),
        callee_addr,
    )
    .await
    .unwrap();
    let incoming = timeout(Duration::from_secs(10), callee.next_incoming_call())
        .await
        .expect("inbound INVITE arrives within 10s")
        .expect("inbound call");
    let cancelled = incoming.cancelled();
    // Hold the Call so the dialog stays established for the duration.
    let _call = incoming.accept().await.expect("accept inbound call");

    // A CANCEL now races in on the same branch.
    peer.send_to(&raw_cancel(callee_addr, peer_addr, branch), callee_addr)
        .await
        .unwrap();

    // Drain responses until the wire goes quiet (there is no TU-side 2xx
    // retransmit, so this terminates). We expect the 200 OK to the INVITE and a
    // 200 to the CANCEL — and crucially never a 487.
    let mut saw_200 = false;
    let mut saw_487 = false;
    let mut buf = [0u8; 4096];
    while let Ok(Ok((n, _))) = timeout(Duration::from_millis(600), peer.recv_from(&mut buf)).await {
        let text = String::from_utf8_lossy(&buf[..n]);
        let first_line = text.lines().next().unwrap_or_default();
        if first_line.contains("200") {
            saw_200 = true;
        }
        if first_line.contains("487") {
            saw_487 = true;
        }
    }
    assert!(
        saw_200,
        "the CANCEL (and the INVITE) should be answered 200"
    );
    assert!(
        !saw_487,
        "a late CANCEL must not 487 an already-accepted call"
    );
    assert!(
        !cancelled.is_cancelled(),
        "cancelled() must not fire once the call has been accepted"
    );

    cancel.cancel();
}

/// A stray `CANCEL` with no INVITE behind it (late duplicate, or a peer bug) is
/// answered `200` and otherwise a no-op — it must not `487` anything or panic
/// the router. Guards the `None`-match arm of the §9.2 handling.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stray_cancel_is_answered_200_without_487() {
    let cancel = CancellationToken::new();

    let callee_account = account("127.0.0.1", 5060);
    let callee = SipEndpoint::new(&callee_account, cancel.clone())
        .await
        .expect("bind callee");
    let callee_addr: SocketAddr = format!("127.0.0.1:{}", callee.local_addr().port())
        .parse()
        .unwrap();

    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();

    // A CANCEL whose branch was never seen as an INVITE.
    peer.send_to(
        &raw_cancel(callee_addr, peer_addr, "z9hG4bK-orphan"),
        callee_addr,
    )
    .await
    .unwrap();

    // The first response is the 200 to the CANCEL.
    let mut buf = [0u8; 4096];
    let (n, _) = timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
        .await
        .expect("a response to the stray CANCEL")
        .unwrap();
    let first_line = String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    assert!(
        first_line.contains("200"),
        "stray CANCEL should be answered 200, got: {first_line}"
    );

    // Nothing else should follow — in particular no 487.
    if let Ok(Ok((n, _))) = timeout(Duration::from_millis(400), peer.recv_from(&mut buf)).await {
        let text = String::from_utf8_lossy(&buf[..n]);
        assert!(
            !text.contains("487"),
            "a stray CANCEL must not 487 anything: {text}"
        );
    }

    cancel.cancel();
}
