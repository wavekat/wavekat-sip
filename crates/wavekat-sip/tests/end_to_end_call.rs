//! End-to-end exercise of the public call API over loopback, on the in-house
//! engine (no external SIP stack). One endpoint dials another; the callee
//! accepts with an SDP answer; the caller confirms the negotiated media and
//! hangs up with a BYE that the callee's router auto-answers.
//!
//! This is the integration counterpart to the in-crate `stack::ua` loopback
//! tests: it drives the *public* surface (`SipEndpoint` / `Caller` /
//! `IncomingCall` / `Call`) exactly as a consumer would.

use std::time::Duration;

use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use wavekat_sip::re_exports::Uri;
use wavekat_sip::{Caller, DtmfDigit, SipAccount, SipEndpoint, Transport};

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

    // The callee side finished accepting.
    let _callee_call = timeout(Duration::from_secs(10), accepted)
        .await
        .expect("accept finishes within 10s")
        .expect("accept task did not panic");

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
