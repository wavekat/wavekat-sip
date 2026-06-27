//! Integration tests for the outbound [`Caller`] surface.
//!
//! Pairs Alice ([`Caller`]) with Bob ([`Callee`]) on two loopback
//! endpoints and exercises:
//!
//! - **`caller_dial_confirms_with_remote_media`** — full dial → accept
//!   → on_confirmed → bye lifecycle. Asserts the [`AcceptedDial`]
//!   carries the negotiated SDP answer and that the BYE shows up as
//!   `Terminated(UasBye)` on Bob's state stream.
//! - **`caller_cancel_is_idempotent_after_terminated`** — Alice dials,
//!   never gets answered, CANCELs. Calling `cancel()` again after the
//!   dialog has terminated must return `Ok(())` without resending.

use std::sync::Arc;
use std::time::Duration;

use rsip::Method;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use wavekat_sip::re_exports::{DialogState, SipAddr, TerminatedReason};
use wavekat_sip::{Callee, Caller, PendingCall, SipAccount, SipEndpoint, Transport};

fn account(name: &str) -> SipAccount {
    SipAccount {
        display_name: name.to_string(),
        username: name.to_string(),
        password: "secret".to_string(),
        domain: "127.0.0.1".to_string(),
        auth_username: None,
        server: Some("127.0.0.1".to_string()),
        port: Some(5060),
        transport: Transport::Udp,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn caller_dial_confirms_with_remote_media() {
    let cancel = CancellationToken::new();

    let (callee_ep, mut callee_rx) = SipEndpoint::new(&account("bob"), cancel.clone())
        .await
        .expect("bind callee endpoint");
    let (caller_ep, mut caller_rx) = SipEndpoint::new(&account("alice"), cancel.clone())
        .await
        .expect("bind caller endpoint");
    let callee_ep = Arc::new(callee_ep);
    let caller_ep = Arc::new(caller_ep);

    let callee_addr = callee_ep.local_addr().expect("callee bound");
    let bob_local_ip = callee_ep.local_ip();

    // Bob: take the INVITE, accept it with an SDP answer. Forward his
    // dialog state to a channel so the test can assert UasBye after
    // Alice hangs up.
    let (bob_state_tx, mut bob_state_rx) = mpsc::unbounded_channel::<DialogState>();
    let callee = Callee::new(account("bob"), callee_ep.clone());
    let bob_ep_for_dispatch = callee_ep.clone();
    tokio::spawn(async move {
        let mut accepted_hold = None;
        while let Some(tx) = callee_rx.recv().await {
            match tx.original.method {
                Method::Invite if accepted_hold.is_none() => {
                    let pending: PendingCall =
                        callee.handle_pending(tx).await.expect("handle_pending");
                    let mut accepted = pending.accept().await.expect("Bob accept");
                    let mut srx =
                        std::mem::replace(&mut accepted.state_rx, mpsc::unbounded_channel().1);
                    let forward_tx = bob_state_tx.clone();
                    tokio::spawn(async move {
                        while let Some(state) = srx.recv().await {
                            if forward_tx.send(state).is_err() {
                                break;
                            }
                        }
                    });
                    accepted_hold = Some(accepted);
                }
                _ => {
                    // In-dialog BYE etc. — dispatch so Bob's dialog state
                    // machine advances.
                    let _ = bob_ep_for_dispatch.dispatch_in_dialog(tx).await;
                }
            }
        }
        drop(accepted_hold);
    });

    // Drain Alice's incoming side.
    tokio::spawn(async move { while caller_rx.recv().await.is_some() {} });

    let caller = Caller::new(account("alice"), caller_ep.clone());
    let target: rsip::Uri = format!("sip:bob@{callee_addr}")
        .try_into()
        .expect("valid target");
    let destination: SipAddr = callee_addr.into();
    let pending = caller
        .dial_with_destination(target, Some(destination))
        .await
        .expect("dial");

    let accepted = timeout(Duration::from_secs(5), pending.on_confirmed())
        .await
        .expect("on_confirmed didn't resolve within 5s")
        .expect("on_confirmed failed");

    // Bob's PendingCall::accept built an SDP answer with Bob's local
    // IP. Alice should have parsed that.
    assert_eq!(
        accepted.remote_media.addr, bob_local_ip,
        "remote_media.addr should be Bob's local IP from the SDP answer"
    );
    assert_eq!(
        accepted.remote_media.payload_type, 0,
        "expected PCMU as the preferred payload type"
    );
    assert_ne!(
        accepted.remote_media.port, 0,
        "remote_media.port should be Bob's bound RTP port"
    );
    assert_ne!(
        accepted.local_rtp_addr.port(),
        0,
        "local_rtp_addr should be bound"
    );
    // Regression: the advertised RTP address must be Alice's real local IP,
    // not the `0.0.0.0` wildcard the socket binds to. Hold/resume re-offers
    // reuse this address, and `c=0.0.0.0` is the legacy RFC 2543 hold signal
    // — a peer reading it stops sending media even on a `sendrecv` resume.
    assert_eq!(
        accepted.local_rtp_addr.ip(),
        caller_ep.local_ip(),
        "local_rtp_addr must advertise the real local IP, not 0.0.0.0"
    );

    // Alice (UAC) hangs up. The BYE comes from the UAC, so both sides
    // see Terminated(UacBye). (Symmetry with UacCancel in
    // pending_call_cancel.rs — the variant names the originator.)
    accepted.dialog.bye().await.expect("alice BYE");

    let saw_bye = timeout(Duration::from_secs(5), async {
        loop {
            match bob_state_rx.recv().await {
                Some(DialogState::Terminated(_, TerminatedReason::UacBye)) => return true,
                Some(_) => continue,
                None => return false,
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(saw_bye, "Bob should see Terminated(UacBye) after Alice BYE");

    callee_ep.shutdown();
    caller_ep.shutdown();
    cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn caller_cancel_is_idempotent_after_terminated() {
    let cancel = CancellationToken::new();

    let (callee_ep, mut callee_rx) = SipEndpoint::new(&account("bob"), cancel.clone())
        .await
        .expect("bind callee endpoint");
    let (caller_ep, mut caller_rx) = SipEndpoint::new(&account("alice"), cancel.clone())
        .await
        .expect("bind caller endpoint");
    let callee_ep = Arc::new(callee_ep);
    let caller_ep = Arc::new(caller_ep);

    let callee_addr = callee_ep.local_addr().expect("callee bound");

    // Bob holds the PendingCall without ever calling accept/reject;
    // signal back as soon as he's on the wire so we don't race the
    // CANCEL against the INVITE handler.
    let (pending_ready_tx, pending_ready_rx) = oneshot::channel::<()>();
    let callee = Callee::new(account("bob"), callee_ep.clone());
    tokio::spawn(async move {
        let mut pending_ready_tx = Some(pending_ready_tx);
        let mut hold: Option<PendingCall> = None;
        while let Some(tx) = callee_rx.recv().await {
            if hold.is_none() && tx.original.method == Method::Invite {
                hold = Some(callee.handle_pending(tx).await.expect("handle_pending"));
                if let Some(tx) = pending_ready_tx.take() {
                    let _ = tx.send(());
                }
            }
        }
        drop(hold);
    });

    tokio::spawn(async move { while caller_rx.recv().await.is_some() {} });

    let caller = Caller::new(account("alice"), caller_ep.clone());
    let target: rsip::Uri = format!("sip:bob@{callee_addr}")
        .try_into()
        .expect("valid target");
    let destination: SipAddr = callee_addr.into();
    let mut pending = caller
        .dial_with_destination(target, Some(destination))
        .await
        .expect("dial");

    timeout(Duration::from_secs(5), pending_ready_rx)
        .await
        .expect("Bob never reached handle_pending")
        .expect("pending_ready dropped");

    // First cancel: actually sends CANCEL.
    pending.cancel().await.expect("first cancel");

    // Wait for Alice's dialog to enter Terminated so we exercise the
    // "settled dialog" branch on the second call.
    let saw_terminated = timeout(Duration::from_secs(5), async {
        loop {
            match pending.state_rx.recv().await {
                Some(DialogState::Terminated(_, _)) => return true,
                Some(_) => continue,
                None => return false,
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        saw_terminated,
        "Alice's dialog should reach Terminated after CANCEL"
    );

    // Second cancel after Terminated must be a silent no-op, not an
    // error. This is the contract the consumer relies on when the user
    // mashes the End button or two code paths both try to cancel.
    pending
        .cancel()
        .await
        .expect("second cancel after Terminated should be Ok");

    callee_ep.shutdown();
    caller_ep.shutdown();
    cancel.cancel();
}
