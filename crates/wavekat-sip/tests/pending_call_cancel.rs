//! Integration test for [`Callee::handle_pending`] + pre-answer CANCEL.
//!
//! Alice INVITEs Bob; Bob calls `handle_pending` and waits without
//! accepting; Alice immediately CANCELs the INVITE. The test asserts:
//!
//! - Bob's `state_rx` observes `Terminated(UacCancel)` (so a UI watcher
//!   can dismiss the ringing indicator).
//! - Alice's `do_invite` resolves with a `487 Request Terminated` final
//!   response (the canonical CANCEL outcome).
//!
//! This covers the regression where wavekat-voice's pending invite map
//! had no path to surface a pre-answer cancel — the INVITE just sat
//! there until the caller's own timeout, and the UI stayed ringing.

use std::sync::Arc;
use std::time::Duration;

use rsip::Method;
use rsipstack::dialog::invitation::InviteOption;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use wavekat_sip::re_exports::{DialogState, TerminatedReason};
use wavekat_sip::{build_sdp, Callee, PendingCall, SipAccount, SipEndpoint, Transport};

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
async fn pre_answer_cancel_terminates_pending_call() {
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
    let caller_addr = caller_ep.local_addr().expect("caller bound");

    // Bob: receive the INVITE, call handle_pending, surface the resulting
    // state_rx so the test can assert Terminated(UacCancel). Hold the
    // PendingCall until the CANCEL arrives — never call accept / reject.
    let (state_tx, mut state_rx) = mpsc::unbounded_channel::<DialogState>();
    let (pending_ready_tx, pending_ready_rx) = oneshot::channel::<()>();
    let callee = Callee::new(account("bob"), callee_ep.clone());
    tokio::spawn(async move {
        let mut pending_ready_tx = Some(pending_ready_tx);
        let mut hold: Option<PendingCall> = None;
        while let Some(tx) = callee_rx.recv().await {
            if hold.is_none() && tx.original.method == Method::Invite {
                let mut call = callee.handle_pending(tx).await.expect("handle_pending");
                let state_tx_inner = state_tx.clone();
                let mut srx = std::mem::replace(&mut call.state_rx, mpsc::unbounded_channel().1);
                tokio::spawn(async move {
                    while let Some(state) = srx.recv().await {
                        if state_tx_inner.send(state).is_err() {
                            break;
                        }
                    }
                });
                hold = Some(call);
                if let Some(tx) = pending_ready_tx.take() {
                    let _ = tx.send(());
                }
            }
            // Anything else is uninteresting for this test.
        }
        drop(hold);
    });

    // Alice doesn't care about her inbound stream — drain it.
    tokio::spawn(async move { while caller_rx.recv().await.is_some() {} });

    let local_ip = caller_ep.local_ip();
    let alice_contact: rsip::Uri = format!("sip:alice@{caller_addr}")
        .try_into()
        .expect("valid contact uri");
    let alice_from: rsip::Uri = format!("sip:alice@{caller_addr}")
        .try_into()
        .expect("valid from uri");
    let bob_to: rsip::Uri = format!("sip:bob@{callee_addr}")
        .try_into()
        .expect("valid to uri");

    let opt = InviteOption {
        caller: alice_from,
        callee: bob_to,
        destination: Some(callee_addr.into()),
        content_type: Some("application/sdp".into()),
        offer: Some(build_sdp(local_ip, 30000)),
        contact: alice_contact,
        ..Default::default()
    };

    // Watch Alice's dialog state stream to learn the Call-ID once the
    // client dialog is created; then we can look up the ClientInviteDialog
    // out of the dialog_layer and call `.cancel()`.
    let (caller_state_sender, mut caller_state_rx) =
        caller_ep.dialog_layer.new_dialog_state_channel();

    // Fire the INVITE in the background — it will sit unanswered until
    // we send CANCEL, at which point it should resolve with 487.
    let caller_ep_invite = caller_ep.clone();
    let invite_task = tokio::spawn(async move {
        caller_ep_invite
            .dialog_layer
            .do_invite(opt, caller_state_sender)
            .await
    });

    // Find Alice's client dialog by waiting for the first Calling state.
    let call_id = timeout(Duration::from_secs(5), async {
        loop {
            match caller_state_rx.recv().await {
                Some(DialogState::Calling(id)) => return Some(id.call_id),
                Some(_) => continue,
                None => return None,
            }
        }
    })
    .await
    .expect("no Calling state within 5s")
    .expect("caller state channel closed");

    // Bob must have his PendingCall set up before we CANCEL — otherwise
    // the CANCEL races the INVITE on his side. Both arrive in order on
    // a single UDP socket, but `handle_pending` is async; this oneshot
    // makes the ordering explicit.
    timeout(Duration::from_secs(5), pending_ready_rx)
        .await
        .expect("Bob never reached handle_pending within 5s")
        .expect("pending_ready channel dropped");

    let client_dialogs = caller_ep
        .dialog_layer
        .get_client_dialog_by_call_id(&call_id);
    let client_dialog = client_dialogs
        .into_iter()
        .next()
        .expect("client dialog should exist after Calling");
    client_dialog.cancel().await.expect("client cancel failed");

    // Bob should see Terminated(UacCancel).
    let saw_cancel = timeout(Duration::from_secs(5), async {
        loop {
            match state_rx.recv().await {
                Some(DialogState::Terminated(_, TerminatedReason::UacCancel)) => return true,
                Some(_) => continue,
                None => return false,
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        saw_cancel,
        "expected Terminated(UacCancel) on callee state stream"
    );

    // Alice's INVITE resolves with 487.
    let (_dialog, resp) = timeout(Duration::from_secs(5), invite_task)
        .await
        .expect("INVITE task didn't finish within 5s")
        .expect("INVITE task panicked")
        .expect("do_invite failed");
    let resp = resp.expect("expected a final response to the cancelled INVITE");
    assert_eq!(
        u16::from(resp.status_code.clone()),
        487,
        "expected 487 Request Terminated, got {}",
        resp.status_code
    );

    callee_ep.shutdown();
    caller_ep.shutdown();
    cancel.cancel();
}
