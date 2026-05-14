//! Integration tests for [`SipEndpoint::dispatch_in_dialog`].
//!
//! Two endpoints bind loopback UDP sockets and exchange real SIP
//! messages: Alice sends an INVITE, Bob accepts via [`Callee`], Alice
//! sends BYE. The test asserts that Bob's `dispatch_in_dialog` returns
//! [`DispatchOutcome::Handled`] and that the callee dialog's state
//! stream observes `Terminated(UacBye)`.
//!
//! These tests are *not* `#[ignore]`d: they use only loopback UDP, no
//! external SIP server, and complete in tens of milliseconds. They run
//! as part of `cargo test --workspace` in CI.

use std::sync::Arc;
use std::time::Duration;

use rsip::Method;
use rsipstack::dialog::invitation::InviteOption;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use wavekat_sip::re_exports::{DialogState, TerminatedReason};
use wavekat_sip::{build_sdp, Callee, DispatchOutcome, SipAccount, SipEndpoint, Transport};

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
async fn remote_bye_dispatches_to_dialog_and_terminates() {
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

    // Bob: accept the first INVITE, then route in-dialog requests
    // (BYE in this test) through dispatch_in_dialog.
    let (outcome_tx, mut outcome_rx) = mpsc::unbounded_channel::<DispatchOutcome>();
    let (state_tx, mut state_rx) = mpsc::unbounded_channel::<DialogState>();
    let callee = Callee::new(account("bob"), callee_ep.clone());
    let callee_ep_task = callee_ep.clone();
    tokio::spawn(async move {
        let mut accepted: Option<wavekat_sip::AcceptedCall> = None;
        while let Some(tx) = callee_rx.recv().await {
            if accepted.is_none() && tx.original.method == Method::Invite {
                let mut call = callee
                    .accept_transaction(tx)
                    .await
                    .expect("accept_transaction");
                let state_tx_inner = state_tx.clone();
                let mut srx = std::mem::replace(&mut call.state_rx, mpsc::unbounded_channel().1);
                tokio::spawn(async move {
                    while let Some(state) = srx.recv().await {
                        if state_tx_inner.send(state).is_err() {
                            break;
                        }
                    }
                });
                accepted = Some(call);
            } else {
                let outcome = callee_ep_task
                    .dispatch_in_dialog(tx)
                    .await
                    .expect("dispatch_in_dialog");
                let _ = outcome_tx.send(outcome);
            }
        }
    });

    // Drain Alice's incoming stream — the client INVITE/BYE transactions
    // are consumed internally by rsipstack, but unrelated inbounds would
    // otherwise back up the channel.
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

    let (caller_state_sender, _caller_state_rx) = caller_ep.dialog_layer.new_dialog_state_channel();
    let (client_dialog, resp) = timeout(
        Duration::from_secs(5),
        caller_ep.dialog_layer.do_invite(opt, caller_state_sender),
    )
    .await
    .expect("INVITE round-trip timed out")
    .expect("do_invite failed");

    let resp = resp.expect("expected a final response to INVITE");
    assert_eq!(
        resp.status_code.kind(),
        rsip::StatusCodeKind::Successful,
        "INVITE was not accepted: {}",
        resp.status_code
    );

    client_dialog.bye().await.expect("bye failed");

    let outcome = timeout(Duration::from_secs(5), outcome_rx.recv())
        .await
        .expect("no dispatch outcome within 5s")
        .expect("outcome channel closed");
    assert_eq!(outcome, DispatchOutcome::Handled);

    let saw_terminated = timeout(Duration::from_secs(5), async {
        loop {
            match state_rx.recv().await {
                Some(DialogState::Terminated(_, TerminatedReason::UacBye)) => return true,
                Some(_) => continue,
                None => return false,
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        saw_terminated,
        "expected Terminated(UacBye) on state stream"
    );

    callee_ep.shutdown();
    caller_ep.shutdown();
    cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dispatch_returns_no_dialog_for_unknown_call_id() {
    // Alice sends an INVITE to Bob, but Bob never accepts it via Callee
    // — instead, he hands every inbound transaction straight to
    // dispatch_in_dialog. Since no dialog is registered for the
    // INVITE's Call-ID, match_dialog returns None, and the dispatcher
    // should reply 481 and surface DispatchOutcome::NoDialog.
    //
    // (Yes, an INVITE is the initial dialog request — but
    // dispatch_in_dialog doesn't special-case it; it just runs
    // match_dialog. Using INVITE here keeps the test simple and
    // exercises the unmatched-tx → 481 → NoDialog path the helper
    // promises.)

    let cancel = CancellationToken::new();
    let (callee_ep, mut callee_rx) = SipEndpoint::new(&account("bob"), cancel.clone())
        .await
        .expect("bind callee endpoint");
    let (caller_ep, _caller_rx) = SipEndpoint::new(&account("alice"), cancel.clone())
        .await
        .expect("bind caller endpoint");
    let callee_ep = Arc::new(callee_ep);
    let caller_ep = Arc::new(caller_ep);

    let callee_addr = callee_ep.local_addr().expect("callee bound");
    let caller_addr = caller_ep.local_addr().expect("caller bound");

    let (outcome_tx, mut outcome_rx) = mpsc::unbounded_channel::<DispatchOutcome>();
    let callee_ep_task = callee_ep.clone();
    tokio::spawn(async move {
        while let Some(tx) = callee_rx.recv().await {
            let outcome = callee_ep_task
                .dispatch_in_dialog(tx)
                .await
                .expect("dispatch_in_dialog");
            let _ = outcome_tx.send(outcome);
        }
    });

    // Send an OPTIONS from Alice to Bob via rsipstack's invitation
    // helper — OPTIONS isn't part of any dialog Bob knows about, so
    // match_dialog will return None.
    let alice_contact: rsip::Uri = format!("sip:alice@{caller_addr}")
        .try_into()
        .expect("valid contact uri");
    let alice_from: rsip::Uri = format!("sip:alice@{caller_addr}")
        .try_into()
        .expect("valid from uri");
    let bob_to: rsip::Uri = format!("sip:bob@{callee_addr}")
        .try_into()
        .expect("valid to uri");

    // Re-use do_invite: it sends an INVITE for a dialog Bob has never
    // accepted. Bob's dispatcher gets the INVITE as an unmatched
    // transaction and replies 481. (do_invite will then surface the
    // 481 as the final response — we ignore the outcome here, we just
    // need Bob's `dispatch_in_dialog` to see an unmatched transaction.)
    let opt = InviteOption {
        caller: alice_from,
        callee: bob_to,
        destination: Some(callee_addr.into()),
        content_type: Some("application/sdp".into()),
        offer: Some(build_sdp(caller_ep.local_ip(), 30000)),
        contact: alice_contact,
        ..Default::default()
    };
    let (sender, _rx) = caller_ep.dialog_layer.new_dialog_state_channel();
    // do_invite will error out once Bob replies 481; we only care that
    // Bob's dispatcher returned NoDialog.
    let _ = timeout(
        Duration::from_secs(5),
        caller_ep.dialog_layer.do_invite(opt, sender),
    )
    .await;

    let outcome = timeout(Duration::from_secs(5), outcome_rx.recv())
        .await
        .expect("no dispatch outcome within 5s")
        .expect("outcome channel closed");
    assert_eq!(outcome, DispatchOutcome::NoDialog);

    callee_ep.shutdown();
    caller_ep.shutdown();
    cancel.cancel();
}
