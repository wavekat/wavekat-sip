//! Integration tests for RFC 4028 session timers over loopback.
//!
//! - **`session_timer_negotiates_and_refreshes_over_loopback`** — full
//!   negotiation round-trip plus one real refresh re-INVITE: Alice's
//!   INVITE advertises `Supported: timer` + `Session-Expires`, Bob
//!   ([`Callee`]) negotiates and echoes in his 200 OK, Alice parses the
//!   grant from the 2xx. Alice then sends a refresh re-INVITE through
//!   the [`SessionDialogOps`] impl; Bob answers it via the
//!   [`TransactionHandle`] carried in `DialogState::Updated` — the
//!   exact wiring the `session_timer` module docs prescribe. Loopback
//!   UDP only, completes in milliseconds, not `#[ignore]`d.
//! - **`watchdog_tears_down_lapsed_session`** — `#[ignore]`d (~60 s of
//!   wall clock): a confirmed call whose peer never refreshes; the
//!   watchdog half of [`session_timer_loop`] must BYE the dialog at
//!   `interval - min(32, interval/3)` and the remote must observe
//!   `Terminated(UacBye)`.

use std::sync::Arc;
use std::time::Duration;

use rsip::prelude::HasHeaders;
use rsip::Method;
use tokio::sync::{mpsc, Notify};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use wavekat_sip::re_exports::{DialogState, SipAddr, StatusCode, TerminatedReason};
use wavekat_sip::{
    build_sdp, session_expires_in, session_timer_loop, supported_timer_header, supports_timer,
    Callee, Caller, Refresher, SessionDialogOps, SessionExpires, SessionTimer, SessionTimerOutcome,
    SipAccount, SipEndpoint, Transport, UasSessionTimer, DEFAULT_SESSION_EXPIRES_SECS,
};

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
async fn session_timer_negotiates_and_refreshes_over_loopback() {
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

    // Bob: accept the INVITE, report his negotiated UasSessionTimer,
    // and answer any refresh re-INVITE through the TransactionHandle —
    // reporting the refresh request's Session-Expires back to the test.
    let (bob_timer_tx, mut bob_timer_rx) = mpsc::unbounded_channel::<Option<UasSessionTimer>>();
    let (bob_refresh_tx, mut bob_refresh_rx) = mpsc::unbounded_channel::<Option<SessionExpires>>();
    let (bob_term_tx, mut bob_term_rx) = mpsc::unbounded_channel::<TerminatedReason>();
    let callee = Callee::new(account("bob"), callee_ep.clone());
    let bob_ep_for_dispatch = callee_ep.clone();
    tokio::spawn(async move {
        let mut accepted_hold = None;
        while let Some(tx) = callee_rx.recv().await {
            match tx.original.method {
                Method::Invite if accepted_hold.is_none() => {
                    let pending = callee.handle_pending(tx).await.expect("handle_pending");
                    let _ = bob_timer_tx.send(pending.session_timer);
                    let uas = pending.session_timer;
                    let mut accepted = pending.accept().await.expect("Bob accept");
                    let answer = build_sdp(bob_local_ip, accepted.local_rtp_addr.port());
                    let mut srx =
                        std::mem::replace(&mut accepted.state_rx, mpsc::unbounded_channel().1);
                    let refresh_tx = bob_refresh_tx.clone();
                    let term_tx = bob_term_tx.clone();
                    tokio::spawn(async move {
                        while let Some(state) = srx.recv().await {
                            match state {
                                DialogState::Updated(_, request, handle) => {
                                    // The module-doc wiring: echo the
                                    // negotiated Session-Expires in the
                                    // 200 to the peer's refresh.
                                    let echo = uas.expect("timer was negotiated").echo;
                                    handle
                                        .respond(
                                            StatusCode::OK,
                                            Some(vec![
                                                rsip::Header::ContentType("application/sdp".into()),
                                                supported_timer_header(),
                                                echo.header(),
                                            ]),
                                            Some(answer.clone()),
                                        )
                                        .await
                                        .expect("respond to refresh");
                                    let _ = refresh_tx.send(session_expires_in(request.headers()));
                                }
                                DialogState::Terminated(_, reason) => {
                                    let _ = term_tx.send(reason);
                                }
                                _ => {}
                            }
                        }
                    });
                    accepted_hold = Some(accepted);
                }
                _ => {
                    // Refresh re-INVITE / BYE — route to the dialog so
                    // its state machine advances.
                    let _ = bob_ep_for_dispatch.dispatch_in_dialog(tx).await;
                }
            }
        }
        drop(accepted_hold);
    });

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

    // Bob (UAS) saw Alice's Supported: timer + Session-Expires and
    // assigned the refresher role to her (the UAC).
    let bob_timer = timeout(Duration::from_secs(5), bob_timer_rx.recv())
        .await
        .expect("Bob never reported his session timer")
        .expect("channel closed")
        .expect("Bob should have negotiated a session timer");
    assert_eq!(bob_timer.timer.interval_secs, DEFAULT_SESSION_EXPIRES_SECS);
    assert!(
        !bob_timer.timer.we_are_refresher,
        "Bob (UAS) should rely on Alice to refresh"
    );
    assert_eq!(bob_timer.echo.refresher, Some(Refresher::Uac));
    assert!(bob_timer.require_timer);

    // Alice (UAC) parsed Bob's echo from the 2xx.
    assert_eq!(
        accepted.session_timer,
        Some(SessionTimer {
            interval_secs: DEFAULT_SESSION_EXPIRES_SECS,
            we_are_refresher: true,
        }),
        "Alice should know she is the refresher for the granted interval"
    );

    // One real refresh re-INVITE through the SessionDialogOps impl —
    // exactly what session_timer_loop sends on its tick.
    let refresh_headers = vec![
        supported_timer_header(),
        SessionExpires {
            interval_secs: DEFAULT_SESSION_EXPIRES_SECS,
            refresher: Some(Refresher::Uac),
        }
        .header(),
    ];
    let offer = build_sdp(caller_ep.local_ip(), accepted.local_rtp_addr.port());
    let resp = timeout(
        Duration::from_secs(5),
        accepted.dialog.refresh(refresh_headers, Some(offer)),
    )
    .await
    .expect("refresh timed out")
    .expect("refresh failed")
    .expect("dialog should still be confirmed");
    assert_eq!(
        resp.status_code.kind(),
        rsip::StatusCodeKind::Successful,
        "refresh re-INVITE should get a 2xx, got {}",
        resp.status_code
    );
    assert_eq!(
        session_expires_in(&resp.headers),
        Some(bob_timer.echo),
        "Bob's 200 to the refresh should echo the negotiated Session-Expires"
    );

    // Bob's state pump saw the refresh as DialogState::Updated and the
    // request carried the session-timer headers.
    let seen = timeout(Duration::from_secs(5), bob_refresh_rx.recv())
        .await
        .expect("Bob never observed the refresh re-INVITE")
        .expect("channel closed");
    assert_eq!(
        seen,
        Some(SessionExpires {
            interval_secs: DEFAULT_SESSION_EXPIRES_SECS,
            refresher: Some(Refresher::Uac),
        })
    );

    // Tear down normally.
    accepted.dialog.bye().await.expect("alice BYE");
    let reason = timeout(Duration::from_secs(5), bob_term_rx.recv())
        .await
        .expect("Bob never saw termination")
        .expect("channel closed");
    assert!(
        matches!(reason, TerminatedReason::UacBye),
        "expected Terminated(UacBye), got {reason:?}"
    );

    callee_ep.shutdown();
    caller_ep.shutdown();
    cancel.cancel();
}

/// Sanity check that Alice's initial INVITE really carries the
/// session-timer headers on the wire (not just in the InviteOption):
/// Bob inspects the raw request before answering.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbound_invite_carries_session_timer_headers() {
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

    let (invite_tx, mut invite_rx) = mpsc::unbounded_channel::<(bool, Option<SessionExpires>)>();
    tokio::spawn(async move {
        while let Some(tx) = callee_rx.recv().await {
            if tx.original.method == Method::Invite {
                let headers = tx.original.headers();
                let _ = invite_tx.send((supports_timer(headers), session_expires_in(headers)));
                // Leave the INVITE unanswered; the test only inspects it.
            }
        }
    });
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

    let (timer_supported, session_expires) = timeout(Duration::from_secs(5), invite_rx.recv())
        .await
        .expect("Bob never received the INVITE")
        .expect("channel closed");
    assert!(timer_supported, "INVITE must carry Supported: timer");
    assert_eq!(
        session_expires,
        Some(SessionExpires {
            interval_secs: DEFAULT_SESSION_EXPIRES_SECS,
            refresher: None,
        }),
        "INVITE must request the default interval, refresher unpinned"
    );

    pending.cancel().await.ok();
    callee_ep.shutdown();
    caller_ep.shutdown();
    cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "watchdog expiry needs ~60s of wall clock (90s interval minus 30s headroom)"]
async fn watchdog_tears_down_lapsed_session() {
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

    // Bob accepts and then never refreshes — the dead-peer scenario.
    let (bob_term_tx, mut bob_term_rx) = mpsc::unbounded_channel::<TerminatedReason>();
    let callee = Callee::new(account("bob"), callee_ep.clone());
    let bob_ep_for_dispatch = callee_ep.clone();
    tokio::spawn(async move {
        let mut accepted_hold = None;
        while let Some(tx) = callee_rx.recv().await {
            match tx.original.method {
                Method::Invite if accepted_hold.is_none() => {
                    let mut accepted = callee
                        .accept_transaction(tx)
                        .await
                        .expect("accept_transaction");
                    let mut srx =
                        std::mem::replace(&mut accepted.state_rx, mpsc::unbounded_channel().1);
                    let term_tx = bob_term_tx.clone();
                    tokio::spawn(async move {
                        while let Some(state) = srx.recv().await {
                            if let DialogState::Terminated(_, reason) = state {
                                let _ = term_tx.send(reason);
                            }
                        }
                    });
                    accepted_hold = Some(accepted);
                }
                _ => {
                    let _ = bob_ep_for_dispatch.dispatch_in_dialog(tx).await;
                }
            }
        }
        drop(accepted_hold);
    });
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

    // Pretend the negotiation put the refresh burden on Bob (who will
    // never deliver): Alice runs the watchdog half with the minimum
    // 90s interval → BYE at 90 - min(32, 30) = 60s.
    let watchdog = SessionTimer {
        interval_secs: 90,
        we_are_refresher: false,
    };
    let outcome = timeout(
        Duration::from_secs(80),
        session_timer_loop(
            &accepted.dialog,
            watchdog,
            None,
            Arc::new(Notify::new()),
            cancel.clone(),
        ),
    )
    .await
    .expect("watchdog never fired");
    assert_eq!(outcome, SessionTimerOutcome::Expired);

    let reason = timeout(Duration::from_secs(5), bob_term_rx.recv())
        .await
        .expect("Bob never saw the watchdog BYE")
        .expect("channel closed");
    assert!(
        matches!(reason, TerminatedReason::UacBye),
        "expected Terminated(UacBye) from the watchdog BYE, got {reason:?}"
    );

    callee_ep.shutdown();
    caller_ep.shutdown();
    cancel.cancel();
}
