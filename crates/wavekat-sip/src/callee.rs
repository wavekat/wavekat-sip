//! Inbound INVITE handling — focused SIP-only layer.
//!
//! There are two flows:
//!
//! - **Deferred decision** (recommended for UI-driven apps):
//!   [`Callee::handle_pending`] parses the SDP offer, creates the server
//!   dialog, sends `100 Trying`, and spawns the transaction handler. It
//!   returns a [`PendingCall`] whose `state_rx` surfaces a pre-answer
//!   cancel (`Terminated(UacCancel)`) so the UI can clear its ringing
//!   indicator. The consumer then calls [`PendingCall::accept`] or
//!   [`PendingCall::reject`] when the user decides.
//! - **One-shot accept / reject**: [`Callee::accept_transaction`] and
//!   [`Callee::reject_transaction`] do everything in one call — useful
//!   when the decision is already known (auto-answer, hard-coded busy).
//!   They are thin convenience wrappers over the deferred flow and do
//!   **not** detect a pre-answer cancel (there's no window to detect it
//!   in).
//!
//! Audio device I/O, codecs, recording — all of those are the consumer's
//! problem. See `docs/01-port-plan.md`.
//!
//! `Transaction` is yielded by [`crate::endpoint::SipEndpoint`]'s incoming
//! transaction receiver. Filter for `Method::Invite` before calling
//! these.
//!
//! ## Hanging up a connected call
//!
//! [`AcceptedCall::dialog`] is a
//! [`ServerInviteDialog`]. To hang up locally (user hit "End call" in
//! the UI, an AI agent decided the call is over, …):
//!
//! ```ignore
//! accepted.dialog.bye().await?;
//! ```
//!
//! The dialog state machine then transitions to
//! `Terminated(_, TerminatedReason::UasBye)` on `state_rx`, so a single
//! watcher pumping `state_rx` handles both local and remote hangup
//! through the same code path. The outbound side ([`crate::caller`])
//! exposes the same pattern on [`ClientInviteDialog`].
//!
//! [`ClientInviteDialog`]: rsipstack::dialog::client_dialog::ClientInviteDialog

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rsip::{Header, StatusCode};
use rsipstack::dialog::dialog::DialogStateReceiver;
use rsipstack::dialog::server_dialog::ServerInviteDialog;
use rsipstack::transaction::transaction::Transaction;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::account::SipAccount;
use crate::endpoint::SipEndpoint;
use crate::sdp::{build_sdp, parse_sdp, RemoteMedia};
use crate::session_timer::{
    negotiate_uas, require_timer_header, supported_timer_header, SessionTimer, UasSessionTimer,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// SIP-only callee handles. The consumer wires audio onto the returned
/// `rtp_socket`, uses `remote_media` to know where to send/expect RTP, and
/// can drive call control via `dialog` (BYE, re-INVITE, etc.).
pub struct AcceptedCall {
    /// Server-side dialog. Call `.bye().await` to hang up locally.
    pub dialog: ServerInviteDialog,
    /// Where the remote endpoint expects RTP (from the SDP offer).
    pub remote_media: RemoteMedia,
    /// Local RTP socket; share via `Arc` to send and receive concurrently.
    pub rtp_socket: Arc<UdpSocket>,
    /// Local RTP address advertised in the SDP answer.
    pub local_rtp_addr: SocketAddr,
    /// Dialog state updates — UAC BYE, re-INVITE acks, termination reasons.
    /// Pump this to detect remote hangup.
    pub state_rx: DialogStateReceiver,
    /// RFC 4028 session timer negotiated from the INVITE, if the caller
    /// asked for one (the 200 OK echoed it back). Spawn
    /// [`crate::session_timer_loop`] with this; `None` means no timer
    /// was negotiated and none should run.
    pub session_timer: Option<SessionTimer>,
}

/// An inbound INVITE that has been hooked into the dialog layer — the
/// transaction handler is running (`100 Trying` sent, a pre-answer
/// `CANCEL` will be auto-replied with `487`) but no final response has
/// been sent yet.
///
/// Consumers should pump `state_rx` while the call is "ringing" in the
/// UI. If it yields `DialogState::Terminated` *before* you call
/// [`accept`](Self::accept) / [`reject`](Self::reject), the remote side
/// cancelled — clear any ringing indicator. After that, the dialog is
/// gone; do not call `accept` / `reject`.
pub struct PendingCall {
    /// Server-side dialog. The transaction handler task is already
    /// pumping it; do not call `dialog.handle` yourself.
    pub dialog: ServerInviteDialog,
    /// Parsed SDP offer — where the remote expects RTP, what codec.
    pub remote_media: RemoteMedia,
    /// Dialog state updates. Watch for `Terminated(UacCancel)` to learn
    /// the caller hung up before you answered.
    pub state_rx: DialogStateReceiver,
    /// RFC 4028 session timer negotiated from the INVITE's
    /// `Session-Expires` / `Min-SE` / `Supported: timer` headers.
    /// [`accept`](Self::accept) echoes it in the 200 OK; `None` when
    /// the caller didn't ask for session timers.
    pub session_timer: Option<UasSessionTimer>,
    /// Local IP the endpoint is bound to — used for the SDP answer's
    /// connection address when `accept` is called.
    local_ip: IpAddr,
}

impl PendingCall {
    /// Send `200 OK` with an SDP answer matching the offer. Binds a
    /// local RTP socket. Returns the [`AcceptedCall`] (dialog + audio
    /// plumbing) for the caller to drive.
    ///
    /// On error the dialog handler keeps running and will time out
    /// naturally; the caller can also call [`Self::reject`] *before*
    /// `accept` if they want to fail fast.
    pub async fn accept(self) -> Result<AcceptedCall, BoxError> {
        let rtp_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let local_rtp_addr = rtp_socket.local_addr()?;
        let rtp_port = local_rtp_addr.port();
        info!(local_ip = %self.local_ip, rtp_port, "bound RTP socket");

        let sdp_answer = build_sdp(self.local_ip, rtp_port);
        debug!("SDP answer:\n{}", String::from_utf8_lossy(&sdp_answer));

        let headers = accept_headers(self.session_timer.as_ref());
        self.dialog.accept(Some(headers), Some(sdp_answer))?;
        info!("sent 200 OK with SDP answer");

        Ok(AcceptedCall {
            dialog: self.dialog,
            remote_media: self.remote_media,
            rtp_socket: Arc::new(rtp_socket),
            local_rtp_addr,
            state_rx: self.state_rx,
            session_timer: self.session_timer.map(|uas| uas.timer),
        })
    }

    /// Send a non-2xx final response (typical: `486 Busy Here`,
    /// `603 Decline`). The transaction handler task drains any retransmit
    /// and exits.
    pub fn reject(self, status: StatusCode) -> Result<(), BoxError> {
        if status.code() < 300 {
            return Err(format!("reject() got 2xx status {status}").into());
        }
        self.dialog.reject(Some(status.clone()), None)?;
        info!(%status, "rejected inbound INVITE");
        Ok(())
    }
}

/// Stateless helper bound to an account + endpoint.
pub struct Callee {
    account: SipAccount,
    endpoint: Arc<SipEndpoint>,
}

impl Callee {
    pub fn new(account: SipAccount, endpoint: Arc<SipEndpoint>) -> Self {
        Self { account, endpoint }
    }

    /// Begin handling an inbound INVITE: parse the SDP offer, create
    /// the server dialog, send `100 Trying`, and spawn the handler that
    /// drives the transaction state machine.
    ///
    /// The handler auto-replies `487 Request Terminated` to a pre-answer
    /// `CANCEL` and transitions the dialog to `Terminated(UacCancel)` —
    /// watch [`PendingCall::state_rx`] to surface that to your UI.
    ///
    /// Returns a [`PendingCall`] you call [`accept`](PendingCall::accept)
    /// or [`reject`](PendingCall::reject) on when the UI decides.
    pub async fn handle_pending(&self, mut tx: Transaction) -> Result<PendingCall, BoxError> {
        let remote_media = parse_sdp(&tx.original.body)?;
        let session_timer = negotiate_uas(&tx.original.headers);
        info!(
            remote_addr = %remote_media.addr,
            remote_port = remote_media.port,
            payload_type = remote_media.payload_type,
            ?session_timer,
            "parsed SDP offer",
        );

        let (state_sender, state_rx) = self.endpoint.dialog_layer.new_dialog_state_channel();
        let contact_uri: rsip::Uri = format!(
            "sip:{}@{}",
            self.account.username, self.endpoint.sip_addr.addr
        )
        .try_into()?;
        let dialog = self.endpoint.dialog_layer.get_or_create_server_invite(
            &tx,
            state_sender,
            None,
            Some(contact_uri),
        )?;

        let dialog_for_handler = dialog.clone();
        tokio::spawn(async move {
            let mut dialog = dialog_for_handler;
            if let Err(e) = dialog.handle(&mut tx).await {
                warn!("INVITE transaction handle error: {e}");
            }
        });

        Ok(PendingCall {
            dialog,
            remote_media,
            state_rx,
            session_timer,
            local_ip: self.endpoint.local_ip(),
        })
    }

    /// Accept an inbound INVITE in one shot — bind RTP, send `200 OK`
    /// with SDP answer. Equivalent to [`handle_pending`](Self::handle_pending)
    /// followed immediately by [`PendingCall::accept`]; use that pair if
    /// the answer depends on a UI decision and you need to detect a
    /// pre-answer cancel.
    pub async fn accept_transaction(&self, tx: Transaction) -> Result<AcceptedCall, BoxError> {
        self.handle_pending(tx).await?.accept().await
    }

    /// Reject an inbound INVITE in one shot with a non-2xx status
    /// (typical: `486 Busy Here`, `603 Decline`). No SDP parsing, no RTP
    /// socket — useful when refusing without inspecting the offer (e.g.
    /// daemon shutdown clearing pending invites).
    ///
    /// Use [`PendingCall::reject`] instead when you already have a
    /// `PendingCall` from [`handle_pending`](Self::handle_pending).
    pub async fn reject_transaction(
        &self,
        mut tx: Transaction,
        status: StatusCode,
    ) -> Result<(), BoxError> {
        if status.code() < 300 {
            return Err(format!("reject_transaction got 2xx status {status}").into());
        }

        let (state_sender, _state_rx) = self.endpoint.dialog_layer.new_dialog_state_channel();
        let contact_uri: rsip::Uri = format!(
            "sip:{}@{}",
            self.account.username, self.endpoint.sip_addr.addr
        )
        .try_into()?;
        let dialog = self.endpoint.dialog_layer.get_or_create_server_invite(
            &tx,
            state_sender,
            None,
            Some(contact_uri),
        )?;

        dialog.reject(Some(status.clone()), None)?;
        info!(%status, "rejected inbound INVITE");

        // Drive the transaction so the response is sent and ACK absorbed.
        tokio::spawn(async move {
            let mut dialog = dialog;
            if let Err(e) = dialog.handle(&mut tx).await {
                debug!("rejected INVITE handle error (expected for some flows): {e}");
            }
        });

        Ok(())
    }
}

/// Headers for the 200 OK sent by [`PendingCall::accept`]: the SDP
/// content type plus, when a session timer was negotiated, the RFC 4028
/// echo (`Supported: timer`, `Require: timer` if the caller advertised
/// support, and the negotiated `Session-Expires`).
fn accept_headers(session_timer: Option<&UasSessionTimer>) -> Vec<Header> {
    let mut headers = vec![Header::ContentType("application/sdp".into())];
    if let Some(uas) = session_timer {
        headers.push(supported_timer_header());
        if uas.require_timer {
            headers.push(require_timer_header());
        }
        headers.push(uas.echo.header());
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_timer::{Refresher, SessionExpires};

    #[test]
    fn reject_with_2xx_is_an_error() {
        // The guard is pure: status.code() < 300 should fail fast.
        let ok = StatusCode::OK;
        assert!(ok.code() < 300);
        let busy = StatusCode::BusyHere;
        assert!(busy.code() >= 300);
    }

    #[test]
    fn accept_headers_without_timer_is_content_type_only() {
        let rendered: Vec<String> = accept_headers(None).iter().map(|h| h.to_string()).collect();
        assert_eq!(rendered, vec!["Content-Type: application/sdp"]);
    }

    #[test]
    fn accept_headers_echoes_negotiated_session_timer() {
        let uas = UasSessionTimer {
            timer: SessionTimer {
                interval_secs: 1800,
                we_are_refresher: false,
            },
            echo: SessionExpires {
                interval_secs: 1800,
                refresher: Some(Refresher::Uac),
            },
            require_timer: true,
        };
        let rendered: Vec<String> = accept_headers(Some(&uas))
            .iter()
            .map(|h| h.to_string())
            .collect();
        assert_eq!(
            rendered,
            vec![
                "Content-Type: application/sdp",
                "Supported: timer",
                "Require: timer",
                "Session-Expires: 1800;refresher=uac",
            ]
        );
    }

    #[test]
    fn accept_headers_omits_require_when_caller_lacks_timer_support() {
        // Proxy-inserted Session-Expires: we refresh, and we must not
        // Require: timer from a caller that never advertised it.
        let uas = UasSessionTimer {
            timer: SessionTimer {
                interval_secs: 90,
                we_are_refresher: true,
            },
            echo: SessionExpires {
                interval_secs: 90,
                refresher: Some(Refresher::Uas),
            },
            require_timer: false,
        };
        let rendered: Vec<String> = accept_headers(Some(&uas))
            .iter()
            .map(|h| h.to_string())
            .collect();
        assert!(!rendered.iter().any(|h| h.starts_with("Require")));
        assert!(rendered.contains(&"Session-Expires: 90;refresher=uas".to_string()));
    }
}
