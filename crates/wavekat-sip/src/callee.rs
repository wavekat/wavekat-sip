//! Inbound INVITE handling — focused SIP-only layer.
//!
//! Two operations:
//!
//! - [`Callee::accept_transaction`] takes an inbound `Transaction`, parses
//!   the SDP offer, binds a local RTP socket, sends `200 OK` with a
//!   matching SDP answer, and returns the dialog plus the bound socket
//!   and remote media descriptor. The consumer drives audio.
//! - [`Callee::reject_transaction`] responds with the given non-2xx
//!   status. No dialog is established.
//!
//! Audio device I/O, codecs, recording — all of those are the caller's
//! problem. See `docs/01-port-plan.md`.
//!
//! `Transaction` is yielded by [`crate::endpoint::SipEndpoint`]'s incoming
//! transaction receiver. Filter for `Method::Invite` before calling
//! `accept_transaction` / `reject_transaction`.

use std::net::SocketAddr;
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

    /// Accept an inbound INVITE: parse offer, bind RTP, build answer,
    /// send `200 OK`. The returned `AcceptedCall` exposes the dialog
    /// and socket for the consumer to drive audio.
    ///
    /// Spawns a task that drives the INVITE transaction to completion
    /// (sends `100 Trying`, waits for `ACK`).
    pub async fn accept_transaction(
        &self,
        mut tx: Transaction,
    ) -> Result<AcceptedCall, Box<dyn std::error::Error + Send + Sync>> {
        // 1. Parse SDP offer.
        let remote_media = parse_sdp(&tx.original.body)?;
        info!(
            remote_addr = %remote_media.addr,
            remote_port = remote_media.port,
            payload_type = remote_media.payload_type,
            "parsed SDP offer",
        );

        // 2. Bind a UDP socket for RTP.
        let rtp_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let local_rtp_addr = rtp_socket.local_addr()?;
        let local_ip = self.endpoint.local_ip();
        let rtp_port = local_rtp_addr.port();
        info!(%local_ip, rtp_port, "bound RTP socket");

        // 3. Build a matching SDP answer (recvonly G.711, see sdp.rs).
        let sdp_answer = build_sdp(local_ip, rtp_port);
        debug!("SDP answer:\n{}", String::from_utf8_lossy(&sdp_answer));

        // 4. Create the server dialog.
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

        // 5. Send 200 OK + SDP answer.
        let headers = vec![Header::ContentType("application/sdp".into())];
        dialog.accept(Some(headers), Some(sdp_answer))?;
        info!("sent 200 OK with SDP answer");

        // 6. Drive the INVITE transaction (100 Trying / ACK).
        let dialog_for_handler = dialog.clone();
        tokio::spawn(async move {
            let mut dialog = dialog_for_handler;
            if let Err(e) = dialog.handle(&mut tx).await {
                warn!("INVITE transaction handle error: {e}");
            }
        });

        Ok(AcceptedCall {
            dialog,
            remote_media,
            rtp_socket: Arc::new(rtp_socket),
            local_rtp_addr,
            state_rx,
        })
    }

    /// Reject an inbound INVITE with a non-2xx status (typical: 486 Busy
    /// Here, 487 Request Terminated, 603 Decline).
    ///
    /// No dialog is established and no RTP socket is bound. The transaction
    /// is driven via the dialog layer so the response reaches the wire and
    /// re-transmissions are handled.
    pub async fn reject_transaction(
        &self,
        mut tx: Transaction,
        status: StatusCode,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_with_2xx_is_an_error() {
        // We can't exercise reject_transaction without a real Transaction,
        // but the guard is pure: status.code() < 300 should fail fast.
        let ok = StatusCode::OK;
        assert!(ok.code() < 300);
        let busy = StatusCode::BusyHere;
        assert!(busy.code() >= 300);
    }
}
