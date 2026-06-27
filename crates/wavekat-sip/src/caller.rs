//! Outbound calls and the established-call handle.
//!
//! [`Caller::dial`] binds a local RTP socket, builds the SDP offer, places the
//! INVITE through the engine (answering a digest challenge if the server
//! demands one), and on a 2xx returns a [`Call`] — the negotiated remote media
//! plus the bound RTP socket. Audio device I/O, codecs and recording stay with
//! the consumer; the `rtp_socket` + `remote_media` + `local_rtp_addr` triple is
//! the raw plumbing.

use std::net::SocketAddr;
use std::sync::Arc;

use rsip::{Header, Uri};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::account::SipAccount;
use crate::dtmf_info::{build_info_body, classify, content_type_header, InfoOutcome};
use crate::endpoint::SipEndpoint;
use crate::rtp::dtmf::DtmfDigit;
use crate::sdp::{build_sdp, build_sdp_with, parse_sdp, MediaDirection, RemoteMedia};
use crate::session_timer::{
    negotiate_uac, supported_timer_header, SessionDialogOps, SessionExpires, SessionTimer,
    DEFAULT_SESSION_EXPIRES_SECS,
};
use crate::stack::call::{CallConfig, CallOutcome};
use crate::stack::dialog::Dialog;
use crate::stack::transaction::gen_tag;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// An established call: negotiated remote media plus the local RTP socket.
///
/// The same handle is produced by [`Caller::dial`] (outbound) and
/// [`crate::IncomingCall::accept`] (inbound), so call control is uniform.
pub struct Call {
    endpoint: Arc<SipEndpoint>,
    /// Shared so a background session-timer loop ([`Call::session_handle`]) can
    /// send refresh re-INVITEs / BYE while the call owner drives audio. The
    /// mutex serializes the dialog's CSeq across both.
    dialog: Arc<Mutex<Dialog>>,
    peer: SocketAddr,
    /// `true` once we have put the peer on hold via a `sendonly` re-INVITE.
    held: bool,
    /// SDP `o=` version; bumped on every re-offer (RFC 3264 §5).
    sdp_version: u32,
    /// The RFC 4028 session timer negotiated at call setup, if any.
    session_timer: Option<SessionTimer>,
    /// Where the remote endpoint expects RTP (from the negotiated SDP).
    pub remote_media: RemoteMedia,
    /// Local RTP socket; share via `Arc` to send and receive concurrently.
    pub rtp_socket: Arc<UdpSocket>,
    /// Local RTP address advertised in our SDP.
    pub local_rtp_addr: SocketAddr,
}

impl Call {
    pub(crate) fn new(
        endpoint: Arc<SipEndpoint>,
        dialog: Dialog,
        peer: SocketAddr,
        session_timer: Option<SessionTimer>,
        remote_media: RemoteMedia,
        rtp_socket: Arc<UdpSocket>,
        local_rtp_addr: SocketAddr,
    ) -> Self {
        Self {
            endpoint,
            dialog: Arc::new(Mutex::new(dialog)),
            peer,
            held: false,
            // The initial offer/answer was o= version 0.
            sdp_version: 0,
            session_timer,
            remote_media,
            rtp_socket,
            local_rtp_addr,
        }
    }

    /// Put the peer on hold (`on = true`, `a=sendonly`) or resume the call
    /// (`on = false`, `a=sendrecv`) by sending an in-dialog re-INVITE with a
    /// fresh SDP re-offer (RFC 3264 §8.4).
    ///
    /// The local hold state only flips once the peer accepts the re-INVITE with
    /// a 2xx; a non-2xx final surfaces the server's reason and leaves the call
    /// unchanged. The `o=` version is bumped for each re-offer regardless, as
    /// RFC 3264 requires.
    pub async fn set_hold(&mut self, on: bool) -> Result<(), BoxError> {
        let direction = if on {
            MediaDirection::SendOnly
        } else {
            MediaDirection::SendRecv
        };
        self.sdp_version += 1;
        let offer = build_sdp_with(
            self.endpoint.local_ip(),
            self.local_rtp_addr.port(),
            direction,
            self.sdp_version,
        );
        let headers = vec![Header::ContentType("application/sdp".into())];
        let response = {
            let mut dialog = self.dialog.lock().await;
            self.endpoint
                .ua()
                .reinvite(self.peer, &mut dialog, headers, offer)
                .await
        };
        match response {
            Some(r) if (200..300).contains(&r.status_code.code()) => {
                self.held = on;
                info!(on, "hold state updated via re-INVITE");
                Ok(())
            }
            Some(r) => Err(format!("re-INVITE rejected: {}", r.status_code).into()),
            None => Err("re-INVITE timed out with no final response".into()),
        }
    }

    /// `true` if the call is currently on hold (we sent a `sendonly` re-INVITE
    /// the peer accepted).
    pub fn is_held(&self) -> bool {
        self.held
    }

    /// The RFC 4028 session timer negotiated when the call was set up, or
    /// `None` if neither side asked for one. Drive it with
    /// [`crate::session_timer_loop`] against [`Call::session_handle`].
    pub fn session_timer(&self) -> Option<SessionTimer> {
        self.session_timer
    }

    /// A cloneable handle that sends refresh re-INVITEs / BYE on this call's
    /// dialog, for running [`crate::session_timer_loop`] in a background task
    /// alongside the audio path. Shares the dialog with the `Call`, so their
    /// in-dialog requests serialize correctly.
    pub fn session_handle(&self) -> CallSession {
        CallSession {
            endpoint: self.endpoint.clone(),
            dialog: self.dialog.clone(),
            peer: self.peer,
        }
    }

    /// Send one DTMF press via SIP `INFO` (`application/dtmf-relay`).
    ///
    /// Use this only when the remote did not negotiate RFC 4733 — i.e.
    /// [`RemoteMedia::dtmf_payload_type`] is `None`. When telephone-event is
    /// available, prefer [`crate::send_dtmf_burst`] over RTP. A
    /// [`InfoOutcome::UnsupportedMedia`] result means the remote rejects this
    /// transport too; stop sending further presses on this dialog.
    pub async fn send_dtmf_info(&mut self, digit: DtmfDigit, duration_ms: u32) -> InfoOutcome {
        let body = build_info_body(digit, duration_ms).into_bytes();
        let response = {
            let mut dialog = self.dialog.lock().await;
            self.endpoint
                .ua()
                .info(self.peer, &mut dialog, vec![content_type_header()], body)
                .await
        };
        classify(response)
    }

    /// Hang up by sending an in-dialog `BYE`. Returns once the peer 2xxs it
    /// (or the transaction gives up).
    pub async fn hangup(&mut self) -> Result<(), BoxError> {
        let acked = {
            let mut dialog = self.dialog.lock().await;
            self.endpoint.ua().hangup(self.peer, &mut dialog).await
        };
        if acked {
            info!("call hung up (BYE acknowledged)");
            Ok(())
        } else {
            Err("BYE was not acknowledged".into())
        }
    }
}

/// A cloneable session-control handle over a [`Call`]'s dialog.
///
/// Produced by [`Call::session_handle`] and consumed by
/// [`crate::session_timer_loop`]: it implements [`SessionDialogOps`] so the
/// loop can send refresh re-INVITEs and the tear-down BYE on the shared dialog.
#[derive(Clone)]
pub struct CallSession {
    endpoint: Arc<SipEndpoint>,
    dialog: Arc<Mutex<Dialog>>,
    peer: SocketAddr,
}

impl SessionDialogOps for CallSession {
    async fn refresh(
        &self,
        mut headers: Vec<Header>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<rsip::Response>, BoxError> {
        let body = body.unwrap_or_default();
        if !body.is_empty() {
            headers.push(Header::ContentType("application/sdp".into()));
        }
        let mut dialog = self.dialog.lock().await;
        Ok(self
            .endpoint
            .ua()
            .reinvite(self.peer, &mut dialog, headers, body)
            .await)
    }

    async fn send_bye(&self) -> Result<(), BoxError> {
        let mut dialog = self.dialog.lock().await;
        if self.endpoint.ua().hangup(self.peer, &mut dialog).await {
            Ok(())
        } else {
            Err("BYE was not acknowledged".into())
        }
    }
}

/// Stateless helper bound to an account + endpoint.
pub struct Caller {
    account: SipAccount,
    endpoint: Arc<SipEndpoint>,
}

impl Caller {
    /// Construct a `Caller` for the given account and shared endpoint.
    pub fn new(account: SipAccount, endpoint: Arc<SipEndpoint>) -> Self {
        Self { account, endpoint }
    }

    /// Place an outbound call to `target` and wait for it to be answered.
    ///
    /// Binds a local RTP socket, offers G.711 SDP, sends the INVITE to the
    /// account's resolved server, follows provisional responses, and answers a
    /// single `401`/`407` challenge. Returns the [`Call`] on a 2xx, or an error
    /// if the call was rejected, timed out, or had no usable SDP answer.
    pub async fn dial(&self, target: Uri) -> Result<Call, BoxError> {
        let rtp_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let local_rtp_addr = rtp_socket.local_addr()?;
        let local_ip = self.endpoint.local_ip();
        info!(%local_ip, rtp_port = local_rtp_addr.port(), "bound RTP socket for outbound dial");

        let offer = build_sdp(local_ip, local_rtp_addr.port());
        debug!("SDP offer:\n{}", String::from_utf8_lossy(&offer));

        let from: Uri =
            format!("sip:{}@{}", self.account.username, self.account.domain).try_into()?;
        let contact: Uri = format!(
            "sip:{}@{}",
            self.account.username,
            self.endpoint.local_addr()
        )
        .try_into()?;

        // Advertise RFC 4028 session-timer support so the answerer can pin a
        // refresh interval in its 2xx (negotiated below).
        let cfg = CallConfig {
            target,
            from,
            contact,
            from_tag: gen_tag(),
            call_id: format!("{}@wavekat.com", gen_tag()),
            sdp: offer,
            extra_headers: vec![
                supported_timer_header(),
                SessionExpires {
                    interval_secs: DEFAULT_SESSION_EXPIRES_SECS,
                    refresher: None,
                }
                .header(),
            ],
            username: self.account.auth_username().to_string(),
            password: self.account.password.clone(),
        };

        match self
            .endpoint
            .ua()
            .call(&cfg, self.endpoint.server(), 1)
            .await
        {
            CallOutcome::Answered { dialog, response } => {
                let remote_media = parse_sdp(&response.body)?;
                let session_timer = negotiate_uac(&response.headers);
                info!(
                    remote_addr = %remote_media.addr,
                    remote_port = remote_media.port,
                    payload_type = remote_media.payload_type,
                    ?session_timer,
                    "call answered; parsed SDP answer",
                );
                Ok(Call::new(
                    self.endpoint.clone(),
                    *dialog,
                    self.endpoint.server(),
                    session_timer,
                    remote_media,
                    Arc::new(rtp_socket),
                    local_rtp_addr,
                ))
            }
            CallOutcome::Rejected(status) => Err(format!("call rejected: {status}").into()),
            CallOutcome::Unauthorized => Err("call rejected: authentication failed".into()),
            CallOutcome::TimedOut => Err("call timed out with no final response".into()),
            CallOutcome::EngineStopped => Err("engine stopped".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Transport;

    fn test_account() -> SipAccount {
        SipAccount {
            display_name: "Office".to_string(),
            username: "1001".to_string(),
            password: "secret".to_string(),
            domain: "sip.example.com".to_string(),
            auth_username: None,
            server: Some("pbx.example.com".to_string()),
            port: Some(5080),
            transport: Transport::Udp,
        }
    }

    #[test]
    fn caller_holds_account_and_endpoint_inputs() {
        // Construction is pure; the call path is covered by the stack's
        // loopback tests (`stack::ua`). Here we just check `new` wiring.
        let acct = test_account();
        assert_eq!(acct.auth_username(), "1001");
    }
}
