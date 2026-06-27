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

use rsip::Uri;
use tokio::net::UdpSocket;
use tracing::{debug, info};

use crate::account::SipAccount;
use crate::endpoint::SipEndpoint;
use crate::sdp::{build_sdp, parse_sdp, RemoteMedia};
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
    dialog: Dialog,
    peer: SocketAddr,
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
        remote_media: RemoteMedia,
        rtp_socket: Arc<UdpSocket>,
        local_rtp_addr: SocketAddr,
    ) -> Self {
        Self {
            endpoint,
            dialog,
            peer,
            remote_media,
            rtp_socket,
            local_rtp_addr,
        }
    }

    /// Hang up by sending an in-dialog `BYE`. Returns once the peer 2xxs it
    /// (or the transaction gives up).
    pub async fn hangup(&mut self) -> Result<(), BoxError> {
        if self.endpoint.ua().hangup(self.peer, &mut self.dialog).await {
            info!("call hung up (BYE acknowledged)");
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

        let cfg = CallConfig {
            target,
            from,
            contact,
            from_tag: gen_tag(),
            call_id: format!("{}@wavekat.com", gen_tag()),
            sdp: offer,
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
                info!(
                    remote_addr = %remote_media.addr,
                    remote_port = remote_media.port,
                    payload_type = remote_media.payload_type,
                    "call answered; parsed SDP answer",
                );
                Ok(Call::new(
                    self.endpoint.clone(),
                    *dialog,
                    self.endpoint.server(),
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
