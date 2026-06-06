//! Outbound INVITE handling — symmetric to [`crate::callee`].
//!
//! [`Caller::dial`] sends an INVITE in the background and returns a
//! [`PendingDial`] whose `state_rx` exposes the early dialog states
//! (`Calling`, `Early`, `Confirmed`, `Terminated`). The consumer pumps
//! that channel while the UI shows a "Dialing…" / "Ringing…" surface,
//! then calls [`PendingDial::on_confirmed`] once a 2xx arrives to
//! collect the negotiated SDP answer plus the bound local RTP socket.
//!
//! The local RTP socket is bound **at `dial` time**, not at
//! `on_confirmed` time, because the SDP offer in the INVITE must carry
//! a concrete local port. Cancelling the dial or dropping the
//! [`PendingDial`] frees the socket.
//!
//! ## Hanging up a connected call
//!
//! [`AcceptedDial::dialog`] is a
//! [`ClientInviteDialog`]. To hang up locally (user hit "End call"):
//!
//! ```ignore
//! accepted.dialog.bye().await?;
//! ```
//!
//! The dialog state machine then transitions to
//! `Terminated(_, TerminatedReason::UacBye)` on `state_rx`, so a single
//! watcher pumping `state_rx` handles both local and remote hangup
//! through the same code path.
//!
//! Audio device I/O, codecs, recording, AI taps — all of those are the
//! consumer's problem. The `rtp_socket` + `remote_media` +
//! `local_rtp_addr` triple is the raw plumbing; route frames anywhere.

use std::net::SocketAddr;
use std::sync::Arc;

use rsipstack::dialog::authenticate::Credential;
use rsipstack::dialog::client_dialog::ClientInviteDialog;
use rsipstack::dialog::dialog::{DialogState, DialogStateReceiver};
use rsipstack::dialog::invitation::{InviteAsyncResult, InviteOption};
use rsipstack::transport::SipAddr;
use tokio::net::{lookup_host, UdpSocket};
use tokio::task::JoinHandle;
use tracing::{debug, info};

use crate::account::SipAccount;
use crate::endpoint::SipEndpoint;
use crate::sdp::{build_sdp, parse_sdp, RemoteMedia};
use crate::session_timer::{
    negotiate_uac, supported_timer_header, SessionExpires, SessionTimer,
    DEFAULT_SESSION_EXPIRES_SECS,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// SIP-only handles for an outbound call that the remote answered.
///
/// Symmetric to [`crate::callee::AcceptedCall`] but with a
/// [`ClientInviteDialog`] (outbound) instead of `ServerInviteDialog`.
/// The audio plumbing fields are deliberately raw so the consumer can
/// drop a mic / recorder / AI pipeline onto them without satisfying a
/// `wavekat-sip` trait.
pub struct AcceptedDial {
    /// Client-side dialog. Call `.bye().await` to hang up locally.
    pub dialog: ClientInviteDialog,
    /// Where the remote endpoint expects RTP (from the SDP answer).
    pub remote_media: RemoteMedia,
    /// Local RTP socket; share via `Arc` to send and receive concurrently.
    pub rtp_socket: Arc<UdpSocket>,
    /// Local RTP address advertised in the SDP offer.
    pub local_rtp_addr: SocketAddr,
    /// Dialog state updates — re-INVITE acks, BYE, termination reasons.
    /// Pump this to detect remote hangup.
    pub state_rx: DialogStateReceiver,
    /// RFC 4028 session timer negotiated from the 2xx, if the remote
    /// supports it. Spawn [`crate::session_timer_loop`] with this to
    /// keep the session refreshed / watched; `None` means the remote
    /// declined session timers and no timer should run.
    pub session_timer: Option<SessionTimer>,
}

/// An outbound INVITE on the wire whose final response has not arrived.
///
/// Pump `state_rx` while the UI shows "Dialing…" / "Ringing…":
///
/// - `Calling(_)` — early dialog created; provisional or no response yet.
/// - `Early(_, _)` — provisional 1xx (180/183) received.
/// - `Confirmed(_)` — remote picked up; call [`on_confirmed`] to get
///   the [`AcceptedDial`] (parsed SDP answer + bound RTP socket).
/// - `Terminated(_, reason)` — call ended; see `TerminatedReason`
///   (`UasBusy`, `UasDecline`, `Timeout`, …).
///
/// If the user hits "End" on the dialing screen, call [`cancel`].
///
/// [`cancel`]: PendingDial::cancel
/// [`on_confirmed`]: PendingDial::on_confirmed
pub struct PendingDial {
    /// Client-side dialog. Use this for [`cancel`](Self::cancel) and,
    /// after promotion to [`AcceptedDial`], for `.bye()`.
    pub dialog: ClientInviteDialog,
    /// Dialog state updates from the moment the INVITE goes on the wire.
    pub state_rx: DialogStateReceiver,
    rtp_socket: Arc<UdpSocket>,
    local_rtp_addr: SocketAddr,
    invite_task: JoinHandle<InviteAsyncResult>,
}

impl PendingDial {
    /// Send `CANCEL` for the pending INVITE. Idempotent: returns
    /// `Ok(())` without re-sending if the dialog has already
    /// confirmed or terminated. Maps to the user hitting "End" on the
    /// dialing screen.
    pub async fn cancel(&self) -> Result<(), BoxError> {
        match self.dialog.state() {
            DialogState::Confirmed(_, _) | DialogState::Terminated(_, _) => {
                debug!("cancel on settled dialog; no-op");
                Ok(())
            }
            _ => {
                self.dialog.cancel().await?;
                info!("sent CANCEL on outbound INVITE");
                Ok(())
            }
        }
    }

    /// Wait for the INVITE transaction to complete and assemble the
    /// [`AcceptedDial`] from the negotiated SDP answer plus the
    /// already-bound local RTP socket.
    ///
    /// Returns an error if the call did not confirm with a 2xx (final
    /// non-2xx, timeout, transport error). On error the local RTP
    /// socket is dropped.
    pub async fn on_confirmed(self) -> Result<AcceptedDial, BoxError> {
        let (_dialog_id, resp) = self.invite_task.await??;
        let resp = resp.ok_or_else::<BoxError, _>(|| "INVITE produced no final response".into())?;
        if resp.status_code.kind() != rsip::StatusCodeKind::Successful {
            return Err(format!("INVITE did not confirm: status {}", resp.status_code).into());
        }
        let remote_media = parse_sdp(&resp.body)?;
        let session_timer = negotiate_uac(&resp.headers);
        info!(
            remote_addr = %remote_media.addr,
            remote_port = remote_media.port,
            payload_type = remote_media.payload_type,
            ?session_timer,
            "parsed SDP answer",
        );
        Ok(AcceptedDial {
            dialog: self.dialog,
            remote_media,
            rtp_socket: self.rtp_socket,
            local_rtp_addr: self.local_rtp_addr,
            state_rx: self.state_rx,
            session_timer,
        })
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

    /// Place an outbound INVITE to `target`. Binds a local RTP socket,
    /// builds the SDP offer, fires the INVITE in the background, and
    /// returns a [`PendingDial`] the consumer pumps for state updates.
    ///
    /// The destination is resolved from the account's
    /// `server`/`port` (typical: a SIP proxy). Use
    /// [`dial_with_destination`](Self::dial_with_destination) to route
    /// directly to an explicit address (UA-to-UA, tests).
    pub async fn dial(&self, target: rsip::Uri) -> Result<PendingDial, BoxError> {
        let destination = resolve_server(&self.account).await?;
        self.dial_with_destination(target, destination).await
    }

    /// Like [`dial`](Self::dial) but with an explicit network
    /// destination override (useful for direct UA-to-UA flows and
    /// tests where no proxy resolves the target URI).
    pub async fn dial_with_destination(
        &self,
        target: rsip::Uri,
        destination: Option<SipAddr>,
    ) -> Result<PendingDial, BoxError> {
        let rtp_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let local_rtp_addr = rtp_socket.local_addr()?;
        let rtp_port = local_rtp_addr.port();
        let local_ip = self.endpoint.local_ip();
        info!(local_ip = %local_ip, rtp_port, "bound RTP socket for outbound dial");

        let offer = build_sdp(local_ip, rtp_port);
        debug!("SDP offer:\n{}", String::from_utf8_lossy(&offer));

        let opt = build_invite_option(
            &self.account,
            &self.endpoint.sip_addr.addr.to_string(),
            target,
            offer,
            destination,
        )?;
        let (state_sender, state_rx) = self.endpoint.dialog_layer.new_dialog_state_channel();
        let (dialog, invite_task) = self
            .endpoint
            .dialog_layer
            .do_invite_async(opt, state_sender)?;
        info!("INVITE on the wire");

        Ok(PendingDial {
            dialog,
            state_rx,
            rtp_socket: Arc::new(rtp_socket),
            local_rtp_addr,
            invite_task,
        })
    }
}

/// Resolve the account's configured SIP server to a single
/// [`SipAddr`]. Returns `None` if the host has no A/AAAA records.
async fn resolve_server(account: &SipAccount) -> Result<Option<SipAddr>, BoxError> {
    let host_port = format!("{}:{}", account.server(), account.port());
    let mut addrs = lookup_host(&host_port).await?;
    Ok(addrs.next().map(SipAddr::from))
}

/// Compose an [`InviteOption`] from `account` + target. `contact_host`
/// is the endpoint's bound `host:port` (used for the `Contact` URI).
fn build_invite_option(
    account: &SipAccount,
    contact_host: &str,
    target: rsip::Uri,
    offer: Vec<u8>,
    destination: Option<SipAddr>,
) -> Result<InviteOption, BoxError> {
    let caller_uri: rsip::Uri =
        format!("sip:{}@{}", account.username, account.domain).try_into()?;
    let contact_uri: rsip::Uri = format!("sip:{}@{}", account.username, contact_host).try_into()?;
    let credential = Credential {
        username: account.auth_username().to_string(),
        password: account.password.clone(),
        realm: None,
    };
    let display_name = if account.display_name.is_empty() {
        None
    } else {
        Some(account.display_name.clone())
    };
    Ok(InviteOption {
        caller_display_name: display_name,
        caller: caller_uri,
        callee: target,
        destination,
        content_type: Some("application/sdp".into()),
        offer: Some(offer),
        contact: contact_uri,
        credential: Some(credential),
        // Advertise RFC 4028 session timers: ask for the default 30 min
        // interval and leave the refresher choice to the answerer (no
        // `refresher` param). A remote without timer support simply
        // omits Session-Expires from its 2xx and no timer runs.
        headers: Some(vec![
            supported_timer_header(),
            SessionExpires {
                interval_secs: DEFAULT_SESSION_EXPIRES_SECS,
                refresher: None,
            }
            .header(),
        ]),
        ..Default::default()
    })
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
    fn build_invite_option_composes_from_account_and_target() {
        let acct = test_account();
        let target: rsip::Uri = "sip:bob@example.com".try_into().unwrap();
        let opt = build_invite_option(
            &acct,
            "192.168.1.50:5060",
            target.clone(),
            b"v=0\r\n".to_vec(),
            None,
        )
        .expect("build_invite_option");

        assert_eq!(opt.caller.to_string(), "sip:1001@sip.example.com");
        assert_eq!(opt.callee, target);
        assert_eq!(opt.contact.to_string(), "sip:1001@192.168.1.50:5060");
        assert_eq!(opt.content_type.as_deref(), Some("application/sdp"));
        assert_eq!(opt.caller_display_name.as_deref(), Some("Office"));

        let cred = opt.credential.expect("credential should be set");
        assert_eq!(cred.username, "1001");
        assert_eq!(cred.password, "secret");
    }

    #[test]
    fn build_invite_option_uses_auth_username_when_set() {
        let mut acct = test_account();
        acct.auth_username = Some("admin".to_string());
        let target: rsip::Uri = "sip:bob@example.com".try_into().unwrap();
        let opt = build_invite_option(&acct, "10.0.0.1:5060", target, vec![], None).unwrap();
        let cred = opt.credential.unwrap();
        assert_eq!(
            cred.username, "admin",
            "credential.username should follow auth_username, not the AOR user"
        );
    }

    #[test]
    fn build_invite_option_omits_display_name_when_empty() {
        let mut acct = test_account();
        acct.display_name = String::new();
        let target: rsip::Uri = "sip:bob@example.com".try_into().unwrap();
        let opt = build_invite_option(&acct, "10.0.0.1:5060", target, vec![], None).unwrap();
        assert!(opt.caller_display_name.is_none());
    }

    #[test]
    fn build_invite_option_carries_offer_body() {
        let acct = test_account();
        let target: rsip::Uri = "sip:bob@example.com".try_into().unwrap();
        let offer = b"v=0\r\nm=audio 30000 RTP/AVP 0\r\n".to_vec();
        let opt = build_invite_option(&acct, "10.0.0.1:5060", target, offer.clone(), None).unwrap();
        assert_eq!(opt.offer.as_deref(), Some(offer.as_slice()));
    }

    #[test]
    fn build_invite_option_advertises_session_timers() {
        let acct = test_account();
        let target: rsip::Uri = "sip:bob@example.com".try_into().unwrap();
        let opt = build_invite_option(&acct, "10.0.0.1:5060", target, vec![], None).unwrap();
        let headers = opt.headers.expect("extra headers should be set");

        let rendered: Vec<String> = headers.iter().map(|h| h.to_string()).collect();
        assert!(
            rendered.iter().any(|h| h == "Supported: timer"),
            "INVITE must advertise Supported: timer, got {rendered:?}"
        );
        assert!(
            rendered
                .iter()
                .any(|h| h == &format!("Session-Expires: {DEFAULT_SESSION_EXPIRES_SECS}")),
            "INVITE must request the default session interval without \
             pinning a refresher, got {rendered:?}"
        );
    }

    #[test]
    fn build_invite_option_threads_destination() {
        let acct = test_account();
        let target: rsip::Uri = "sip:bob@example.com".try_into().unwrap();
        let dest: SipAddr = "127.0.0.1:5060".parse::<SocketAddr>().unwrap().into();
        let opt = build_invite_option(&acct, "10.0.0.1:5060", target, vec![], Some(dest.clone()))
            .unwrap();
        assert_eq!(opt.destination, Some(dest));
    }
}
