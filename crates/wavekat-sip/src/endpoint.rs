//! Shared SIP endpoint: a bound UDP transport + the clean-room engine, with
//! inbound requests routed to new calls or auto-answered in-dialog.
//!
//! `SipEndpoint` owns the [`Ua`](crate::stack::ua::Ua) (engine + router) and a
//! background task that drains inbound requests:
//!
//! - a brand-new `INVITE` (no `To` tag) becomes a [`crate::IncomingCall`] on
//!   the `next_incoming_call` stream;
//! - in-dialog requests (`BYE`, `OPTIONS`, `INFO`, re-`INVITE`) are
//!   auto-answered `200 OK`;
//! - the `ACK` for a 2xx is absorbed.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rsip::headers::ToTypedHeader;
use rsip::message::HeadersExt;
use rsip::{Method, StatusCode};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::account::{SipAccount, Transport};
use crate::callee::IncomingCall;
use crate::resolve::resolve_sip_server;
use crate::sdp::parse_sdp;
use crate::stack::response::build_response;
use crate::stack::transaction::gen_tag;
use crate::stack::ua::{Incoming, Ua};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A bound SIP endpoint: the engine, plus inbound-call routing.
pub struct SipEndpoint {
    ua: Arc<Ua>,
    account: SipAccount,
    server: SocketAddr,
    local_ip: IpAddr,
    transport: Transport,
    cancel: CancellationToken,
    incoming_calls: Mutex<mpsc::Receiver<Incoming>>,
}

impl SipEndpoint {
    /// Bind transport, start the engine, and begin routing inbound requests.
    ///
    /// The account's `server`/`port` are resolved (RFC 3263 subset) to the
    /// next-hop address all requests are sent to.
    pub async fn new(
        account: &SipAccount,
        cancel: CancellationToken,
    ) -> Result<Arc<Self>, BoxError> {
        let local_ip = detect_local_ip(account)?;
        let bind_addr = SocketAddr::new(local_ip, 0);
        info!("Binding SIP transport to {bind_addr}");

        let ua = Arc::new(Ua::bind(bind_addr, cancel.clone()).await?);
        let server = resolve_sip_server(account)
            .await?
            .ok_or("could not resolve SIP server address")?;
        info!(%server, "resolved SIP server");

        let (calls_tx, calls_rx) = mpsc::channel(16);
        let endpoint = Arc::new(Self {
            ua: ua.clone(),
            account: account.clone(),
            server,
            local_ip,
            transport: account.transport,
            cancel,
            incoming_calls: Mutex::new(calls_rx),
        });

        // Inbound router: new INVITE → calls stream; in-dialog → auto-answer.
        tokio::spawn(async move {
            while let Some(inc) = ua.next_incoming().await {
                route_inbound(&ua, inc, &calls_tx).await;
            }
        });

        Ok(endpoint)
    }

    /// Local IP this endpoint is bound to.
    pub fn local_ip(&self) -> IpAddr {
        self.local_ip
    }

    /// Local socket address (IP + port) this endpoint is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.ua.local_addr()
    }

    /// Transport this endpoint was bound for.
    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// Stop the engine and free the socket.
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }

    /// Await the next inbound call (a new `INVITE`). Returns `None` when the
    /// endpoint shuts down. Unparseable offers are skipped.
    pub async fn next_incoming_call(self: &Arc<Self>) -> Option<IncomingCall> {
        loop {
            let incoming = self.incoming_calls.lock().await.recv().await?;
            match parse_sdp(&incoming.request.body) {
                Ok(remote_media) => {
                    return Some(IncomingCall::new(
                        self.clone(),
                        incoming.key,
                        incoming.peer,
                        incoming.request,
                        remote_media,
                    ));
                }
                Err(e) => warn!(error = %e, "inbound INVITE has no usable SDP offer; skipping"),
            }
        }
    }

    pub(crate) fn ua(&self) -> &Ua {
        &self.ua
    }

    pub(crate) fn server(&self) -> SocketAddr {
        self.server
    }

    pub(crate) fn account(&self) -> &SipAccount {
        &self.account
    }
}

/// Route one inbound request: new call, in-dialog auto-answer, or drop.
async fn route_inbound(ua: &Ua, inc: Incoming, calls_tx: &mpsc::Sender<Incoming>) {
    let has_to_tag = inc
        .request
        .to_header()
        .ok()
        .and_then(|to| to.typed().ok())
        .map(|to| to.tag().is_some())
        .unwrap_or(false);

    match inc.request.method() {
        // A fresh INVITE (no dialog tag yet) is a new inbound call.
        Method::Invite if !has_to_tag => {
            let _ = calls_tx.send(inc).await;
        }
        // The ACK for a 2xx we sent: it confirms our dialog; nothing to reply.
        Method::Ack => debug!("absorbing 2xx ACK"),
        // Any other in-dialog request (BYE / OPTIONS / INFO / re-INVITE):
        // acknowledge it so the peer's transaction completes.
        _ => {
            if let Some(response) =
                build_response(&inc.request, StatusCode::OK, Some(&gen_tag()), None, None)
            {
                let _ = ua.answer(inc.key, response).await;
            }
        }
    }
}

/// Detect the local IP that routes to the SIP server.
///
/// Opens a temporary UDP socket, connects to the server (no data sent), and
/// reads back the OS-chosen source address. Uses the OS resolver, not the
/// SRV-aware [`crate::resolve`] path: it only needs *a* route to pick a source
/// IP.
fn detect_local_ip(account: &SipAccount) -> Result<IpAddr, BoxError> {
    let dest = format!("{}:{}", account.server(), account.port());
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(&dest)?;
    Ok(sock.local_addr()?.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_account(server: Option<&str>, port: Option<u16>) -> SipAccount {
        SipAccount {
            display_name: "Test".to_string(),
            username: "1001".to_string(),
            password: "secret".to_string(),
            domain: "localhost".to_string(),
            auth_username: None,
            server: server.map(|s| s.to_string()),
            port,
            transport: Transport::default(),
        }
    }

    #[test]
    fn detect_local_ip_returns_non_unspecified() {
        let account = make_account(Some("1.1.1.1"), Some(5060));
        let ip = detect_local_ip(&account).expect("detects a local ip");
        assert!(!ip.is_unspecified());
    }

    #[test]
    fn detect_local_ip_uses_server_field() {
        let account = make_account(Some("8.8.8.8"), Some(5060));
        assert!(detect_local_ip(&account).is_ok());
    }

    #[test]
    fn detect_local_ip_falls_back_to_domain() {
        // No explicit server → uses the domain (localhost resolves locally).
        let account = make_account(None, None);
        assert!(detect_local_ip(&account).is_ok());
    }
}
