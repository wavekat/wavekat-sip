//! Inbound calls: accept with an SDP answer, or reject.
//!
//! [`crate::SipEndpoint::next_incoming_call`] yields an [`IncomingCall`] for
//! each new inbound INVITE, with the offer already parsed into
//! [`RemoteMedia`]. [`IncomingCall::accept`] binds an RTP socket, answers
//! `200 OK` with matching SDP, and returns a [`Call`]; [`IncomingCall::reject`]
//! sends a non-2xx final.

use std::net::SocketAddr;
use std::sync::Arc;

use rsip::{Request, StatusCode, Uri};
use tokio::net::UdpSocket;
use tracing::{debug, info};

use crate::caller::Call;
use crate::endpoint::SipEndpoint;
use crate::sdp::{build_sdp, RemoteMedia};
use crate::stack::dialog::Dialog;
use crate::stack::response::{build_response, ResponseBody};
use crate::stack::transaction::{gen_tag, TransactionKey};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A new inbound INVITE awaiting accept/reject.
pub struct IncomingCall {
    endpoint: Arc<SipEndpoint>,
    key: TransactionKey,
    peer: SocketAddr,
    request: Request,
    /// Where the caller expects RTP (parsed from its SDP offer).
    pub remote_media: RemoteMedia,
}

impl IncomingCall {
    pub(crate) fn new(
        endpoint: Arc<SipEndpoint>,
        key: TransactionKey,
        peer: SocketAddr,
        request: Request,
        remote_media: RemoteMedia,
    ) -> Self {
        Self {
            endpoint,
            key,
            peer,
            request,
            remote_media,
        }
    }

    /// Accept the call: bind an RTP socket, answer `200 OK` with an SDP answer,
    /// and return the established [`Call`].
    pub async fn accept(self) -> Result<Call, BoxError> {
        let rtp_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let local_rtp_addr = rtp_socket.local_addr()?;
        let local_ip = self.endpoint.local_ip();
        info!(%local_ip, rtp_port = local_rtp_addr.port(), "bound RTP socket for inbound call");

        let answer = build_sdp(local_ip, local_rtp_addr.port());
        debug!("SDP answer:\n{}", String::from_utf8_lossy(&answer));

        let to_tag = gen_tag();
        let contact: Uri = format!(
            "sip:{}@{}",
            self.endpoint.account().username,
            self.endpoint.local_addr()
        )
        .try_into()?;

        let response = build_response(
            &self.request,
            StatusCode::OK,
            Some(&to_tag),
            Some(&contact),
            Some(ResponseBody {
                content_type: "application/sdp",
                bytes: answer,
            }),
        )
        .ok_or("could not build 200 OK")?;

        if !self.endpoint.ua().answer(self.key, response).await {
            return Err("engine stopped before the 200 OK was sent".into());
        }
        info!("sent 200 OK with SDP answer");

        let dialog = Dialog::uas(&self.request, to_tag, contact)
            .ok_or("inbound INVITE lacked the headers a dialog requires")?;

        Ok(Call::new(
            self.endpoint.clone(),
            dialog,
            self.peer,
            self.remote_media,
            Arc::new(rtp_socket),
            local_rtp_addr,
        ))
    }

    /// Reject the call with a non-2xx final response (e.g. `486 Busy Here`).
    pub async fn reject(self, status: StatusCode) -> Result<(), BoxError> {
        if status.code() < 300 {
            return Err(format!("reject() got a non-failure status {status}").into());
        }
        let response = build_response(&self.request, status.clone(), Some(&gen_tag()), None, None)
            .ok_or("could not build reject response")?;
        if !self.endpoint.ua().answer(self.key, response).await {
            return Err("engine stopped before the reject was sent".into());
        }
        info!(%status, "rejected inbound INVITE");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rsip::StatusCode;

    #[test]
    fn reject_requires_non_2xx() {
        // A 2xx is not a rejection; the guard is exercised live in the
        // `stack::ua` loopback tests. Here we assert the status classification
        // the guard relies on.
        assert!(StatusCode::OK.code() < 300);
        assert!(StatusCode::BusyHere.code() >= 300);
    }
}
