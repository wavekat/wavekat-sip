//! Inbound calls: accept with an SDP answer, or reject.
//!
//! [`crate::SipEndpoint::next_incoming_call`] yields an [`IncomingCall`] for
//! each new inbound INVITE, with the offer already parsed into
//! [`RemoteMedia`]. [`IncomingCall::accept`] binds an RTP socket, answers
//! `200 OK` with matching SDP, and returns a [`Call`]; [`IncomingCall::reject`]
//! sends a non-2xx final.

use std::net::SocketAddr;
use std::sync::Arc;

use rsip::headers::UntypedHeader;
use rsip::message::HeadersExt;
use rsip::{Request, StatusCode, Uri};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::caller::Call;
use crate::endpoint::SipEndpoint;
use crate::sdp::{
    build_sdp_with, select_codec, select_dtmf, CodecMenu, MediaDirection, RemoteMedia,
};
use crate::session_timer::{negotiate_uas, require_timer_header, supported_timer_header};
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
    /// Fired if the caller `CANCEL`s before this call is accepted or rejected;
    /// surfaced via [`Self::cancelled`].
    cancelled: CancellationToken,
    /// The UAS `To` tag for this call, generated once at construction and
    /// reused across every response we send — `180 Ringing`, the `200 OK` /
    /// reject final, and the established dialog. RFC 3261 §12.1.1 requires the
    /// tag on an early-dialog `18x` to match the one on the final response;
    /// generating a fresh tag per response would hand the caller two different
    /// dialogs.
    local_tag: String,
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
        cancelled: CancellationToken,
    ) -> Self {
        Self {
            endpoint,
            key,
            peer,
            request,
            cancelled,
            local_tag: gen_tag(),
            remote_media,
        }
    }

    /// Send a `180 Ringing` provisional: tell the caller the call is alerting
    /// (so it can play ringback), and — per RFC 3261 §9.1 — unblock its ability
    /// to `CANCEL` if it hangs up before we answer. A caller may not send
    /// `CANCEL` until it has received a provisional response, so without this a
    /// pre-answer hangup produces no signal and the call appears to ring
    /// forever.
    ///
    /// Safe to call while the call rings and before deciding: it leaves the
    /// INVITE acceptable/rejectable, and shares its `To` tag with the eventual
    /// final response so the early and confirmed dialogs agree. Idempotent in
    /// effect — the engine simply resends the latest provisional on an INVITE
    /// retransmit.
    pub async fn ring(&self) -> Result<(), BoxError> {
        let response = build_response(
            &self.request,
            StatusCode::Ringing,
            Some(&self.local_tag),
            None,
            None,
        )
        .ok_or("could not build 180 Ringing response")?;
        if !self.endpoint.ua().answer(self.key.clone(), response).await {
            return Err("engine stopped before 180 Ringing was sent".into());
        }
        debug!("sent 180 Ringing");
        Ok(())
    }

    /// A token that fires if the caller `CANCEL`s before the call is accepted or
    /// rejected — i.e. they hung up while it was still ringing. Watch it
    /// alongside the accept/reject decision to surface a missed call. Once
    /// [`accept`](Self::accept) or [`reject`](Self::reject) is called the INVITE
    /// is no longer cancellable and the token will not fire.
    pub fn cancelled(&self) -> CancellationToken {
        self.cancelled.clone()
    }

    /// The caller's `From` header value (e.g. `"Bob <sip:bob@example.com>;tag=…"`),
    /// for displaying who is calling. `None` if the INVITE lacked a parseable
    /// `From` (malformed; shouldn't happen in practice).
    pub fn caller(&self) -> Option<String> {
        self.request
            .from_header()
            .ok()
            .map(|h| h.value().to_string())
    }

    /// Accept the call: bind an RTP socket, answer `200 OK` with an SDP answer,
    /// and return the established [`Call`].
    ///
    /// The answer is a real RFC 3264 intersection of the offer: Opus wherever
    /// the offer contains it (at the offer's payload type), else the offer's
    /// first G.711 — echoed back as a [`CodecMenu::Pinned`] body, never the
    /// full menu. The returned call's [`RemoteMedia::codec`] is rewritten to
    /// that selection, so it is always the *negotiated* codec, not the peer's
    /// first preference.
    ///
    /// If the offer contains no codec this stack knows, the INVITE is answered
    /// `488 Not Acceptable Here` and an error is returned. Check
    /// [`IncomingCall::remote_media`]'s `codec`/`opus_payload_type` before
    /// accepting to decide earlier.
    pub async fn accept(self) -> Result<Call, BoxError> {
        // No longer cancellable once we commit to answering.
        self.endpoint.unregister_incoming(&self.key);

        let Some(codec) = select_codec(&self.remote_media) else {
            // Nothing we can speak: the SIP-correct refusal is a 488 final.
            let response = build_response(
                &self.request,
                StatusCode::NotAcceptableHere,
                Some(&self.local_tag),
                None,
                None,
            )
            .ok_or("could not build 488 response")?;
            self.endpoint.ua().answer(self.key, response).await;
            return Err(format!(
                "no supported codec in the offer (first payload type {}); answered 488",
                self.remote_media.payload_type
            )
            .into());
        };
        let dtmf = select_dtmf(&self.remote_media, codec);

        let rtp_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let local_rtp_addr = rtp_socket.local_addr()?;
        let local_ip = self.endpoint.local_ip();
        info!(%local_ip, rtp_port = local_rtp_addr.port(), ?codec, "bound RTP socket for inbound call");

        let answer = build_sdp_with(
            local_ip,
            local_rtp_addr.port(),
            CodecMenu::Pinned { codec, dtmf },
            MediaDirection::SendRecv,
            0,
        );
        debug!("SDP answer:\n{}", String::from_utf8_lossy(&answer));

        let to_tag = self.local_tag.clone();
        let contact: Uri = format!(
            "sip:{}@{}",
            self.endpoint.account().username,
            self.endpoint.local_addr()
        )
        .try_into()?;

        // RFC 4028: if the caller asked for a session timer, honor it and echo
        // the agreed interval (plus Require: timer when the peer supports it).
        let uas_timer = negotiate_uas(&self.request.headers);

        let mut response = build_response(
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

        if let Some(uas) = &uas_timer {
            response.headers.push(supported_timer_header());
            response.headers.push(uas.echo.header());
            if uas.require_timer {
                response.headers.push(require_timer_header());
            }
        }

        if !self.endpoint.ua().answer(self.key, response).await {
            return Err("engine stopped before the 200 OK was sent".into());
        }
        info!("sent 200 OK with SDP answer");

        let dialog = Dialog::uas(&self.request, to_tag, contact)
            .ok_or("inbound INVITE lacked the headers a dialog requires")?;

        // The parsed offer's `codec` is only the peer's first preference;
        // overwrite it with our selection so the established call (and every
        // re-offer pinned from it) carries the negotiated codec.
        let mut remote_media = self.remote_media;
        remote_media.codec = Some(codec);

        Ok(Call::new(
            self.endpoint.clone(),
            dialog,
            self.peer,
            uas_timer.map(|u| u.timer),
            remote_media,
            Arc::new(rtp_socket),
            local_rtp_addr,
        ))
    }

    /// Reject the call with a non-2xx final response (e.g. `486 Busy Here`).
    pub async fn reject(self, status: StatusCode) -> Result<(), BoxError> {
        // No longer cancellable once we commit to rejecting.
        self.endpoint.unregister_incoming(&self.key);
        if status.code() < 300 {
            return Err(format!("reject() got a non-failure status {status}").into());
        }
        let response = build_response(
            &self.request,
            status.clone(),
            Some(&self.local_tag),
            None,
            None,
        )
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
