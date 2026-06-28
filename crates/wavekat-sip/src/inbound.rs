//! Inbound in-dialog requests surfaced to the consumer.
//!
//! By default [`SipEndpoint`](crate::SipEndpoint) auto-answers every in-dialog
//! request (`BYE` / `OPTIONS` / `INFO` / re-`INVITE`) with `200 OK`. A consumer
//! that needs to *handle* a peer's re-`INVITE` (e.g. answer an RFC 4028 session
//! refresh with a fresh SDP answer, or apply a peer-initiated hold) or read an
//! inbound `INFO` (e.g. SIP-INFO DTMF) opts in via
//! [`Call::inbound_requests`](crate::Call::inbound_requests). From then on the
//! endpoint routes that dialog's re-`INVITE` / `INFO` here instead of
//! auto-answering them; the consumer answers each [`InboundRequest`] itself.
//!
//! `BYE` and `OPTIONS` are always auto-answered by the endpoint, even after
//! opting in — call teardown and keepalive don't need consumer involvement.

use std::sync::Arc;

use rsip::{Headers, Method, Request, StatusCode};

use crate::stack::response::{build_response, ResponseBody};
use crate::stack::transaction::TransactionKey;
use crate::stack::ua::Ua;

/// A single inbound in-dialog request (a peer re-`INVITE` or `INFO`) awaiting a
/// response from the consumer.
///
/// Inspect it with [`method`](Self::method) / [`headers`](Self::headers) /
/// [`body`](Self::body), then answer exactly once with
/// [`respond`](Self::respond) or [`ok`](Self::ok). Dropping it without
/// answering leaves the peer's transaction to time out.
pub struct InboundRequest {
    ua: Arc<Ua>,
    key: TransactionKey,
    request: Request,
}

impl InboundRequest {
    pub(crate) fn new(ua: Arc<Ua>, key: TransactionKey, request: Request) -> Self {
        Self { ua, key, request }
    }

    /// The request method — [`Method::Invite`] for a re-INVITE (re-offer /
    /// session refresh), [`Method::Info`] for SIP INFO, [`Method::Notify`] for a
    /// transfer-progress sipfrag, or [`Method::Refer`] for a peer-initiated
    /// transfer.
    pub fn method(&self) -> &Method {
        self.request.method()
    }

    /// The request's headers (e.g. to read `Session-Expires` on a refresh).
    pub fn headers(&self) -> &Headers {
        &self.request.headers
    }

    /// The request body (e.g. an SDP re-offer or a `application/dtmf-relay`
    /// INFO payload).
    pub fn body(&self) -> &[u8] {
        &self.request.body
    }

    /// The `CSeq` method+number is in [`headers`](Self::headers); this is the
    /// raw request for callers that need full access.
    pub fn request(&self) -> &Request {
        &self.request
    }

    /// Answer with `status`, optional `extra_headers`, and an optional SDP body
    /// (sent as `application/sdp`). Returns `true` if the engine sent it.
    ///
    /// Use this to answer a re-INVITE: `200 OK` with the SDP answer for a
    /// session refresh or a peer hold, or a non-2xx to decline.
    pub async fn respond(
        self,
        status: StatusCode,
        extra_headers: Vec<rsip::Header>,
        sdp: Option<Vec<u8>>,
    ) -> bool {
        let body = sdp.map(|bytes| ResponseBody {
            content_type: "application/sdp",
            bytes,
        });
        let Some(mut response) = build_response(&self.request, status, None, None, body) else {
            return false;
        };
        for header in extra_headers {
            response.headers.push(header);
        }
        self.ua.answer(self.key, response).await
    }

    /// Answer `200 OK` with no body — the right reply for an `INFO`, or a
    /// re-INVITE you accept without renegotiating media.
    pub async fn ok(self) -> bool {
        self.respond(StatusCode::OK, Vec::new(), None).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsip::message::HeadersExt;

    fn info_request() -> Request {
        let raw = "INFO sip:bob@10.0.0.1:5060 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK-info\r\n\
             From: <sip:alice@atlanta.example.com>;tag=alice\r\n\
             To: <sip:bob@biloxi.example.com>;tag=ourtag\r\n\
             Call-ID: call-dlg\r\n\
             CSeq: 2 INFO\r\n\
             Content-Type: application/dtmf-relay\r\n\
             Content-Length: 21\r\n\r\n\
             Signal=5\nDuration=160";
        Request::try_from(raw.as_bytes()).unwrap()
    }

    #[test]
    fn exposes_method_headers_and_body() {
        // Construction needs a Ua, which needs a runtime; the accessors are
        // pure on the request, so test them on the parsed request directly.
        let req = info_request();
        assert_eq!(*req.method(), Method::Info);
        assert_eq!(req.body, b"Signal=5\nDuration=160");
        assert!(req.cseq_header().is_ok());
    }
}
