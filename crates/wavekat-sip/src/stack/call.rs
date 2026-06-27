//! Outbound INVITE request builder + result types — RFC 3261 §13 (UAC side).
//!
//! Pure composition: `build_invite` assembles the INVITE (with the SDP offer)
//! and `CallConfig`/`CallOutcome` describe the inputs and result. The driving
//! (send, follow provisionals, answer a challenge, build the dialog and ACK)
//! lives in [`ua`](super::ua).

use std::net::SocketAddr;

use rsip::headers::{ToTypedHeader, UntypedHeader};
use rsip::message::HeadersExt;
use rsip::{Header, Headers, Method, Request, StatusCode, Uri};

use super::auth::Credentials;
use super::dialog::Dialog;
use super::transaction::gen_branch;

/// Everything needed to place a call and answer a challenge.
pub(crate) struct CallConfig {
    /// Request-URI and `To` — the callee, e.g. `sip:bob@example.com`.
    pub target: Uri,
    /// `From` — our address of record.
    pub from: Uri,
    /// Our contact — Request-URI of in-dialog requests the peer sends us.
    pub contact: Uri,
    pub from_tag: String,
    pub call_id: String,
    /// SDP offer carried in the INVITE body (empty for a late offer).
    pub sdp: Vec<u8>,
    /// Extra headers added to the INVITE (e.g. `Supported: timer` and
    /// `Session-Expires` for RFC 4028).
    pub extra_headers: Vec<Header>,
    pub username: String,
    pub password: String,
}

impl CallConfig {
    fn creds(&self) -> Credentials<'_> {
        Credentials {
            username: &self.username,
            password: &self.password,
        }
    }

    /// Credentials for answering a challenge (used by the `ua` router).
    pub(crate) fn creds_for_retry(&self) -> Credentials<'_> {
        self.creds()
    }
}

/// The result of placing a call.
pub(crate) enum CallOutcome {
    /// The callee answered; the confirmed dialog plus the 2xx response (whose
    /// body carries the SDP answer). Boxed because both are large.
    Answered {
        dialog: Box<Dialog>,
        response: Box<rsip::Response>,
    },
    /// The callee (or proxy) rejected the call with this final status.
    Rejected(StatusCode),
    /// Credentials were rejected.
    Unauthorized,
    /// No final response before the transaction timed out.
    TimedOut,
    /// The engine stopped before a result was reached.
    EngineStopped,
}

/// Compose an INVITE bound to `local_addr`, carrying the SDP offer.
pub(crate) fn build_invite(cfg: &CallConfig, cseq: u32, local_addr: SocketAddr) -> Request {
    let mut headers = Headers::default();
    headers.push(Header::Via(rsip::headers::Via::new(format!(
        "SIP/2.0/UDP {local_addr};branch={}",
        gen_branch()
    ))));
    headers.push(Header::MaxForwards(rsip::headers::MaxForwards::default()));

    let from = rsip::typed::From {
        display_name: None,
        uri: cfg.from.clone(),
        params: vec![rsip::common::uri::param::Param::Tag(
            rsip::common::uri::param::Tag::new(cfg.from_tag.clone()),
        )],
    };
    let to = rsip::typed::To {
        display_name: None,
        uri: cfg.target.clone(),
        params: vec![],
    };
    let contact = rsip::typed::Contact {
        display_name: None,
        uri: cfg.contact.clone(),
        params: vec![],
    };
    headers.push(Header::From(from.into()));
    headers.push(Header::To(to.into()));
    headers.push(Header::Contact(contact.into()));
    headers.push(Header::CallId(rsip::headers::CallId::new(
        cfg.call_id.clone(),
    )));
    headers.push(Header::CSeq(
        rsip::typed::CSeq {
            seq: cseq,
            method: Method::Invite,
        }
        .into(),
    ));
    for header in &cfg.extra_headers {
        headers.push(header.clone());
    }
    if !cfg.sdp.is_empty() {
        headers.push(Header::ContentType(rsip::headers::ContentType::new(
            "application/sdp",
        )));
    }
    headers.push(Header::ContentLength(rsip::headers::ContentLength::from(
        cfg.sdp.len() as u32,
    )));

    Request {
        method: Method::Invite,
        uri: cfg.target.clone(),
        version: rsip::Version::V2,
        headers,
        body: cfg.sdp.clone(),
    }
}

/// Build the `CANCEL` for an in-flight INVITE (RFC 3261 §9.1).
///
/// CANCEL matches the INVITE hop-by-hop, so it copies the INVITE's **top Via**
/// (same branch), Request-URI, `From`, `To` (no tag added), and `Call-ID`, with
/// the same `CSeq` number but method `CANCEL`. Returns `None` if the INVITE is
/// missing a header CANCEL must echo.
pub(crate) fn build_cancel(invite: &Request) -> Option<Request> {
    let via = invite.via_header().ok()?.clone();
    let from = invite.from_header().ok()?.clone();
    let to = invite.to_header().ok()?.clone();
    let call_id = invite.call_id_header().ok()?.clone();
    let seq = cseq_of(invite);

    let mut headers = Headers::default();
    headers.push(Header::Via(via));
    headers.push(Header::MaxForwards(rsip::headers::MaxForwards::default()));
    headers.push(Header::From(from));
    headers.push(Header::To(to));
    headers.push(Header::CallId(call_id));
    headers.push(Header::CSeq(
        rsip::typed::CSeq {
            seq,
            method: Method::Cancel,
        }
        .into(),
    ));
    headers.push(Header::ContentLength(
        rsip::headers::ContentLength::default(),
    ));

    Some(Request {
        method: Method::Cancel,
        uri: invite.uri.clone(),
        version: rsip::Version::V2,
        headers,
        body: Vec::new(),
    })
}

pub(crate) fn cseq_of(request: &Request) -> u32 {
    request
        .cseq_header()
        .ok()
        .and_then(|c| c.typed().ok())
        .map(|c| c.seq)
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CallConfig {
        CallConfig {
            target: Uri::try_from("sip:bob@example.com").unwrap(),
            from: Uri::try_from("sip:alice@example.com").unwrap(),
            contact: Uri::try_from("sip:alice@127.0.0.1:5060").unwrap(),
            from_tag: "alicetag".into(),
            call_id: "call-xyz".into(),
            sdp: b"v=0\r\n".to_vec(),
            extra_headers: Vec::new(),
            username: "alice".into(),
            password: "secret".into(),
        }
    }

    #[test]
    fn build_invite_carries_sdp() {
        let cfg = config();
        let invite = build_invite(&cfg, 1, "127.0.0.1:5060".parse().unwrap());
        assert_eq!(*invite.method(), Method::Invite);
        assert_eq!(invite.body, b"v=0\r\n");
        assert!(invite
            .headers
            .iter()
            .any(|h| matches!(h, Header::ContentType(_))));
    }

    #[test]
    fn build_invite_carries_extra_headers() {
        let mut cfg = config();
        cfg.extra_headers = vec![Header::Supported("timer".into())];
        let invite = build_invite(&cfg, 1, "127.0.0.1:5060".parse().unwrap());
        assert!(invite.to_string().contains("Supported: timer"));
    }

    #[test]
    fn build_cancel_matches_invite_branch_and_cseq() {
        let cfg = config();
        let invite = build_invite(&cfg, 4, "127.0.0.1:5060".parse().unwrap());
        let cancel = build_cancel(&invite).expect("cancel built");

        assert_eq!(*cancel.method(), Method::Cancel);
        // Same Request-URI and same top Via branch as the INVITE (hop-by-hop).
        assert_eq!(cancel.uri, invite.uri);
        let inv_branch = invite
            .via_header()
            .unwrap()
            .typed()
            .unwrap()
            .branch()
            .unwrap()
            .to_string();
        let can_branch = cancel
            .via_header()
            .unwrap()
            .typed()
            .unwrap()
            .branch()
            .unwrap()
            .to_string();
        assert_eq!(can_branch, inv_branch, "CANCEL reuses the INVITE branch");
        // Same CSeq number, method CANCEL.
        let cseq = cancel.cseq_header().unwrap().typed().unwrap();
        assert_eq!(cseq.seq, 4);
        assert_eq!(cseq.method, Method::Cancel);
    }

    #[test]
    fn cseq_of_reads_sequence() {
        let cfg = config();
        let invite = build_invite(&cfg, 7, "127.0.0.1:5060".parse().unwrap());
        assert_eq!(cseq_of(&invite), 7);
    }
}
