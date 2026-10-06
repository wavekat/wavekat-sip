//! REGISTER request builder + result types — RFC 3261 §10.
//!
//! Pure composition: `build_register` assembles the request and the
//! `RegisterConfig`/`RegisterOutcome` types describe the inputs and result.
//! The driving (send, await, answer a challenge over the shared engine) lives
//! in [`ua`](super::ua); the digest math is [`auth`](super::auth).

use std::net::SocketAddr;

use rsip::headers::UntypedHeader;
use rsip::message::HeadersExt;
use rsip::{Header, Headers, Method, Request, StatusCode, Uri};

use super::auth::Credentials;
use super::transaction::{gen_branch, transport_of, via_value};

/// Everything needed to compose a REGISTER and answer a challenge.
pub(crate) struct RegisterConfig {
    /// Request-URI — the registrar domain, e.g. `sip:example.com`.
    pub registrar_uri: Uri,
    /// Address of record — `From`/`To`, e.g. `sip:alice@example.com`.
    pub aor: Uri,
    /// Our contact — where we receive calls, e.g. `sip:alice@10.0.0.1:5060`.
    pub contact: Uri,
    /// Stable `From` tag for this registration.
    pub from_tag: String,
    /// Stable `Call-ID` for this registration.
    pub call_id: String,
    /// Requested registration lifetime in seconds.
    pub expires: u32,
    pub username: String,
    pub password: String,
}

impl RegisterConfig {
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

/// The result of a register attempt.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RegisterOutcome {
    /// Registered; the server granted this lifetime (seconds).
    Registered { expires: u32 },
    /// Credentials rejected (a second challenge, or an unanswerable one).
    Unauthorized,
    /// `423 Interval Too Brief`: the requested lifetime is below the
    /// registrar's minimum, which it named in `Min-Expires` (RFC 3261 §10.3
    /// step 7). Retrying at that interval is the caller's call — RFC 3261
    /// §10.2.8.
    IntervalTooBrief { min_expires: u32 },
    /// The server returned a non-2xx, non-auth final response.
    Failed(StatusCode),
    /// No final response before the transaction timed out.
    TimedOut,
    /// The engine stopped before a result was reached.
    EngineStopped,
}

/// One register attempt: what it reached, and the `CSeq` of the last REGISTER
/// it actually put on the wire.
///
/// Answering a challenge sends a second REGISTER at the next sequence number
/// (RFC 3261 §8.1.3.5), so the `CSeq` handed in is not necessarily the one the
/// registrar last saw. §10.2 requires every REGISTER sharing a `Call-ID` to
/// increment it, so the caller has to resume from where the wire left off, not
/// from where it started.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RegisterAttempt {
    pub outcome: RegisterOutcome,
    pub last_cseq: u32,
}

/// Build a REGISTER request bound to `local_addr` (for the `Via` sent-by) with
/// the given CSeq.
pub(crate) fn build_register(cfg: &RegisterConfig, cseq: u32, local_addr: SocketAddr) -> Request {
    let mut headers = Headers::default();
    headers.push(Header::Via(rsip::headers::Via::new(via_value(
        transport_of(&cfg.contact),
        local_addr,
        &gen_branch(),
    ))));
    headers.push(Header::MaxForwards(rsip::headers::MaxForwards::default()));

    let from = rsip::typed::From {
        display_name: None,
        uri: cfg.aor.clone(),
        params: vec![rsip::common::uri::param::Param::Tag(
            rsip::common::uri::param::Tag::new(cfg.from_tag.clone()),
        )],
    };
    let to = rsip::typed::To {
        display_name: None,
        uri: cfg.aor.clone(),
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
            method: Method::Register,
        }
        .into(),
    ));
    headers.push(Header::Expires(rsip::headers::Expires::from(cfg.expires)));
    headers.push(Header::ContentLength(
        rsip::headers::ContentLength::default(),
    ));

    Request {
        method: Method::Register,
        uri: cfg.registrar_uri.clone(),
        version: rsip::Version::V2,
        headers,
        body: Vec::new(),
    }
}

/// Build a REGISTER binding *query* (RFC 3261 §10.2.3): the same request as
/// [`build_register`] but with no `Contact` and no `Expires`. A registrar
/// answers a query with the current bindings and cannot add or remove one
/// because of it, which makes it a side-effect-free way to ask "is a SIP
/// registrar listening here?".
pub(crate) fn build_register_query(
    cfg: &RegisterConfig,
    cseq: u32,
    local_addr: SocketAddr,
) -> Request {
    let mut request = build_register(cfg, cseq, local_addr);
    request
        .headers
        .retain(|h| !matches!(h, Header::Contact(_) | Header::Expires(_)));
    request
}

/// The answer to an unauthenticated binding query — see
/// [`Registrar::probe`](crate::Registrar::probe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterProbe {
    /// A final response arrived, so a SIP server is listening on this
    /// transport. A `401`/`407` challenge is the usual answer; it is
    /// reported, never answered.
    Answered {
        /// The final response's status code.
        status: u16,
    },
    /// No final response before the transaction timed out.
    TimedOut,
    /// The engine stopped before a response arrived (cancelled, or the
    /// stream transport closed).
    EngineStopped,
}

/// The lifetime the server granted, from the response `Expires` header.
pub(crate) fn granted_expires(response: &rsip::Response) -> Option<u32> {
    response.expires_header()?.seconds().ok()
}

/// The shortest lifetime the registrar will accept, from a `423`'s
/// `Min-Expires` header (RFC 3261 §20.23). `None` when the header is missing —
/// mandatory on a `423`, but a header we cannot read is one we cannot obey.
pub(crate) fn min_expires(response: &rsip::Response) -> Option<u32> {
    response.min_expires_header()?.seconds().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsip::headers::ToTypedHeader;

    fn config() -> RegisterConfig {
        RegisterConfig {
            registrar_uri: Uri::try_from("sip:example.com").unwrap(),
            aor: Uri::try_from("sip:alice@example.com").unwrap(),
            contact: Uri::try_from("sip:alice@10.0.0.1:5060").unwrap(),
            from_tag: "alicetag".into(),
            call_id: "reg-call".into(),
            expires: 60,
            username: "alice".into(),
            password: "secret".into(),
        }
    }

    #[test]
    fn build_register_has_expected_shape() {
        let cfg = config();
        let req = build_register(&cfg, 1, "10.0.0.1:5060".parse().unwrap());
        assert_eq!(*req.method(), Method::Register);
        assert_eq!(req.uri.to_string(), "sip:example.com");
        assert_eq!(req.cseq_header().unwrap().typed().unwrap().seq, 1);
        assert_eq!(
            req.from_header()
                .unwrap()
                .typed()
                .unwrap()
                .tag()
                .unwrap()
                .value(),
            "alicetag"
        );
        assert_eq!(req.expires_header().unwrap().seconds().unwrap(), 60);
        // RFC 3581: REGISTER advertises rport so the registrar binds our public
        // address — the NAT pinhole that later inbound calls and in-dialog
        // requests are routed through.
        let via = req.via_header().unwrap().to_string();
        assert!(via.contains(";rport"), "REGISTER Via lacks rport: {via}");
    }

    /// A binding query carries neither `Contact` nor `Expires` — RFC 3261
    /// §10.2.3 — so it cannot create or remove a binding. Everything else
    /// (Via with rport, From tag, Call-ID, CSeq) matches a normal REGISTER.
    #[test]
    fn build_register_query_omits_contact_and_expires() {
        let cfg = config();
        let req = build_register_query(&cfg, 7, "10.0.0.1:5060".parse().unwrap());
        assert_eq!(*req.method(), Method::Register);
        assert!(
            req.contact_header().is_err(),
            "query must not carry Contact"
        );
        assert!(
            req.expires_header().is_none(),
            "query must not carry Expires"
        );
        assert_eq!(req.cseq_header().unwrap().typed().unwrap().seq, 7);
        assert_eq!(
            req.call_id_header().unwrap().to_string(),
            "Call-ID: reg-call"
        );
        assert!(req.via_header().unwrap().to_string().contains(";rport"));
    }

    /// RFC 3261 §10.3 step 7: a `423` names the shortest lifetime the
    /// registrar will accept, which §10.2.8 says to retry at.
    #[test]
    fn min_expires_reads_the_header() {
        let raw =
            "SIP/2.0 423 Interval Too Brief\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-x\r\n\
             From: <sip:a@b>;tag=a\r\nTo: <sip:a@b>;tag=s\r\nCall-ID: c\r\nCSeq: 1 REGISTER\r\n\
             Min-Expires: 3600\r\nContent-Length: 0\r\n\r\n";
        let resp = rsip::Response::try_from(raw.as_bytes()).unwrap();
        assert_eq!(min_expires(&resp), Some(3600));
    }

    /// A `423` without the mandatory header names nothing to adjust to, and a
    /// non-numeric one is no better — both must read as absent rather than
    /// being guessed at.
    #[test]
    fn min_expires_is_none_when_absent_or_unparsable() {
        let response = |extra: &str| {
            let raw = format!(
                "SIP/2.0 423 Interval Too Brief\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-x\r\n\
                 From: <sip:a@b>;tag=a\r\nTo: <sip:a@b>;tag=s\r\nCall-ID: c\r\nCSeq: 1 REGISTER\r\n\
                 {extra}Content-Length: 0\r\n\r\n"
            );
            rsip::Response::try_from(raw.as_bytes()).unwrap()
        };
        assert_eq!(min_expires(&response("")), None);
        assert_eq!(min_expires(&response("Min-Expires: soon\r\n")), None);
    }

    #[test]
    fn granted_expires_reads_the_header() {
        let raw = "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-x\r\n\
             From: <sip:a@b>;tag=a\r\nTo: <sip:a@b>;tag=s\r\nCall-ID: c\r\nCSeq: 1 REGISTER\r\n\
             Expires: 120\r\nContent-Length: 0\r\n\r\n";
        let resp = rsip::Response::try_from(raw.as_bytes()).unwrap();
        assert_eq!(granted_expires(&resp), Some(120));
    }
}
