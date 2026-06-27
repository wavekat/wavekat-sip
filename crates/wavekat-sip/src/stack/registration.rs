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
use super::transaction::gen_branch;

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
    /// The server returned a non-2xx, non-auth final response.
    Failed(StatusCode),
    /// No final response before the transaction timed out.
    TimedOut,
    /// The engine stopped before a result was reached.
    EngineStopped,
}

/// Build a REGISTER request bound to `local_addr` (for the `Via` sent-by) with
/// the given CSeq.
pub(crate) fn build_register(cfg: &RegisterConfig, cseq: u32, local_addr: SocketAddr) -> Request {
    let mut headers = Headers::default();
    headers.push(Header::Via(rsip::headers::Via::new(format!(
        "SIP/2.0/UDP {local_addr};branch={}",
        gen_branch()
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

/// The lifetime the server granted, from the response `Expires` header.
pub(crate) fn granted_expires(response: &rsip::Response) -> Option<u32> {
    response.expires_header()?.seconds().ok()
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
