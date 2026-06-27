//! REGISTER flow on the engine — RFC 3261 §10.
//!
//! This is the first *composed* flow on the clean-room stack: it drives a
//! non-INVITE client transaction ([`transaction`](super::transaction)) over
//! the UDP [`engine`](super::engine), and answers a `401`/`407` challenge with
//! the digest [`auth`](super::auth) orchestration. It is the logic the
//! migrated `Registrar` will sit on; here it is exercised end-to-end against a
//! loopback fake registrar.

use std::net::SocketAddr;

use rsip::headers::UntypedHeader;
use rsip::message::HeadersExt;
use rsip::{Header, Headers, Method, Request, StatusCode, Uri};
use tokio::sync::mpsc;

use super::auth::{self, Credentials};
use super::engine::{EngineHandle, Event};
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

/// Drive one registration to completion: send REGISTER, answer a single
/// `401`/`407` challenge, and report the outcome.
///
/// `events` must be the engine's event stream; this flow assumes it is the
/// only one in flight (the migrated endpoint adds per-transaction routing).
pub(crate) async fn drive_register(
    engine: &EngineHandle,
    peer: SocketAddr,
    events: &mut mpsc::Receiver<Event>,
    cfg: &RegisterConfig,
    first_cseq: u32,
) -> RegisterOutcome {
    let mut request = build_register(cfg, first_cseq, engine.local_addr());
    if !engine.start_client(request.clone(), peer).await {
        return RegisterOutcome::EngineStopped;
    }
    let mut challenged = false;

    loop {
        let Some(event) = events.recv().await else {
            return RegisterOutcome::EngineStopped;
        };
        match event {
            Event::Response { response, .. } => {
                let code = response.status_code().code();
                if (200..300).contains(&code) {
                    return RegisterOutcome::Registered {
                        expires: granted_expires(&response).unwrap_or(cfg.expires),
                    };
                }
                if code == 401 || code == 407 {
                    if challenged {
                        // A second challenge means our credentials were rejected.
                        return RegisterOutcome::Unauthorized;
                    }
                    challenged = true;
                    match auth::build_retry(&request, &response, cfg.creds()) {
                        Some(retry) => {
                            request = retry;
                            if !engine.start_client(request.clone(), peer).await {
                                return RegisterOutcome::EngineStopped;
                            }
                        }
                        None => return RegisterOutcome::Unauthorized,
                    }
                    continue;
                }
                return RegisterOutcome::Failed(response.status_code().clone());
            }
            Event::TimedOut { .. } => return RegisterOutcome::TimedOut,
            // Terminated arrives after the final response is delivered; ignore.
            _ => continue,
        }
    }
}

/// The lifetime the server granted, from the response `Expires` header.
fn granted_expires(response: &rsip::Response) -> Option<u32> {
    response.expires_header()?.seconds().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::engine;
    use crate::stack::transaction::Timers;
    use crate::stack::transport::UdpTransport;
    use rsip::headers::ToTypedHeader;
    use rsip::SipMessage;
    use std::time::Duration;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

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

    fn fast_timers() -> Timers {
        Timers {
            t1: Duration::from_millis(1),
            t2: Duration::from_millis(4),
            t4: Duration::from_millis(5),
        }
    }

    /// Reply to a received REGISTER: 401 challenge if it has no Authorization,
    /// else 200 OK. Returns the granted Expires used in the 200.
    fn reply(register: &Request, has_auth: bool) -> String {
        let via = register.via_header().unwrap().to_string();
        let from = register.from_header().unwrap().to_string();
        let to = register.to_header().unwrap().to_string();
        let call_id = register.call_id_header().unwrap().to_string();
        let cseq = register.cseq_header().unwrap().to_string();
        if has_auth {
            format!(
                "SIP/2.0 200 OK\r\n{via}\r\n{from}\r\n{to};tag=srv\r\n{call_id}\r\n{cseq}\r\n\
                 Expires: 60\r\nContent-Length: 0\r\n\r\n"
            )
        } else {
            format!(
                "SIP/2.0 401 Unauthorized\r\n{via}\r\n{from}\r\n{to};tag=srv\r\n{call_id}\r\n{cseq}\r\n\
                 WWW-Authenticate: Digest realm=\"example.com\", nonce=\"abc123\", qop=\"auth\"\r\n\
                 Content-Length: 0\r\n\r\n"
            )
        }
    }

    #[tokio::test]
    async fn register_succeeds_after_digest_challenge() {
        let cancel = CancellationToken::new();
        let (handle, mut events) = engine::start_with_timers(
            "127.0.0.1:0".parse().unwrap(),
            fast_timers(),
            cancel.clone(),
        )
        .await
        .unwrap();

        let registrar = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let registrar_addr = registrar.local_addr().unwrap();

        // Fake registrar: challenge the first REGISTER, accept the second.
        let server = tokio::spawn(async move {
            // First REGISTER → 401.
            let (msg, src) = registrar.recv().await.unwrap();
            let SipMessage::Request(req1) = msg else {
                panic!("expected REGISTER")
            };
            assert!(req1.authorization_header().is_none());
            let resp: SipMessage = rsip::Response::try_from(reply(&req1, false).as_bytes())
                .unwrap()
                .into();
            registrar.send_to(&resp, src).await.unwrap();

            // Second REGISTER (now authorized) → 200.
            let (msg, src) = registrar.recv().await.unwrap();
            let SipMessage::Request(req2) = msg else {
                panic!("expected REGISTER")
            };
            assert!(req2.authorization_header().is_some());
            let resp: SipMessage = rsip::Response::try_from(reply(&req2, true).as_bytes())
                .unwrap()
                .into();
            registrar.send_to(&resp, src).await.unwrap();
        });

        let cfg = config();
        let outcome = timeout(
            Duration::from_secs(3),
            drive_register(&handle, registrar_addr, &mut events, &cfg, 1),
        )
        .await
        .expect("register completes");

        assert_eq!(outcome, RegisterOutcome::Registered { expires: 60 });
        server.await.unwrap();
        cancel.cancel();
    }

    #[tokio::test]
    async fn rejected_credentials_yield_unauthorized() {
        let cancel = CancellationToken::new();
        let (handle, mut events) = engine::start_with_timers(
            "127.0.0.1:0".parse().unwrap(),
            fast_timers(),
            cancel.clone(),
        )
        .await
        .unwrap();
        let registrar = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let registrar_addr = registrar.local_addr().unwrap();

        // Always challenge — credentials never accepted.
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (msg, src) = registrar.recv().await.unwrap();
                let SipMessage::Request(req) = msg else {
                    panic!("expected REGISTER")
                };
                let resp: SipMessage = rsip::Response::try_from(reply(&req, false).as_bytes())
                    .unwrap()
                    .into();
                registrar.send_to(&resp, src).await.unwrap();
            }
        });

        let cfg = config();
        let outcome = timeout(
            Duration::from_secs(3),
            drive_register(&handle, registrar_addr, &mut events, &cfg, 1),
        )
        .await
        .expect("register completes");

        assert_eq!(outcome, RegisterOutcome::Unauthorized);
        server.await.unwrap();
        cancel.cancel();
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
}
