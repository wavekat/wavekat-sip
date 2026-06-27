//! Outbound INVITE flow on the engine — RFC 3261 §13 (UAC side).
//!
//! The second composed flow: place a call through the client INVITE
//! transaction, follow provisional responses, answer a `401`/`407` with the
//! digest orchestration, and on a 2xx build the [`Dialog`](super::dialog) and
//! send the ACK (which, for a 2xx, rides outside any transaction). A confirmed
//! call is then torn down with an in-dialog BYE.
//!
//! This is the logic the migrated `Caller` will sit on; here it is exercised
//! end-to-end against a loopback fake callee.

use std::net::SocketAddr;

use rsip::headers::{ToTypedHeader, UntypedHeader};
use rsip::message::HeadersExt;
use rsip::{Header, Headers, Method, Request, StatusCode, Uri};
use tokio::sync::mpsc;

use super::auth::{self, Credentials};
use super::dialog::Dialog;
use super::engine::{EngineHandle, Event};
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
}

/// The result of placing a call.
pub(crate) enum CallOutcome {
    /// The callee answered; the confirmed dialog is ready for media + BYE.
    /// Boxed because a `Dialog` is much larger than the other variants.
    Answered(Box<Dialog>),
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

/// Place a call: send the INVITE, follow provisional responses, answer one
/// challenge, and on a 2xx build the dialog and send the ACK.
pub(crate) async fn place_call(
    engine: &EngineHandle,
    peer: SocketAddr,
    events: &mut mpsc::Receiver<Event>,
    cfg: &CallConfig,
    first_cseq: u32,
) -> CallOutcome {
    let mut request = build_invite(cfg, first_cseq, engine.local_addr());
    if !engine.start_client(request.clone(), peer).await {
        return CallOutcome::EngineStopped;
    }
    let mut challenged = false;

    loop {
        let Some(event) = events.recv().await else {
            return CallOutcome::EngineStopped;
        };
        match event {
            Event::Response { response, .. } => {
                let code = response.status_code().code();
                if code < 200 {
                    // Provisional (100/180/183) — keep waiting for the final.
                    continue;
                }
                if (200..300).contains(&code) {
                    let Some(dialog) = Dialog::uac(&request, &response, cfg.contact.clone()) else {
                        return CallOutcome::Rejected(response.status_code().clone());
                    };
                    // ACK the 2xx outside any transaction (RFC 3261 §13.2.2.4),
                    // reusing the INVITE's CSeq number.
                    let cseq = cseq_of(&request);
                    let ack = dialog.ack_2xx(cseq);
                    engine
                        .send_out_of_dialog(rsip::SipMessage::Request(ack), peer)
                        .await;
                    return CallOutcome::Answered(Box::new(dialog));
                }
                if code == 401 || code == 407 {
                    if challenged {
                        return CallOutcome::Unauthorized;
                    }
                    challenged = true;
                    match auth::build_retry(&request, &response, cfg.creds()) {
                        Some(retry) => {
                            request = retry;
                            if !engine.start_client(request.clone(), peer).await {
                                return CallOutcome::EngineStopped;
                            }
                        }
                        None => return CallOutcome::Unauthorized,
                    }
                    continue;
                }
                // Non-2xx final: the client INVITE transaction sends the ACK.
                return CallOutcome::Rejected(response.status_code().clone());
            }
            Event::TimedOut { .. } => return CallOutcome::TimedOut,
            _ => continue,
        }
    }
}

/// Tear down a confirmed call with an in-dialog BYE; returns `true` on a 2xx.
pub(crate) async fn hangup(
    engine: &EngineHandle,
    peer: SocketAddr,
    events: &mut mpsc::Receiver<Event>,
    dialog: &mut Dialog,
) -> bool {
    let bye = dialog.new_request(Method::Bye);
    if !engine.start_client(bye, peer).await {
        return false;
    }
    loop {
        let Some(event) = events.recv().await else {
            return false;
        };
        match event {
            Event::Response { response, .. } => {
                return (200..300).contains(&response.status_code().code());
            }
            Event::TimedOut { .. } => return false,
            _ => continue,
        }
    }
}

fn cseq_of(request: &Request) -> u32 {
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
    use crate::stack::engine;
    use crate::stack::transaction::Timers;
    use crate::stack::transport::UdpTransport;
    use rsip::SipMessage;
    use std::time::Duration;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    fn config() -> CallConfig {
        CallConfig {
            target: Uri::try_from("sip:bob@example.com").unwrap(),
            from: Uri::try_from("sip:alice@example.com").unwrap(),
            contact: Uri::try_from("sip:alice@127.0.0.1:5060").unwrap(),
            from_tag: "alicetag".into(),
            call_id: "call-xyz".into(),
            sdp: b"v=0\r\n".to_vec(),
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

    fn echo_headers(req: &Request) -> String {
        format!(
            "{}\r\n{}\r\n{}\r\n{}\r\n",
            req.via_header().unwrap(),
            req.from_header().unwrap(),
            req.call_id_header().unwrap(),
            req.cseq_header().unwrap(),
        )
    }

    #[tokio::test]
    async fn call_is_answered_acked_and_hung_up() {
        let cancel = CancellationToken::new();
        let (handle, mut events) = engine::start_with_timers(
            "127.0.0.1:0".parse().unwrap(),
            fast_timers(),
            cancel.clone(),
        )
        .await
        .unwrap();
        let callee = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let callee_addr = callee.local_addr().unwrap();

        let server = tokio::spawn(async move {
            // INVITE → 180 then 200 (with Contact + To tag).
            let (msg, src) = callee.recv().await.unwrap();
            let SipMessage::Request(invite) = msg else {
                panic!("expected INVITE")
            };
            assert_eq!(*invite.method(), Method::Invite);
            let h = echo_headers(&invite);
            let ringing = format!("SIP/2.0 180 Ringing\r\n{h}To: <sip:bob@example.com>;tag=bob\r\nContent-Length: 0\r\n\r\n");
            callee
                .send_to(&SipMessage::try_from(ringing.as_bytes()).unwrap(), src)
                .await
                .unwrap();
            let ok = format!("SIP/2.0 200 OK\r\n{h}To: <sip:bob@example.com>;tag=bob\r\nContact: <sip:bob@127.0.0.1:5070>\r\nContent-Length: 0\r\n\r\n");
            callee
                .send_to(&SipMessage::try_from(ok.as_bytes()).unwrap(), src)
                .await
                .unwrap();

            // Expect the ACK.
            let (msg, _) = callee.recv().await.unwrap();
            let SipMessage::Request(ack) = msg else {
                panic!("expected ACK")
            };
            assert_eq!(*ack.method(), Method::Ack);

            // Then the BYE → 200.
            let (msg, src) = callee.recv().await.unwrap();
            let SipMessage::Request(bye) = msg else {
                panic!("expected BYE")
            };
            assert_eq!(*bye.method(), Method::Bye);
            let h = echo_headers(&bye);
            let ok = format!("SIP/2.0 200 OK\r\n{h}To: <sip:bob@example.com>;tag=bob\r\nContent-Length: 0\r\n\r\n");
            callee
                .send_to(&SipMessage::try_from(ok.as_bytes()).unwrap(), src)
                .await
                .unwrap();
        });

        let cfg = config();
        let outcome = timeout(
            Duration::from_secs(3),
            place_call(&handle, callee_addr, &mut events, &cfg, 1),
        )
        .await
        .expect("call completes");

        let mut dialog = match outcome {
            CallOutcome::Answered(d) => *d,
            _ => panic!("expected Answered"),
        };
        assert!(dialog.is_confirmed());

        let hung = timeout(
            Duration::from_secs(3),
            hangup(&handle, callee_addr, &mut events, &mut dialog),
        )
        .await
        .expect("bye completes");
        assert!(hung);

        server.await.unwrap();
        cancel.cancel();
    }

    #[tokio::test]
    async fn rejected_call_reports_status() {
        let cancel = CancellationToken::new();
        let (handle, mut events) = engine::start_with_timers(
            "127.0.0.1:0".parse().unwrap(),
            fast_timers(),
            cancel.clone(),
        )
        .await
        .unwrap();
        let callee = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let callee_addr = callee.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (msg, src) = callee.recv().await.unwrap();
            let SipMessage::Request(invite) = msg else {
                panic!("expected INVITE")
            };
            let h = echo_headers(&invite);
            let busy = format!("SIP/2.0 486 Busy Here\r\n{h}To: <sip:bob@example.com>;tag=bob\r\nContent-Length: 0\r\n\r\n");
            callee
                .send_to(&SipMessage::try_from(busy.as_bytes()).unwrap(), src)
                .await
                .unwrap();
            // The client INVITE transaction ACKs the non-2xx itself.
            let (msg, _) = callee.recv().await.unwrap();
            assert!(matches!(msg, SipMessage::Request(r) if *r.method() == Method::Ack));
        });

        let cfg = config();
        let outcome = timeout(
            Duration::from_secs(3),
            place_call(&handle, callee_addr, &mut events, &cfg, 1),
        )
        .await
        .expect("call completes");

        match outcome {
            CallOutcome::Rejected(status) => assert_eq!(status.code(), 486),
            _ => panic!("expected Rejected(486)"),
        }
        server.await.unwrap();
        cancel.cancel();
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
}
