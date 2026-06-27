//! Dialogs — RFC 3261 §12.
//!
//! A dialog is the peer-to-peer relationship established by an INVITE/2xx: it
//! pins the Call-ID, the local/remote tags and CSeqs, the remote target
//! (peer Contact), and — crucially — the **route set** captured from
//! `Record-Route`. Every in-dialog request (BYE, re-INVITE, INFO) is built
//! from this state.
//!
//! ## The route-set bug this layer fixes
//!
//! The defect that motivated the whole clean-room engine was an in-dialog
//! re-INVITE's ACK/route being addressed straight to the Contact instead of
//! through the stored route set, breaking hold/resume behind a proxy/SBC.
//! Here that cannot happen: the route set is captured **once** at dialog
//! establishment and [`Dialog::new_request`] replays it on *every* in-dialog
//! request, regardless of what later responses carry (a re-INVITE 2xx with no
//! `Record-Route` does not erase it). The remote target is the Request-URI;
//! the route set is the `Route` headers — never conflated.
//!
//! Loose routing (`;lr`, universal in modern proxies) is assumed: Request-URI
//! = remote target, `Route` = the stored set. Strict routing (legacy) is out
//! of scope per the plan.

use rsip::common::uri::param::{Param, Tag};
use rsip::common::uri::{UriWithParams, UriWithParamsList};
use rsip::headers::{ToTypedHeader, UntypedHeader};
use rsip::message::HeadersExt;
use rsip::{Header, Headers, Method, Request, Response, Uri};

use super::transaction::gen_branch;

/// One end of a dialog: identity (display name + URI) plus its dialog tag.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Party {
    display_name: Option<String>,
    uri: Uri,
    tag: String,
}

/// Identifies a dialog: Call-ID + local tag + remote tag (RFC 3261 §12).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct DialogId {
    pub call_id: String,
    pub local_tag: String,
    pub remote_tag: String,
}

impl DialogId {
    /// The dialog an inbound in-dialog request belongs to, from our point of
    /// view: our tag is the request's `To` tag, the peer's is its `From` tag.
    pub(crate) fn from_request(request: &Request) -> Option<Self> {
        let to = request.to_header().ok()?.typed().ok()?;
        let from = request.from_header().ok()?.typed().ok()?;
        Some(Self {
            call_id: request.call_id_header().ok()?.value().to_string(),
            local_tag: to.tag()?.value().to_string(),
            remote_tag: from.tag()?.value().to_string(),
        })
    }
}

/// A confirmed (or early) dialog and the state needed to build in-dialog
/// requests through it.
pub(crate) struct Dialog {
    call_id: String,
    /// Us — placed in `From` on requests we send.
    local: Party,
    /// The peer — placed in `To` on requests we send.
    remote: Party,
    /// Our Contact: the `Contact` header and `Via` sent-by on our requests.
    local_contact: Uri,
    /// The peer's Contact: the Request-URI of our in-dialog requests.
    remote_target: Uri,
    /// Captured route set, already oriented for sending (UAC: reversed).
    route_set: Vec<UriWithParams>,
    /// CSeq of the last request we sent in this dialog.
    local_seq: u32,
    /// `true` once established by a 2xx; `false` for an early (1xx) dialog.
    confirmed: bool,
}

impl Dialog {
    /// Create the UAC-side dialog from the INVITE we sent and the response
    /// that established it (a 2xx, or a 1xx carrying a To tag for an early
    /// dialog). Returns `None` if the response lacks the remote tag or Contact
    /// a dialog requires.
    pub(crate) fn uac(invite: &Request, response: &Response, local_contact: Uri) -> Option<Self> {
        let from = invite.from_header().ok()?.typed().ok()?;
        let to = response.to_header().ok()?.typed().ok()?;
        let cseq = invite.cseq_header().ok()?.typed().ok()?;

        // UAC stores the route set in reverse of the response's Record-Route.
        let mut route_set = collect_routes(response.headers.iter());
        route_set.reverse();

        Some(Self {
            call_id: invite.call_id_header().ok()?.value().to_string(),
            local: Party {
                display_name: from.display_name.clone(),
                uri: from.uri.clone(),
                tag: tag_of(&from.params)?,
            },
            remote: Party {
                display_name: to.display_name.clone(),
                uri: to.uri.clone(),
                tag: tag_of(&to.params)?,
            },
            local_contact,
            remote_target: response.contact_header().ok()?.typed().ok()?.uri,
            route_set,
            local_seq: cseq.seq,
            confirmed: response.status_code().code() >= 200,
        })
    }

    /// Create the UAS-side dialog from an inbound INVITE and the local tag we
    /// place on our answer. We are the callee, so the request's `From` is the
    /// peer and its `To` (plus our tag) is us.
    pub(crate) fn uas(invite: &Request, local_tag: String, local_contact: Uri) -> Option<Self> {
        let from = invite.from_header().ok()?.typed().ok()?;
        let to = invite.to_header().ok()?.typed().ok()?;

        // UAS stores the route set in the order of the request's Record-Route.
        let route_set = collect_routes(invite.headers.iter());

        Some(Self {
            call_id: invite.call_id_header().ok()?.value().to_string(),
            local: Party {
                display_name: to.display_name.clone(),
                uri: to.uri.clone(),
                tag: local_tag,
            },
            remote: Party {
                display_name: from.display_name.clone(),
                uri: from.uri.clone(),
                tag: tag_of(&from.params)?,
            },
            local_contact,
            remote_target: invite.contact_header().ok()?.typed().ok()?.uri,
            route_set,
            // Our first in-dialog request will be CSeq 1.
            local_seq: 0,
            confirmed: true,
        })
    }

    /// This dialog's identity.
    pub(crate) fn id(&self) -> DialogId {
        DialogId {
            call_id: self.call_id.clone(),
            local_tag: self.local.tag.clone(),
            remote_tag: self.remote.tag.clone(),
        }
    }

    pub(crate) fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// Promote an early dialog to confirmed when its 2xx arrives.
    pub(crate) fn confirm(&mut self) {
        self.confirmed = true;
    }

    pub(crate) fn remote_target(&self) -> &Uri {
        &self.remote_target
    }

    /// Build the next in-dialog request (BYE, re-INVITE, INFO, …).
    ///
    /// Increments the local CSeq, addresses the Request-URI to the remote
    /// target, and replays the stored route set as `Route` headers. The caller
    /// adds any body (e.g. SDP for a re-INVITE) and content headers.
    pub(crate) fn new_request(&mut self, method: Method) -> Request {
        self.local_seq += 1;
        let branch = gen_branch();

        let mut headers = Headers::default();
        // Via sent-by is our own contact address; UDP is our only transport.
        let host = self.local_contact.host_with_port.to_string();
        headers.push(Header::Via(rsip::headers::Via::new(format!(
            "SIP/2.0/UDP {host};branch={branch}"
        ))));
        headers.push(Header::MaxForwards(rsip::headers::MaxForwards::default()));

        let from = rsip::typed::From {
            display_name: self.local.display_name.clone(),
            uri: self.local.uri.clone(),
            params: vec![Param::Tag(Tag::new(self.local.tag.clone()))],
        };
        let to = rsip::typed::To {
            display_name: self.remote.display_name.clone(),
            uri: self.remote.uri.clone(),
            params: vec![Param::Tag(Tag::new(self.remote.tag.clone()))],
        };
        headers.push(Header::From(from.into()));
        headers.push(Header::To(to.into()));
        headers.push(Header::CallId(rsip::headers::CallId::new(
            self.call_id.clone(),
        )));
        headers.push(Header::CSeq(
            rsip::typed::CSeq {
                seq: self.local_seq,
                method,
            }
            .into(),
        ));

        // Replay the stored route set — this is the bug fix: it is reused on
        // *every* in-dialog request, never recomputed from a Contact.
        if !self.route_set.is_empty() {
            let list: UriWithParamsList = self.route_set.clone().into();
            headers.push(Header::Route(rsip::typed::Route(list).into()));
        }

        let contact = rsip::typed::Contact {
            display_name: None,
            uri: self.local_contact.clone(),
            params: vec![],
        };
        headers.push(Header::Contact(contact.into()));
        headers.push(Header::ContentLength(
            rsip::headers::ContentLength::default(),
        ));

        Request {
            method,
            uri: self.remote_target.clone(),
            version: rsip::Version::V2,
            headers,
            body: Vec::new(),
        }
    }
}

/// Pull the tag value out of a header's params.
fn tag_of(params: &[Param]) -> Option<String> {
    params.iter().find_map(|p| match p {
        Param::Tag(tag) => Some(tag.value().to_string()),
        _ => None,
    })
}

/// Collect every `Record-Route` entry across the message's headers, in order.
fn collect_routes<'a>(headers: impl Iterator<Item = &'a Header>) -> Vec<UriWithParams> {
    let mut routes = Vec::new();
    for header in headers {
        if let Header::RecordRoute(rr) = header {
            if let Ok(typed) = rr.typed() {
                routes.extend(typed.uris().iter().cloned());
            }
        }
    }
    routes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite() -> Request {
        let raw = "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-inv\r\n\
             Record-Route: <sip:p1.example.com;lr>\r\n\
             From: \"Alice\" <sip:alice@atlanta.example.com>;tag=alice\r\n\
             To: <sip:bob@biloxi.example.com>\r\n\
             Contact: <sip:alice@10.0.0.1:5060>\r\n\
             Call-ID: call-dlg\r\n\
             CSeq: 314 INVITE\r\n\
             Content-Length: 0\r\n\r\n";
        Request::try_from(raw.as_bytes()).unwrap()
    }

    fn ok_response() -> Response {
        // Two Record-Route entries: UAC must reverse them.
        let raw = "SIP/2.0 200 OK\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-inv\r\n\
             Record-Route: <sip:p1.example.com;lr>\r\n\
             Record-Route: <sip:p2.example.com;lr>\r\n\
             From: \"Alice\" <sip:alice@atlanta.example.com>;tag=alice\r\n\
             To: <sip:bob@biloxi.example.com>;tag=bob\r\n\
             Contact: <sip:bob@192.168.9.9:5060>\r\n\
             Call-ID: call-dlg\r\n\
             CSeq: 314 INVITE\r\n\
             Content-Length: 0\r\n\r\n";
        Response::try_from(raw.as_bytes()).unwrap()
    }

    fn local_contact() -> Uri {
        Uri::try_from("sip:alice@10.0.0.1:5060").unwrap()
    }

    #[test]
    fn uac_dialog_captures_identity_and_target() {
        let dialog = Dialog::uac(&invite(), &ok_response(), local_contact()).unwrap();
        assert!(dialog.is_confirmed());
        assert_eq!(
            dialog.id(),
            DialogId {
                call_id: "call-dlg".into(),
                local_tag: "alice".into(),
                remote_tag: "bob".into(),
            }
        );
        assert_eq!(
            dialog.remote_target().to_string(),
            "sip:bob@192.168.9.9:5060"
        );
    }

    #[test]
    fn in_dialog_request_uses_target_route_set_and_tags() {
        let mut dialog = Dialog::uac(&invite(), &ok_response(), local_contact()).unwrap();
        let bye = dialog.new_request(Method::Bye);

        // Request-URI is the remote target, not a route.
        assert_eq!(bye.uri.to_string(), "sip:bob@192.168.9.9:5060");
        assert_eq!(*bye.method(), Method::Bye);

        // CSeq advanced from the INVITE's 314 → 315, method BYE.
        let cseq = bye.cseq_header().unwrap().typed().unwrap();
        assert_eq!(cseq.seq, 315);
        assert_eq!(cseq.method, Method::Bye);

        // From carries our tag, To the remote tag.
        assert_eq!(
            bye.from_header()
                .unwrap()
                .typed()
                .unwrap()
                .tag()
                .unwrap()
                .value(),
            "alice"
        );
        assert_eq!(
            bye.to_header()
                .unwrap()
                .typed()
                .unwrap()
                .tag()
                .unwrap()
                .value(),
            "bob"
        );

        // Route set present and REVERSED for the UAC: p2 before p1.
        let route = bye
            .headers
            .iter()
            .find_map(|h| match h {
                Header::Route(r) => Some(r.to_string()),
                _ => None,
            })
            .expect("Route header present");
        let p2 = route.find("p2").expect("p2 in route");
        let p1 = route.find("p1").expect("p1 in route");
        assert!(p2 < p1, "UAC route set must be reversed: {route}");

        // Fresh transaction branch.
        let branch = bye
            .via_header()
            .unwrap()
            .typed()
            .unwrap()
            .branch()
            .unwrap()
            .to_string();
        assert!(branch.starts_with("z9hG4bK"));
    }

    #[test]
    fn route_set_is_replayed_on_every_request() {
        // The regression guard: a second in-dialog request still carries the
        // route set captured at establishment (never dropped to the Contact).
        let mut dialog = Dialog::uac(&invite(), &ok_response(), local_contact()).unwrap();
        let _bye = dialog.new_request(Method::Bye);
        let reinvite = dialog.new_request(Method::Invite);
        assert!(reinvite
            .headers
            .iter()
            .any(|h| matches!(h, Header::Route(_))));
        // And the CSeq keeps advancing.
        assert_eq!(reinvite.cseq_header().unwrap().typed().unwrap().seq, 316);
    }

    #[test]
    fn uas_dialog_orients_parties_and_matches_inbound() {
        let dialog = Dialog::uas(&invite(), "ourtag".into(), local_contact()).unwrap();
        // We are the callee: remote is the caller (alice), local is us (bob)+tag.
        let id = dialog.id();
        assert_eq!(id.local_tag, "ourtag");
        assert_eq!(id.remote_tag, "alice");

        // An inbound in-dialog request (the peer's BYE) maps to this dialog:
        // its To tag is ours, its From tag is theirs.
        let bye_raw = "BYE sip:bob@10.0.0.1:5060 SIP/2.0\r\n\
             Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK-bye\r\n\
             From: \"Alice\" <sip:alice@atlanta.example.com>;tag=alice\r\n\
             To: <sip:bob@biloxi.example.com>;tag=ourtag\r\n\
             Call-ID: call-dlg\r\n\
             CSeq: 1 BYE\r\n\
             Content-Length: 0\r\n\r\n";
        let inbound = Request::try_from(bye_raw.as_bytes()).unwrap();
        assert_eq!(DialogId::from_request(&inbound), Some(dialog.id()));
    }

    #[test]
    fn early_dialog_from_provisional_is_not_confirmed() {
        let raw = "SIP/2.0 180 Ringing\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-inv\r\n\
             From: \"Alice\" <sip:alice@atlanta.example.com>;tag=alice\r\n\
             To: <sip:bob@biloxi.example.com>;tag=bob\r\n\
             Contact: <sip:bob@192.168.9.9:5060>\r\n\
             Call-ID: call-dlg\r\n\
             CSeq: 314 INVITE\r\n\
             Content-Length: 0\r\n\r\n";
        let ringing = Response::try_from(raw.as_bytes()).unwrap();
        let mut dialog = Dialog::uac(&invite(), &ringing, local_contact()).unwrap();
        assert!(!dialog.is_confirmed());
        dialog.confirm();
        assert!(dialog.is_confirmed());
    }
}
