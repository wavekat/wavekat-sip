//! Build a SIP response to an inbound request — RFC 3261 §8.2.6.
//!
//! A UAS response echoes the request's `Via`, `From`, `Call-ID` and `CSeq`
//! unchanged, copies `To` (adding a local tag if the request had none), and
//! optionally carries a `Contact` and a body. This is the small bit of
//! response composition the callee and the endpoint's auto-answer need.

use rsip::headers::{ToTypedHeader, UntypedHeader};
use rsip::message::HeadersExt;
use rsip::{Header, Headers, Request, Response, StatusCode, Uri};

/// A body to attach to a response: its content type and bytes.
pub(crate) struct ResponseBody<'a> {
    pub content_type: &'a str,
    pub bytes: Vec<u8>,
}

/// Build a response to `request` with `status`.
///
/// - `to_tag`: if the request's `To` had no tag, this one is added (a UAS must
///   tag its responses to establish a dialog); ignored if `To` already carries
///   one.
/// - `contact`: added as a `Contact` header (e.g. on a 2xx so the peer can
///   route in-dialog requests back).
/// - `body`: optional SDP (or other) body with its content type.
pub(crate) fn build_response(
    request: &Request,
    status: StatusCode,
    to_tag: Option<&str>,
    contact: Option<&Uri>,
    body: Option<ResponseBody<'_>>,
) -> Option<Response> {
    let mut headers = Headers::default();

    // Via(s), From, Call-ID, CSeq are echoed verbatim. Record-Route is also
    // copied unchanged and in order (RFC 3261 §12.1.1): a UAS MUST mirror every
    // Record-Route from the request into its 2xx so the peer's reversed route
    // set (§12.1.2) sends in-dialog requests — crucially the terminating BYE —
    // back through the proxies that recorded themselves, not straight to our
    // Contact. Behind NAT our Contact is a private address, so dropping these
    // strands the peer's BYE and the call never tears down on remote hangup.
    for header in request.headers.iter() {
        match header {
            Header::Via(_)
            | Header::From(_)
            | Header::CallId(_)
            | Header::CSeq(_)
            | Header::RecordRoute(_) => {
                headers.push(header.clone());
            }
            _ => {}
        }
    }

    // To, with a local tag added when absent.
    let mut to = request.to_header().ok()?.typed().ok()?;
    if to.tag().is_none() {
        if let Some(tag) = to_tag {
            to.params.push(rsip::common::uri::param::Param::Tag(
                rsip::common::uri::param::Tag::new(tag.to_string()),
            ));
        }
    }
    headers.push(Header::To(to.into()));

    if let Some(uri) = contact {
        let contact = rsip::typed::Contact {
            display_name: None,
            uri: uri.clone(),
            params: vec![],
        };
        headers.push(Header::Contact(contact.into()));
    }

    let body_bytes = match body {
        Some(b) => {
            headers.push(Header::ContentType(rsip::headers::ContentType::new(
                b.content_type,
            )));
            b.bytes
        }
        None => Vec::new(),
    };
    headers.push(Header::ContentLength(rsip::headers::ContentLength::from(
        body_bytes.len() as u32,
    )));

    Some(Response {
        status_code: status,
        version: request.version.clone(),
        headers,
        body: body_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite() -> Request {
        let raw = "INVITE sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-r\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>\r\n\
             Call-ID: call-r\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Length: 0\r\n\r\n";
        Request::try_from(raw.as_bytes()).unwrap()
    }

    #[test]
    fn ok_echoes_dialog_headers_and_adds_to_tag() {
        let resp = build_response(
            &invite(),
            StatusCode::OK,
            Some("srvtag"),
            Some(&Uri::try_from("sip:bob@10.0.0.2:5060").unwrap()),
            Some(ResponseBody {
                content_type: "application/sdp",
                bytes: b"v=0\r\n".to_vec(),
            }),
        )
        .unwrap();

        assert_eq!(resp.status_code.code(), 200);
        assert_eq!(
            resp.to_header()
                .unwrap()
                .typed()
                .unwrap()
                .tag()
                .unwrap()
                .value(),
            "srvtag"
        );
        assert_eq!(
            resp.from_header()
                .unwrap()
                .typed()
                .unwrap()
                .tag()
                .unwrap()
                .value(),
            "alice"
        );
        assert_eq!(resp.cseq_header().unwrap().typed().unwrap().seq, 1);
        assert_eq!(resp.body, b"v=0\r\n");
        assert!(resp.headers.iter().any(|h| matches!(h, Header::Contact(_))));
    }

    #[test]
    fn ok_echoes_record_route_in_order() {
        // RFC 3261 §12.1.1: every Record-Route the proxy chain inserted must be
        // mirrored into the 2xx, in the same order, so the peer can build its
        // route set and send the in-dialog BYE back through the proxies. The
        // 2talk gateway behind a NAT exposed this: without the echo the peer's
        // BYE targeted our private Contact and the call never tore down.
        let raw = "INVITE sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-r\r\n\
             Record-Route: <sip:proxy1.example.com;lr>\r\n\
             Record-Route: <sip:proxy2.example.com;lr>\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>\r\n\
             Call-ID: call-r\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Length: 0\r\n\r\n";
        let invite = Request::try_from(raw.as_bytes()).unwrap();
        let resp = build_response(&invite, StatusCode::OK, Some("srvtag"), None, None).unwrap();

        let record_routes: Vec<String> = resp
            .headers
            .iter()
            .filter_map(|h| match h {
                Header::RecordRoute(rr) => Some(rr.value().to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(
            record_routes,
            vec![
                "<sip:proxy1.example.com;lr>".to_string(),
                "<sip:proxy2.example.com;lr>".to_string(),
            ],
            "2xx must mirror Record-Route values verbatim and in order"
        );
    }

    #[test]
    fn reject_keeps_existing_to_tag() {
        let raw = "BYE sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-b\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>;tag=bob\r\n\
             Call-ID: call-r\r\n\
             CSeq: 2 BYE\r\n\
             Content-Length: 0\r\n\r\n";
        let bye = Request::try_from(raw.as_bytes()).unwrap();
        let resp = build_response(&bye, StatusCode::OK, Some("ignored"), None, None).unwrap();
        // Existing tag is preserved, not overwritten.
        assert_eq!(
            resp.to_header()
                .unwrap()
                .typed()
                .unwrap()
                .tag()
                .unwrap()
                .value(),
            "bob"
        );
        assert_eq!(resp.body.len(), 0);
    }
}
