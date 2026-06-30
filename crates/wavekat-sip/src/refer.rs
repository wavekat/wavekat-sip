//! Call transfer primitives — `REFER` (RFC 3515) for blind and attended
//! transfer, the latter with `Replaces` (RFC 3891).
//!
//! A blind transfer is one in-dialog `REFER` carrying a `Refer-To` header with
//! the transfer target's URI: the *transferor* (us) asks the *transferee* (the
//! far end) to place a fresh call to the *transfer target*. The transferee
//! accepts with `202 Accepted`, then reports progress back over an implicit
//! subscription as a sequence of `NOTIFY`s whose body is a
//! `message/sipfrag` (RFC 3420) status line — `SIP/2.0 100 Trying`, then a
//! final `SIP/2.0 200 OK` (the target answered) or a failure status.
//!
//! An **attended** transfer is the same in-dialog `REFER` to the transferee,
//! except the `Refer-To` URI embeds a `Replaces` header (RFC 3891) naming a
//! dialog the transferor *already established* to the target during a
//! consultation call. The transferee's `INVITE` then replaces that leg rather
//! than ringing the target afresh, so the held party and the consulted target
//! are connected on the call the target already accepted.
//!
//! This module is the wire-format glue only: it builds the `Refer-To` header
//! and parses a sipfrag status line. The `REFER` request itself goes out
//! through [`Call::blind_transfer`](crate::Call::blind_transfer) /
//! [`Call::attended_transfer`](crate::Call::attended_transfer); the `NOTIFY`s
//! arrive on the call's [`InboundRequests`](crate::InboundRequests) stream (the
//! consumer reads each body with [`parse_sipfrag_status`]).

use rsip::{Header, Uri};

/// The dialog-identity triple (RFC 3261 §12) the consumer reads off the
/// consultation [`Call`](crate::Call) so it can be named in an attended
/// transfer's `Replaces` (RFC 3891).
///
/// These are *our* view of the consultation dialog: `local_tag` is the tag we
/// placed in `From`, `remote_tag` the target's tag (its `To` tag in our
/// requests). [`refer_to_with_replaces`] swaps them into the target's frame of
/// reference when it builds the header — see there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialogTriplet {
    /// The dialog's `Call-ID` (identical on both peers).
    pub call_id: String,
    /// Our local tag (`From` tag on requests we send in this dialog).
    pub local_tag: String,
    /// The target's tag (`To` tag on requests we send in this dialog).
    pub remote_tag: String,
}

/// Build the `Refer-To` header naming the blind-transfer target.
///
/// RFC 3515 §2.1: the header value is the target URI in name-addr/addr-spec
/// form. We emit the bare addr-spec (`Refer-To: <sip:carol@example.com>`),
/// which every compliant transferee accepts.
pub fn refer_to_header(target: &Uri) -> Header {
    Header::Other("Refer-To".into(), format!("<{target}>"))
}

/// Build the `Refer-To` header for an **attended** transfer: the target URI
/// with an embedded `Replaces` header (RFC 3891) identifying the consultation
/// dialog the transferee should take over.
///
/// The `Replaces` value is `call-id;to-tag=…;from-tag=…` **from the target's
/// point of view** — so our consultation dialog's `remote_tag` (the target's
/// own tag) becomes `to-tag`, and our `local_tag` becomes `from-tag`. The whole
/// value is percent-escaped and carried as a URI header, e.g.
/// `Refer-To: <sip:bob@biloxi?Replaces=call-2%3Bto-tag%3Dbob%3Bfrom-tag%3Dus>`
/// (RFC 3891 §4).
pub fn refer_to_with_replaces(target: &Uri, replaces: &DialogTriplet) -> Header {
    // From the target's frame: its tag is our `remote_tag` (the to-tag), ours is
    // the from-tag. This swap is the whole subtlety of RFC 3891 dialog matching.
    let raw = format!(
        "{};to-tag={};from-tag={}",
        replaces.call_id, replaces.remote_tag, replaces.local_tag
    );
    let escaped = escape_uri_header_value(&raw);
    Header::Other("Refer-To".into(), format!("<{target}?Replaces={escaped}>"))
}

/// Percent-escape a SIP URI header value (RFC 3261 §19.1.1): everything outside
/// the unreserved set (`ALPHA / DIGIT / "-" / "_" / "." / "~"`) is `%`-encoded.
/// Deliberately conservative — escaping the separators (`;`, `=`) and `@` is
/// exactly what an embedded `Replaces` needs, matching the RFC 3891 examples.
fn escape_uri_header_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Parse the SIP status code out of a `message/sipfrag` `NOTIFY` body
/// (RFC 3515 §2.4.5 / RFC 3420).
///
/// The body's first line is a SIP status line — e.g. `SIP/2.0 200 OK` — so we
/// read the numeric code after the version token. Returns `None` if the body
/// isn't a recognizable status line (e.g. a request-line fragment, or empty).
///
/// Codes `< 200` are provisional (the transfer is still progressing); `200..=299`
/// mean the target answered (transfer succeeded); anything `>= 300` is a final
/// failure (target busy, declined, unreachable, …).
pub fn parse_sipfrag_status(body: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(body).ok()?;
    let first_line = text.lines().next()?.trim();
    let mut parts = first_line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("SIP/") {
        return None;
    }
    parts.next()?.parse::<u16>().ok()
}

/// `true` if a sipfrag status code is a final transfer result (success or
/// failure), i.e. the transferee's call to the target reached a final response.
pub fn is_final_sipfrag(code: u16) -> bool {
    code >= 200
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refer_to_wraps_the_target_uri() {
        let uri = Uri::try_from("sip:carol@example.com").unwrap();
        let Header::Other(name, value) = refer_to_header(&uri) else {
            panic!("expected Header::Other");
        };
        assert_eq!(name, "Refer-To");
        assert_eq!(value, "<sip:carol@example.com>");
    }

    #[test]
    fn refer_to_with_replaces_embeds_escaped_dialog() {
        let uri = Uri::try_from("sip:bob@biloxi.example.com").unwrap();
        let replaces = DialogTriplet {
            call_id: "call-2@host".into(),
            local_tag: "ustag".into(),
            remote_tag: "bobtag".into(),
        };
        let Header::Other(name, value) = refer_to_with_replaces(&uri, &replaces) else {
            panic!("expected Header::Other");
        };
        assert_eq!(name, "Refer-To");
        // The target's own tag (our remote_tag) is the to-tag; ours is from-tag.
        // Separators (`;`, `=`) and `@` are percent-escaped per RFC 3891 §4.
        assert_eq!(
            value,
            "<sip:bob@biloxi.example.com?Replaces=call-2%40host%3Bto-tag%3Dbobtag%3Bfrom-tag%3Dustag>"
        );
    }

    #[test]
    fn escape_leaves_unreserved_untouched() {
        assert_eq!(escape_uri_header_value("aZ09-_.~"), "aZ09-_.~");
        assert_eq!(escape_uri_header_value("a;b=c@d"), "a%3Bb%3Dc%40d");
    }

    #[test]
    fn parses_final_and_provisional_sipfrag() {
        assert_eq!(parse_sipfrag_status(b"SIP/2.0 100 Trying"), Some(100));
        assert_eq!(parse_sipfrag_status(b"SIP/2.0 200 OK"), Some(200));
        assert_eq!(
            parse_sipfrag_status(b"SIP/2.0 486 Busy Here\r\n"),
            Some(486)
        );
        // Leading/trailing whitespace and a trailing CRLF are tolerated.
        assert_eq!(
            parse_sipfrag_status(b"  SIP/2.0 180 Ringing \r\n"),
            Some(180)
        );
    }

    #[test]
    fn rejects_non_status_bodies() {
        assert_eq!(parse_sipfrag_status(b""), None);
        assert_eq!(parse_sipfrag_status(b"INVITE sip:x@y SIP/2.0"), None);
        assert_eq!(parse_sipfrag_status(b"garbage"), None);
    }

    #[test]
    fn finality_threshold_is_200() {
        assert!(!is_final_sipfrag(100));
        assert!(!is_final_sipfrag(180));
        assert!(is_final_sipfrag(200));
        assert!(is_final_sipfrag(486));
    }
}
