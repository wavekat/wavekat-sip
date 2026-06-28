//! Call transfer primitives — `REFER` (RFC 3515) for blind transfer.
//!
//! A blind transfer is one in-dialog `REFER` carrying a `Refer-To` header with
//! the transfer target's URI: the *transferor* (us) asks the *transferee* (the
//! far end) to place a fresh call to the *transfer target*. The transferee
//! accepts with `202 Accepted`, then reports progress back over an implicit
//! subscription as a sequence of `NOTIFY`s whose body is a
//! `message/sipfrag` (RFC 3420) status line — `SIP/2.0 100 Trying`, then a
//! final `SIP/2.0 200 OK` (the target answered) or a failure status.
//!
//! This module is the wire-format glue only: it builds the `Refer-To` header
//! and parses a sipfrag status line. The `REFER` request itself goes out
//! through [`Call::blind_transfer`](crate::Call::blind_transfer); the `NOTIFY`s
//! arrive on the call's [`InboundRequests`](crate::InboundRequests) stream (the
//! consumer reads each body with [`parse_sipfrag_status`]).

use rsip::{Header, Uri};

/// Build the `Refer-To` header naming the blind-transfer target.
///
/// RFC 3515 §2.1: the header value is the target URI in name-addr/addr-spec
/// form. We emit the bare addr-spec (`Refer-To: <sip:carol@example.com>`),
/// which every compliant transferee accepts.
pub fn refer_to_header(target: &Uri) -> Header {
    Header::Other("Refer-To".into(), format!("<{target}>"))
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
