//! Stream framing: turning a byte stream back into discrete SIP messages.
//!
//! A datagram transport delivers exactly one SIP message per read. A stream
//! transport delivers bytes, so message boundaries must be reconstructed:
//! read to the `\r\n\r\n` header terminator, take `Content-Length` from the
//! headers, then wait for exactly that many body bytes (RFC 3261 §7.5).
//!
//! Sans-IO on purpose — this module owns no socket, so every boundary case is
//! a plain unit test.

use rsip::SipMessage;

use super::transport::parse;

/// Largest header block we will buffer before declaring the peer broken.
/// Without a cap, a peer that never sends `\r\n\r\n` grows the buffer without
/// limit.
pub(crate) const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Why a stream could not be framed.
///
/// Every variant is fatal for the connection: once framing is lost there is no
/// way to resynchronise onto the next message boundary, so the only safe
/// response is to drop the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FramingError {
    /// RFC 3261 §20.14 requires `Content-Length` on a stream transport.
    /// Assuming zero would resynchronise onto a body and corrupt every
    /// message after it.
    #[error("SIP message on a stream transport has no Content-Length")]
    MissingContentLength,
    /// The header block exceeded [`MAX_HEADER_BYTES`] with no terminator.
    #[error("SIP header block exceeded {MAX_HEADER_BYTES} bytes")]
    HeadersTooLarge,
    /// The bytes formed a complete block but did not parse as SIP.
    #[error("could not parse SIP message")]
    Malformed,
}

/// Accumulates stream bytes and yields whole SIP messages.
pub(crate) struct Framer {
    buf: Vec<u8>,
}

impl Framer {
    /// A framer with an empty buffer.
    pub(crate) fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Add freshly read bytes to the buffer.
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Take the next complete message, if one is buffered.
    ///
    /// `Ok(None)` means "need more bytes" and is the normal case between
    /// reads. `Err` means the stream can no longer be framed.
    pub(crate) fn next_message(&mut self) -> Result<Option<SipMessage>, FramingError> {
        // RFC 5626 §3.5.1 keepalives are bare CRLFs between messages. No SIP
        // message starts with CRLF, so a leading one is always keepalive and
        // never part of the message that follows.
        while self.buf.starts_with(b"\r\n") {
            self.buf.drain(..2);
        }

        let Some(end) = find_header_end(&self.buf) else {
            if self.buf.len() > MAX_HEADER_BYTES {
                return Err(FramingError::HeadersTooLarge);
            }
            return Ok(None);
        };

        let body_len =
            content_length(&self.buf[..end]).ok_or(FramingError::MissingContentLength)?;
        let total = end + body_len;
        if self.buf.len() < total {
            return Ok(None);
        }

        let raw: Vec<u8> = self.buf.drain(..total).collect();
        match parse(&raw) {
            Some(msg) => Ok(Some(msg)),
            None => Err(FramingError::Malformed),
        }
    }
}

/// Byte offset just past the `\r\n\r\n` that ends the header block.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Parse `Content-Length` (or its compact form `l`) out of a header block.
/// Header names are case-insensitive (RFC 3261 §7.3.1).
fn content_length(headers: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(headers).ok()?;
    for line in text.split("\r\n") {
        // A line with no colon is the start line; skip it rather than
        // aborting the scan.
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if name == "content-length" || name == "l" {
            return value.trim().parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete, well-formed REGISTER with an empty body.
    fn register() -> Vec<u8> {
        b"REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-1\r\n\
From: <sip:alice@example.com>;tag=a\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: call-1\r\n\
CSeq: 1 REGISTER\r\n\
Content-Length: 0\r\n\r\n"
            .to_vec()
    }

    /// An INVITE whose 4-byte body is "abcd".
    fn invite_with_body() -> Vec<u8> {
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-2\r\n\
From: <sip:alice@example.com>;tag=a\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: call-2\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 4\r\n\r\nabcd"
            .to_vec()
    }

    #[test]
    fn empty_framer_yields_nothing() {
        let mut f = Framer::new();
        assert_eq!(f.next_message(), Ok(None));
    }

    #[test]
    fn frames_one_whole_message() {
        let mut f = Framer::new();
        f.push(&register());
        assert!(f.next_message().expect("frames").is_some());
        assert_eq!(f.next_message(), Ok(None));
    }

    #[test]
    fn frames_message_split_mid_header() {
        let raw = register();
        let (a, b) = raw.split_at(40);
        let mut f = Framer::new();
        f.push(a);
        assert_eq!(
            f.next_message(),
            Ok(None),
            "incomplete headers yield nothing"
        );
        f.push(b);
        assert!(f.next_message().expect("frames").is_some());
    }

    #[test]
    fn frames_two_messages_from_one_read() {
        let mut both = register();
        both.extend_from_slice(&register());
        let mut f = Framer::new();
        f.push(&both);
        assert!(f.next_message().expect("first").is_some());
        assert!(f.next_message().expect("second").is_some());
        assert_eq!(f.next_message(), Ok(None));
    }

    #[test]
    fn frames_body_split_across_reads() {
        let raw = invite_with_body();
        let cut = raw.len() - 2;
        let mut f = Framer::new();
        f.push(&raw[..cut]);
        assert_eq!(f.next_message(), Ok(None), "partial body yields nothing");
        f.push(&raw[cut..]);
        let msg = f.next_message().expect("frames").expect("message");
        assert_eq!(msg.body(), b"abcd");
    }

    /// RFC 5626 §3.5.1: CRLFCRLF is the connection keepalive. Bare CRLFs
    /// between messages must be skipped, not treated as a message.
    #[test]
    fn skips_bare_crlf_keepalive_between_messages() {
        let mut buf = b"\r\n\r\n".to_vec();
        buf.extend_from_slice(&register());
        let mut f = Framer::new();
        f.push(&buf);
        assert!(f.next_message().expect("frames past keepalive").is_some());
    }

    #[test]
    fn keepalive_alone_is_not_a_message() {
        let mut f = Framer::new();
        f.push(b"\r\n\r\n");
        assert_eq!(f.next_message(), Ok(None));
    }

    /// RFC 3261 §20.14: on a stream transport, absent Content-Length is a
    /// protocol error. Treating it as zero resynchronises the stream onto a
    /// body and corrupts every message after it.
    #[test]
    fn missing_content_length_is_an_error() {
        let raw = b"REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-3\r\n\
CSeq: 1 REGISTER\r\n\r\n";
        let mut f = Framer::new();
        f.push(raw);
        assert_eq!(f.next_message(), Err(FramingError::MissingContentLength));
    }

    #[test]
    fn oversized_header_block_is_an_error() {
        let mut f = Framer::new();
        f.push(b"REGISTER sip:example.com SIP/2.0\r\n");
        f.push(&vec![b'x'; MAX_HEADER_BYTES + 1]);
        assert_eq!(f.next_message(), Err(FramingError::HeadersTooLarge));
    }

    #[test]
    fn content_length_is_case_insensitive() {
        let raw = b"REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-4\r\n\
From: <sip:alice@example.com>;tag=a\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: call-4\r\n\
CSeq: 1 REGISTER\r\n\
content-length: 0\r\n\r\n";
        let mut f = Framer::new();
        f.push(raw);
        assert!(f.next_message().expect("frames").is_some());
    }

    /// `l` is the compact form of Content-Length (RFC 3261 §20).
    #[test]
    fn compact_content_length_form_is_accepted() {
        let raw = b"REGISTER sip:example.com SIP/2.0\r\n\
Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-5\r\n\
From: <sip:alice@example.com>;tag=a\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: call-5\r\n\
CSeq: 1 REGISTER\r\n\
l: 0\r\n\r\n";
        let mut f = Framer::new();
        f.push(raw);
        assert!(f.next_message().expect("frames").is_some());
    }

    #[test]
    fn unparseable_message_is_an_error() {
        let raw = b"NOT A SIP MESSAGE AT ALL\r\n\
Content-Length: 0\r\n\r\n";
        let mut f = Framer::new();
        f.push(raw);
        assert_eq!(f.next_message(), Err(FramingError::Malformed));
    }
}
