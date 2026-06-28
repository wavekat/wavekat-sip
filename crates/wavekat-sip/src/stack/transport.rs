//! Transport: SIP message (de)serialization and a bound UDP socket.
//!
//! RFC 3261 §18. This is the bytes-on-the-wire layer the transaction engine
//! drives. UDP is the primary path (one datagram = one SIP message); TCP
//! framing is a later addition (the plan keeps it out of the initial cut).
//!
//! Message parsing/serialization is delegated to `rsip` — we own only the
//! socket plumbing.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use rsip::SipMessage;
use tokio::net::UdpSocket;
use tracing::{debug, trace};

use super::transaction::Reliability;

/// Largest datagram we will read. SIP-over-UDP messages must fit in a single
/// datagram (RFC 3261 §18.1.1 caps them below the path MTU); 64 KiB is the
/// IPv4 datagram ceiling and leaves ample headroom.
const MAX_DATAGRAM: usize = 65_535;

/// Parse a received buffer into a SIP message, or `None` if it is malformed.
pub(crate) fn parse(bytes: &[u8]) -> Option<SipMessage> {
    SipMessage::try_from(bytes).ok()
}

/// Serialize a SIP message to its on-the-wire bytes.
pub(crate) fn serialize(msg: &SipMessage) -> Vec<u8> {
    msg.clone().into()
}

/// A bound UDP transport.
pub(crate) struct UdpTransport {
    socket: Arc<UdpSocket>,
}

impl UdpTransport {
    /// Bind a UDP socket to `local` (use port 0 to let the OS choose).
    pub(crate) async fn bind(local: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(local).await?;
        Ok(Self {
            socket: Arc::new(socket),
        })
    }

    /// The address the socket is bound to (with the OS-assigned port resolved).
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// UDP is always unreliable — retransmission timers apply.
    pub(crate) fn reliability(&self) -> Reliability {
        Reliability::Unreliable
    }

    /// Send one SIP message to `dst`.
    pub(crate) async fn send_to(&self, msg: &SipMessage, dst: SocketAddr) -> io::Result<()> {
        let bytes = serialize(msg);
        debug!(
            %dst,
            bytes = bytes.len(),
            "\n>>> SEND to {dst} >>>\n{}",
            String::from_utf8_lossy(&bytes).trim_end(),
        );
        self.socket.send_to(&bytes, dst).await?;
        Ok(())
    }

    /// Receive the next parseable SIP message and its source address.
    ///
    /// Malformed datagrams are dropped (logged at debug — a peer message that
    /// fails to parse is exactly the kind of thing we want visible when
    /// debugging) and reception continues, so a single bad packet cannot stall
    /// the engine.
    pub(crate) async fn recv(&self) -> io::Result<(SipMessage, SocketAddr)> {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let (n, src) = self.socket.recv_from(&mut buf).await?;
            debug!(
                %src,
                bytes = n,
                "\n<<< RECV from {src} <<<\n{}",
                String::from_utf8_lossy(&buf[..n]).trim_end(),
            );
            match parse(&buf[..n]) {
                Some(msg) => return Ok((msg, src)),
                None => {
                    trace!(%src, bytes = n, "dropping unparseable datagram");
                    debug!(%src, bytes = n, "^ datagram above was unparseable; dropped");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsip::{Request, Response};

    fn options() -> Request {
        let raw = "OPTIONS sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-opt\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>\r\n\
             Call-ID: call-opt\r\n\
             CSeq: 4 OPTIONS\r\n\
             Content-Length: 0\r\n\r\n";
        Request::try_from(raw.as_bytes()).unwrap()
    }

    #[test]
    fn parse_round_trips_serialize() {
        let msg: SipMessage = options().into();
        let bytes = serialize(&msg);
        let back = parse(&bytes).expect("parses");
        assert_eq!(back, msg);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse(b"not a sip message\r\n\r\n").is_none());
    }

    #[tokio::test]
    async fn udp_round_trip_between_two_sockets() {
        let a = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let b = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let b_addr = b.local_addr().unwrap();

        let sent: SipMessage = options().into();
        a.send_to(&sent, b_addr).await.unwrap();

        let (got, src) = b.recv().await.unwrap();
        assert_eq!(got, sent);
        assert_eq!(src, a.local_addr().unwrap());
    }

    #[tokio::test]
    async fn recv_skips_malformed_then_delivers() {
        let a = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let b = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let b_addr = b.local_addr().unwrap();

        // Raw garbage datagram, then a valid message.
        a.socket.send_to(b"garbage", b_addr).await.unwrap();
        let good: SipMessage = options().into();
        a.send_to(&good, b_addr).await.unwrap();

        let (got, _) = b.recv().await.unwrap();
        assert_eq!(got, good);
    }

    #[test]
    fn response_serializes_and_parses() {
        let raw = "SIP/2.0 200 OK\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-opt\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>;tag=bob\r\n\
             Call-ID: call-opt\r\n\
             CSeq: 4 OPTIONS\r\n\
             Content-Length: 0\r\n\r\n";
        let resp = Response::try_from(raw.as_bytes()).unwrap();
        let msg: SipMessage = resp.into();
        assert_eq!(parse(&serialize(&msg)).unwrap(), msg);
    }
}
