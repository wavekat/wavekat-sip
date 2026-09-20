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

use crate::account::Transport;

use super::stream::StreamTransport;
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

/// Everything the transport needs in order to be established.
///
/// A bare [`Transport`] is not enough for TLS, which also needs the name to
/// verify and the trust policy. `From<Transport>` exists so the many call sites
/// that only ever speak UDP or TCP can keep passing the enum.
#[derive(Debug, Clone)]
pub(crate) struct TransportSetup {
    pub(crate) transport: Transport,
    #[cfg(feature = "tls")]
    pub(crate) tls: Option<TlsSetup>,
}

/// The TLS-only half of [`TransportSetup`].
#[cfg(feature = "tls")]
#[derive(Debug, Clone)]
pub(crate) struct TlsSetup {
    /// The account's SIP domain — RFC 5922 §7.1. Never the SRV target.
    pub(crate) server_name: String,
    pub(crate) policy: crate::account::TlsPolicy,
}

impl From<Transport> for TransportSetup {
    fn from(transport: Transport) -> Self {
        Self {
            transport,
            #[cfg(feature = "tls")]
            tls: None,
        }
    }
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

/// The bound transport the engine drives, in whichever shape the account
/// selected.
///
/// An enum rather than a trait object: there are exactly two shapes, the crate
/// carries no `async-trait` dependency, and keeping the dispatch visible is
/// worth more here than open extension.
pub(crate) enum BoundTransport {
    /// UDP — one datagram per message, retransmission timers apply.
    Datagram(UdpTransport),
    /// TCP (and, later, TLS) — a framed byte stream to one next hop.
    Stream(StreamTransport),
}

impl BoundTransport {
    /// Bind (UDP) or connect (stream) for `transport`.
    ///
    /// `local` selects the outbound interface on the datagram path and is
    /// ignored on the stream path, where connecting assigns the source
    /// address. `peer` is the resolved next hop.
    pub(crate) async fn bind(
        local: SocketAddr,
        peer: SocketAddr,
        setup: &TransportSetup,
    ) -> io::Result<Self> {
        match setup.transport {
            Transport::Udp => Ok(Self::Datagram(UdpTransport::bind(local).await?)),
            Transport::Tcp | Transport::Tls => {
                Ok(Self::Stream(StreamTransport::connect(peer, setup).await?))
            }
        }
    }

    /// The address this transport sends from.
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Datagram(t) => t.local_addr(),
            Self::Stream(t) => t.local_addr(),
        }
    }

    /// Whether RFC 3261 §17 retransmission timers apply.
    pub(crate) fn reliability(&self) -> Reliability {
        match self {
            Self::Datagram(t) => t.reliability(),
            Self::Stream(t) => t.reliability(),
        }
    }

    /// Send one SIP message to `dst`.
    pub(crate) async fn send_to(&self, msg: &SipMessage, dst: SocketAddr) -> io::Result<()> {
        match self {
            Self::Datagram(t) => t.send_to(msg, dst).await,
            Self::Stream(t) => t.send_to(msg, dst).await,
        }
    }

    /// Receive the next message and the address it came from.
    pub(crate) async fn recv(&self) -> io::Result<(SipMessage, SocketAddr)> {
        match self {
            Self::Datagram(t) => t.recv().await,
            Self::Stream(t) => t.recv().await,
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

    /// `From<Transport>` is the compatibility shim every UDP/TCP call site
    /// leans on: it must carry the transport through unchanged and, under the
    /// `tls` feature, start with no TLS setup attached.
    #[test]
    fn transport_setup_from_transport_round_trips_udp_and_tcp() {
        let udp: TransportSetup = Transport::Udp.into();
        assert_eq!(udp.transport, Transport::Udp);
        #[cfg(feature = "tls")]
        assert!(udp.tls.is_none());

        let tcp: TransportSetup = Transport::Tcp.into();
        assert_eq!(tcp.transport, Transport::Tcp);
        #[cfg(feature = "tls")]
        assert!(tcp.tls.is_none());
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

    #[tokio::test]
    async fn udp_kind_binds_a_datagram_transport() {
        let peer: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let t = BoundTransport::bind(
            "127.0.0.1:0".parse().expect("addr"),
            peer,
            &Transport::Udp.into(),
        )
        .await
        .expect("binds");
        assert!(matches!(t, BoundTransport::Datagram(_)));
        assert!(!t.reliability().is_reliable(), "UDP is unreliable");
    }

    #[tokio::test]
    async fn tcp_kind_binds_a_stream_transport() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let peer = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let t = BoundTransport::bind(
            "127.0.0.1:0".parse().expect("addr"),
            peer,
            &Transport::Tcp.into(),
        )
        .await
        .expect("binds");
        assert!(
            matches!(t, BoundTransport::Stream(_)),
            "TCP must not silently bind UDP"
        );
        assert!(t.reliability().is_reliable(), "TCP is reliable");
    }

    /// The regression this whole phase exists for: before it, selecting TCP
    /// produced a UDP socket reporting itself as unreliable.
    #[tokio::test]
    async fn tcp_local_addr_is_the_connections_not_a_udp_sockets() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let peer = listener.local_addr().expect("addr");
        let accepted = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.expect("accept");
            sock.peer_addr().expect("peer addr")
        });

        let t = BoundTransport::bind(
            "127.0.0.1:0".parse().expect("addr"),
            peer,
            &Transport::Tcp.into(),
        )
        .await
        .expect("binds");
        let seen_by_server = accepted.await.expect("accept task");
        assert_eq!(
            t.local_addr().expect("local addr"),
            seen_by_server,
            "local_addr must be the TCP connection's address"
        );
    }

    /// Without the `tls` feature, `Transport::Tls` must fail loudly rather
    /// than silently falling back to a cleartext transport. With the feature
    /// on, this same selection is exercised end-to-end in
    /// `tests/tls_transport.rs`.
    ///
    /// Connects to a real listener rather than a closed port: the TCP
    /// handshake happens before the feature check (see `StreamTransport::
    /// connect`'s doc comment), so a closed port would fail with
    /// `ConnectionRefused` before ever reaching the case this test targets.
    #[cfg(not(feature = "tls"))]
    #[tokio::test]
    async fn tls_kind_is_rejected_without_the_tls_feature() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let peer = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let result = BoundTransport::bind(
            "127.0.0.1:0".parse().expect("addr"),
            peer,
            &Transport::Tls.into(),
        )
        .await;
        match result {
            Ok(_) => panic!("TLS must not silently downgrade to another transport"),
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::Unsupported),
        }
    }
}
