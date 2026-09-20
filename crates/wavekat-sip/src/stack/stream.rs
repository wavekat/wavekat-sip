//! A connection-oriented SIP transport.
//!
//! We are a User Agent: we connect out to one next hop, and every response and
//! in-dialog request comes back down that same connection. That is also what
//! makes inbound requests work behind NAT — the server reuses the connection
//! we opened rather than trying to reach us.
//!
//! A write half behind a mutex serialises concurrent sends; a read task owns
//! the read half, frames it with [`Framer`], and publishes whole messages on a
//! channel that [`StreamTransport::recv`] drains.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use rsip::SipMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, trace, warn};

use super::framing::Framer;
use super::transaction::Reliability;
use super::transport::serialize;

/// Read buffer size. TCP hands us whatever it has; the framer reassembles.
const READ_CHUNK: usize = 8 * 1024;

/// Depth of the read task → `recv()` channel.
const INBOUND_DEPTH: usize = 64;

/// A connected SIP transport over a byte stream.
pub(crate) struct StreamTransport {
    write: Arc<Mutex<OwnedWriteHalf>>,
    inbound: Mutex<mpsc::Receiver<(SipMessage, SocketAddr)>>,
    local: SocketAddr,
    peer: SocketAddr,
}

impl StreamTransport {
    /// Connect to `peer` and start reading framed messages from it.
    pub(crate) async fn connect(peer: SocketAddr) -> io::Result<Self> {
        let sock = TcpStream::connect(peer).await?;
        // SIP is request/response over small messages; Nagle's algorithm
        // would hold a request back waiting for more bytes that are not
        // coming.
        sock.set_nodelay(true)?;
        let local = sock.local_addr()?;
        let (read, write) = sock.into_split();

        let (tx, rx) = mpsc::channel(INBOUND_DEPTH);
        tokio::spawn(read_task(read, peer, tx));

        Ok(Self {
            write: Arc::new(Mutex::new(write)),
            inbound: Mutex::new(rx),
            local,
            peer,
        })
    }

    /// The local address of the established connection.
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    /// A stream transport is always reliable — RFC 3261 §17 retransmission
    /// timers are suppressed for it.
    pub(crate) fn reliability(&self) -> Reliability {
        Reliability::Reliable
    }

    /// Send one SIP message. `dst` must be the connected peer; a stream
    /// transport has exactly one.
    pub(crate) async fn send_to(&self, msg: &SipMessage, dst: SocketAddr) -> io::Result<()> {
        if dst != self.peer {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("stream transport is connected to {}, not {dst}", self.peer),
            ));
        }
        let bytes = serialize(msg);
        debug!(
            dst = %self.peer,
            bytes = bytes.len(),
            "\n>>> SEND to {} >>>\n{}",
            self.peer,
            String::from_utf8_lossy(&bytes).trim_end(),
        );
        self.write.lock().await.write_all(&bytes).await
    }

    /// Await the next framed message from the connection.
    pub(crate) async fn recv(&self) -> io::Result<(SipMessage, SocketAddr)> {
        self.inbound.lock().await.recv().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::ConnectionReset, "stream connection closed")
        })
    }
}

/// Own the read half, frame it, and publish whole messages.
///
/// Ends on EOF, a read error, or a framing error. A framing error is fatal by
/// design: once message boundaries are lost there is no way to find the next
/// one, so continuing would feed the engine garbage.
async fn read_task(
    mut read: OwnedReadHalf,
    peer: SocketAddr,
    tx: mpsc::Sender<(SipMessage, SocketAddr)>,
) {
    let mut framer = Framer::new();
    let mut chunk = vec![0u8; READ_CHUNK];
    loop {
        let n = match read.read(&mut chunk).await {
            Ok(0) => {
                debug!(%peer, "stream closed by peer");
                return;
            }
            Ok(n) => n,
            Err(e) => {
                warn!(%peer, error = %e, "stream read failed");
                return;
            }
        };
        trace!(%peer, bytes = n, "stream read");
        framer.push(&chunk[..n]);

        loop {
            match framer.next_message() {
                Ok(Some(msg)) => {
                    debug!(
                        src = %peer,
                        "\n<<< RECV from {peer} <<<\n{}",
                        String::from_utf8_lossy(&serialize(&msg)).trim_end(),
                    );
                    if tx.send((msg, peer)).await.is_err() {
                        return;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    warn!(%peer, error = %e, "stream framing failed; dropping connection");
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn options_to(dst: SocketAddr) -> SipMessage {
        let raw = format!(
            "OPTIONS sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/TCP {dst};branch=z9hG4bK-opt\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>\r\n\
             Call-ID: call-opt\r\n\
             CSeq: 4 OPTIONS\r\n\
             Content-Length: 0\r\n\r\n"
        );
        rsip::Request::try_from(raw.as_bytes())
            .expect("valid request")
            .into()
    }

    fn ok_response() -> Vec<u8> {
        b"SIP/2.0 200 OK\r\n\
Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-opt\r\n\
From: <sip:alice@example.com>;tag=alice\r\n\
To: <sip:bob@example.com>;tag=bob\r\n\
Call-ID: call-opt\r\n\
CSeq: 4 OPTIONS\r\n\
Content-Length: 0\r\n\r\n"
            .to_vec()
    }

    #[tokio::test]
    async fn connects_and_reports_a_local_addr() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let t = StreamTransport::connect(addr).await.expect("connects");
        let local = t.local_addr().expect("local addr");
        assert_eq!(local.ip().to_string(), "127.0.0.1");
        assert_ne!(local.port(), 0, "the OS assigned a real port");
    }

    #[tokio::test]
    async fn is_always_reliable() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let t = StreamTransport::connect(addr).await.expect("connects");
        assert!(t.reliability().is_reliable());
    }

    #[tokio::test]
    async fn sends_a_message_the_peer_can_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.expect("read");
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        let t = StreamTransport::connect(addr).await.expect("connects");
        t.send_to(&options_to(addr), addr).await.expect("sends");

        let got = server.await.expect("server task");
        assert!(
            got.starts_with("OPTIONS sip:bob@example.com SIP/2.0\r\n"),
            "{got}"
        );
    }

    #[tokio::test]
    async fn rejects_a_send_to_an_unconnected_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let t = StreamTransport::connect(addr).await.expect("connects");
        let elsewhere: SocketAddr = "127.0.0.1:1".parse().expect("addr");
        assert!(t.send_to(&options_to(addr), elsewhere).await.is_err());
    }

    #[tokio::test]
    async fn receives_a_response_from_the_same_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await.expect("read");
            sock.write_all(&ok_response()).await.expect("write");
            // Hold the connection open so the read task does not see EOF.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let t = StreamTransport::connect(addr).await.expect("connects");
        t.send_to(&options_to(addr), addr).await.expect("sends");
        let (msg, src) = t.recv().await.expect("receives");
        assert!(matches!(msg, SipMessage::Response(_)));
        assert_eq!(src, addr, "source is the connected peer");
    }

    /// Two messages written in one TCP segment must both surface — the
    /// framing case a datagram transport never has to handle.
    #[tokio::test]
    async fn receives_two_messages_written_together() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut both = ok_response();
            both.extend_from_slice(&ok_response());
            sock.write_all(&both).await.expect("write");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let t = StreamTransport::connect(addr).await.expect("connects");
        assert!(t.recv().await.is_ok(), "first message");
        assert!(t.recv().await.is_ok(), "second message");
    }

    #[tokio::test]
    async fn connect_to_a_closed_port_fails() {
        // Bind then drop, so the port is almost certainly unused.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        assert!(StreamTransport::connect(addr).await.is_err());
    }
}
