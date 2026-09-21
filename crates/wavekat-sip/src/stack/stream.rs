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
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rsip::SipMessage;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

use super::framing::Framer;
use super::transaction::Reliability;
use super::transport::serialize;

/// The byte stream underneath a [`StreamTransport`].
///
/// An enum rather than a generic parameter or a trait object: a generic would
/// leak up through `BoundTransport` into the engine, and `transport.rs` already
/// states the crate's preference for dispatch that stays visible. The framer
/// and the read task above this are identical for both arms — a TLS connection
/// is a TCP connection with a handshake in front of it.
pub(crate) enum SipStream {
    Tcp(TcpStream),
    /// Boxed: a rustls connection is large enough that an inline variant would
    /// set the enum's size for the TCP arm too.
    #[cfg(feature = "tls")]
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for SipStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "tls")]
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for SipStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "tls")]
            Self::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "tls")]
            Self::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "tls")]
            Self::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Read buffer size. TCP hands us whatever it has; the framer reassembles.
const READ_CHUNK: usize = 8 * 1024;

/// Depth of the read task → `recv()` channel.
const INBOUND_DEPTH: usize = 64;

/// A connected SIP transport over a byte stream.
pub(crate) struct StreamTransport {
    write: Arc<Mutex<WriteHalf<SipStream>>>,
    inbound: Mutex<mpsc::Receiver<(SipMessage, SocketAddr)>>,
    /// Aborted on drop. See the `Drop` impl.
    reader: JoinHandle<()>,
    local: SocketAddr,
    peer: SocketAddr,
}

/// Closes the connection when the transport goes away.
///
/// `tokio::io::split` shares the stream between the two halves, and the
/// socket closes only once both are gone. The write half drops with `self`;
/// the read half lives in the read task, which is parked in `read()` on an
/// idle connection and has no other reason to wake. Aborting it drops that
/// half, the stream goes with it, and the peer sees the close.
///
/// TCP's `into_split` did this implicitly — its `OwnedWriteHalf` shuts down
/// the write direction on drop, and the peer's answering close ended the read
/// task. `tokio::io::split`'s `WriteHalf` has no such `Drop`, which is why
/// this has to be explicit. It is also abrupt for TLS: no `close_notify` is
/// sent, because `Drop` cannot await one.
impl Drop for StreamTransport {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

impl StreamTransport {
    /// Connect to `peer` and start reading framed messages from it.
    ///
    /// For TLS the TCP connection is established first and then upgraded, so a
    /// refused port and a refused certificate stay distinguishable.
    pub(crate) async fn connect(
        peer: SocketAddr,
        setup: &super::transport::TransportSetup,
    ) -> io::Result<Self> {
        let sock = TcpStream::connect(peer).await?;
        // SIP is request/response over small messages; Nagle's algorithm would
        // hold a request back waiting for more bytes that are not coming.
        sock.set_nodelay(true)?;
        let local = sock.local_addr()?;

        let stream = match setup.transport {
            #[cfg(feature = "tls")]
            crate::account::Transport::Tls => {
                let tls = setup.tls.as_ref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "TLS transport selected without a TLS setup",
                    )
                })?;
                SipStream::Tls(Box::new(
                    super::tls::connect(sock, &tls.server_name, &tls.policy).await?,
                ))
            }
            #[cfg(not(feature = "tls"))]
            crate::account::Transport::Tls => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "TLS transport requires the `tls` feature",
                ))
            }
            _ => SipStream::Tcp(sock),
        };

        let (read, write) = tokio::io::split(stream);
        let (tx, rx) = mpsc::channel(INBOUND_DEPTH);
        let reader = tokio::spawn(read_task(read, peer, tx));

        Ok(Self {
            write: Arc::new(Mutex::new(write)),
            inbound: Mutex::new(rx),
            reader,
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
        write_message(&mut *self.write.lock().await, &bytes).await
    }

    /// Await the next framed message from the connection.
    pub(crate) async fn recv(&self) -> io::Result<(SipMessage, SocketAddr)> {
        self.inbound.lock().await.recv().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::ConnectionReset, "stream connection closed")
        })
    }
}

/// Write one serialized SIP message and flush it.
///
/// The flush is a no-op for TCP and load-bearing for TLS: tokio-rustls reports
/// a write complete once the bytes are in the session's buffer, and under
/// socket backpressure they stay there until something flushes. Without it a
/// request can "send" successfully, never reach the wire, and surface only as
/// a transaction timeout.
async fn write_message<W: AsyncWrite + Unpin + ?Sized>(w: &mut W, bytes: &[u8]) -> io::Result<()> {
    w.write_all(bytes).await?;
    w.flush().await
}

/// Own the read half, frame it, and publish whole messages.
///
/// Ends on EOF, a read error, or a framing error. A framing error is fatal by
/// design: once message boundaries are lost there is no way to find the next
/// one, so continuing would feed the engine garbage.
async fn read_task(
    mut read: ReadHalf<SipStream>,
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
    use crate::account::Transport;
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

        let t = StreamTransport::connect(addr, &Transport::Tcp.into())
            .await
            .expect("connects");
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
        let t = StreamTransport::connect(addr, &Transport::Tcp.into())
            .await
            .expect("connects");
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

        let t = StreamTransport::connect(addr, &Transport::Tcp.into())
            .await
            .expect("connects");
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
        let t = StreamTransport::connect(addr, &Transport::Tcp.into())
            .await
            .expect("connects");
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

        let t = StreamTransport::connect(addr, &Transport::Tcp.into())
            .await
            .expect("connects");
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

        let t = StreamTransport::connect(addr, &Transport::Tcp.into())
            .await
            .expect("connects");
        assert!(t.recv().await.is_ok(), "first message");
        assert!(t.recv().await.is_ok(), "second message");
    }

    /// Models the one property of a TLS session that matters here: a write
    /// is "accepted" once the bytes are in its buffer, and they only reach
    /// the socket on flush. tokio-rustls' `poll_write` behaves exactly this
    /// way when the socket is under backpressure.
    #[derive(Default)]
    struct BufferedUntilFlush {
        pending: Vec<u8>,
        wire: Vec<u8>,
    }

    impl AsyncWrite for BufferedUntilFlush {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.get_mut().pending.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            this.wire.append(&mut this.pending);
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    #[tokio::test]
    async fn a_sent_message_is_flushed_out_of_a_buffering_stream() {
        let mut w = BufferedUntilFlush::default();
        write_message(&mut w, b"OPTIONS sip:bob@example.com SIP/2.0\r\n\r\n")
            .await
            .expect("writes");
        assert_eq!(
            w.wire, b"OPTIONS sip:bob@example.com SIP/2.0\r\n\r\n",
            "the message must reach the wire, not sit in the session buffer"
        );
    }

    /// The peer is idle, so the read task is parked in `read()` with nothing
    /// to wake it. Dropping the transport must still close the connection —
    /// otherwise that task holds the read half, and with it the socket, for
    /// the life of the process.
    #[tokio::test]
    async fn dropping_the_transport_closes_an_idle_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 64];
            tokio::time::timeout(std::time::Duration::from_secs(2), sock.read(&mut buf)).await
        });

        let t = StreamTransport::connect(addr, &Transport::Tcp.into())
            .await
            .expect("connects");
        drop(t);

        let read = server
            .await
            .expect("server task")
            .expect("the peer must see the connection close, not wait forever");
        assert_eq!(read.expect("read"), 0, "EOF");
    }

    #[tokio::test]
    async fn connect_to_a_closed_port_fails() {
        // Bind then drop, so the port is almost certainly unused.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        assert!(StreamTransport::connect(addr, &Transport::Tcp.into())
            .await
            .is_err());
    }

    /// `TransportSetup { transport: Tls, tls: None }` is representable —
    /// `Transport::Tls.into()` (the `From<Transport>` shim every plain
    /// UDP/TCP call site relies on) produces exactly that — even though this
    /// module can never actually negotiate TLS from it. `BoundTransport::
    /// bind` always builds a real `TlsSetup` when it selects `Transport::
    /// Tls` (see `endpoint.rs`), so this hazard path is unreached in
    /// practice, but it must still fail clearly rather than panic or silently
    /// fall back to cleartext if something ever reaches it directly.
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn tls_transport_without_a_tls_setup_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let result = StreamTransport::connect(addr, &Transport::Tls.into()).await;
        match result {
            Ok(_) => panic!("must not connect without a TLS setup"),
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidInput),
        }
    }

    /// Without the `tls` feature at all, `Transport::Tls` must fail clearly —
    /// `io::ErrorKind::Unsupported` — rather than silently connecting in
    /// cleartext or panicking. `account.rs`'s `Transport::Tls` doc comment
    /// makes this contract explicit for a consumer who enables it without the
    /// feature.
    #[cfg(not(feature = "tls"))]
    #[tokio::test]
    async fn tls_transport_without_the_feature_is_unsupported() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let result = StreamTransport::connect(addr, &Transport::Tls.into()).await;
        match result {
            Ok(_) => panic!("must not connect without the tls feature"),
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::Unsupported),
        }
    }

    /// `SipStream` must delegate reads and writes to its inner transport
    /// unchanged — the framer and read task above it depend on that, and a
    /// future `Tls` arm has to satisfy the same contract.
    #[tokio::test]
    async fn sip_stream_delegates_reads_and_writes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            sock.write_all(b"hello through the enum")
                .await
                .expect("write");
            let mut buf = vec![0u8; 64];
            let n = sock.read(&mut buf).await.expect("read");
            buf.truncate(n);
            buf
        });

        let client = TcpStream::connect(addr).await.expect("connect");
        let mut stream = SipStream::Tcp(client);

        let mut buf = vec![0u8; 64];
        let n = stream.read(&mut buf).await.expect("read through SipStream");
        assert_eq!(&buf[..n], b"hello through the enum");

        stream
            .write_all(b"back through the enum")
            .await
            .expect("write through SipStream");
        stream.flush().await.expect("flush through SipStream");

        let got = server.await.expect("server task");
        assert_eq!(got, b"back through the enum");
    }
}
