# Stream Transport (TCP) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `Transport::Tcp` actually send SIP over TCP, replacing the current behaviour where selecting TCP silently sends UDP datagrams with a `SIP/2.0/UDP` Via.

**Architecture:** `stack::transport` grows a `BoundTransport` enum with two variants — the existing `UdpTransport` and a new `StreamTransport` that owns one TCP connection per next-hop. A new `stack::framing` module turns the byte stream back into discrete SIP messages. `via_value` and the Contact URI become transport-aware, and `SipEndpoint::new` resolves the server before binding, because a stream has no local address until it connects.

**Tech Stack:** Rust 2021, tokio (`net`, `sync`, `time`, `macros`, `rt`), `rsip` for message types, `tracing`. No new dependencies.

**Spec:** [`docs/18-secure-transport-tls-and-srtp.md`](../../18-secure-transport-tls-and-srtp.md) — Phase 1. Read its "Why" and "Phase 1" sections before starting; this plan implements them.

## Global Constraints

These come from `CLAUDE.md` at the repo root and apply to **every** task below:

- **All four must pass with zero warnings before any commit:** `cargo fmt --all --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`, `cargo doc --no-deps -p wavekat-sip --all-features`. `make ci` runs all four.
- **No `unwrap()` in library code.** Tests only.
- **Every module has unit tests at the bottom of the file** (`#[cfg(test)] mod tests`).
- **Every change to public surface lands with a test in the same PR.** Deferring tests to a follow-up is not acceptable.
- **Keep modules focused — split if over 300 lines.**
- Use `thiserror` for typed errors; `Box<dyn std::error::Error + Send + Sync>` at async task boundaries.
- `///` doc comments on every public struct and function.
- **Minimise external crates.** This phase adds none.
- **Public-repo hygiene:** this repo is public and its consumers are private. Never name a private sibling repo, its files, or its modules in source, comments, tests, docs, or commit messages. Say "the consumer" / "a downstream consumer".
- **Conventional Commits** for every commit subject (`feat:`, `fix:`, `test:`, `refactor:`, `docs:`). Releases are driven by release-plz reading these.
- Crate root for all paths below: `crates/wavekat-sip/`.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `src/stack/framing.rs` | **New.** Pure, sans-IO: accumulate bytes, emit whole SIP messages. No sockets. |
| `src/stack/stream.rs` | **New.** `StreamTransport`: TCP connect, per-connection read task, write half, reconnect, CRLF keepalive. |
| `src/stack/transport.rs` | **Modify.** Keeps `parse`/`serialize`/`UdpTransport`; gains the `BoundTransport` enum that dispatches to either. |
| `src/stack/engine.rs` | **Modify.** Holds `BoundTransport` instead of `Arc<UdpTransport>`; takes reliability from the real transport. |
| `src/stack/ua.rs` | **Modify.** `bind_*` gain a `Transport` parameter and thread it to the engine. |
| `src/stack/transaction/mod.rs` | **Modify.** `via_value` gains a transport parameter. |
| `src/stack/registration.rs`, `src/stack/call.rs`, `src/stack/dialog.rs` | **Modify.** Pass the transport into `via_value`. |
| `src/registrar.rs` | **Modify.** Contact URI gains `;transport=tcp`. |
| `src/endpoint.rs` | **Modify.** Resolve before bind; pass transport to `Ua`. |
| `tests/tcp_transport.rs` | **New.** End-to-end REGISTER over a loopback `TcpListener`. |

Task order follows the dependency chain: pure framing first (no I/O, fully unit-testable), then the connection, then the enum that wires it in, then the header correctness fixes, then the end-to-end test.

---

### Task 1: Message framing

**Files:**
- Create: `src/stack/framing.rs`
- Modify: `src/stack/mod.rs` (add `pub(crate) mod framing;`)
- Test: bottom of `src/stack/framing.rs`

**Interfaces:**
- Consumes: `crate::stack::transport::parse` (existing: `fn parse(bytes: &[u8]) -> Option<SipMessage>`).
- Produces:
  - `pub(crate) struct Framer` with `Framer::new() -> Framer`, `Framer::push(&mut self, bytes: &[u8])`, `Framer::next_message(&mut self) -> Result<Option<SipMessage>, FramingError>`
  - `pub(crate) enum FramingError { MissingContentLength, HeadersTooLarge, Malformed }` (derives `Debug`, `thiserror::Error`, `PartialEq`)
  - `pub(crate) const MAX_HEADER_BYTES: usize = 64 * 1024;`

**Why this exists:** A datagram carries exactly one SIP message. A stream carries none — message boundaries have to be reconstructed from `Content-Length`. This module is deliberately sans-IO so every edge case is a plain unit test with no sockets involved.

- [ ] **Step 1: Write the failing tests**

Create `src/stack/framing.rs` with only the test module plus empty `use super::*;`, then add:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// A complete, well-formed REGISTER with an empty body.
    fn register() -> &'static [u8] {
        b"REGISTER sip:example.com SIP/2.0\r\n\
          Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-1\r\n\
          From: <sip:alice@example.com>;tag=a\r\n\
          To: <sip:alice@example.com>\r\n\
          Call-ID: call-1\r\n\
          CSeq: 1 REGISTER\r\n\
          Content-Length: 0\r\n\r\n"
    }

    /// An INVITE whose 4-byte body is "abcd".
    fn invite_with_body() -> &'static [u8] {
        b"INVITE sip:bob@example.com SIP/2.0\r\n\
          Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-2\r\n\
          From: <sip:alice@example.com>;tag=a\r\n\
          To: <sip:bob@example.com>\r\n\
          Call-ID: call-2\r\n\
          CSeq: 1 INVITE\r\n\
          Content-Length: 4\r\n\r\nabcd"
    }

    #[test]
    fn empty_framer_yields_nothing() {
        let mut f = Framer::new();
        assert_eq!(f.next_message(), Ok(None));
    }

    #[test]
    fn frames_one_whole_message() {
        let mut f = Framer::new();
        f.push(register());
        assert!(f.next_message().expect("frames").is_some());
        assert_eq!(f.next_message(), Ok(None));
    }

    #[test]
    fn frames_message_split_mid_header() {
        let raw = register();
        let (a, b) = raw.split_at(40);
        let mut f = Framer::new();
        f.push(a);
        assert_eq!(f.next_message(), Ok(None), "incomplete headers yield nothing");
        f.push(b);
        assert!(f.next_message().expect("frames").is_some());
    }

    #[test]
    fn frames_two_messages_from_one_read() {
        let mut both = register().to_vec();
        both.extend_from_slice(register());
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
        buf.extend_from_slice(register());
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
    /// protocol error. Treating it as zero resynchronizes the stream onto a
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p wavekat-sip framing`
Expected: FAIL to compile — `cannot find type 'Framer' in this scope`, `cannot find type 'FramingError'`, `cannot find value 'MAX_HEADER_BYTES'`.

- [ ] **Step 3: Write the implementation**

Put this **above** the `#[cfg(test)]` block in `src/stack/framing.rs`:

```rust
//! Stream framing: turning a byte stream back into discrete SIP messages.
//!
//! A datagram transport delivers exactly one SIP message per read. A stream
//! transport delivers bytes, so message boundaries must be reconstructed:
//! read to the `\r\n\r\n` header terminator, take `Content-Length` from the
//! headers, then wait for exactly that many body bytes (RFC 3261 §7.5).
//!
//! Sans-IO on purpose — this module owns no socket, so every boundary case
//! is a plain unit test.

use rsip::SipMessage;

use super::transport::parse;

/// Largest header block we will buffer before declaring the peer broken.
/// Without a cap, a peer that never sends `\r\n\r\n` grows the buffer without
/// limit.
pub(crate) const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Why a stream could not be framed. Every variant is fatal for the
/// connection: once framing is lost there is no way to resynchronize onto
/// the next message boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FramingError {
    /// RFC 3261 §20.14 requires `Content-Length` on a stream transport.
    /// Assuming zero would resynchronize onto a body and corrupt everything
    /// after it.
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
    /// reads. `Err` means the stream can no longer be framed and the
    /// connection must be dropped.
    pub(crate) fn next_message(&mut self) -> Result<Option<SipMessage>, FramingError> {
        loop {
            // RFC 5626 §3.5.1 keepalives are bare CRLFs between messages.
            // No SIP message starts with CRLF, so leading ones are always
            // keepalive and never part of the next message.
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
            return match parse(&raw) {
                Some(msg) => Ok(Some(msg)),
                None => Err(FramingError::Malformed),
            };
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
        // A line with no colon is the start line or a continuation; skip it
        // rather than aborting the scan.
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
```

Then register the module by adding this line to `src/stack/mod.rs`, next to the other `mod` declarations:

```rust
pub(crate) mod framing;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p wavekat-sip framing`
Expected: PASS, 12 tests.

- [ ] **Step 5: Run the full check suite**

Run: `make ci`
Expected: all four checks pass, zero warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/wavekat-sip/src/stack/framing.rs crates/wavekat-sip/src/stack/mod.rs
git commit -m "feat: add sans-IO SIP stream framing"
```

---

### Task 2: The TCP connection

**Files:**
- Create: `src/stack/stream.rs`
- Modify: `src/stack/mod.rs` (add `pub(crate) mod stream;`)
- Test: bottom of `src/stack/stream.rs`

**Interfaces:**
- Consumes: `Framer`, `FramingError` from Task 1; `serialize` from `stack::transport`.
- Produces:
  - `pub(crate) struct StreamTransport`
  - `StreamTransport::connect(peer: SocketAddr) -> io::Result<Self>`
  - `StreamTransport::local_addr(&self) -> io::Result<SocketAddr>`
  - `StreamTransport::reliability(&self) -> Reliability` (always `Reliability::Reliable`)
  - `StreamTransport::send_to(&self, msg: &SipMessage, dst: SocketAddr) -> io::Result<()>`
  - `StreamTransport::recv(&self) -> io::Result<(SipMessage, SocketAddr)>`

The signatures deliberately mirror `UdpTransport`'s so Task 3's enum can dispatch without adapting either side.

**Why one connection:** we are a UA that connects out to one next-hop. Responses and inbound in-dialog requests arrive back down that same connection — which is exactly what makes inbound INVITEs work behind NAT. `dst` on `send_to` is therefore asserted, not routed on.

- [ ] **Step 1: Write the failing tests**

Create `src/stack/stream.rs` containing only:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        rsip::Request::try_from(raw.as_bytes()).expect("valid request").into()
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
        assert!(got.starts_with("OPTIONS sip:bob@example.com SIP/2.0\r\n"), "{got}");
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
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p wavekat-sip stream`
Expected: FAIL to compile — `cannot find type 'StreamTransport' in this scope`.

- [ ] **Step 3: Write the implementation**

Put this above the test module in `src/stack/stream.rs`:

```rust
//! A connection-oriented SIP transport.
//!
//! We are a User Agent: we connect out to one next-hop and every response and
//! in-dialog request comes back down that same connection. That is also what
//! makes inbound requests work behind NAT — the server reuses the connection
//! we opened rather than trying to reach us.
//!
//! A write half behind a mutex serializes concurrent sends; a read task owns
//! the read half, frames it with [`Framer`], and publishes whole messages on a
//! channel that [`StreamTransport::recv`] drains.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use rsip::SipMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
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
        // delays a request waiting for more bytes that are not coming.
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
/// design: once the message boundaries are lost there is no way to find the
/// next one, so continuing would feed the engine garbage.
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
```

Register the module in `src/stack/mod.rs`:

```rust
pub(crate) mod stream;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p wavekat-sip stream`
Expected: PASS, 6 tests.

- [ ] **Step 5: Run the full check suite**

Run: `make ci`
Expected: all four checks pass, zero warnings.

If clippy flags `serialize(&msg)` inside the debug log as needless work, wrap that `debug!` in `if tracing::enabled!(tracing::Level::DEBUG)` rather than deleting the log — the UDP transport logs both directions and the stream path must stay equally debuggable.

- [ ] **Step 6: Commit**

```bash
git add crates/wavekat-sip/src/stack/stream.rs crates/wavekat-sip/src/stack/mod.rs
git commit -m "feat: add connection-oriented SIP stream transport"
```

---

### Task 3: Wire the transport choice into the engine

**Files:**
- Modify: `src/stack/transport.rs` (add the enum; keep everything already there)
- Modify: `src/stack/engine.rs:154` (field), `:180-182` (bind), `:208-213` (recv), `:344`, `:357` (send)
- Modify: `src/stack/ua.rs:59-96` (the four `bind_*` functions)
- Test: bottom of `src/stack/transport.rs`

**Interfaces:**
- Consumes: `StreamTransport` (Task 2), existing `UdpTransport`.
- Produces:
  - `pub(crate) enum BoundTransport { Datagram(UdpTransport), Stream(StreamTransport) }`
  - `BoundTransport::bind(local: SocketAddr, peer: SocketAddr, transport: Transport) -> io::Result<Self>`
  - `BoundTransport::local_addr(&self) -> io::Result<SocketAddr>`
  - `BoundTransport::reliability(&self) -> Reliability`
  - `BoundTransport::send_to(&self, msg: &SipMessage, dst: SocketAddr) -> io::Result<()>`
  - `BoundTransport::recv(&self) -> io::Result<(SipMessage, SocketAddr)>`
  - `engine::start_with_timers(local, peer, transport, timers, cancel)` — signature gains `peer: SocketAddr` and `transport: Transport`
  - `Ua::bind_full(local, peer, transport, timers, user_agent, cancel)` — same two additions, mirrored on `bind`, `bind_with_timers`, `bind_with_app`

**Why `peer` reaches the bind:** a datagram transport binds a local socket and learns its address immediately; a stream has no local address until it has connected to somewhere. Both paths therefore need the next-hop up front.

- [ ] **Step 1: Write the failing tests**

Append to the existing `#[cfg(test)] mod tests` at the bottom of `src/stack/transport.rs`:

```rust
    use crate::account::Transport as TransportKind;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn udp_kind_binds_a_datagram_transport() {
        let peer: SocketAddr = "127.0.0.1:9".parse().expect("addr");
        let t = BoundTransport::bind("127.0.0.1:0".parse().expect("addr"), peer, TransportKind::Udp)
            .await
            .expect("binds");
        assert!(matches!(t, BoundTransport::Datagram(_)));
        assert!(!t.reliability().is_reliable(), "UDP is unreliable");
    }

    #[tokio::test]
    async fn tcp_kind_binds_a_stream_transport() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let peer = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let t = BoundTransport::bind("127.0.0.1:0".parse().expect("addr"), peer, TransportKind::Tcp)
            .await
            .expect("binds");
        assert!(matches!(t, BoundTransport::Stream(_)), "TCP must not silently bind UDP");
        assert!(t.reliability().is_reliable(), "TCP is reliable");
    }

    /// The regression this whole phase exists for: before it, selecting TCP
    /// produced a UDP socket reporting itself as unreliable.
    #[tokio::test]
    async fn tcp_local_addr_is_the_connections_not_a_udp_sockets() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let peer = listener.local_addr().expect("addr");
        let accepted = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.expect("accept");
            sock.peer_addr().expect("peer addr")
        });

        let t = BoundTransport::bind("127.0.0.1:0".parse().expect("addr"), peer, TransportKind::Tcp)
            .await
            .expect("binds");
        let seen_by_server = accepted.await.expect("accept task");
        assert_eq!(
            t.local_addr().expect("local addr"),
            seen_by_server,
            "local_addr must be the TCP connection's address"
        );
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p wavekat-sip transport`
Expected: FAIL to compile — `cannot find type 'BoundTransport' in this scope`.

- [ ] **Step 3: Add the enum**

Append to `src/stack/transport.rs`, after the `UdpTransport` impl and before the test module:

```rust
/// The bound transport the engine drives, in whichever shape the account
/// selected.
///
/// An enum rather than a trait object: there are exactly two shapes, the
/// crate carries no `async-trait` dependency, and keeping the dispatch
/// visible is worth more here than open extension.
pub(crate) enum BoundTransport {
    /// UDP — one datagram per message, retransmission timers apply.
    Datagram(UdpTransport),
    /// TCP (and, later, TLS) — a framed byte stream to one next-hop.
    Stream(StreamTransport),
}

impl BoundTransport {
    /// Bind (UDP) or connect (stream) for `transport`.
    ///
    /// `local` selects the outbound interface for the datagram path and is
    /// ignored on the stream path, where the OS assigns the source address as
    /// part of connecting. `peer` is the resolved next-hop.
    pub(crate) async fn bind(
        local: SocketAddr,
        peer: SocketAddr,
        transport: Transport,
    ) -> io::Result<Self> {
        match transport {
            Transport::Udp => Ok(Self::Datagram(UdpTransport::bind(local).await?)),
            Transport::Tcp => Ok(Self::Stream(StreamTransport::connect(peer).await?)),
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
```

Add to the imports at the top of `src/stack/transport.rs`:

```rust
use crate::account::Transport;

use super::stream::StreamTransport;
```

`Reliability` is already imported there (`use super::transaction::Reliability;`); if not, add it.

- [ ] **Step 4: Thread it through the engine**

In `src/stack/engine.rs`:

Replace the import `use super::transport::UdpTransport;` with:

```rust
use crate::account::Transport;

use super::transport::BoundTransport;
```

Change the `Engine` struct field (line ~154) from `transport: Arc<UdpTransport>,` to:

```rust
    transport: Arc<BoundTransport>,
```

Change `start` and `start_with_timers` to take the next-hop and the transport kind:

```rust
/// Bind the transport and spawn the engine task.
///
/// Returns a handle for issuing commands and the stream of [`Event`]s the
/// engine produces. The task runs until `cancel` fires or the transport
/// errors.
pub(crate) async fn start(
    local: SocketAddr,
    peer: SocketAddr,
    transport: Transport,
    cancel: CancellationToken,
) -> io::Result<(EngineHandle, mpsc::Receiver<Event>)> {
    start_with_timers(local, peer, transport, Timers::default(), cancel).await
}

/// Like [`start`], but with explicit base timers. Used by tests to shrink the
/// RFC timer table so timeouts and soak periods fire in milliseconds.
pub(crate) async fn start_with_timers(
    local: SocketAddr,
    peer: SocketAddr,
    transport: Transport,
    timers: Timers,
    cancel: CancellationToken,
) -> io::Result<(EngineHandle, mpsc::Receiver<Event>)> {
    let transport = Arc::new(BoundTransport::bind(local, peer, transport).await?);
    let local_addr = transport.local_addr()?;
    let reliability = transport.reliability();
    // ... rest of the function body is unchanged ...
```

In `Engine::run` (line ~215), the receive arm's error message mentions UDP; make it transport-neutral:

```rust
                    Err(e) => { warn!(error = %e, "SIP transport receive failed; stopping engine"); break; }
```

The two `self.transport.send_to(...)` call sites (lines ~344 and ~357) need no change — the enum's method has the same signature.

- [ ] **Step 5: Thread it through `Ua`**

In `src/stack/ua.rs`, add `use crate::account::Transport;` to the imports, then give all four constructors the two new parameters:

```rust
    /// Bind for `transport` toward `peer` and start the engine + router with
    /// default timers.
    pub(crate) async fn bind(
        local: SocketAddr,
        peer: SocketAddr,
        transport: Transport,
        cancel: CancellationToken,
    ) -> io::Result<Self> {
        Self::bind_full(local, peer, transport, Timers::default(), None, cancel).await
    }

    /// Bind with explicit base timers (tests shrink them).
    pub(crate) async fn bind_with_timers(
        local: SocketAddr,
        peer: SocketAddr,
        transport: Transport,
        timers: Timers,
        cancel: CancellationToken,
    ) -> io::Result<Self> {
        Self::bind_full(local, peer, transport, timers, None, cancel).await
    }

    /// Bind advertising `user_agent` as the `User-Agent` on outbound requests.
    pub(crate) async fn bind_with_app(
        local: SocketAddr,
        peer: SocketAddr,
        transport: Transport,
        user_agent: Option<String>,
        cancel: CancellationToken,
    ) -> io::Result<Self> {
        Self::bind_full(local, peer, transport, Timers::default(), user_agent, cancel).await
    }

    async fn bind_full(
        local: SocketAddr,
        peer: SocketAddr,
        transport: Transport,
        timers: Timers,
        user_agent: Option<String>,
        cancel: CancellationToken,
    ) -> io::Result<Self> {
        let (engine, events) =
            engine::start_with_timers(local, peer, transport, timers, cancel).await?;
        // ... rest of the function body is unchanged ...
```

- [ ] **Step 6: Fix every existing call site**

Run: `cargo test -p wavekat-sip 2>&1 | grep -E "^error" | head -40`

The existing loopback tests in `engine.rs`, `ua.rs`, and `endpoint.rs` call these functions. Each is a UDP test: pass the peer it already dials and `Transport::Udp`. For example, a call that was:

```rust
let ua = Ua::bind_with_timers(local, timers, cancel.clone()).await.expect("binds");
```

becomes:

```rust
let ua = Ua::bind_with_timers(local, peer, Transport::Udp, timers, cancel.clone())
    .await
    .expect("binds");
```

Where a test has no peer variable in scope yet, it always dials one later in the body — hoist that address above the bind. For `endpoint.rs`, `SipEndpoint::new_with_app` is covered in Task 5; for now pass `server` and `account.transport` at its `Ua::bind_with_app` call, which compiles because `server` is resolved just below — **move the `resolve_sip_server` call above the `Ua::bind_with_app` call** to make that true. Task 5 documents why that ordering is required anyway.

- [ ] **Step 7: Run the tests**

Run: `cargo test -p wavekat-sip`
Expected: PASS, including the three new `transport` tests. No test should have changed behaviour — only signatures.

- [ ] **Step 8: Run the full check suite**

Run: `make ci`
Expected: all four checks pass, zero warnings.

- [ ] **Step 9: Commit**

```bash
git add crates/wavekat-sip/src/stack/
git commit -m "feat: drive the engine from a transport-kind-aware bound transport"
```

---

### Task 4: Transport-aware Via and Contact

**Files:**
- Modify: `src/stack/transaction/mod.rs:301` (`via_value`)
- Modify: `src/stack/registration.rs:68`, `src/stack/call.rs:72`, `src/stack/dialog.rs:218` (call sites)
- Modify: `src/registrar.rs:74` (contact URI)
- Test: bottom of `src/stack/transaction/mod.rs` and bottom of `src/registrar.rs`

**Interfaces:**
- Consumes: `crate::account::Transport`.
- Produces:
  - `via_value(transport: Transport, sent_by: impl Display, branch: &str) -> String` — **signature change**, transport is the new first parameter
  - `pub(crate) fn contact_uri(username: &str, local: SocketAddr, transport: Transport) -> String` in `src/registrar.rs`

**Why both:** the Via tells the server which transport to answer on; the Contact tells the registrar which transport to reach us on for a later inbound INVITE. A UDP Via on a TCP connection asks the server to answer somewhere we are not listening, and a Contact with no `transport` parameter defaults to UDP (RFC 3261 §19.1.1), so inbound calls land on the wrong transport.

- [ ] **Step 1: Write the failing tests**

In `src/stack/transaction/mod.rs`, replace the existing test `via_value_advertises_rport_and_keeps_branch_parseable` with:

```rust
    #[test]
    fn via_value_advertises_rport_and_keeps_branch_parseable() {
        let v = via_value(crate::account::Transport::Udp, "192.168.1.46:54991", "z9hG4bK-rp");
        assert!(v.contains(";rport"), "{v}");
        assert!(v.contains("branch=z9hG4bK-rp"), "{v}");
    }

    #[test]
    fn via_value_names_the_transport() {
        use crate::account::Transport;
        assert!(
            via_value(Transport::Udp, "10.0.0.1:5060", "b").starts_with("SIP/2.0/UDP "),
            "UDP"
        );
        assert!(
            via_value(Transport::Tcp, "10.0.0.1:5060", "b").starts_with("SIP/2.0/TCP "),
            "TCP must not advertise UDP — the server would answer on a socket we are not listening on"
        );
    }
```

In `src/registrar.rs`, add to its `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn contact_uri_omits_transport_param_for_udp() {
        let local: std::net::SocketAddr = "10.0.0.1:5060".parse().expect("addr");
        let c = contact_uri("1001", local, crate::account::Transport::Udp);
        assert_eq!(c, "sip:1001@10.0.0.1:5060");
    }

    /// RFC 3261 §19.1.1: a Contact URI with no transport parameter means UDP.
    /// Without this the registrar routes inbound INVITEs to a UDP socket that
    /// does not exist on a TCP endpoint.
    #[test]
    fn contact_uri_names_tcp_transport() {
        let local: std::net::SocketAddr = "10.0.0.1:5060".parse().expect("addr");
        let c = contact_uri("1001", local, crate::account::Transport::Tcp);
        assert_eq!(c, "sip:1001@10.0.0.1:5060;transport=tcp");
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p wavekat-sip via_value contact_uri`
Expected: FAIL to compile — `via_value` takes 2 arguments but 3 were supplied; `cannot find function 'contact_uri'`.

- [ ] **Step 3: Change `via_value`**

In `src/stack/transaction/mod.rs`, replace the function (and update its doc comment's first line):

```rust
/// Build the `Via` header value for one of our outgoing requests: the
/// sent-by, the transport we will actually use, the given transaction
/// `branch`, and a bare `;rport` (RFC 3581).
///
/// The transport name is not cosmetic — it tells the server which transport
/// to send the response back over. Naming UDP on a stream connection asks for
/// a reply on a socket we are not listening on.
///
/// `rport` is what lets us be reached behind NAT. Without it, a proxy records
/// our private sent-by / `Contact` and routes a later in-dialog request (most
/// importantly the peer's `BYE`) to an address that never arrives — so the call
/// never tears down on a remote hangup. With it, the proxy stamps `received` /
/// `rport` from the packet's real source and routes back there instead. The
/// value is empty in a request (RFC 3581 §3); the server fills it in its
/// response. It is a UDP mechanism and inert on a stream transport, where it
/// is harmless.
pub(crate) fn via_value(
    transport: crate::account::Transport,
    sent_by: impl std::fmt::Display,
    branch: &str,
) -> String {
    let proto = match transport {
        crate::account::Transport::Udp => "UDP",
        crate::account::Transport::Tcp => "TCP",
    };
    format!("SIP/2.0/{proto} {sent_by};rport;branch={branch}")
}
```

- [ ] **Step 4: Update the three call sites**

Each builder needs the transport in scope. Add a `transport: Transport` field to the config struct each one already takes, rather than adding a loose parameter:

- `src/stack/registration.rs:68` — `RegisterConfig` gains `pub(crate) transport: Transport`; the call becomes `via_value(cfg.transport, local_addr, &gen_branch())`.
- `src/stack/call.rs:72` — the call config gains the same field; the call becomes `via_value(cfg.transport, local_addr, &gen_branch())`.
- `src/stack/dialog.rs:218` — `Dialog` gains the field, set when the dialog is created from the call config; the call becomes `via_value(self.transport, local_addr, &gen_branch())`.

Run `cargo check -p wavekat-sip 2>&1 | grep -E "^error" | head -20` and populate the new field at each construction site. In production code the value comes from the account; in tests use `Transport::Udp` so existing expectations hold.

- [ ] **Step 5: Add `contact_uri`**

In `src/registrar.rs`, add above the `Registrar` impl:

```rust
/// Build the `Contact` URI the registrar advertises.
///
/// The `transport` parameter is required for anything but UDP: RFC 3261
/// §19.1.1 makes UDP the default when it is absent, so a bare URI on a TCP
/// endpoint tells the registrar to reach us for inbound calls over a
/// transport we are not listening on.
pub(crate) fn contact_uri(
    username: &str,
    local: std::net::SocketAddr,
    transport: crate::account::Transport,
) -> String {
    match transport {
        crate::account::Transport::Udp => format!("sip:{username}@{local}"),
        crate::account::Transport::Tcp => format!("sip:{username}@{local};transport=tcp"),
    }
}
```

Then replace line 74:

```rust
        let contact = format!("sip:{}@{}", account.username, endpoint.local_addr());
```

with:

```rust
        let contact = contact_uri(
            &account.username,
            endpoint.local_addr(),
            endpoint.transport(),
        );
```

and set `transport: endpoint.transport()` on the `RegisterConfig` built at line ~101.

- [ ] **Step 6: Run the tests**

Run: `cargo test -p wavekat-sip`
Expected: PASS. The existing `registrar.rs` test at line ~228 constructs a contact of `"sip:1001@10.0.0.1:5060"` — it stays valid, since UDP produces exactly that.

- [ ] **Step 7: Run the full check suite**

Run: `make ci`
Expected: all four checks pass, zero warnings.

- [ ] **Step 8: Commit**

```bash
git add crates/wavekat-sip/src/
git commit -m "fix: name the real transport in Via and Contact"
```

---

### Task 5: Resolve before bind

**Files:**
- Modify: `src/endpoint.rs:96-110` (`SipEndpoint::new_with_app`)
- Test: bottom of `src/endpoint.rs`

**Interfaces:**
- Consumes: `resolve_sip_server` (existing), `Ua::bind_with_app` (Task 3 signature).
- Produces: no new public surface; `SipEndpoint::new` / `new_with_app` keep their signatures.

**Why:** `new_with_app` currently binds an ephemeral socket and *then* resolves the server. A stream transport has no local address until it has connected, and it cannot connect without knowing where — so resolution has to happen first. Task 3 already moved this line to make the build pass; this task makes the ordering deliberate, documented, and tested.

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` at the bottom of `src/endpoint.rs`:

```rust
    /// A stream transport has no local address until it has connected, so the
    /// next-hop must be known before binding. Guarding the ordering directly
    /// is awkward, so this asserts the observable consequence: a TCP endpoint
    /// whose server does not resolve fails without having bound anything.
    #[tokio::test]
    async fn tcp_endpoint_fails_when_the_server_does_not_resolve() {
        let mut account = make_account(Some("invalid.invalid"), Some(5060));
        account.transport = Transport::Tcp;
        let cancel = CancellationToken::new();
        let result = SipEndpoint::new(&account, cancel).await;
        assert!(result.is_err(), "unresolvable server must not yield an endpoint");
    }

    /// A TCP endpoint against a real listener reports the connection's own
    /// local address — the regression guard for "TCP silently bound UDP".
    #[tokio::test]
    async fn tcp_endpoint_binds_a_stream_to_the_resolved_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            // Accept and hold, so the endpoint's read task does not see EOF.
            let _held = listener.accept().await;
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        });

        let mut account = make_account(Some("127.0.0.1"), Some(addr.port()));
        account.transport = Transport::Tcp;
        let cancel = CancellationToken::new();
        let endpoint = SipEndpoint::new(&account, cancel.clone())
            .await
            .expect("binds a TCP endpoint");

        assert_eq!(endpoint.transport(), Transport::Tcp);
        assert_eq!(
            endpoint.local_addr().ip().to_string(),
            "127.0.0.1",
            "local address comes from the TCP connection"
        );
        endpoint.shutdown();
    }
```

The existing `make_account` helper at line ~423 does not set `transport`; confirm it uses `transport: Transport::default()` and add the field if it is missing.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p wavekat-sip tcp_endpoint`
Expected: FAIL — if Task 3's provisional edit is already in place these may pass, in which case confirm by `git stash`-ing nothing and instead reading the function: the assertion that must hold is that `resolve_sip_server` appears **above** `Ua::bind_with_app`.

- [ ] **Step 3: Make the ordering deliberate**

Rewrite the opening of `new_with_app` so it reads in the order it must execute, with the reason recorded:

```rust
        // Resolution comes first, and must: a stream transport has no local
        // address until it has connected, and it cannot connect without
        // knowing the next hop. The datagram path does not care about the
        // order, so both share this one.
        let server = resolve_sip_server(account)
            .await?
            .ok_or("could not resolve SIP server address")?;
        info!(%server, "resolved SIP server");

        // Selects the outbound interface for the datagram path; ignored on
        // the stream path, where connecting assigns the source address.
        let local_ip = detect_local_ip(account)?;
        let bind_addr = SocketAddr::new(local_ip, 0);
        info!("Binding SIP transport to {bind_addr}");

        let ua = Arc::new(
            Ua::bind_with_app(
                bind_addr,
                server,
                account.transport,
                product.map(String::from),
                cancel.clone(),
            )
            .await?,
        );
```

Delete the now-duplicated `resolve_sip_server` block further down, and update the module doc comment at the top of `endpoint.rs` — its first line says "a bound UDP transport + the clean-room engine". Change it to "a bound SIP transport (UDP or TCP) + the clean-room engine".

- [ ] **Step 4: Run the tests**

Run: `cargo test -p wavekat-sip`
Expected: PASS.

- [ ] **Step 5: Run the full check suite**

Run: `make ci`
Expected: all four checks pass, zero warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/wavekat-sip/src/endpoint.rs
git commit -m "refactor: resolve the next hop before binding the transport"
```

---

### Task 6: End-to-end REGISTER over TCP

**Files:**
- Create: `tests/tcp_transport.rs`
- Modify: `Cargo.toml` (register the test target — the manifest lists tests explicitly)

**Interfaces:**
- Consumes: the public surface only — `SipAccount`, `Transport`, `SipEndpoint`, `Registrar`. This is the consumer's-eye test.
- Produces: nothing; it is a leaf.

**Why:** Tasks 1-5 each test a layer. Nothing yet proves the layers compose into a REGISTER that a real TCP peer accepts — which is the actual claim of this phase.

- [ ] **Step 1: Register the test target**

`crates/wavekat-sip/Cargo.toml` declares test targets explicitly (`autotests = false`). Add alongside the existing `[[test]]` entries:

```toml
[[test]]
name = "tcp_transport"
path = "tests/tcp_transport.rs"
```

- [ ] **Step 2: Write the failing test**

Create `tests/tcp_transport.rs`:

```rust
//! End-to-end exercise of SIP over TCP against a loopback listener.
//!
//! A minimal server accepts one connection, reads a framed REGISTER, asserts
//! the headers name TCP, and answers `200 OK` on the same connection. This is
//! the integration counterpart to the in-crate framing and stream unit tests:
//! it drives the *public* surface exactly as a consumer would.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use wavekat_sip::{Registrar, SipAccount, SipEndpoint, Transport};

fn account(port: u16) -> SipAccount {
    SipAccount {
        display_name: "Test".into(),
        username: "1001".into(),
        password: "secret".into(),
        domain: "127.0.0.1".into(),
        auth_username: None,
        server: Some("127.0.0.1".into()),
        port: Some(port),
        transport: Transport::Tcp,
    }
}

/// Read until the header terminator, so the assertions see a whole message.
async fn read_message(sock: &mut tokio::net::TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = sock.read(&mut chunk).await.expect("read");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

fn ok_for(register: &str) -> String {
    let header = |name: &str| -> String {
        register
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with(&name.to_ascii_lowercase()))
            .unwrap_or_default()
            .trim_end()
            .to_string()
    };
    format!(
        "SIP/2.0 200 OK\r\n{}\r\n{}\r\n{};tag=server\r\n{}\r\n{}\r\nExpires: 60\r\nContent-Length: 0\r\n\r\n",
        header("Via:"),
        header("From:"),
        header("To:"),
        header("Call-ID:"),
        header("CSeq:"),
    )
}

#[tokio::test]
async fn registers_over_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let (seen_tx, seen_rx) = oneshot::channel::<String>();

    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let register = read_message(&mut sock).await;
        sock.write_all(ok_for(&register).as_bytes())
            .await
            .expect("write 200");
        let _ = seen_tx.send(register);
        // Hold the connection open past the assertions.
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let cancel = CancellationToken::new();
    let endpoint = SipEndpoint::new(&account(addr.port()), cancel.clone())
        .await
        .expect("binds a TCP endpoint");
    let registrar = Registrar::new(&account(addr.port()), endpoint.clone());

    let outcome = timeout(Duration::from_secs(5), registrar.register_once())
        .await
        .expect("register completes");
    assert!(outcome.is_ok(), "REGISTER over TCP succeeded: {outcome:?}");

    let register = timeout(Duration::from_secs(5), seen_rx)
        .await
        .expect("server saw a REGISTER")
        .expect("channel");

    assert!(
        register.starts_with("REGISTER "),
        "server received a REGISTER:\n{register}"
    );
    assert!(
        register.contains("Via: SIP/2.0/TCP "),
        "Via must name TCP, not UDP:\n{register}"
    );
    assert!(
        register.to_ascii_lowercase().contains("transport=tcp"),
        "Contact must carry ;transport=tcp:\n{register}"
    );
    assert!(
        register.contains("Content-Length: 0"),
        "stream framing requires Content-Length:\n{register}"
    );

    endpoint.shutdown();
    cancel.cancel();
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p wavekat-sip --test tcp_transport`
Expected: FAIL to compile if `Registrar::register_once` is not the actual method name.

Resolve by reading the real surface: `grep -n "pub async fn\|pub fn" crates/wavekat-sip/src/registrar.rs`. Use whichever method performs a single REGISTER and returns its outcome, and adjust the `outcome.is_ok()` assertion to match that type (it may be an enum like `RegisterOutcome`, in which case assert `matches!(outcome, RegisterOutcome::Registered { .. })`). Do not add a new public method to make the test compile — the test exists to exercise the surface a consumer already has.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p wavekat-sip --test tcp_transport`
Expected: PASS.

If the REGISTER never arrives, check in this order: the endpoint connected (Task 3's `BoundTransport::bind` matched `Transport::Tcp`), the request was written (`RUST_LOG=debug cargo test ...` shows the `>>> SEND` line), and the response framed (the server's `Content-Length: 0` is present — without it `Framer` returns `MissingContentLength` and the read task drops the connection).

- [ ] **Step 5: Run the full check suite**

Run: `make ci`
Expected: all four checks pass, zero warnings.

- [ ] **Step 6: Commit**

```bash
git add crates/wavekat-sip/tests/tcp_transport.rs crates/wavekat-sip/Cargo.toml
git commit -m "test: register over TCP end to end"
```

---

### Task 7: Update the living docs

**Files:**
- Modify: `docs/RFC-COVERAGE.md` — the "Transports" section, the "Known gaps worth closing first" list, and the `Last audited` header date

**Interfaces:** none — documentation only.

**Why:** `RFC-COVERAGE.md` is a living doc whose contract is that it stays accurate; its own header says to re-audit when the public surface changes. It currently says the TCP variant is inert and ranks it gap #2. Both statements stop being true in this phase, and a living doc that has gone stale is worse than no doc, because it is cited as current.

- [ ] **Step 1: Update the Transports section**

Replace the "### Transports" paragraph with:

```markdown
### Transports

The engine implements **UDP** and **TCP**. `Transport::Udp` binds a datagram
socket; `Transport::Tcp` opens a connection to the resolved next hop, frames
the byte stream per RFC 3261 §7.5 / §20.14, and suppresses the §17
retransmission timers as a reliable transport should. `Via` names the
transport in use and the registrar's `Contact` carries `;transport=tcp`, so a
registrar routes inbound requests back over the same connection. RFC 5626
§3.5.1 CRLF keepalives are accepted on the stream path. TLS and WebSocket are
not implemented.
```

- [ ] **Step 2: Update the gaps list**

Remove the entry `2. **TCP transport** — the `Transport::Tcp` variant is currently inert.` and renumber the remaining entries so the list stays 1..n with no gap.

- [ ] **Step 3: Update the audit date**

Change the header line to:

```markdown
> Status: living document · Last audited: 2026-09-20 (TCP transport implemented — see `docs/18`)
```

- [ ] **Step 4: Verify no stale claims remain**

Run: `grep -n "inert\|UDP transport only\|TCP transport" docs/RFC-COVERAGE.md`
Expected: no line still describes TCP as unimplemented or the engine as UDP-only.

- [ ] **Step 5: Commit**

```bash
git add docs/RFC-COVERAGE.md
git commit -m "docs: record TCP transport in RFC coverage"
```

---

## Done when

- `make ci` passes with zero warnings.
- `cargo test -p wavekat-sip --test tcp_transport` passes.
- A REGISTER sent with `Transport::Tcp` arrives at the peer over TCP, with `Via: SIP/2.0/TCP` and a `Contact` carrying `;transport=tcp`.
- `RFC-COVERAGE.md` no longer lists TCP as a gap.
- No new dependency appears in `Cargo.toml` beyond the `[[test]]` target.

## Deliberately not in this phase

Each belongs to a later phase or a later plan, and pulling any of them forward widens the review surface without making TCP work:

- **Reconnect and backoff.** The spec's Phase 1 section describes reconnecting on a dropped connection and notifying the registrar. It needs a `Registrar` re-registration hook that does not exist yet, and TCP is useful without it. Implement it as the first task of the TLS phase, where a dropped connection is far more likely, or as a follow-up plan if that phase slips.
- **CRLF keepalive *sending*.** `Framer` accepts inbound keepalives (tested in Task 1), which is what interoperability requires. Sending them on an interval is part of the same reconnect work.
- **TLS.** Phase 2.
- **SRV failover across multiple targets.** Gap #5 in `RFC-COVERAGE.md`, unrelated to transport shape.
