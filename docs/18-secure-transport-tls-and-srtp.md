# Secure transport: stream transports, SIP over TLS, and SRTP — plan

Date: 2026-09-20

## Why

Everything this crate sends today is readable by anyone on the path.
`RFC-COVERAGE.md` already ranks the two halves of that problem as gaps
#2 and #4: the `Transport::Tcp` variant is inert, and "credentials
currently ride plaintext except for the digest exchange itself".

The second half understates it. Digest auth protects the *password*
from recovery, and nothing else. Every REGISTER, every INVITE, every
`From`/`To` — who is calling whom, from what number, at what time —
travels in cleartext, and the RTP carrying the conversation is raw
PCM on an unauthenticated UDP port. An observer on the same café
Wi-Fi does not need to break anything to record the call; they need
`tcpdump` and any RTP player.

There is also a live correctness bug. `Transport::Tcp` is not merely
unimplemented — it is *misimplemented*, in a way that is worse than
having no TCP at all:

- `resolve.rs` asks DNS for `_sip._tcp` and returns whatever that SRV
  record names — typically a port the server listens on for TCP only.
- `stack::transaction` has a `From<Transport> for Reliability` mapping
  `Tcp` to `Reliable`, but **nothing calls it**. `stack::engine` takes
  its reliability from `UdpTransport::reliability()`, which is a
  hard-coded `Unreliable`. The transaction layer's single piece of TCP
  awareness is dead code.
- `stack::engine` binds a `UdpTransport` regardless of the setting.
- `via_value` hard-codes `SIP/2.0/UDP` on every request.

So selecting TCP sends UDP datagrams, to an address chosen by a
TCP-only SRV record, carrying a Via that instructs the server to answer
over UDP. If the server happens to also listen on UDP at that port it
works by accident and nobody notices. If it does not — the normal case
for an SBC that publishes a TCP-only port — nothing answers, and the
transaction layer dutifully retransmits into the void until it times
out. The failure is indistinguishable from an unreachable server, which
is the worst way for a configuration bug to present.

## Non-goals

- **Not** a server-side TLS listener. We are a UA; we connect out.
  Inbound calls arrive over the connection we already opened.
- **Not** DTLS-SRTP (RFC 5763/5764). Classic SIP trunks and on-premise
  PBXes key SRTP with SDES (RFC 4568); DTLS-SRTP is the WebRTC path and
  would be a separate plan.
- **Not** SIP over WebSocket (RFC 7118). The stream abstraction below
  would make it cheap later, but it is not in this plan.
- **Not** SRTCP. The crate implements no RTCP at all, so there is
  nothing to protect. If RTCP lands later (gap #3), SRTCP lands with it.
- **Not** a general certificate-management story. This crate validates
  and reports; policy decisions belong to the consumer.

## Shape of the work

Three phases, each a release. They are strictly ordered, because each
is the foundation of the next:

| Phase | Ships | Why it must come first |
|-------|-------|------------------------|
| 1 | Stream transport, TCP over it | TLS is this plus a handshake. Everything hard about a stream — framing, connection lifecycle, transport-aware headers — is inherited unchanged. |
| 2 | SIP over TLS (`sips:`, 5061) | SDES keys travel *in* the SDP. Offering SRTP over cleartext signaling hands the key to the same observer, so phase 3 is meaningless without this. |
| 3 | SRTP via SDES | — |

Phase 1 is also a bug fix worth shipping on its own merits: it makes
`Transport::Tcp` mean what it says.

---

## Phase 1 — stream transport

### The abstraction

`stack/transport.rs` is currently "SIP message (de)serialization and a
bound UDP socket". It becomes a two-variant enum. Not a trait object:
there are exactly two shapes, the crate has no `async-trait`
dependency, and an enum keeps the dispatch visible.

```rust
pub(crate) enum BoundTransport {
    Datagram(UdpTransport),   // today's implementation, unchanged
    Stream(StreamTransport),
}
```

`StreamTransport` owns one connection per next-hop: a write half behind
a mutex, a read task feeding the same inbound channel the UDP path
uses, and the reconnect logic. `stack::engine` holds a `BoundTransport`
instead of an `Arc<UdpTransport>`. The transaction machines above it do
not change: they already take a `Reliability` and honour it correctly.
What phase 1 adds is a *truthful source* for it — which is also what
makes the existing `From<Transport> for Reliability` impl live code for
the first time.

Per the module-size rule, this splits: `stack/transport.rs` keeps the
enum and the shared `parse`/`serialize`, `stack/framing.rs` holds the
framer, `stack/stream.rs` the connection.

### Framing is the actual work

A datagram carries exactly one SIP message; a stream carries none. The
framer accumulates bytes, finds the `\r\n\r\n` header terminator,
parses `Content-Length`, waits for that many body bytes, emits, and
repeats with the remainder. Three rules that are easy to get wrong and
expensive to get wrong:

- **A missing `Content-Length` on a stream is a protocol error**, not
  an implied zero (RFC 3261 §20.14). Treating it as zero resynchronizes
  the stream onto a body, and every subsequent message is garbage.
- **Bare `CRLF` between messages must be skipped.** `CRLFCRLF` is the
  connection keepalive (RFC 5626 §3.5.1), and a peer may send it at any
  point between messages.
- **A header block larger than a sane cap is a protocol error.** Without
  one, a peer that never sends `\r\n\r\n` grows our buffer without limit.

That keepalive is also the answer to NAT on a stream transport: a
4-byte ping on the existing connection, replacing the UDP `OPTIONS`
loop. `StreamTransport` sends `CRLFCRLF` on an interval and expects
`CRLF` back; a configurable interval with the `Registrar`'s existing
keepalive cadence as the default.

### Connection lifecycle

Connect lazily on first send. On a read error or clean close, mark the
connection dead, reconnect with exponential backoff (capped), and
surface the event so `Registrar` re-REGISTERs — a new connection means
a new source port, so the registrar's binding is stale until it does.

In-dialog requests reuse the same connection as a matter of course,
which is what makes inbound INVITEs work at all behind NAT: the server
sends them down the connection we opened.

### Three header fixes that ride along

Each of these is silently wrong today and becomes visibly wrong the
moment a real TCP peer is on the other end:

- `via_value(transport, sent_by, branch)` emits `SIP/2.0/TCP` or
  `SIP/2.0/TLS`. A server told `UDP` will answer over UDP.
- `Contact` gains `;transport=tcp|tls`. Without it the registrar
  records a UDP contact and routes inbound INVITEs to a socket nobody
  is listening on.
- `;rport` stays on the Via. It is meaningless on a stream (RFC 3581 is
  a UDP mechanism) but harmless, and removing it conditionally is more
  code than leaving it.

### One ordering inversion

`SipEndpoint::new` currently binds an ephemeral socket, *then* resolves
the server. A stream's local address does not exist until the
connection is established, so resolution moves ahead of binding.
`detect_local_ip` stays for the datagram path and for choosing an
outbound interface.

### Tests

- Framer unit tests, at the bottom of `framing.rs`: a message split
  mid-header; two messages in one read; a body split across reads; a
  bare-CRLF keepalive between messages; a missing `Content-Length`;
  an oversized header block; a body shorter than its declared length.
- `via_value` and `Contact` assertions per transport.
- An end-to-end REGISTER against a loopback `TcpListener`, mirroring
  the existing `tests/end_to_end_call.rs` shape.
- A reconnect test: kill the listener mid-dialog, assert the transport
  reconnects and the registrar is notified.

---

## Phase 2 — SIP over TLS

### Dependencies

`tokio-rustls` and `rustls-platform-verifier`, behind a non-default
`tls` cargo feature so consumers that do not need TLS do not pay for
it. `rustls` rather than `native-tls`: no OpenSSL in anyone's
cross-build, and it is already the TLS stack most Rust consumers carry.
`rustls-platform-verifier` reads the OS trust store — Keychain on
macOS, CryptoAPI on Windows, the ca-certificates bundle on Linux — so
a private CA an administrator has already installed system-wide works
with no extra configuration.

### Verify the SIP domain, not the resolved target

This is the detail most SIP-TLS implementations get wrong, and getting
it wrong removes the protection entirely.

RFC 5922 §7.1: the identity to check is the **domain from the SIP URI**,
not the hostname the SRV lookup returned. If `sip.example.com` has an
SRV record pointing at `edge-3.some-provider.net`, the certificate must
match `sip.example.com`. Verifying `edge-3.some-provider.net` instead
means whoever can answer the DNS query also chooses which name the
certificate has to match — and they can point it at a host whose
certificate they legitimately hold.

So the verification name comes from the account's domain, and SNI is
sent for that same name. `resolve.rs` gains `_sips._tcp` alongside
`_sip._udp` / `_sip._tcp`, defaults to port 5061 for TLS, and `sips:`
is accepted wherever a URI is parsed.

### Trust policy

```rust
pub enum TlsPolicy {
    /// Validate against the operating system's trust store.
    SystemRoots,
    /// Accept exactly one certificate, by SHA-256 of its DER encoding.
    Pinned { sha256: [u8; 32] },
}
```

`Pinned` is a `rustls::client::danger::ServerCertVerifier` that
compares the leaf's digest and ignores chain, expiry, and name — the
fingerprint *is* the identity under this policy — which is the standard
answer for the self-signed on-premise PBX, which is a large share of
real SIP deployments.

There is deliberately **no "skip verification" variant**. Consumers ask
for it, every softphone has one, and it is the setting people enable to
make an error message disappear — after which the connection has
ceremony and no security, permanently, with nothing on screen saying
so. The enum makes it unrepresentable. Pinning covers the legitimate
case and stays narrow: it trusts one certificate, not every
certificate.

### Reporting failures usefully

A pinning workflow needs to tell the consumer *what* it saw, or the
consumer can only offer a blind "trust anyway". So the error is typed
and carries the evidence:

```rust
pub struct UntrustedCertificate {
    pub sha256: [u8; 32],
    pub subject: String,
    pub issuer: String,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
    pub reason: CertFailure,  // Expired | NotYetValid | NameMismatch { presented } | UnknownIssuer | Malformed
}
```

The connection that produced it is **dropped, never continued**. We
report what was presented; we do not proceed on it. A consumer that
then pins the fingerprint is making a trust-on-first-use decision with
the facts in front of it, and its own UI should say plainly that an
attacker present at that moment would be the thing getting pinned.

On success, `RegistrarDiagnostics` exposes the peer certificate's
subject, issuer, expiry, and fingerprint, so a consumer can show what
it is connected to and warn before a certificate lapses.

### Tests

Certificates generated in-test with `rcgen` (a dev-dependency), so
there is nothing to rotate in the repo:

- valid chain against a test root → connects
- expired, not-yet-valid, name-mismatch, unknown-issuer → each fails
  with its own `CertFailure`, and reports the right fingerprint
- SRV target differs from the SIP domain → the **domain** is verified
  (the RFC 5922 regression test; this is the one that would silently
  pass if the check were wrong)
- pinned fingerprint matches a self-signed cert → connects
- pinned fingerprint does not match → fails, even though the chain is
  otherwise valid
- a `sips:` URI defaults to 5061 and `_sips._tcp`

---

## Phase 3 — SRTP

### Wrap the socket, do not pass a flag

The obvious implementation — thread an `Option<SrtpContext>` into
`send_loop` — is wrong. `rtp::dtmf::send_dtmf_burst` takes its own
`Arc<UdpSocket>` and writes to the wire on a separate path, so it would
keep sending **DTMF in the clear** while the audio was encrypted. DTMF
is where callers enter PINs, card numbers, and account codes; it is the
most sensitive traffic on the call.

So the socket itself is wrapped, and the plaintext socket stops being
reachable from the sending paths:

```rust
pub struct RtpTransport {
    socket: Arc<UdpSocket>,
    outbound: Option<SrtpContext>,  // our key
    inbound: Option<SrtpContext>,   // the peer's key
}
```

`send_loop`, `send_dtmf_burst`, the receive loop and `DtmfReceiver` all
take `Arc<RtpTransport>`. With nothing negotiated it is a passthrough,
so the plaintext path is byte-identical to today. The property worth
having is structural: a future sender cannot forget to encrypt, because
there is no longer an unencrypted thing to send on.

This is a breaking change to four public signatures — a major bump.

### The transform

New `srtp/` module on RustCrypto (`aes`, `ctr`, `hmac`, `sha1`), behind
an `srtp` feature. Scope: `AES_CM_128_HMAC_SHA1_80` and
`AES_CM_128_HMAC_SHA1_32`, which is what SIP deployments actually
negotiate.

- `srtp/kdf.rs` — RFC 3711 §4.3 key derivation, labels `0x00`/`0x01`/`0x02`.
  The SRTCP labels `0x03`–`0x05` are absent, since there is no RTCP.
- `srtp/cipher.rs` — AES-CM keystream with the §4.1.1 IV, HMAC-SHA1
  over header ‖ ciphertext ‖ ROC truncated to 80 or 32 bits.
- `srtp/session.rs` — rollover counter, replay window, `protect` /
  `unprotect`.

Hand-rolled rather than pulled in, for the reason the crate already
hand-rolls SDP and the RTP header: the transform is a keystream XOR, a
counter, and an auth tag, and RFC 3711 publishes test vectors for the
keystream and the KDF, so correctness is checkable rather than trusted.
The alternatives each cost more than they save — the maintained Rust
SRTP implementation drags a slice of a WebRTC stack into a crate with
four dependencies, and the C reference library puts a build toolchain
requirement on every consumer's every target.

**The cipher is not where SRTP implementations break.** The rollover
counter and the replay window are. RFC 3711's index is
`2^16 * ROC + SEQ`, so both sides must agree on the ROC across a
sequence wrap that either may observe first, and a receiver must reject
replays without rejecting legitimate reordering. Those get the most
tests: wrap at 65535, a packet arriving just *before* a wrap that
belongs to the previous ROC, the Appendix A estimator at each boundary,
a duplicate inside the window, a packet below the window, and a large
forward jump.

### SDES keying

In `sdp.rs`, per RFC 4568:

- The profile becomes `RTP/SAVP` and the offer carries
  `a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:<base64 key‖salt>`, with a
  tag-2 `_32` line for interoperability.
- Keys are 128-bit key + 112-bit salt from the OS CSPRNG, generated
  fresh per call and never reused across calls or directions.
- Answering an offer: pick the strongest offered suite we support,
  generate **our own** key for our sending direction, echo the tag.
- `parse_sdp` gains the crypto attributes; a malformed or
  unsupported-suite `a=crypto` is ignored rather than fatal, so a
  peer offering suites we do not implement degrades per policy instead
  of failing the parse.

### Never key over cleartext signaling

An SDES key sits in the SDP body in base64. If the signaling is not
encrypted, that body is readable, and "encrypted" media that ships its
key alongside it protects nobody — it only looks like it does.

So the offer builder takes the signaling transport and **refuses to
emit `a=crypto` over UDP or TCP**, returning a typed error rather than
a weaker offer. A consumer whose policy is "always encrypt" on a
cleartext transport has a configuration error, and it should hear about
it at configuration time rather than discover it as a call that appears
to have worked.

### Policy and negotiation

```rust
pub enum MediaEncryption {
    /// Encrypt when the signaling is encrypted; otherwise plain RTP.
    Automatic,
    /// Require SRTP. Fail the call rather than send in the clear.
    Always,
    /// Never offer or accept SRTP.
    Never,
}
```

`Automatic` is the default and is safe on every existing configuration:
a UDP account behaves exactly as it does today, a TLS account gets
SRTP.

Outbound under `Automatic`: offer `RTP/SAVP`; on `488 Not Acceptable
Here` or `606 Not Acceptable`, retry **once** with `RTP/AVP`. Standards-
compliant, unambiguous, and the cost — one extra round trip — falls
only on peers that refuse SRTP. The result is cached per next-hop, so
only the first call to such a peer pays it, and the cache is dropped on
restart so a peer that gains SRTP support is re-probed.

Inbound under `Automatic`: mirror the offer. A `RTP/SAVP` offer is
answered with SAVP, a plain offer with plain.

Under `Always`, there is no fallback and an inbound `RTP/AVP` offer is
rejected `488`. Under `Never`, no crypto line is offered and an
`a=crypto` in an offer is ignored.

`Call` exposes whether the established media is encrypted, and with
which suite, so a consumer can say so honestly — and can tell a
TLS-signaled call with plain RTP apart from a genuinely private one.
Those are different guarantees and a consumer must not be forced to
conflate them.

### Tests

- RFC 3711 published KDF and keystream vectors.
- `protect` → `unprotect` round-trip for both suites.
- A tampered auth tag, a tampered payload, and a truncated packet each
  fail to authenticate.
- ROC and replay-window cases enumerated above.
- `build_sdp` ↔ `parse_sdp` round-trip with crypto lines, matching the
  existing round-trip convention.
- The offer builder returns an error for a crypto offer on a cleartext
  transport.
- Negotiation: SAVP offer answered SAVP; `488` under `Automatic`
  triggers exactly one AVP retry; `488` under `Always` does not retry;
  inbound AVP under `Always` is rejected.

---

## Public surface

Less of this is additive than it looks, and the spec should say so
plainly rather than discover it at bump time:

| Item | Phase | Note |
|------|-------|------|
| `Transport::Tls` | 2 | new variant — non-exhaustive match sites in consumers break |
| `TlsPolicy`, `UntrustedCertificate`, `CertFailure` | 2 | behind `tls` |
| `PeerCertificate` on `RegistrarDiagnostics` | 2 | behind `tls` |
| `MediaEncryption` | 3 | behind `srtp` |
| `RtpTransport` | 3 | replaces `Arc<UdpSocket>` in four public fns — **breaking** |
| `Call::media_encryption()` | 3 | behind `srtp` |

`SipAccount` gains `tls_policy: TlsPolicy` and
`media_encryption: MediaEncryption`, both `#[serde(default)]`, so
existing *deserialized* configurations keep working — a consumer's
stored config file does not need to change.

Consumers that build a `SipAccount` with a struct literal do, though:
adding a public field to a struct that is not `#[non_exhaustive]`
breaks every such construction. `Transport::Tls` breaks exhaustive
`match` arms the same way. Both are genuine breaks, and on an 0.x line
each minor bump is allowed to carry them — but "additive" would be the
wrong word in the release notes, and a consumer reading them deserves
to know a one-line edit is waiting. Marking the struct
`#[non_exhaustive]` now would only move the break earlier without
removing it, so it is not worth doing for its own sake.

### Features

```toml
[features]
default = []
tls  = ["dep:tokio-rustls", "dep:rustls-platform-verifier"]
srtp = ["dep:aes", "dep:ctr", "dep:hmac", "dep:sha1", "dep:rand"]
```

A consumer that wants neither sees no new dependency. `docs.rs` already
builds with `all-features`, so both are documented.

## Releases

| Version | Contents |
|---------|----------|
| 0.3.0 | Phase 1. Breaking only in that `Transport::Tcp` now behaves differently — correctly. |
| 0.4.0 | Phase 2. `Transport::Tls` is a new variant. |
| 0.5.0 | Phase 3. Breaking: the RTP signatures. |

## `RFC-COVERAGE.md`

The living doc is re-audited at each phase. Gap #2 (TCP) closes in
phase 1, gap #4 (TLS) in phase 2. Phase 3 moves RFC 3711 and RFC 4568
out of the absent table and into the implemented one, with the scope
stated precisely: two AES-CM suites, SDES keying only, no SRTCP, no
DTLS-SRTP. RFC 5922 (SIP domain identity in TLS) is a new row in
phase 2.
