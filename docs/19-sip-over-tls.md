# SIP over TLS — plan

> Status: planned · Date: 2026-09-20

Phase 2 of [18-secure-transport-tls-and-srtp.md](18-secure-transport-tls-and-srtp.md).
Phase 1 (stream transport, making `Transport::Tcp` real) shipped in
v0.2.2–v0.2.3. This doc is the phase-2 design as it stands against the
code that phase 1 actually left behind, and it supersedes doc 18's
phase-2 section where the two differ.

Phase 3 (SRTP via SDES) is explicitly **not** in this plan.

## Why now

`RFC-COVERAGE.md` ranks TLS as gap #4. Digest auth protects the
password from recovery and nothing else: every REGISTER, every INVITE,
every `From`/`To` — who called whom, from what number, at what time —
still travels in cleartext. An observer on the path needs `tcpdump`,
not a break.

TLS is also the precondition for SRTP. SDES carries the media key *in
the SDP body*; offering SRTP over cleartext signaling hands the key to
the same observer that the encryption was meant to defeat. Phase 3 is
meaningless without this one, which is why the order is fixed.

## What phase 1 already gave us

Most of the hard parts of a stream transport are done and do not
change:

- `stack/framing.rs` — the `Framer` (header terminator, `Content-Length`,
  bare-`CRLF` keepalive skipping, oversized-header cap).
- `stack/stream.rs` — the read task, the write mutex, `send_to`, `recv`,
  and `Reliability::Reliable`.
- `stack/transport.rs` — `BoundTransport` is already a
  `Datagram | Stream` enum, and the engine already takes its
  reliability from it.
- `transaction::via_value` / `contact_uri` are already transport-aware
  and already emit `SIP/2.0/TCP` and `;transport=tcp`.

TLS is that transport with a handshake in front of it. The framer and
the read task do not know the difference and are not modified.

## Non-goals

- **Not** a server-side TLS listener. We are a UA: we connect out, and
  inbound requests arrive on the connection we opened.
- **Not** SRTP or DTLS-SRTP. Separate plan.
- **Not** certificate *management*. This crate validates and reports;
  policy belongs to the consumer.
- **Not** X.509 identity reporting. See "What we report", below — we
  deliberately report a fingerprint and a reason, not a parsed subject.

---

## The stream layer

### `SipStream`: an enum, not a generic

`StreamTransport` is currently nailed to TCP's split halves:

```rust
write: Arc<Mutex<OwnedWriteHalf>>,
async fn read_task(read: OwnedReadHalf, ...)
```

Three ways to admit a second stream type:

| Option | Cost |
|--------|------|
| **Enum implementing `AsyncRead`/`AsyncWrite` by delegation** | ~40 lines of delegation; `tokio::io::split`'s internal lock instead of TCP's `into_split` |
| Generic `StreamTransport<S>` | The parameter leaks into `BoundTransport` and up into `engine.rs` |
| `Box<dyn AsyncRead + AsyncWrite + Send + Unpin>` | Erases the dispatch that `transport.rs` deliberately keeps visible |

We take the enum, for the reason already written into `BoundTransport`:
there are exactly two shapes, the crate carries no `async-trait`
dependency, and visible dispatch is worth more here than open
extension. The split-lock cost is irrelevant at SIP signaling message
rates — this is a handful of messages per call, not a data plane.

```rust
enum SipStream {
    Tcp(TcpStream),
    #[cfg(feature = "tls")]
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}
```

`Box` on the TLS arm: a rustls connection is large enough that an
unboxed variant would set the enum's size for both arms.

With the `tls` feature off the variant does not exist, so a consumer
that does not want TLS compiles exactly today's code plus one
delegation layer.

`StreamTransport::connect` gains the transport and, for TLS, the name
to verify. Everything downstream of the split — `read_task`, `Framer`,
`send_to`, `recv` — is untouched.

### `stack/tls.rs` (new)

One module, one concern: turn a `TlsPolicy` into a
`rustls::ClientConfig`, and perform the handshake.

- `SystemRoots` → `rustls-platform-verifier`, which reads the OS trust
  store (Keychain, CryptoAPI, the ca-certificates bundle). A private CA
  an administrator has already installed system-wide therefore works
  with no crate-level configuration at all.
- `Pinned { sha256 }` → a `rustls::client::danger::ServerCertVerifier`
  that compares the SHA-256 of the leaf's DER and ignores chain,
  expiry, and name. Under this policy the fingerprint *is* the
  identity.

Keeps `stack/transport.rs` and `stack/stream.rs` under the 300-line
module rule.

---

## Verify the SIP domain, not the resolved target

This is the detail that, done wrong, leaves a connection that looks
exactly like a working one and protects nothing. It gets a named
regression test.

**RFC 5922 §7.1**: the identity to check is the domain from the SIP
URI, not the hostname SRV returned. If `sip.example.com` has an SRV
record naming `edge-3.some-provider.net`, the certificate must match
`sip.example.com`.

Verifying the SRV target instead means whoever can answer the DNS query
also chooses which name the certificate must match — and they can point
it at a host whose certificate they legitimately hold. The check would
still pass. That is the whole attack.

So the verification name and the SNI both come from `account.domain`.
The resolved `SocketAddr` is where we connect; it is never what we
verify.

---

## What we report

A rejected certificate **drops the connection**. There is no
continue-anyway path, at any layer.

> **Amended after review:** the code block and table below are as
> originally planned (five variants, mapped onto five
> `rustls::CertificateError` cases). Review added four more variants —
> `Revoked`, `BadSignature`, `PinMismatch`, and the catch-all `Other`.
> See "Amendments after review" at the end of this doc for what shipped
> and why; the code block and table are left as planned rather than
> rewritten, per this doc's own rule for plan docs.

```rust
pub struct UntrustedCertificate {
    pub sha256: [u8; 32],
    pub reason: CertFailure,
}

pub enum CertFailure {
    Expired,
    NotYetValid,
    NameMismatch { presented: Vec<String> },
    UnknownIssuer,
    Malformed,
}
```

Fingerprint and reason only. Doc 18 proposed also carrying subject,
issuer, and the validity window, but rustls hands a verifier raw DER,
so those fields would cost an X.509 parser dependency plus its parsing
and tests. A consumer's trust-on-first-use prompt needs the fingerprint
it is about to pin and the reason the chain failed; the rest is
decoration. `RegistrarDiagnostics` is unchanged in this phase.

`NameMismatch` carries what the certificate *did* present, because that
is the one failure where a consumer can usually diagnose a
misconfiguration from the message alone.

Every variant maps onto a `rustls::CertificateError` that rustls 0.23
already produces, so none of this needs a certificate parser of our
own — `presented` in particular comes straight out of rustls rather
than from reading the leaf's SANs ourselves:

| `CertFailure` | `rustls::CertificateError` |
|---------------|----------------------------|
| `Expired` | `Expired` / `ExpiredContext { .. }` |
| `NotYetValid` | `NotValidYet` / `NotValidYetContext { .. }` |
| `NameMismatch { presented }` | `NotValidForNameContext { presented, .. }`, falling back to `NotValidForName` with an empty list |
| `UnknownIssuer` | `UnknownIssuer` |
| `Malformed` | `BadEncoding` |

The `sha256` is computed over the leaf DER the verifier is handed, so
it is available on every path including `Malformed`.

### No "skip verification" variant

```rust
pub enum TlsPolicy {
    /// Validate against the operating system's trust store.
    SystemRoots,
    /// Accept exactly one certificate, by SHA-256 of its DER encoding.
    Pinned { sha256: [u8; 32] },
}
```

Consumers will ask for an insecure variant and every softphone has one.
It is also the setting people enable to make an error message go away,
after which the connection has ceremony and no security, permanently,
with nothing on screen saying so. The enum makes that unrepresentable.

`Pinned` covers the legitimate case it is usually asked for — the
self-signed on-premise PBX — and stays narrow: it trusts one
certificate, not every certificate. A consumer that pins a fingerprint
after a failure is making a decision with the facts in front of it, and
its own UI should say plainly that an attacker present at that moment
is the thing getting pinned.

---

## The rest of the surface

### `transport_of` is wrong today

`stack/transaction/mod.rs` folds rsip's `Tls` and `TlsSctp` down to
`Transport::Tcp`. That was harmless while `Transport::Tls` did not
exist. The moment it does, a peer `Contact` carrying `;transport=tls`
would be read back as TCP, and — because `via_value` derives the `Via`
protocol from exactly this function — we would advertise `SIP/2.0/TCP`
on a TLS connection and ask the server to answer on a transport we are
not speaking. Fixed here as part of the change that makes it matter.

### Resolution and ports

- `resolve.rs` maps transport → SRV service. TLS is **`_sips._tcp`**,
  not `_sip._tls` (RFC 3263 §4.1).
- `SipAccount::port()` hard-codes 5060. It becomes transport-aware:
  5061 under TLS, 5060 otherwise.
- `sips:` is accepted wherever a URI is parsed.

### Headers

One match arm each, alongside the existing TCP arms:

- `via_value` → `SIP/2.0/TLS`
- `contact_uri` → `;transport=tls`

`;rport` stays. It is a UDP mechanism (RFC 3581) and meaningless on a
stream, but harmless, and removing it conditionally is more code than
leaving it.

### Files touched

| File | Change |
|------|--------|
| `stack/stream.rs` | `SipStream` enum; `connect` takes transport + verification name |
| `stack/tls.rs` *(new)* | `ClientConfig` per policy, the `Pinned` verifier, the handshake |
| `stack/transport.rs` | third `BoundTransport::bind` arm |
| `stack/transaction/mod.rs` | `via_value`, `contact_uri`, and the `transport_of` fix |
| `resolve.rs` | `_sips._tcp`; transport-aware default port |
| `account.rs` | `Transport::Tls`; `tls_policy`; `port()` |
| `lib.rs` | export `TlsPolicy`, `UntrustedCertificate`, `CertFailure` |

---

## Dependencies

> **Amended after review:** the `[features]` line below is as planned.
> What shipped adds `dep:rustls` as its own explicit dependency (both
> `rustls` and `tokio-rustls` need their crypto provider pinned — see
> below) and `serde_json` as a dev-dependency. Details in "Amendments
> after review" at the end of this doc.

```toml
[features]
default = []
tls = ["dep:tokio-rustls", "dep:rustls-platform-verifier", "dep:sha2"]
```

Against `tokio-rustls` 0.26 / `rustls` 0.23, which is what the error
mapping above is written for.

`rustls` rather than `native-tls`: no OpenSSL in anyone's cross-build,
and it is already the TLS stack most Rust consumers carry. A consumer
that does not enable `tls` gains no dependency at all. `docs.rs`
already builds with `all-features`, so the surface is documented
either way.

`rcgen` as a dev-dependency: test certificates are generated in-test,
so there is nothing checked into the repo and nothing to rotate.

## Tests

Per the project rule, unit tests live at the bottom of each module; the
byte path is already covered by phase 1's framer and stream tests, so
what is new here is the TLS behaviour.

- Valid chain against a test root → connects.
- Expired, not-yet-valid, name-mismatch, unknown-issuer → each fails
  with its own `CertFailure` and reports the correct fingerprint.
- **SRV target differs from the SIP domain → the domain is verified.**
  The RFC 5922 regression test, and the one that would silently pass if
  the check were written the obvious wrong way.
- Pinned fingerprint matches a self-signed certificate → connects.
- Pinned fingerprint does not match → fails, *even though the chain is
  otherwise valid*.
- A `sips:` URI defaults to port 5061 and queries `_sips._tcp`.
- `via_value` and `contact_uri` assertions for `Transport::Tls`.
- `transport_of` maps `;transport=tls` to `Transport::Tls`.

Anything needing a real TLS server goes in `tests/` as `#[ignore]`.

## Release

Ships in the **0.2.x** line, per maintainer decision.

This is a compatible-range release carrying two source-breaking
changes, and the release notes must say so rather than call it
additive:

- `Transport::Tls` is a new variant — an exhaustive `match` on
  `Transport` in a consumer stops compiling.
- `SipAccount` gains `tls_policy: TlsPolicy` — a consumer building the
  struct with a literal stops compiling. It is `#[serde(default)]`, so
  *deserialized* configurations are unaffected and no stored config
  file needs to change.

Cargo treats `0.2.3 → 0.2.4` as compatible, so a consumer depending on
`"0.2"` picks both up on a routine update. Marking either type
`#[non_exhaustive]` would move the break earlier without removing it,
so it is not done for its own sake.

## `RFC-COVERAGE.md`

Re-audited when this lands: gap #4 (TLS) closes, and RFC 5922 (SIP
domain identity in TLS) becomes a new row. The scope is stated
precisely — client-side only, SDES/SRTP still absent.

---

## Amendments after review

This plan doc is a point-in-time record and is not rewritten after the
fact (see `docs/README.md`). Review moved the implementation away from
what is planned above in four ways; they are recorded here rather than
edited into the sections above, except for the two inline notes that
point back to this section.

**1. `CertFailure` shipped with nine variants, not five.** The planned
`Expired` / `NotYetValid` / `NameMismatch` / `UnknownIssuer` /
`Malformed` are unchanged. Four more were added:

- **`PinMismatch`** — a chain can be perfectly valid and simply not be
  the certificate `TlsPolicy::Pinned` pinned. Collapsing that into
  `UnknownIssuer` or `Malformed` would describe a chain problem that
  was not the actual failure; a consumer offering a re-pin prompt needs
  to say plainly that the certificate changed. It maps from
  `rustls::CertificateError::ApplicationVerificationFailure`, which
  only the pinned verifier produces.
- **`Revoked`** and **`BadSignature`** — the two strongest attack
  signals TLS produces. The original `Malformed`-or-nothing shape would
  have forced both into the catch-all, and the catch-all's doc
  originally read "not about the certificate at all" — which would
  have shipped a revoked certificate reported as a non-certificate
  failure. That is the opposite of the honest-reporting argument this
  type exists to make, so both got their own variant instead.
- **`Other(String)`** — the catch-all for any `rustls::Error` not
  already covered. It carries both a non-certificate TLS failure (a
  protocol error, no shared cipher suite) reported as-is, and any of
  `rustls::CertificateError`'s less common variants this crate has not
  given its own case; the latter is prefixed `"certificate: "` so a
  consumer can still tell the two apart by inspecting the message.

The enum is `#[non_exhaustive]`, so a consumer's `match` already has to
handle "some other reason" regardless of how many named variants exist.

The mapping table above gains three rows:

| `CertFailure` | `rustls::CertificateError` |
|---------------|----------------------------|
| `Revoked` | `Revoked` |
| `BadSignature` | `BadSignature` |
| `PinMismatch` | `ApplicationVerificationFailure` |
| `Other(String)` | Any other `rustls::CertificateError` (prefixed `"certificate: "`), or any `rustls::Error` that is not `InvalidCertificate` at all |

**2. The crypto provider is pinned to `ring`, not left at rustls'
default.** Both `rustls` and `tokio-rustls` are declared with
`default-features = false` and the `ring` feature explicitly enabled,
rather than pulling in rustls' default `aws_lc_rs` provider. Reason:
`aws-lc-sys` needs a C toolchain (and NASM on Windows) to build — the
same category of cross-build burden this doc's "Dependencies" section
above cites (there, OpenSSL) as the reason for choosing `rustls` over
`native-tls` in the first place. Picking the default provider here
would have reintroduced that burden one dependency layer down, so both
crates are pinned to `ring` instead.

**3. Two dependency-list corrections.** `sha2` (used to fingerprint the
leaf DER) ships as planned, under the `tls` feature. Two dev-only
additions were not in the original plan:

- `rcgen` was already planned as a dev-dependency for in-test
  certificate generation (unchanged).
- `serde_json` is also a dev-dependency, added to exercise
  `TlsPolicy`'s derived `Serialize`/`Deserialize` round-trip — the path
  a consumer's own stored account config relies on via
  `#[serde(default)]`. It is not used by the library itself.

**4. The platform-verifier call site.** `stack/tls.rs` builds the
system-roots verifier with
`rustls_platform_verifier::Verifier::new(provider)`, which returns
`Result<Verifier, rustls::Error>`; `Verifier` implements
`rustls::client::danger::ServerCertVerifier`. This doc did not commit
to a specific call, so there is no correction to make here — noted for
completeness since the other three amendments are all API-shape
changes from what was planned.
