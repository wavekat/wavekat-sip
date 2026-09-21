# SIP over TLS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `Transport::Tls` — SIP signaling over TLS, with the certificate verified against the account's SIP domain (RFC 5922) and an optional SHA-256 pin for self-signed servers.

**Architecture:** Phase 1 already built the stream transport; TLS is that transport with a handshake in front of it. `StreamTransport` stops owning TCP's split halves and owns a `SipStream` enum (`Tcp` | `Tls`) that implements `AsyncRead`/`AsyncWrite` by delegation, so `Framer`, the read task, `send_to` and `recv` are untouched. A new `stack/tls.rs` turns a `TlsPolicy` into a `rustls::ClientConfig` and performs the handshake. The extra data TLS needs — the name to verify and the policy — reaches the transport through a new internal `TransportSetup`, introduced behind `impl Into<TransportSetup>` so the ~10 existing call sites that pass a bare `Transport` keep compiling.

**Tech Stack:** Rust 2021, tokio, `rsip`, `tracing`. New, all behind a non-default `tls` feature: `tokio-rustls` 0.26, `rustls` 0.23, `rustls-platform-verifier` 0.7, `sha2` 0.10. Dev-only: `rcgen` 0.14.

**Spec:** [`docs/19-sip-over-tls.md`](../../19-sip-over-tls.md) — read it in full before starting. It supersedes doc 18's phase-2 section.

## Global Constraints

These come from `CLAUDE.md` at the repo root and apply to **every** task below:

- **All four must pass with zero warnings before any commit:** `cargo fmt --all --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`, `cargo doc --no-deps -p wavekat-sip --all-features`. `make ci` runs all four.
  **From Task 3 onward, clippy and test must also be run with `--all-features`** — the TLS code is feature-gated and is otherwise never compiled.
- **No `unwrap()` in library code.** Tests only. (`expect()` in tests is the house style.)
- **Every module has unit tests at the bottom of the file** (`#[cfg(test)] mod tests`).
- **Every change to public surface lands with a test in the same PR.** Deferring tests to a follow-up is not acceptable.
- **Keep modules focused — split if over 300 lines.** `stack/stream.rs` is at 288 lines before this work, which is why the TLS setup goes in its own `stack/tls.rs` rather than into `stream.rs`.
- Use `thiserror` for typed errors; `Box<dyn std::error::Error + Send + Sync>` at async task boundaries.
- `///` doc comments on every public struct and function.
- **Minimise external crates.** The four added here are all behind `tls`; a consumer that does not enable it gains nothing.
- **Public-repo hygiene:** this repo is public and its consumers are private. Never name a private sibling repo, its files, or its modules in source, comments, tests, docs, or commit messages. Say "the consumer" / "a downstream consumer".
- **Conventional Commits** for every commit subject, under 50 characters. Releases are driven by release-plz reading these.
- **Stay on the 0.2.x line.** Do not touch `version` in `Cargo.toml`; release-plz handles it.
- Crate root for all paths below: `crates/wavekat-sip/`. Work on branch `feat/sip-over-tls`.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `src/stack/tls.rs` | **New.** The only module that knows rustls exists: `TlsPolicy` → `ClientConfig`, the pinning verifier, the fingerprint-recording wrapper, the handshake, and the `rustls::Error` → `CertFailure` mapping. |
| `src/tls_error.rs` | **New.** The public error surface: `UntrustedCertificate`, `CertFailure`, `untrusted_certificate()`. Separate from `stack/tls.rs` because `stack` is entirely `pub(crate)` and these types are public. |
| `src/stack/stream.rs` | **Modify.** `SipStream` enum; `connect` takes a `&TransportSetup`. Read task and framing untouched. |
| `src/stack/transport.rs` | **Modify.** `TransportSetup` / `TlsSetup`; third `BoundTransport::bind` arm. |
| `src/stack/transaction/mod.rs` | **Modify.** `via_value`, `contact_uri`, and the `transport_of` fix. |
| `src/stack/ua.rs`, `src/stack/engine.rs` | **Modify.** Thread `impl Into<TransportSetup>` instead of `Transport`. |
| `src/account.rs` | **Modify.** `Transport::Tls`; `tls_policy` field; transport-aware `port()`. |
| `src/resolve.rs` | **Modify.** `_sips._tcp` service name. |
| `src/endpoint.rs` | **Modify.** Build the `TransportSetup`, passing `account.domain` as the verification name. |
| `src/lib.rs` | **Modify.** Export the new public types. |
| `tests/tls_transport.rs` | **New.** End-to-end REGISTER over a loopback rustls server, plus the RFC 5922 regression test. |

---

## Task 1: Teach the crate what TLS is

No TLS code yet — just the surface that must agree about it. All pure, all unit-testable, no new dependencies. At the end of this task `Transport::Tls` exists and every header, URI and DNS decision is correct, but binding it returns an error.

**Files:**
- Modify: `src/account.rs` (the `Transport` enum, `port()`)
- Modify: `src/stack/transaction/mod.rs:298-355` (`contact_uri`, `transport_of`, `via_value`)
- Modify: `src/resolve.rs:146-154` (`location_plan`)
- Modify: `src/stack/transport.rs:124-130` (`BoundTransport::bind`)
- Test: unit tests at the bottom of each of those files

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `Transport::Tls` variant; `SipAccount::port()` returning 5061 under TLS; `via_value` emitting `SIP/2.0/TLS`; `contact_uri` emitting `;transport=tls`; `transport_of` returning `Transport::Tls` for `;transport=tls`.

- [ ] **Step 1: Write the failing tests**

In `src/account.rs`, inside the existing `mod tests`:

```rust
#[test]
fn tls_port_defaults_to_5061() {
    let mut acct = make_account();
    acct.transport = Transport::Tls;
    assert_eq!(acct.port(), 5061);
}

#[test]
fn explicit_port_still_wins_under_tls() {
    let mut acct = make_account();
    acct.transport = Transport::Tls;
    acct.port = Some(5080);
    assert_eq!(acct.port(), 5080);
}

#[test]
fn udp_and_tcp_ports_are_unchanged() {
    let mut acct = make_account();
    acct.transport = Transport::Tcp;
    assert_eq!(acct.port(), 5060);
    acct.transport = Transport::Udp;
    assert_eq!(acct.port(), 5060);
}
```

In `src/stack/transaction/mod.rs`, inside the existing `mod tests`:

```rust
#[test]
fn via_value_names_tls() {
    let local: std::net::SocketAddr = "10.0.0.1:5061".parse().expect("addr");
    assert!(via_value(crate::account::Transport::Tls, local, "b").starts_with("SIP/2.0/TLS "));
}

#[test]
fn contact_uri_names_tls_transport() {
    let local: std::net::SocketAddr = "10.0.0.1:5061".parse().expect("addr");
    let c = contact_uri("1001", local, crate::account::Transport::Tls);
    assert_eq!(c, "sip:1001@10.0.0.1:5061;transport=tls");
}

/// The round trip that guarantees the Via we emit agrees with the Contact we
/// published: a TLS Contact read back must not degrade to TCP.
#[test]
fn transport_of_reads_tls_back_as_tls() {
    let local: std::net::SocketAddr = "10.0.0.1:5061".parse().expect("addr");
    let uri: rsip::Uri = contact_uri("1001", local, crate::account::Transport::Tls)
        .try_into()
        .expect("parses");
    assert_eq!(transport_of(&uri), crate::account::Transport::Tls);
    assert!(via_value(transport_of(&uri), local, "b").starts_with("SIP/2.0/TLS "));
}

/// RFC 3261 §19.1.2: a `sips:` URI means TLS even with no `transport`
/// parameter. A peer is entitled to send us one, and reading it as UDP would
/// route an in-dialog request onto a transport nobody is listening on.
#[test]
fn transport_of_reads_the_sips_scheme_as_tls() {
    let uri: rsip::Uri = "sips:1001@10.0.0.1:5061".try_into().expect("parses");
    assert_eq!(transport_of(&uri), crate::account::Transport::Tls);
}

/// The parameter still wins where both are present.
#[test]
fn an_explicit_transport_param_beats_the_scheme() {
    let uri: rsip::Uri = "sip:1001@10.0.0.1:5060;transport=tcp"
        .try_into()
        .expect("parses");
    assert_eq!(transport_of(&uri), crate::account::Transport::Tcp);
}
```

In `src/resolve.rs`, inside the existing `mod tests` — mirror the shape of the existing `Transport::Tcp` SRV test at line ~446:

```rust
#[test]
fn tls_queries_the_sips_service() {
    let acct = account(Some("pbx.example.com"), None, Transport::Tls);
    assert_eq!(
        location_plan(&acct),
        LocationPlan::Srv {
            name: "_sips._tcp.pbx.example.com".to_string(),
            host: "pbx.example.com".to_string(),
            port: 5061,
        }
    );
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```sh
cargo test --workspace 2>&1 | tail -30
```

Expected: compile errors — `no variant named Tls found for enum Transport`.

- [ ] **Step 3: Add the variant**

In `src/account.rs`:

```rust
/// Transport protocol for SIP signaling.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    Udp,
    Tcp,
    /// SIP over TLS (RFC 3261 §26.2.1). Defaults to port 5061 and is located
    /// via `_sips._tcp` SRV records.
    Tls,
}
```

And make `port()` transport-aware:

```rust
    /// SIP port: defaults to 5061 under TLS, 5060 otherwise.
    ///
    /// RFC 3261 §26.2.1 assigns TLS its own default port; a TLS account that
    /// fell back to 5060 would connect to the cleartext port and fail the
    /// handshake.
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(match self.transport {
            Transport::Tls => 5061,
            Transport::Udp | Transport::Tcp => 5060,
        })
    }
```

- [ ] **Step 4: Fix the three transport-aware functions**

In `src/stack/transaction/mod.rs`, `contact_uri`:

```rust
    match transport {
        crate::account::Transport::Udp => format!("sip:{username}@{local}"),
        crate::account::Transport::Tcp => format!("sip:{username}@{local};transport=tcp"),
        crate::account::Transport::Tls => format!("sip:{username}@{local};transport=tls"),
    }
```

`via_value`:

```rust
    let proto = match transport {
        crate::account::Transport::Udp => "UDP",
        crate::account::Transport::Tcp => "TCP",
        crate::account::Transport::Tls => "TLS",
    };
```

`transport_of` — this is the bug fix doc 19 calls out. It currently folds
rsip's `Tls` into `Transport::Tcp`, which was harmless only while
`Transport::Tls` did not exist. The scheme fallback is the other half of
doc 19's "`sips:` is accepted wherever a URI is parsed": we never *emit*
`sips:` (our own `Contact` carries `;transport=tls`, which is what makes the
round trip through this function work), but a peer may well send one, and
RFC 3261 §19.1.2 makes TLS its default transport.

```rust
    for param in &uri.params {
        if let rsip::common::uri::param::Param::Transport(t) = param {
            return match t {
                rsip::transport::Transport::Tls | rsip::transport::Transport::TlsSctp => {
                    Transport::Tls
                }
                rsip::transport::Transport::Tcp | rsip::transport::Transport::Sctp => {
                    Transport::Tcp
                }
                _ => Transport::Udp,
            };
        }
    }
    // RFC 3261 §19.1.2: `sips:` implies TLS when no parameter says otherwise.
    if matches!(uri.scheme, Some(rsip::common::uri::Scheme::Sips)) {
        return Transport::Tls;
    }
    Transport::Udp
```

> Verified against rsip 0.4.0: `Uri::scheme` is `Option<Scheme>` and
> `Scheme` is `{ Sip, Sips, Other(String) }`, so the expression above compiles
> as written.

- [ ] **Step 5: Fix SRV service selection**

In `src/resolve.rs`, `location_plan`. The existing code interpolates a
protocol into `_sip._{proto}`, but TLS's service name is `_sips._tcp` — the
`s` moves to the first label — so the whole prefix has to come from the match:

```rust
    // RFC 3263 §4.1. Note the TLS name is `_sips._tcp`, not `_sip._tls`.
    let service = match account.transport {
        Transport::Udp => "_sip._udp",
        Transport::Tcp => "_sip._tcp",
        Transport::Tls => "_sips._tcp",
    };
    LocationPlan::Srv {
        name: format!("{service}.{host}"),
        host,
        port: account.port(),
    }
```

- [ ] **Step 6: Make `bind` reject TLS for now**

In `src/stack/transport.rs`, `BoundTransport::bind`. Task 4 replaces this arm;
until then it must be an honest error rather than a silent downgrade:

```rust
            Transport::Tls => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TLS transport requires the `tls` feature",
            )),
```

- [ ] **Step 7: Run the tests to verify they pass**

```sh
make ci
```

Expected: all four checks pass. If clippy flags a non-exhaustive match anywhere
not listed above, fix it there — that is clippy finding a call site this plan
missed, and it is a real one.

- [ ] **Step 8: Commit**

```sh
git add -A
git commit -m "feat: add Transport::Tls surface"
```

---

## Task 2: `SipStream` — one stream type, two shapes

A pure refactor with no behaviour change: `StreamTransport` stops owning TCP's
split halves and owns a delegating enum instead. Only the `Tcp` arm exists at
the end of this task. **The existing `stream.rs` tests and `tests/tcp_transport.rs`
must pass unchanged** — that is the whole proof that this task is behaviour-preserving,
so do not edit them.

**Files:**
- Modify: `src/stack/stream.rs`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `enum SipStream` implementing `AsyncRead`/`AsyncWrite`;
  `StreamTransport` fields retyped to `tokio::io::WriteHalf<SipStream>` /
  `ReadHalf<SipStream>`. `StreamTransport::connect(peer: SocketAddr)` keeps its
  signature until Task 4.

- [ ] **Step 1: Add the enum and its delegating impls**

At the top of `src/stack/stream.rs`, after the existing imports:

```rust
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The byte stream underneath a [`StreamTransport`].
///
/// An enum rather than a generic parameter or a trait object: a generic would
/// leak up through `BoundTransport` into the engine, and `transport.rs` already
/// states the crate's preference for dispatch that stays visible. The framer
/// and the read task above this are identical for both arms — a TLS connection
/// is a TCP connection with a handshake in front of it.
pub(crate) enum SipStream {
    Tcp(TcpStream),
}

impl AsyncRead for SipStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
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
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}
```

- [ ] **Step 2: Retype `StreamTransport` and the read task**

Replace the `tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf}` imports with
`tokio::io::{ReadHalf, WriteHalf}` (keep `AsyncReadExt`/`AsyncWriteExt`), then:

```rust
pub(crate) struct StreamTransport {
    write: Arc<Mutex<WriteHalf<SipStream>>>,
    inbound: Mutex<mpsc::Receiver<(SipMessage, SocketAddr)>>,
    local: SocketAddr,
    peer: SocketAddr,
}
```

In `connect`, swap `sock.into_split()` for `tokio::io::split`:

```rust
        let local = sock.local_addr()?;
        let (read, write) = tokio::io::split(SipStream::Tcp(sock));
```

and change the read task's signature:

```rust
async fn read_task(
    mut read: ReadHalf<SipStream>,
    peer: SocketAddr,
    tx: mpsc::Sender<(SipMessage, SocketAddr)>,
) {
```

Its body does not change.

> **Why the split changes:** `TcpStream::into_split` is TCP-specific. `tokio::io::split`
> works on any `AsyncRead + AsyncWrite` at the cost of an internal lock. That cost
> is a non-issue here — SIP signaling is a handful of small messages per call, not
> a data plane.

- [ ] **Step 3: Run the existing tests unchanged**

```sh
cargo test --workspace 2>&1 | tail -20
```

Expected: PASS, including all six existing `stream.rs` tests and
`tests/tcp_transport.rs`. No test file is edited in this task.

- [ ] **Step 4: Commit**

```sh
make ci && git add -A && git commit -m "refactor: stream transport over SipStream"
```

---

## Task 3: The `tls` feature and the TLS module

Adds the dependencies, the public error surface, and `stack/tls.rs`. Nothing is
wired into the transport yet — this task ends with a tested, unreachable module.

**Files:**
- Modify: `Cargo.toml` (features, deps, dev-deps)
- Modify: `.github/workflows/ci.yml`, `Makefile`
- Create: `src/tls_error.rs`
- Create: `src/stack/tls.rs`
- Modify: `src/stack/mod.rs` (declare the module), `src/lib.rs` (declare + export)

**Interfaces:**
- Consumes: nothing from Tasks 1–2.
- Produces:
  - `pub enum TlsPolicy { SystemRoots, Pinned { sha256: [u8; 32] } }` (`Clone`, `Debug`, `Default` = `SystemRoots`, `Serialize`, `Deserialize`, `PartialEq`, `Eq`)
  - `pub struct UntrustedCertificate { pub sha256: [u8; 32], pub reason: CertFailure }`
  - `pub enum CertFailure { Expired, NotYetValid, NameMismatch { presented: Vec<String> }, UnknownIssuer, PinMismatch, Malformed, Other(String) }`
  - `pub fn untrusted_certificate(err: &(dyn std::error::Error + 'static)) -> Option<&UntrustedCertificate>`
  - `pub(crate) async fn stack::tls::connect(tcp: TcpStream, server_name: &str, policy: &TlsPolicy) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>>`

> **Note against the spec:** doc 19 lists five `CertFailure` variants. This plan
> adds two. `PinMismatch` is genuinely distinct — the chain may be perfectly
> valid and simply not be the certificate we pinned, and a consumer must be able
> to say so. `Other(String)` is the catch-all for the `rustls::Error` values that
> are not certificate problems at all (protocol errors, no shared cipher suite);
> without it the mapping would have to lie. Task 5 amends doc 19 to match.

- [ ] **Step 1: Add the dependencies and the feature**

In `crates/wavekat-sip/Cargo.toml`:

```toml
[features]
default = []
# SIP over TLS (`Transport::Tls`). See docs/19-sip-over-tls.md.
tls = ["dep:tokio-rustls", "dep:rustls", "dep:rustls-platform-verifier", "dep:sha2"]
```

Under `[dependencies]`, after `hickory-resolver`:

```toml
# SIP over TLS, all optional behind the `tls` feature. `rustls` rather than
# `native-tls`: no OpenSSL in a consumer's cross-build.
tokio-rustls = { version = "0.26", optional = true, default-features = false, features = ["ring", "tls12", "logging"] }
rustls = { version = "0.23", optional = true, default-features = false, features = ["ring", "std", "tls12", "logging"] }
rustls-platform-verifier = { version = "0.7", optional = true }
sha2 = { version = "0.10", optional = true }
```

**`ring`, not the default `aws_lc_rs`.** Both crates default to the `aws_lc_rs`
provider, which pulls `aws-lc-sys` and needs a C toolchain (and NASM on
Windows) to build. That is the same cross-build burden this plan cites for
choosing rustls over `native-tls` in the first place, so taking it back via a
default feature would defeat the point. `ring` is pure-Rust-plus-vendored-asm
and is what `rustls-platform-verifier` itself uses for testing.
`default-features = false` is what actually removes `aws_lc_rs`; adding
`features = ["ring"]` alone would enable *both* providers.

Under `[dev-dependencies]`:

```toml
# Test certificates are generated in-test, so nothing is checked into the repo
# and nothing has to be rotated.
rcgen = "0.14"
```

- [ ] **Step 2: Make CI actually compile this code**

`cargo test --workspace` does not enable `tls`, so without this step every test
written in this task and Task 4 is silently skipped in CI.

In `.github/workflows/ci.yml`, replace the clippy and test steps:

```yaml
      - run: cargo clippy --workspace --all-features -- -D warnings
      - run: cargo clippy --workspace -- -D warnings
      - name: Run tests
        run: cargo test --workspace --all-features 2>&1 | tee test-output.txt
      - name: Run tests (no features)
        run: cargo test --workspace
```

Both feature sets are checked on purpose: `--all-features` proves the TLS code
works, and the bare run proves a consumer who does not want TLS still compiles.

Mirror it in the `Makefile` `ci` target:

```make
ci:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-features -- -D warnings
	cargo clippy --workspace -- -D warnings
	cargo test --workspace --all-features
	cargo test --workspace
	cargo doc --no-deps -p wavekat-sip --all-features
```

- [ ] **Step 3: Write the public error surface**

Create `src/tls_error.rs`:

```rust
//! What we report about a certificate we refused.
//!
//! A rejected certificate drops the connection — there is no continue-anyway
//! path at any layer. What a consumer gets instead is the fingerprint it would
//! be pinning and the reason the chain failed, which is what a
//! trust-on-first-use prompt needs in order to be honest.

use std::fmt;

/// Why a server's certificate was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CertFailure {
    /// The certificate's validity period has ended.
    Expired,
    /// The certificate's validity period has not begun.
    NotYetValid,
    /// The certificate is valid, but for other names. RFC 5922 §7.1 requires
    /// the account's SIP domain, not the host an SRV record named.
    NameMismatch {
        /// The names the certificate did present.
        presented: Vec<String>,
    },
    /// The chain did not reach a trusted root.
    UnknownIssuer,
    /// The chain was fine, but the leaf is not the certificate pinned by
    /// [`TlsPolicy::Pinned`](crate::TlsPolicy::Pinned).
    PinMismatch,
    /// The certificate could not be parsed.
    Malformed,
    /// A TLS failure that is not about the certificate at all.
    Other(String),
}

impl fmt::Display for CertFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired => write!(f, "certificate has expired"),
            Self::NotYetValid => write!(f, "certificate is not yet valid"),
            Self::NameMismatch { presented } => {
                write!(f, "certificate is not valid for this SIP domain")?;
                if !presented.is_empty() {
                    write!(f, " (presented: {})", presented.join(", "))?;
                }
                Ok(())
            }
            Self::UnknownIssuer => write!(f, "certificate is not signed by a trusted issuer"),
            Self::PinMismatch => write!(f, "certificate does not match the pinned fingerprint"),
            Self::Malformed => write!(f, "certificate could not be parsed"),
            Self::Other(msg) => write!(f, "TLS failure: {msg}"),
        }
    }
}

/// A certificate we refused, and enough about it for a consumer to decide what
/// to do next.
///
/// The fingerprint is the SHA-256 of the leaf's DER encoding — the same value
/// [`TlsPolicy::Pinned`](crate::TlsPolicy::Pinned) takes, so a consumer can
/// offer to pin exactly what it just saw. A consumer that does so is making a
/// trust-on-first-use decision, and its own UI should say plainly that an
/// attacker present at that moment is the thing being pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedCertificate {
    /// SHA-256 of the leaf certificate's DER encoding.
    pub sha256: [u8; 32],
    /// Why it was refused.
    pub reason: CertFailure,
}

impl UntrustedCertificate {
    /// The fingerprint as lowercase hex, the form a user is shown and compares.
    pub fn fingerprint_hex(&self) -> String {
        self.sha256.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl fmt::Display for UntrustedCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (sha256:{})", self.reason, self.fingerprint_hex())
    }
}

impl std::error::Error for UntrustedCertificate {}

/// Find an [`UntrustedCertificate`] inside an error returned by this crate.
///
/// TLS failures surface as `io::Error`s wrapping this type, which in turn reach
/// a consumer inside a boxed error. Walking the `source()` chain by hand to find
/// it is fiddly enough that the crate should just do it.
pub fn untrusted_certificate(
    err: &(dyn std::error::Error + 'static),
) -> Option<&UntrustedCertificate> {
    let mut cur = Some(err);
    while let Some(e) = cur {
        if let Some(u) = e.downcast_ref::<UntrustedCertificate>() {
            return Some(u);
        }
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            if let Some(inner) = io.get_ref() {
                if let Some(u) = inner.downcast_ref::<UntrustedCertificate>() {
                    return Some(u);
                }
            }
        }
        cur = e.source();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn untrusted() -> UntrustedCertificate {
        UntrustedCertificate {
            sha256: [0xab; 32],
            reason: CertFailure::UnknownIssuer,
        }
    }

    #[test]
    fn fingerprint_is_lowercase_hex_of_the_full_digest() {
        let hex = untrusted().fingerprint_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("abab"));
    }

    #[test]
    fn display_carries_the_reason_and_the_fingerprint() {
        let s = untrusted().to_string();
        assert!(s.contains("trusted issuer"), "{s}");
        assert!(s.contains("sha256:abab"), "{s}");
    }

    #[test]
    fn name_mismatch_lists_what_was_presented() {
        let f = CertFailure::NameMismatch {
            presented: vec!["edge-3.example.net".to_string()],
        };
        assert!(f.to_string().contains("edge-3.example.net"));
    }

    #[test]
    fn found_through_an_io_error_wrapper() {
        let io = std::io::Error::new(std::io::ErrorKind::InvalidData, untrusted());
        let boxed: Box<dyn std::error::Error + Send + Sync> = Box::new(io);
        let found = untrusted_certificate(boxed.as_ref()).expect("found");
        assert_eq!(found.reason, CertFailure::UnknownIssuer);
    }

    #[test]
    fn absent_from_an_unrelated_error() {
        let io = std::io::Error::other("something else");
        assert!(untrusted_certificate(&io).is_none());
    }
}
```

- [ ] **Step 4: Run the error-surface tests**

Declare the module in `src/lib.rs` (`pub mod tls_error;`) and export
`pub use tls_error::{untrusted_certificate, CertFailure, UntrustedCertificate};`.

**Export `TlsPolicy` in this task too**, not in Task 4 —
`pub use account::{SipAccount, TlsPolicy, Transport};` — because
`CertFailure`'s doc comments link to `crate::TlsPolicy`, and a link to a type
the crate does not export is a broken intra-doc link, which is a `cargo doc`
warning and so fails this task's own zero-warning gate. Add `TlsPolicy` to
`src/account.rs` first (Step 7 has it), then:

```sh
cargo test --workspace tls_error 2>&1 | tail -20
```

Expected: 5 tests PASS. Note this module is **not** feature-gated — a consumer
can name the types without enabling `tls`, which keeps their `match` arms stable.

- [ ] **Step 5: Write the failing TLS module tests**

Create `src/stack/tls.rs` with only this test module at first, so the failures
are real:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        date_time_ymd, BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair,
    };

    /// A self-signed CA, and a leaf it signs for `names`.
    fn chain(names: &[&str]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "wavekat test ca");
        let ca_key = KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let owned: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        let leaf_params = CertificateParams::new(owned).expect("leaf params");
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).expect("leaf cert");

        (
            ca_cert.der().to_vec(),
            leaf.der().to_vec(),
            leaf_key.serialize_der(),
        )
    }

    /// A self-signed leaf with an explicit validity window, for the
    /// expired / not-yet-valid cases.
    fn self_signed_valid(
        name: &str,
        from: (i32, u8, u8),
        to: (i32, u8, u8),
    ) -> (Vec<u8>, Vec<u8>) {
        let mut params = CertificateParams::new(vec![name.to_string()]).expect("params");
        params.not_before = date_time_ymd(from.0, from.1, from.2);
        params.not_after = date_time_ymd(to.0, to.1, to.2);
        let key = KeyPair::generate().expect("key");
        let cert = params.self_signed(&key).expect("cert");
        (cert.der().to_vec(), key.serialize_der())
    }

    #[test]
    fn fingerprints_the_leaf_der() {
        let (_ca, leaf, _key) = chain(&["sip.example.com"]);
        let a = sha256(&leaf);
        let b = sha256(&leaf);
        assert_eq!(a, b, "the digest is stable");
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn maps_expiry_to_its_own_failure() {
        let err = rustls::Error::InvalidCertificate(rustls::CertificateError::Expired);
        assert_eq!(cert_failure(&err), CertFailure::Expired);
    }

    #[test]
    fn maps_not_yet_valid_to_its_own_failure() {
        let err = rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidYet);
        assert_eq!(cert_failure(&err), CertFailure::NotYetValid);
    }

    #[test]
    fn maps_unknown_issuer_to_its_own_failure() {
        let err = rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
        assert_eq!(cert_failure(&err), CertFailure::UnknownIssuer);
    }

    #[test]
    fn maps_bad_encoding_to_malformed() {
        let err = rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding);
        assert_eq!(cert_failure(&err), CertFailure::Malformed);
    }

    /// rustls hands us the names the certificate presented, so reporting them
    /// costs no certificate parser of our own.
    #[test]
    fn name_mismatch_carries_the_presented_names() {
        let err = rustls::Error::InvalidCertificate(
            rustls::CertificateError::NotValidForNameContext {
                expected: rustls::pki_types::ServerName::try_from("sip.example.com")
                    .expect("name")
                    .to_owned(),
                presented: vec!["edge-3.example.net".to_string()],
            },
        );
        assert_eq!(
            cert_failure(&err),
            CertFailure::NameMismatch {
                presented: vec!["edge-3.example.net".to_string()]
            }
        );
    }

    #[test]
    fn pin_mismatch_has_its_own_failure() {
        let err = rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        );
        assert_eq!(cert_failure(&err), CertFailure::PinMismatch);
    }

    #[test]
    fn a_non_certificate_failure_is_not_reported_as_one() {
        let err = rustls::Error::NoCertificatesPresented;
        assert!(matches!(cert_failure(&err), CertFailure::Other(_)));
    }

    #[test]
    fn both_policies_build_a_usable_client_config() {
        assert!(client_config(&TlsPolicy::SystemRoots).is_ok());
        assert!(client_config(&TlsPolicy::Pinned { sha256: [7u8; 32] }).is_ok());
    }

    #[test]
    fn a_pinned_verifier_accepts_only_its_own_fingerprint() {
        let (_ca, leaf, _key) = chain(&["sip.example.com"]);
        let der = rustls::pki_types::CertificateDer::from(leaf.clone());
        let name = rustls::pki_types::ServerName::try_from("sip.example.com").expect("name");
        let now = rustls::pki_types::UnixTime::now();

        let right = PinnedVerifier::new(sha256(&leaf), provider());
        assert!(right
            .verify_server_cert(&der, &[], &name, &[], now)
            .is_ok());

        let wrong = PinnedVerifier::new([0u8; 32], provider());
        assert!(wrong
            .verify_server_cert(&der, &[], &name, &[], now)
            .is_err());
    }

    /// Pinning trusts one certificate, not a chain: an expired self-signed cert
    /// whose fingerprint matches is still the certificate the operator pinned.
    #[test]
    fn a_pinned_verifier_ignores_chain_and_expiry() {
        let (leaf, _key) = self_signed_valid("pbx.local", (2020, 1, 1), (2021, 1, 1));
        let der = rustls::pki_types::CertificateDer::from(leaf.clone());
        let name = rustls::pki_types::ServerName::try_from("totally-different.example")
            .expect("name");
        let v = PinnedVerifier::new(sha256(&leaf), provider());
        assert!(v
            .verify_server_cert(&der, &[], &name, &[], rustls::pki_types::UnixTime::now())
            .is_ok());
    }
}
```

- [ ] **Step 6: Run them to verify they fail**

```sh
cargo test --workspace --all-features tls:: 2>&1 | tail -20
```

Expected: compile errors — `cannot find function sha256`, `cert_failure`,
`client_config`, `provider`, `PinnedVerifier`.

- [ ] **Step 7: Write the module**

Above that test module in `src/stack/tls.rs`:

```rust
//! TLS setup for the stream transport: policy → `rustls::ClientConfig`, the
//! handshake, and the failure mapping.
//!
//! The only module in the crate that names rustls. Everything above it sees a
//! [`SipStream`](super::stream::SipStream) and does not know whether bytes are
//! encrypted.

use std::io;
use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

use crate::account::TlsPolicy;
use crate::tls_error::{CertFailure, UntrustedCertificate};

/// SHA-256 of a certificate's DER encoding — the fingerprint a consumer pins.
fn sha256(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

/// The process-wide crypto provider, installed on first use.
fn provider() -> Arc<CryptoProvider> {
    if let Some(p) = CryptoProvider::get_default() {
        return p.clone();
    }
    // Racing callers are fine: whoever loses simply reads the winner's value.
    let _ = rustls::crypto::ring::default_provider().install_default();
    CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))
}

/// Translate a rustls failure into what we tell the consumer.
fn cert_failure(err: &rustls::Error) -> CertFailure {
    match err {
        rustls::Error::InvalidCertificate(c) => match c {
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                CertFailure::Expired
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                CertFailure::NotYetValid
            }
            CertificateError::NotValidForNameContext { presented, .. } => {
                CertFailure::NameMismatch {
                    presented: presented.clone(),
                }
            }
            CertificateError::NotValidForName => CertFailure::NameMismatch {
                presented: Vec::new(),
            },
            CertificateError::UnknownIssuer => CertFailure::UnknownIssuer,
            CertificateError::BadEncoding => CertFailure::Malformed,
            // What `PinnedVerifier` returns on a mismatch; nothing else in this
            // crate's configuration produces it.
            CertificateError::ApplicationVerificationFailure => CertFailure::PinMismatch,
            other => CertFailure::Other(other.to_string()),
        },
        other => CertFailure::Other(other.to_string()),
    }
}

/// Accept exactly one certificate, by fingerprint.
///
/// Chain, expiry and name are all ignored on purpose: under
/// [`TlsPolicy::Pinned`] the fingerprint *is* the identity. That is what makes
/// it usable for the self-signed on-premise server it exists to serve, and it
/// stays narrow — it trusts one certificate, not every certificate.
#[derive(Debug)]
struct PinnedVerifier {
    sha256: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl PinnedVerifier {
    fn new(sha256: [u8; 32], provider: Arc<CryptoProvider>) -> Self {
        Self { sha256, provider }
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if sha256(end_entity.as_ref()) == self.sha256 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Wrap a verifier so the leaf's fingerprint is available after a failure.
///
/// A verifier can only return a `rustls::Error`, and the platform verifier is
/// opaque to us, so there is no other way to tell the consumer *which*
/// certificate was refused — which is exactly what a pinning prompt needs.
#[derive(Debug)]
struct RecordingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    seen: Arc<Mutex<Option<[u8; 32]>>>,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut slot) = self.seen.lock() {
            *slot = Some(sha256(end_entity.as_ref()));
        }
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Build the client config for `policy`, plus the slot its verifier records the
/// leaf fingerprint into.
fn config_with_recorder(
    policy: &TlsPolicy,
) -> io::Result<(rustls::ClientConfig, Arc<Mutex<Option<[u8; 32]>>>)> {
    let provider = provider();
    let inner: Arc<dyn ServerCertVerifier> = match policy {
        TlsPolicy::SystemRoots => Arc::new(
            rustls_platform_verifier::Verifier::new(provider.clone())
                .map_err(|e| io::Error::other(format!("platform trust store unavailable: {e}")))?,
        ),
        TlsPolicy::Pinned { sha256 } => Arc::new(PinnedVerifier::new(*sha256, provider.clone())),
    };

    let seen = Arc::new(Mutex::new(None));
    let recording = Arc::new(RecordingVerifier {
        inner,
        seen: seen.clone(),
    });

    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("no usable TLS protocol versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(recording)
        .with_no_client_auth();

    Ok((config, seen))
}

/// Build the client config for `policy`.
fn client_config(policy: &TlsPolicy) -> io::Result<rustls::ClientConfig> {
    config_with_recorder(policy).map(|(c, _)| c)
}

/// Perform the TLS handshake on an established TCP connection.
///
/// `server_name` is the **account's SIP domain**, never the host an SRV lookup
/// returned — RFC 5922 §7.1. It is both the name verified and the SNI sent. If
/// the SRV target were verified instead, whoever can answer the DNS query would
/// also choose which name the certificate has to match, and could point it at a
/// host whose certificate they legitimately hold.
pub(crate) async fn connect(
    tcp: TcpStream,
    server_name: &str,
    policy: &TlsPolicy,
) -> io::Result<TlsStream<TcpStream>> {
    let (config, seen) = config_with_recorder(policy)?;
    let name = ServerName::try_from(server_name.to_string()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{server_name}` is not a valid TLS server name"),
        )
    })?;

    TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await
        .map_err(|e| {
            // A TLS error wraps the rustls error as its source; anything that
            // reached the verifier has a fingerprint recorded for it.
            let rustls_err = e
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<rustls::Error>());
            let fingerprint = seen.lock().ok().and_then(|s| *s);
            match (rustls_err, fingerprint) {
                (Some(re), Some(sha256)) => io::Error::new(
                    io::ErrorKind::InvalidData,
                    UntrustedCertificate {
                        sha256,
                        reason: cert_failure(re),
                    },
                ),
                _ => e,
            }
        })
}
```

Declare it in `src/stack/mod.rs`:

```rust
#[cfg(feature = "tls")]
pub(crate) mod tls;
```

Add `TlsPolicy` to `src/account.rs` (it lives there, not behind the feature, so
a consumer's config struct compiles either way):

```rust
/// How to decide whether to trust a TLS server's certificate.
///
/// There is deliberately no "skip verification" variant. It is the setting
/// people enable to make an error message disappear, after which the connection
/// has ceremony and no security, permanently, with nothing saying so.
/// [`Pinned`](TlsPolicy::Pinned) covers the case it is usually asked for — the
/// self-signed on-premise server — and stays narrow: it trusts one certificate,
/// not every certificate.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TlsPolicy {
    /// Validate against the operating system's trust store. A private CA an
    /// administrator has installed system-wide works with no extra setup.
    #[default]
    SystemRoots,
    /// Accept exactly one certificate, by SHA-256 of its DER encoding.
    Pinned {
        /// The pinned fingerprint. [`UntrustedCertificate::sha256`] reports the
        /// value to pin.
        sha256: [u8; 32],
    },
}
```

- [ ] **Step 8: Run the tests to verify they pass**

```sh
cargo test --workspace --all-features 2>&1 | tail -20
```

Expected: the 10 new `stack::tls` tests and the 5 `tls_error` tests PASS.

- [ ] **Step 9: Commit**

```sh
make ci && git add -A && git commit -m "feat: add tls feature and TLS setup module"
```

---

## Task 4: Wire TLS into the transport

The connecting task: `TransportSetup` carries the domain and policy down to
`StreamTransport::connect`, and TLS becomes reachable.

**Files:**
- Modify: `src/stack/transport.rs` (`TransportSetup`, `TlsSetup`, `bind`)
- Modify: `src/stack/stream.rs` (`connect` takes the setup; `SipStream::Tls`)
- Modify: `src/stack/engine.rs:176-190`, `src/stack/ua.rs:83-110` (thread `impl Into<TransportSetup>`)
- Modify: `src/account.rs` (`tls_policy` field), `src/endpoint.rs:100-125`
- Modify: `src/lib.rs` (export `TlsPolicy`; the doc example's `SipAccount` literal)
- Modify: every `SipAccount` struct literal — `src/caller.rs`, `src/registrar.rs`,
  `src/resolve.rs`, `tests/end_to_end_call.rs`, `tests/tcp_transport.rs`,
  `tests/srv_resolution.rs` (see the table in Step 5)
- Test: `tests/tls_transport.rs` (new)

**Interfaces:**
- Consumes: `Transport::Tls` (Task 1); `SipStream` (Task 2); `stack::tls::connect`, `TlsPolicy`, `UntrustedCertificate` (Task 3).
- Produces: `pub(crate) struct TransportSetup { transport: Transport, tls: Option<TlsSetup> }` with `From<Transport>`; `SipAccount::tls_policy: TlsPolicy`.

- [ ] **Step 1: Add `TransportSetup`**

In `src/stack/transport.rs`, above `BoundTransport`:

```rust
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
```

- [ ] **Step 2: Replace the `bind` TLS arm from Task 1**

```rust
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
```

- [ ] **Step 3: Give `SipStream` its TLS arm**

In `src/stack/stream.rs`:

```rust
pub(crate) enum SipStream {
    Tcp(TcpStream),
    /// Boxed: a rustls connection is large enough that an inline variant would
    /// set the enum's size for the TCP arm too.
    #[cfg(feature = "tls")]
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}
```

Add the matching arm to each of the four delegating methods, e.g.:

```rust
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "tls")]
            Self::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
```

And change `connect`:

```rust
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
        tokio::spawn(read_task(read, peer, tx));

        Ok(Self {
            write: Arc::new(Mutex::new(write)),
            inbound: Mutex::new(rx),
            local,
            peer,
        })
    }
```

Update the six existing `stream.rs` tests to pass a setup:
`StreamTransport::connect(addr, &Transport::Tcp.into())`.

- [ ] **Step 4: Thread the setup through the engine and the UA**

In `src/stack/engine.rs`, change both `start` and `start_with_timers` to take
`transport: impl Into<TransportSetup>`, then at the top of `start_with_timers`:

```rust
    let setup = transport.into();
    let transport = Arc::new(BoundTransport::bind(local, peer, &setup).await?);
```

`start` forwards `transport` unchanged. Do the same in `src/stack/ua.rs` for
`bind`, `bind_with_app` and `bind_with_timers`. Because the parameter is
`impl Into<TransportSetup>`, **every existing call site passing `Transport::Udp`
or `Transport::Tcp` compiles unchanged** — do not edit the ~10 test call sites.

`Ua` stores `setup.transport` wherever it currently stores the `Transport`.

- [ ] **Step 5: Add the account field and build the setup**

In `src/account.rs`, on `SipAccount`:

```rust
    /// How to verify the server's certificate under [`Transport::Tls`].
    /// Ignored for UDP and TCP.
    #[serde(default)]
    pub tls_policy: TlsPolicy,
```

**This breaks every `SipAccount` struct literal in the crate — 18 of them
across 9 files.** `cargo build` will name them all; the full list, so none is
missed when working file by file:

| File | Sites |
|------|-------|
| `src/account.rs` | 4 |
| `src/endpoint.rs` | 3 |
| `src/caller.rs` | 2 |
| `src/registrar.rs` | 2 |
| `src/resolve.rs` | 2 |
| `src/lib.rs` | 1 — **a doc example**, so it also breaks `cargo test --doc` |
| `tests/end_to_end_call.rs` | 2 |
| `tests/tcp_transport.rs` | 2 |
| `tests/srv_resolution.rs` | 2 |

Each gains `tls_policy: TlsPolicy::default()`. The `src/lib.rs` one is a
consumer-facing example: rather than adding the field there, prefer
`..Default::default()` only if `SipAccount` already derives `Default` — check
first; if it does not, add the explicit field and do **not** add a `Default`
derive as a drive-by.

Update the test helper `make_account()` in `src/account.rs` the same way, and
add:

```rust
#[test]
fn tls_policy_defaults_to_system_roots() {
    assert_eq!(make_account().tls_policy, TlsPolicy::SystemRoots);
}

#[test]
fn a_config_without_tls_policy_still_deserializes() {
    let toml = r#"
        display_name = "Test"
        username = "1001"
        password = "secret"
        domain = "sip.example.com"
    "#;
    let acct: SipAccount = toml_from_str(toml);
    assert_eq!(acct.tls_policy, TlsPolicy::SystemRoots);
}
```

> If the crate has no TOML dev-dependency, write the second test against
> `serde_json` if one is available, and otherwise drop it — `#[serde(default)]`
> is already covered by the first. Do not add a dependency for it.

In `src/endpoint.rs`, replace `account.transport` in the `Ua::bind_with_app`
call with a built setup:

```rust
        let setup = crate::stack::transport::TransportSetup {
            transport: account.transport,
            #[cfg(feature = "tls")]
            tls: match account.transport {
                // RFC 5922 §7.1: verify the account's SIP domain, never the
                // host an SRV record named. `server` may be an SRV target or a
                // bare IP; neither is the identity the certificate must match.
                Transport::Tls => Some(crate::stack::transport::TlsSetup {
                    server_name: account.domain.clone(),
                    policy: account.tls_policy.clone(),
                }),
                _ => None,
            },
        };
```

`TlsPolicy` is already exported from `src/lib.rs` by Task 3; do not re-add it.

- [ ] **Step 6: Write the end-to-end tests**

Create `tests/tls_transport.rs`. Model the REGISTER exchange on the existing
`tests/tcp_transport.rs`; the helpers below are the TLS-specific part.

```rust
//! SIP over TLS against a loopback rustls server.

#![cfg(feature = "tls")]

use std::net::SocketAddr;
use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use wavekat_sip::{untrusted_certificate, CertFailure, SipAccount, TlsPolicy, Transport};

/// A CA and a leaf it signs for `names`.
fn chain(names: &[&str]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "wavekat test ca");
    let ca_key = KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let owned: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    let leaf_params = CertificateParams::new(owned).expect("leaf params");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).expect("leaf");

    (
        ca_cert.der().to_vec(),
        leaf.der().to_vec(),
        leaf_key.serialize_der(),
    )
}

/// A TLS listener that answers one connection, on an OS-assigned port.
async fn tls_listener(leaf: Vec<u8>, key: Vec<u8>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf)],
            PrivateKeyDer::try_from(key).expect("key"),
        )
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let handle = tokio::spawn(async move {
        if let Ok((sock, _)) = listener.accept().await {
            // Drive the handshake; the client's assertion is about whether it
            // completed, so the SIP exchange itself is not needed here.
            let _ = acceptor.accept(sock).await;
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    });
    (addr, handle)
}

fn account(server: &str, port: u16, policy: TlsPolicy) -> SipAccount {
    SipAccount {
        display_name: "Test".to_string(),
        username: "1001".to_string(),
        password: "secret".to_string(),
        domain: "sip.example.com".to_string(),
        auth_username: None,
        server: Some(server.to_string()),
        port: Some(port),
        transport: Transport::Tls,
        tls_policy: policy,
    }
}
```

Then the cases. Each connects a `SipEndpoint` (mirroring `tests/tcp_transport.rs`)
and asserts on the outcome:

```rust
/// The RFC 5922 §7.1 regression test.
///
/// The certificate is valid for the SRV target and *not* for the SIP domain.
/// If the implementation verified the resolved host, this would connect — which
/// is exactly the failure that leaves a connection looking secure while whoever
/// answers the DNS query chooses the identity.
#[tokio::test]
async fn verifies_the_sip_domain_not_the_resolved_target() {
    let (_ca, leaf, key) = chain(&["edge-3.example.net"]);
    let (addr, _h) = tls_listener(leaf, key).await;
    // domain is sip.example.com; we connect to 127.0.0.1 standing in for the
    // SRV target the certificate *is* valid for.
    let acct = account("127.0.0.1", addr.port(), TlsPolicy::SystemRoots);

    let err = connect_endpoint(&acct).await.expect_err("must not connect");
    let u = untrusted_certificate(err.as_ref()).expect("reports the certificate");
    assert!(
        matches!(u.reason, CertFailure::NameMismatch { .. }),
        "expected a name mismatch, got {:?}",
        u.reason
    );
}

#[tokio::test]
async fn a_pinned_self_signed_certificate_connects() {
    let mut params = CertificateParams::new(vec!["pbx.local".to_string()]).expect("params");
    params.distinguished_name.push(DnType::CommonName, "pbx");
    let key = KeyPair::generate().expect("key");
    let cert = params.self_signed(&key).expect("cert");
    let der = cert.der().to_vec();
    let sha256: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&der).into();

    let (addr, _h) = tls_listener(der, key.serialize_der()).await;
    let acct = account("127.0.0.1", addr.port(), TlsPolicy::Pinned { sha256 });
    assert!(connect_endpoint(&acct).await.is_ok());
}

/// Pinning trusts one certificate, not a category of them: a chain that would
/// otherwise validate is still refused when it is not the pinned one.
#[tokio::test]
async fn a_wrong_pin_is_refused_despite_a_valid_chain() {
    let (_ca, leaf, key) = chain(&["sip.example.com"]);
    let (addr, _h) = tls_listener(leaf, key).await;
    let acct = account("127.0.0.1", addr.port(), TlsPolicy::Pinned { sha256: [0u8; 32] });

    let err = connect_endpoint(&acct).await.expect_err("must not connect");
    let u = untrusted_certificate(err.as_ref()).expect("reports the certificate");
    assert_eq!(u.reason, CertFailure::PinMismatch);
    assert_eq!(u.fingerprint_hex().len(), 64, "reports what it saw");
}

#[tokio::test]
async fn an_untrusted_chain_is_refused_and_reports_its_fingerprint() {
    let (_ca, leaf, key) = chain(&["sip.example.com"]);
    let (addr, _h) = tls_listener(leaf, key).await;
    let acct = account("127.0.0.1", addr.port(), TlsPolicy::SystemRoots);

    let err = connect_endpoint(&acct).await.expect_err("must not connect");
    let u = untrusted_certificate(err.as_ref()).expect("reports the certificate");
    assert!(matches!(
        u.reason,
        CertFailure::UnknownIssuer | CertFailure::NameMismatch { .. }
    ));
    assert_ne!(u.sha256, [0u8; 32]);
}
```

The helper, against the real signature
(`SipEndpoint::new(&SipAccount, CancellationToken) -> Result<Arc<SipEndpoint>, BoxError>`):

```rust
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Attempt a connection, with a timeout so a hung handshake fails the test
/// rather than the suite.
async fn connect_endpoint(
    acct: &SipAccount,
) -> Result<std::sync::Arc<wavekat_sip::SipEndpoint>, BoxError> {
    let cancel = tokio_util::sync::CancellationToken::new();
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        wavekat_sip::SipEndpoint::new(acct, cancel.clone()),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err("timed out establishing the endpoint".into()),
    }
}
```

> **If `SipEndpoint::new` turns out to do more than connect** (it also starts the
> inbound router), and that makes these assertions awkward, test
> `StreamTransport::connect` directly instead via a `#[cfg(test)]` path — the
> assertions above are about the handshake outcome, not about REGISTER. Keep the
> same four cases either way.

- [ ] **Step 7: Run the tests**

```sh
cargo test --workspace --all-features 2>&1 | tail -30
```

Expected: all four TLS integration tests PASS. `verifies_the_sip_domain_not_the_resolved_target`
is the one that matters most — if it fails by *connecting*, the verification name
is being taken from the resolved target and must be fixed before proceeding.

- [ ] **Step 8: Verify the no-feature build still works**

```sh
cargo test --workspace && cargo clippy --workspace -- -D warnings
```

Expected: PASS. `tests/tls_transport.rs` compiles to nothing via its
`#![cfg(feature = "tls")]`.

- [ ] **Step 9: Commit**

```sh
make ci && git add -A && git commit -m "feat: implement SIP over TLS"
```

---

## Task 5: Documentation

**Files:**
- Modify: `docs/19-sip-over-tls.md` (the `CertFailure` amendment)
- Modify: `docs/RFC-COVERAGE.md`
- Modify: `README.md`

- [ ] **Step 1: Amend the spec's `CertFailure`**

Doc 19 lists five variants; the implementation has seven. Update its
"What we report" code block and mapping table to include `PinMismatch`
(from `CertificateError::ApplicationVerificationFailure`, which only
`PinnedVerifier` produces) and `Other(String)` (any `rustls::Error` that is not
a certificate problem), with the one-line reason each exists. Plan docs are
point-in-time records, so note the amendment in place rather than rewriting the
doc's history.

- [ ] **Step 2: Re-audit `RFC-COVERAGE.md`**

Read the file first and follow its existing table shapes. Close gap #4 (TLS),
add a row for **RFC 5922** (SIP domain identity in TLS), and state the scope
precisely: client-side only, no TLS listener, SDES/SRTP still absent. Keep the
gap numbering of the untouched entries intact.

- [ ] **Step 3: Document the feature in `README.md`**

Add a short section covering: enabling `features = ["tls"]`, setting
`transport = "tls"`, the 5061 / `_sips._tcp` defaults, the two `TlsPolicy`
variants, and a brief example of catching a failure with
`untrusted_certificate()` to offer a pin. State plainly that there is no
skip-verification option and why.

- [ ] **Step 4: Verify the docs build**

```sh
cargo doc --no-deps -p wavekat-sip --all-features 2>&1 | tail -20
```

Expected: zero warnings. Broken intra-doc links are warnings and must be fixed.

- [ ] **Step 5: Commit and open the PR**

```sh
make ci && git add -A && git commit -m "docs: document SIP over TLS"
git push -u origin feat/sip-over-tls
```

The PR description must call out that this is a **compatible-range release
carrying two source-breaking changes** — `Transport::Tls` breaks exhaustive
matches, and `SipAccount::tls_policy` breaks struct literals — since cargo
treats `0.2.3 → 0.2.4` as compatible and a consumer on `"0.2"` picks both up on
a routine update.

---

## Notes for the executor

**Order matters.** Tasks 1 and 2 are independent of each other; 3 depends on
neither; 4 depends on all three. Do not start 4 until 1–3 are committed and
green.

**The one test that must not be weakened.**
`verifies_the_sip_domain_not_the_resolved_target` is the reason this feature is
worth having. If it is hard to set up, make the setup harder — do not relax the
assertion. A TLS implementation that verifies the resolved target has ceremony
and no security, and it looks identical to one that works.

**The dependency APIs in this plan were checked against the vendored sources**
— rustls 0.23.40, rustls-platform-verifier 0.7.0, rcgen 0.14.10, rsip 0.4.0 —
not written from memory. `rustls_platform_verifier::Verifier::new(provider)`
returns `Result<Verifier, rustls::Error>` and `Verifier` implements
`ServerCertVerifier`. If something still does not compile, adapt to the real
API: the requirement is "a `ServerCertVerifier` backed by the OS trust store",
not a particular call.

**Do not add a "skip verification" variant**, however the request arrives. It is
the single decision in this design most likely to be argued with, and the
argument is in `docs/19-sip-over-tls.md`.
