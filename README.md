<p align="center">
  <a href="https://github.com/wavekat/wavekat-sip">
    <img src="https://github.com/wavekat/wavekat-brand/raw/main/assets/banners/wavekat-sip-narrow.svg" alt="WaveKat SIP">
  </a>
</p>

[![Crates.io](https://img.shields.io/crates/v/wavekat-sip.svg)](https://crates.io/crates/wavekat-sip)
[![docs.rs](https://docs.rs/wavekat-sip/badge.svg)](https://docs.rs/wavekat-sip)

SIP signaling and RTP transport for [WaveKat](https://wavekat.com) voice
pipelines, on a from-scratch SIP engine (no external SIP stack). Same pattern as
[wavekat-vad](https://github.com/wavekat/wavekat-vad) and
[wavekat-turn](https://github.com/wavekat/wavekat-turn).

> [!WARNING]
> Early development. API will change between minor versions.

## What this crate is

A small, focused SIP/RTP toolkit for building softphones, voice bots, and
recording bridges in Rust. It owns the wire-level concerns —

- **SIP signaling**: REGISTER (digest auth + keepalive), outbound and inbound
  calls (`Caller` / `IncomingCall`), in-dialog hold/resume, DTMF (RFC 4733 +
  INFO fallback), and RFC 4028 session timers.
- **SDP**: offer/answer for Opus (preferred, with in-band FEC) and G.711
  (PCMU + PCMA) fallback; answers and mid-call re-offers pin the negotiated
  codec. Negotiation only — encode/decode stays with the consumer.
- **RTP**: header parser, a debug-friendly receive loop, and a codec-agnostic
  send loop.

— and stays out of the audio device, codec, and call-orchestration layers
so it remains light and embeddable.

## Quick Start

```sh
cargo add wavekat-sip
```

Register an account against your SIP server:

```rust,no_run
use tokio_util::sync::CancellationToken;
use wavekat_sip::{Registrar, SipAccount, SipEndpoint, TlsPolicy, Transport};

# async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let account = SipAccount {
    display_name: "Office".into(),
    username: "1001".into(),
    password: "secret".into(),
    domain: "sip.example.com".into(),
    auth_username: None,
    server: None,
    port: None,
    transport: Transport::Udp,
    tls_policy: TlsPolicy::default(),
};

let cancel = CancellationToken::new();
let endpoint = SipEndpoint::new(&account, cancel.clone()).await?;

// Expires: 60s, re-register every 50s.
let registrar = Registrar::new(account, endpoint, cancel, 60, 50)?;
registrar.register().await?;
registrar.keepalive_loop().await;
# Ok(())
# }
```

Place an outbound call and hang up:

```rust,no_run
use std::sync::Arc;
use wavekat_sip::{Caller, SipAccount, SipEndpoint};

# async fn run(account: SipAccount, endpoint: Arc<SipEndpoint>)
#     -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let caller = Caller::new(account, endpoint);
let target: wavekat_sip::re_exports::Uri = "sip:bob@example.com".try_into()?;
let mut call = caller.dial(target).await?;

// Wire call.rtp_socket + call.remote_media to your audio / AI pipeline, then:
call.hangup().await?;
# Ok(())
# }
```

Answer inbound calls from the endpoint's incoming stream:

```rust,no_run
# use std::sync::Arc;
# use wavekat_sip::SipEndpoint;
# async fn run(endpoint: Arc<SipEndpoint>)
#     -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
while let Some(incoming) = endpoint.next_incoming_call().await {
    // Inspect incoming.remote_media, then accept (or reject):
    let _call = incoming.accept().await?;
}
# Ok(())
# }
```

## TLS

SIP over TLS (`Transport::Tls`, RFC 3261 §26.2) is behind the `tls`
feature, off by default:

```sh
cargo add wavekat-sip --features tls
```

Set `transport: Transport::Tls` on the account. Unless an explicit
`port` is set, the account resolves against port **5061** and, when a
`server` isn't an IP literal, locates it via `_sips._tcp` SRV records
(RFC 3263 §4.1) rather than `_sip._tcp`. Certificate verification checks
the account's `domain` — never the host an SRV lookup happened to
return — per RFC 5922 §7.3; verifying the resolved target instead would
let whoever answers the DNS query pick which name the certificate has
to match.

`tls_policy` selects how a server certificate is trusted. There are
exactly two variants, and deliberately no third one that skips
verification:

- `TlsPolicy::SystemRoots` (the default) — validate against the
  operating system's trust store.
- `TlsPolicy::Pinned { sha256 }` — trust exactly one certificate, by
  the SHA-256 of its DER encoding. This is the variant for the
  legitimate case people usually want a bypass for: a self-signed
  certificate on an on-premise server. It stays narrow on purpose — it
  trusts *one* certificate, not every certificate a peer might present.

There is no `Insecure` or `skip_verify` option, and there will not be
one. It is the setting people reach for to make a certificate error
message go away, and once it's on, the connection has all the ceremony
of TLS and none of the security, permanently, with nothing on screen
saying so. A rejected certificate always drops the connection; the way
back in is `Pinned`, made with the actual fingerprint in hand — not a
flag that silences the check.

A failed connection carries an `UntrustedCertificate` (fingerprint +
typed `CertFailure` reason) that [`untrusted_certificate`] can pull out
of the returned error, so your own UI can offer to pin what it just
saw:

```rust,no_run
use tokio_util::sync::CancellationToken;
use wavekat_sip::{untrusted_certificate, SipAccount, SipEndpoint, TlsPolicy, Transport};

# async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let account = SipAccount {
    display_name: "Office".into(),
    username: "1001".into(),
    password: "secret".into(),
    domain: "sip.example.com".into(),
    auth_username: None,
    server: None,
    port: None, // defaults to 5061 under TLS
    transport: Transport::Tls,
    tls_policy: TlsPolicy::SystemRoots,
};

let cancel = CancellationToken::new();
match SipEndpoint::new(&account, cancel).await {
    Ok(endpoint) => {
        // ... register / place calls
        # let _ = endpoint;
    }
    Err(err) => {
        if let Some(cert) = untrusted_certificate(err.as_ref()) {
            // Tell the operator plainly what they'd be trusting, and let
            // them decide — this is a trust-on-first-use decision, made
            // with the facts in front of them, not a setting flipped once
            // to silence the error.
            eprintln!(
                "refused: {} — pin sha256:{}?",
                cert.reason,
                cert.fingerprint_hex()
            );
        }
        return Err(err);
    }
}
# Ok(())
# }
```

[`untrusted_certificate`]: https://docs.rs/wavekat-sip/latest/wavekat_sip/fn.untrusted_certificate.html

## Status

| Module      | State                                                  |
|-------------|--------------------------------------------------------|
| `account`   | Stable — runtime SIP account type.                     |
| `endpoint`  | Working — shared SIP endpoint + transport + routing.   |
| `registrar` | Working — REGISTER + auth + keepalive + unregister.    |
| `resolve`   | Working — RFC 3263 (subset) SRV + A/AAAA fallback.     |
| `caller`    | Working — outbound dial, hold/resume, DTMF, hangup.    |
| `callee`    | Working — inbound INVITE accept/reject.                |
| `sdp`       | Working — Opus + G.711 offer/answer (negotiation only). |
| `rtp`       | Working — header parser, receive loop, send loop.      |

## Architecture

```
PSTN / SIP trunk
       │
       ▼
   wavekat-sip   (in-house transport, transactions, dialogs)
       │
       ├─ account ──── credentials + endpoint config
       ├─ endpoint ─── UDP transport + transaction/dialog engine + routing
       ├─ registrar ── REGISTER / digest auth / keepalive
       ├─ caller ───── outbound INVITE / hold / DTMF / hangup
       ├─ callee ───── inbound INVITE accept / reject
       ├─ sdp ──────── offer/answer for telephony codecs
       └─ rtp ──────── RTP header parse / receive / send
       │
       ▼
   your app  ──► audio device I/O, codec, recording, AI pipeline
```

## About WaveKat

`wavekat-sip` is part of WaveKat, an open-source ecosystem of Rust crates for building real-time voice pipelines. It handles SIP signaling and RTP transport, alongside sibling crates for voice activity detection, turn detection, speech-to-text, and text-to-speech.

See [wavekat.com](https://wavekat.com) for the full project.

## Stars

<a href="https://stars.wavekat.com/wavekat/wavekat-sip">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://stars.wavekat.com/wavekat/wavekat-sip/chart.svg?theme=dark">
    <img alt="wavekat/wavekat-sip stars" src="https://stars.wavekat.com/wavekat/wavekat-sip/chart.svg?theme=light">
  </picture>
</a>

## License

Licensed under [Apache 2.0](LICENSE).

Copyright 2026 WaveKat.

### Acknowledgements

- [`rsip`](https://crates.io/crates/rsip) — SIP message types.
