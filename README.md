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
- **SDP**: minimal offer/answer for G.711 (PCMU + PCMA) telephony audio.
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
use wavekat_sip::{Registrar, SipAccount, SipEndpoint, Transport};

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

## Status

| Module      | State                                                  |
|-------------|--------------------------------------------------------|
| `account`   | Stable — runtime SIP account type.                     |
| `endpoint`  | Working — shared SIP endpoint + transport + routing.   |
| `registrar` | Working — REGISTER + auth + keepalive + unregister.    |
| `resolve`   | Working — RFC 3263 (subset) SRV + A/AAAA fallback.     |
| `caller`    | Working — outbound dial, hold/resume, DTMF, hangup.    |
| `callee`    | Working — inbound INVITE accept/reject.                |
| `sdp`       | Working — minimal G.711 offer/answer.                  |
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
