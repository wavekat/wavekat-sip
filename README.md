<p align="center">
  <a href="https://github.com/wavekat/wavekat-sip">
    <img src="https://github.com/wavekat/wavekat-brand/raw/main/assets/banners/wavekat-sip-narrow.svg" alt="WaveKat SIP">
  </a>
</p>

[![Crates.io](https://img.shields.io/crates/v/wavekat-sip.svg)](https://crates.io/crates/wavekat-sip)
[![docs.rs](https://docs.rs/wavekat-sip/badge.svg)](https://docs.rs/wavekat-sip)

SIP signaling and RTP transport for [WaveKat](https://wavekat.com) voice pipelines, built on
[`rsipstack`](https://crates.io/crates/rsipstack). Same pattern as
[wavekat-vad](https://github.com/wavekat/wavekat-vad) and
[wavekat-turn](https://github.com/wavekat/wavekat-turn).

> [!WARNING]
> Early development. API will change between minor versions.

## What this crate is

A small, focused SIP/RTP toolkit for building softphones, voice bots, and
recording bridges in Rust. It owns the wire-level concerns —

- **SIP signaling**: REGISTER (with digest auth + keepalive), INVITE (in/out),
  BYE, dialog tracking.
- **SDP**: minimal offer/answer for G.711 telephony audio.
- **RTP**: header parser and a receive loop suitable for transcription /
  recording / debug.

— and stays out of the audio device, codec, and call-orchestration layers
so it remains light and embeddable.

## Quick Start

```sh
cargo add wavekat-sip
```

Register an account against your SIP server:

```rust,no_run
use std::sync::Arc;
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
let (endpoint, _incoming) = SipEndpoint::new(&account, cancel.clone()).await?;
let endpoint = Arc::new(endpoint);

// Expires: 60s, re-register every 50s.
let registrar = Registrar::new(account, endpoint, cancel, 60, 50)?;
registrar.register().await?;
registrar.keepalive_loop().await;
# Ok(())
# }
```

INVITE wrappers (`Caller`, `Callee`) land in the next release. Until then,
drive `SipEndpoint::dialog_layer` directly.

## Status

| Module      | State                                                |
|-------------|------------------------------------------------------|
| `account`   | Stable — runtime SIP account type.                   |
| `endpoint`  | Working — shared SIP endpoint + transport.           |
| `registrar` | Working — REGISTER + auth + keepalive + unregister.  |
| `sdp`       | Working — minimal G.711 offer/answer.                |
| `rtp`       | Header parser + debug receive loop. RTP send next.   |
| `caller`    | _Planned_ — outbound INVITE wrapper.                 |
| `callee`    | _Planned_ — inbound INVITE accept/reject helper.     |

## Architecture

```
PSTN / SIP trunk
       │
       ▼
   wavekat-sip   ──►  rsipstack (transport, transactions, dialogs)
       │
       ├─ account ──── credentials + endpoint config
       ├─ endpoint ─── UDP/TCP transport + DialogLayer
       ├─ registrar ── REGISTER / digest auth / keepalive
       ├─ sdp ──────── offer/answer for telephony codecs
       └─ rtp ──────── RTP header parse + receive
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

- [`rsipstack`](https://crates.io/crates/rsipstack) — the SIP transaction /
  dialog engine this crate wraps.
- [`rsip`](https://crates.io/crates/rsip) — SIP message types.
