//! SIP signaling and RTP transport for voice pipelines.
//!
//! `wavekat-sip` is a small, focused toolkit for building softphones, voice
//! bots, and recording bridges in Rust. It wraps [`rsipstack`] and owns the
//! wire-level concerns — SIP registration, dialogs, SDP offer/answer, and
//! RTP framing — while staying out of audio device I/O, codec work, and
//! call orchestration so it remains light and embeddable.
//!
//! [`rsipstack`]: https://crates.io/crates/rsipstack
//!
//! # Scope
//!
//! What this crate covers:
//!
//! - **SIP signaling** — REGISTER with digest auth and keepalive
//!   re-registration ([`Registrar`]), shared transport + dialog layer
//!   ([`SipEndpoint`]).
//! - **SDP** — minimal G.711 (PCMU + PCMA) offer/answer with round-trip
//!   parsing ([`build_sdp`], [`parse_sdp`]).
//! - **RTP** — header parser ([`RtpHeader`]) and a debug-friendly receive
//!   loop ([`receive_rtp`]) suitable for transcription, recording, or
//!   smoke-testing inbound media.
//!
//! Explicitly out of scope (push these to the consuming application):
//!
//! - Audio device I/O (e.g. `cpal`), codec encode/decode, jitter buffering,
//!   recording, WAV writing.
//! - Account persistence (TOML files, system keychain).
//! - Call orchestration, AI pipeline, business logic.
//!
//! Inbound INVITE handling lives in [`Callee`]; the outbound `caller`
//! wrapper and an RTP send helper are still on the
//! [roadmap](https://github.com/wavekat/wavekat-sip/blob/main/docs/01-port-plan.md).
//!
//! # Quick start: register against a SIP server
//!
//! ```no_run
//! use std::sync::Arc;
//! use tokio_util::sync::CancellationToken;
//! use wavekat_sip::{Registrar, SipAccount, SipEndpoint, Transport};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let account = SipAccount {
//!     display_name: "Office".into(),
//!     username: "1001".into(),
//!     password: "secret".into(),
//!     domain: "sip.example.com".into(),
//!     auth_username: None,
//!     server: None,
//!     port: None,
//!     transport: Transport::Udp,
//! };
//!
//! let cancel = CancellationToken::new();
//! let (endpoint, _incoming) = SipEndpoint::new(&account, cancel.clone()).await?;
//! let endpoint = Arc::new(endpoint);
//!
//! // Expires: 60s, re-register every 50s.
//! let registrar = Registrar::new(account, endpoint, cancel, 60, 50)?;
//! registrar.register().await?;
//! registrar.keepalive_loop().await;
//! # Ok(())
//! # }
//! ```
//!
//! The `_incoming` stream returned by [`SipEndpoint::new`] yields inbound
//! transactions (INVITE, OPTIONS, …). For INVITEs, hand the transaction to
//! [`Callee::accept_transaction`] or [`Callee::reject_transaction`].
//!
//! # Building SDP and parsing the answer
//!
//! ```
//! use std::net::{IpAddr, Ipv4Addr};
//! use wavekat_sip::{build_sdp, parse_sdp};
//!
//! let local_ip: IpAddr = Ipv4Addr::new(192, 168, 1, 50).into();
//! let offer = build_sdp(local_ip, 20000);
//!
//! // ... send `offer` in an INVITE, receive an SDP answer ...
//! let answer = offer.clone(); // simulate a loopback answer
//! let media = parse_sdp(&answer).expect("valid SDP");
//! assert_eq!(media.port, 20000);
//! assert_eq!(media.payload_type, 0); // PCMU
//! ```
//!
//! # Reading RTP headers off the wire
//!
//! For real receive loops use [`receive_rtp`]; to inspect individual
//! packets, parse directly:
//!
//! ```
//! use wavekat_sip::RtpHeader;
//!
//! let packet = [
//!     0x80, 0x00, 0x04, 0xD2, // V=2, PT=0 (PCMU), seq=1234
//!     0x00, 0x00, 0x16, 0x2E, // timestamp
//!     0xDE, 0xAD, 0xBE, 0xEF, // SSRC
//! ];
//! let header = RtpHeader::parse(&packet).unwrap();
//! assert_eq!(header.payload_type, 0);
//! assert_eq!(header.sequence, 1234);
//! assert_eq!(header.header_len(), 12);
//! ```
//!
//! # Module map
//!
//! | Module          | Purpose                                                        |
//! |-----------------|----------------------------------------------------------------|
//! | [`account`]     | Runtime [`SipAccount`] + [`Transport`] enum.                   |
//! | [`endpoint`]    | [`SipEndpoint`] — bound transport, dialog layer, RX stream.    |
//! | [`registrar`]   | REGISTER + digest auth + keepalive re-registration.            |
//! | [`callee`]      | Inbound INVITE accept/reject helper.                           |
//! | [`sdp`]         | Minimal G.711 offer/answer build + parse.                      |
//! | [`rtp`]         | RTP header parser and async receive loop.                      |
//!
//! # Stability
//!
//! Pre-1.0. The public API will shift between minor versions while the
//! `caller` helper lands. Pin an exact version if you need stability
//! today.
//!
//! # License
//!
//! Licensed under Apache 2.0. Copyright 2026 WaveKat.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod account;
pub mod callee;
pub mod endpoint;
pub mod registrar;
pub mod rtp;
pub mod sdp;

pub use account::{SipAccount, Transport};
pub use callee::{AcceptedCall, Callee, PendingCall};
pub use endpoint::{DispatchOutcome, SipEndpoint};
pub use registrar::{Registrar, RegistrarDiagnostics};
pub use rtp::{receive_rtp, RtpHeader};
pub use sdp::{build_sdp, parse_sdp, RemoteMedia};

/// Re-exports of upstream types that appear in our public API. Pinning
/// them here lets consumers depend only on `wavekat-sip` without taking
/// a direct dep on `rsip` / `rsipstack`.
pub mod re_exports {
    pub use rsip::{Header, Method, StatusCode};
    pub use rsipstack::dialog::dialog::{DialogState, DialogStateReceiver, TerminatedReason};
    pub use rsipstack::dialog::DialogId;
    pub use rsipstack::transaction::transaction::Transaction;
}

/// Short git hash this crate was built from, or `"unknown"` if unavailable.
pub const GIT_HASH: &str = env!("WAVEKAT_SIP_GIT_HASH");
