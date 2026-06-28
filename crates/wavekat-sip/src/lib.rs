//! SIP signaling and RTP transport for voice pipelines.
//!
//! `wavekat-sip` is a small, focused toolkit for building softphones, voice
//! bots, and recording bridges in Rust. It owns the wire-level concerns — SIP
//! registration, dialogs, SDP offer/answer, and RTP framing — on a from-scratch
//! engine (no external SIP stack), while staying out of audio device I/O, codec
//! work, and call orchestration so it remains light and embeddable.
//!
//! The SIP transaction/dialog/transport engine is built in-house (see the
//! `stack` plan in `docs/08-own-sip-stack.md`); only the [`rsip`] crate is used,
//! for SIP message types. The engine is an internal detail — consumers depend on
//! `wavekat-sip` alone.
//!
//! [`rsip`]: https://crates.io/crates/rsip
//!
//! # Scope
//!
//! What this crate covers:
//!
//! - **SIP signaling** — REGISTER with digest auth and keepalive
//!   re-registration ([`Registrar`]), a bound endpoint with inbound-call
//!   routing ([`SipEndpoint`]), outbound calls ([`Caller`]), and inbound calls
//!   ([`IncomingCall`]).
//! - **SDP** — minimal G.711 (PCMU + PCMA) offer/answer with round-trip
//!   parsing ([`build_sdp`], [`parse_sdp`]).
//! - **RTP** — header parser ([`RtpHeader`]), a debug-friendly receive loop
//!   ([`receive_rtp`]), and a codec-agnostic send loop ([`send_loop`]).
//!
//! Explicitly out of scope (push these to the consuming application): audio
//! device I/O, codec encode/decode, jitter buffering, recording; account
//! persistence; call orchestration / AI pipeline / business logic.
//!
//! # Quick start: register against a SIP server
//!
//! ```no_run
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
//! let endpoint = SipEndpoint::new(&account, cancel.clone()).await?;
//!
//! // Expires: 60s, re-register every 50s.
//! let registrar = Registrar::new(account, endpoint, cancel, 60, 50)?;
//! registrar.register().await?;
//! registrar.keepalive_loop().await;
//! # Ok(())
//! # }
//! ```
//!
//! # Placing an outbound call
//!
//! ```no_run
//! use std::sync::Arc;
//! use wavekat_sip::{Caller, SipAccount, SipEndpoint};
//!
//! # async fn run(account: SipAccount, endpoint: Arc<SipEndpoint>)
//! #     -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! let caller = Caller::new(account, endpoint);
//! let target: wavekat_sip::re_exports::Uri = "sip:bob@example.com".try_into()?;
//! let mut call = caller.dial(target).await?;
//!
//! // Wire RTP to your audio / AI pipeline using call.rtp_socket and
//! // call.remote_media. Hang up locally with:
//! call.hangup().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Answering inbound calls
//!
//! ```no_run
//! use std::sync::Arc;
//! use wavekat_sip::SipEndpoint;
//!
//! # async fn run(endpoint: Arc<SipEndpoint>)
//! #     -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! while let Some(incoming) = endpoint.next_incoming_call().await {
//!     // Inspect incoming.remote_media, then accept (or reject):
//!     let _call = incoming.accept().await?;
//! }
//! # Ok(())
//! # }
//! ```
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
//! let answer = offer.clone(); // simulate a loopback answer
//! let media = parse_sdp(&answer).expect("valid SDP");
//! assert_eq!(media.port, 20000);
//! assert_eq!(media.payload_type, 0); // PCMU
//! ```
//!
//! # Reading RTP headers off the wire
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
//! | [`endpoint`]    | [`SipEndpoint`] — bound transport, engine, inbound-call routing.|
//! | [`registrar`]   | REGISTER + digest auth + keepalive re-registration.            |
//! | [`resolve`]     | RFC 3263 (subset) server location: SRV + A/AAAA fallback.      |
//! | [`callee`]      | [`IncomingCall`] — inbound INVITE accept/reject.               |
//! | [`caller`]      | [`Caller`] outbound dial + the [`Call`] handle.                |
//! | [`sdp`]         | Minimal G.711 offer/answer build + parse.                      |
//! | [`rtp`]         | RTP header parser, debug receive loop, codec-agnostic send loop. |
//!
//! # Stability
//!
//! Pre-1.0. The public API may still shift between minor versions.
//!
//! # License
//!
//! Licensed under Apache 2.0. Copyright 2026 WaveKat.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod account;
pub mod callee;
pub mod caller;
pub mod dtmf_info;
pub mod endpoint;
pub mod inbound;
pub mod refer;
pub mod registrar;
pub mod resolve;
pub mod rtp;
pub mod sdp;
pub mod session_timer;
// Internal clean-room SIP engine (see `docs/08-own-sip-stack.md`). Entirely
// `pub(crate)`: it never appears in this crate's public API.
pub(crate) mod stack;

pub use account::{SipAccount, Transport};
pub use callee::IncomingCall;
pub use caller::{Call, CallSession, Caller, InboundRequests};
pub use dtmf_info::{build_info_body, content_type_header, InfoOutcome};
pub use endpoint::SipEndpoint;
pub use inbound::InboundRequest;
pub use refer::{is_final_sipfrag, parse_sipfrag_status, refer_to_header};
pub use registrar::{Registrar, RegistrarDiagnostics};
pub use resolve::{order_candidates, resolve_sip_server, SrvRecord};
pub use rtp::dtmf::{
    build_event_payload, build_rtp_dtmf_packet, send_dtmf_burst, DtmfBurstConfig, DtmfDigit,
    DEFAULT_VOLUME_DBM0,
};
pub use rtp::dtmf_recv::{parse_event_payload, DtmfEvent, DtmfEventPayload, DtmfReceiver};
pub use rtp::{receive_rtp, send_loop, RtpHeader, RtpSendConfig};
pub use sdp::{build_sdp, build_sdp_with, parse_sdp, MediaDirection, RemoteMedia, DTMF_DEFAULT_PT};
pub use session_timer::{
    min_se_in, negotiate_uac, negotiate_uas, require_timer_header, session_expires_in,
    session_timer_loop, supported_timer_header, supports_timer, Refresher, SessionDialogOps,
    SessionExpires, SessionTimer, SessionTimerOutcome, UasSessionTimer,
    DEFAULT_SESSION_EXPIRES_SECS, MIN_SESSION_EXPIRES_SECS,
};

/// Re-exports of the [`rsip`] message types that appear in our public API.
/// Pinning them here lets consumers depend only on `wavekat-sip`.
pub mod re_exports {
    pub use rsip::{Header, Headers, Method, StatusCode, Uri};
}

/// Short git hash this crate was built from, or `"unknown"` if unavailable.
pub const GIT_HASH: &str = env!("WAVEKAT_SIP_GIT_HASH");
