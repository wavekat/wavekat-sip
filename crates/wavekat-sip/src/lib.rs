//! SIP signaling and RTP transport for voice pipelines.
//!
//! See the [crate README](https://github.com/wavekat/wavekat-sip) for the
//! big picture and `docs/01-port-plan.md` for the roadmap.

pub mod account;
pub mod endpoint;
pub mod registrar;
pub mod rtp;
pub mod sdp;

pub use account::{SipAccount, Transport};
pub use endpoint::SipEndpoint;
pub use registrar::Registrar;
pub use rtp::{receive_rtp, RtpHeader};
pub use sdp::{build_sdp, parse_sdp, RemoteMedia};

/// Short git hash this crate was built from, or `"unknown"` if unavailable.
pub const GIT_HASH: &str = env!("WAVEKAT_SIP_GIT_HASH");
