//! SIP signaling and RTP transport for voice pipelines.
//!
//! See the [crate README](https://github.com/wavekat/wavekat-sip) for the
//! big picture and `docs/01-port-plan.md` for the roadmap.

pub mod account;
pub mod callee;
pub mod endpoint;
pub mod registrar;
pub mod rtp;
pub mod sdp;

pub use account::{SipAccount, Transport};
pub use callee::{AcceptedCall, Callee};
pub use endpoint::SipEndpoint;
pub use registrar::Registrar;
pub use rtp::{receive_rtp, RtpHeader};
pub use sdp::{build_sdp, parse_sdp, RemoteMedia};

/// Re-exports of upstream types that appear in our public API. Pinning
/// them here lets consumers depend only on `wavekat-sip` without taking
/// a direct dep on `rsip` / `rsipstack`.
pub mod re_exports {
    pub use rsip::{Header, Method, StatusCode};
    pub use rsipstack::transaction::transaction::Transaction;
}

/// Short git hash this crate was built from, or `"unknown"` if unavailable.
pub const GIT_HASH: &str = env!("WAVEKAT_SIP_GIT_HASH");
