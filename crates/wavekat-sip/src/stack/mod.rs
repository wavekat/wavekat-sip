//! Clean-room SIP transaction/dialog/transport engine — internal only.
//!
//! This module is the from-scratch SIP engine described in
//! `docs/08-own-sip-stack.md`. It is built flow-by-flow and is **entirely
//! `pub(crate)`**: none of its types ever appear in `wavekat_sip::*`
//! signatures, so it can evolve or be replaced without breaking downstream
//! consumers. The crate's existing public wrappers (`Caller`, `Callee`,
//! `Registrar`, …) own the public API; this engine sits behind them.
//!
//! Scope is the **User Agent** path this crate actually drives — REGISTER,
//! INVITE/re-INVITE, BYE, CANCEL, INFO, OPTIONS — and nothing else. No
//! proxy/registrar-server/B2BUA/SBC roles (see the plan's non-goals).
//!
//! We keep the `rsip` crate for SIP *message* types (`Request`, `Response`,
//! headers, digest math) and write only the **stateful** layer on top:
//! transactions (RFC 3261 §17), dialogs (§12), transport, and digest
//! orchestration.
//!
//! ## Build status
//!
//! Phase 1 (this module today): the RFC 3261 §17 transaction state
//! machines, expressed sans-IO — each machine maps an input event
//! (received message, fired timer) to a list of [`transaction::TxAction`]s
//! (send a message, arm/stop a timer, hand a message to the transaction
//! user). That keeps the timer-heavy core fully unit-testable against the
//! RFC timer tables with no sockets or wall-clock, and lets a thin
//! transport runner drive it in a later phase.
//!
//! Later phases add the dialog layer, digest orchestration, and the
//! transport serve loop, then migrate each flow off the external stack.

// The engine is built out flow-by-flow ahead of the wrappers that will
// consume it, so during the migration many `pub(crate)` items are exercised
// only by this module's own unit tests. Allow dead code here (and only here)
// rather than sprinkling per-item attributes; it is removed phase by phase as
// `endpoint`/`caller`/`callee`/`registrar` are re-pointed at the engine.
#![allow(dead_code)]

pub(crate) mod auth;
pub(crate) mod dialog;
pub(crate) mod engine;
pub(crate) mod registration;
pub(crate) mod transaction;
pub(crate) mod transport;
