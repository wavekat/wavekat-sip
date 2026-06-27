# Internal `stack` engine, Phase 7 — UA router (one engine, many flows)

> Status: implemented · Date: 2026-06-27 · Branch: `feat/drop-rsipstack`

Adds `src/stack/ua.rs` — the multiplexing layer that lets a single engine
serve a registration, several calls, and keepalives at once. This is the
foundation the public-wrapper cutover sits on. Continues
[08-own-sip-stack.md](08-own-sip-stack.md).

## What landed

- A **router task** owning the engine's single event stream and a
  `TransactionKey → Sender<Event>` table. A flow subscribes its key
  (with a oneshot ack, so a fast reply can't arrive before the
  subscription is live), then starts its transaction; events are fanned
  to the owning flow, and a `Terminated` event drops the subscription.
- Unmatched inbound requests — new INVITEs and the 2xx ACK — are routed
  to an `incoming` stream for the callee / dialog layer.
- `Ua::{register, call, hangup, send_in_dialog, answer, next_incoming}`
  as the **single canonical drivers**. The earlier standalone
  `drive_register` / `place_call` / `hangup` are removed;
  `registration.rs` / `call.rs` keep the request builders and the
  `*Config` / `*Outcome` types.

## Tests

- `register_then_call_share_one_engine` — a REGISTER (with digest
  challenge) and an INVITE complete over one `Ua` against one peer.
- `inbound_invite_reaches_incoming_and_can_be_answered` — an inbound
  INVITE surfaces on `next_incoming` and the answer reaches the caller.

## Remaining work to drop `rsipstack`

The engine (transactions, transport, dialogs, auth) and this router are
complete. The final phase is the **breaking public-API cutover**:

1. Replace `SipEndpoint` with a `Ua`-backed type (bind + the inbound
   stream).
2. Re-point `Registrar` onto `Ua::register` + keepalive.
3. Re-point `Caller` / `PendingDial` / `AcceptedDial` onto `Ua::call`,
   exposing crate-owned dialog/state types (replacing the re-exported
   `DialogState` / `DialogStateReceiver`) plus the RTP socket + parsed
   `RemoteMedia` (already crate-owned in `sdp.rs`).
4. Re-point `Callee` / `PendingCall` / `AcceptedCall` onto
   `Ua::next_incoming` + `Ua::answer` + `Dialog::uas`.
5. Adapt `session_timer` and `dtmf_info` onto the new dialog handle.
6. Replace the `rsipstack` re-exports in `lib.rs::re_exports` with
   crate-owned types; drop `rsipstack` from `Cargo.toml`.

Steps 1–6 change the public surface together, so unlike phases 1–7
(always green) they land as one cutover commit.
