# Internal `stack` engine, Phase 6 — outbound INVITE call flow

> Status: implemented · Date: 2026-06-27

Adds `src/stack/call.rs` — the outbound call flow (RFC 3261 §13, UAC
side), the second composed flow on the clean-room stack. Continues
[08-own-sip-stack.md](08-own-sip-stack.md).

## What landed

- `build_invite(cfg, cseq, local_addr)` — compose an INVITE carrying the
  SDP offer.
- `place_call(engine, peer, events, cfg, cseq)` — send the INVITE, follow
  provisional responses (100/180/183), answer one `401`/`407` via
  `auth::build_retry`, and on a 2xx build the `Dialog` and send the ACK
  (which, for a 2xx, rides **outside** any transaction per §13.2.2.4,
  reusing the INVITE's CSeq). Returns a `CallOutcome`
  (`Answered(Dialog)` / `Rejected(status)` / `Unauthorized` / `TimedOut`).
- `hangup(engine, peer, events, dialog)` — tear the call down with an
  in-dialog BYE.

Ties together the client INVITE transaction (§17.1.1, including the
transaction-owned non-2xx ACK), the dialog layer's route-set reuse, and
the 2xx-ACK path the engine surfaces as out-of-dialog.

## Tests

3 tests, two of them **full loopback round-trips against a fake callee**:

- `call_is_answered_acked_and_hung_up` — INVITE → 180 → 200 (with Contact
  + To tag); the flow ACKs, returns a confirmed dialog, then BYEs and the
  callee 200s.
- `rejected_call_reports_status` — INVITE → 486; the client INVITE
  transaction ACKs the non-2xx itself and the flow reports `Rejected(486)`.
- `build_invite_carries_sdp` — body + `Content-Type` checks.

## State of the engine

Both signaling flows our UA needs — REGISTER and INVITE — now run
end-to-end on the clean-room stack with real SIP over real UDP. The
engine (transactions, transport, dialogs, auth) is functionally complete
for the UA path.

## Remaining for full `rsipstack` removal

The engine is done; what's left is **wiring and a public-API swap** — the
big-bang the plan flags:

1. An engine-backed endpoint with a per-dialog/transaction event router
   (so REGISTER, calls, and keepalives share one engine), plus inbound
   INVITE (UAS) acceptance.
2. Re-point the public wrappers — `Registrar`, `Caller`, `Callee`,
   `SipEndpoint`, `session_timer`, `dtmf_info` — onto the engine flows,
   keeping their public type names.
3. Replace the `rsipstack` re-exports in `lib.rs::re_exports`
   (`DialogState`, `DialogStateReceiver`, `TerminatedReason`,
   `TransactionHandle`, `DialogId`, `Transaction`, `SipAddr`) with
   crate-owned types.
4. Drop `rsipstack` from `Cargo.toml` and the crate docs.

Steps 2–4 are a single cutover (the public surface changes together), so
they land as one focused phase rather than the incremental, always-green
slices used so far.
