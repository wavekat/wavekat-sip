# 17 · Reinstate the deferred call features on the in-house engine

> Status: In progress · Follows `docs/16` (the `rsipstack` cutover).

## Why

`docs/16` swapped the public wrappers off `rsipstack` and onto the
clean-room engine (`stack`, built across `docs/09`–`docs/15`). To land the
cutover as one coherent change, a set of `rsipstack`-coupled features were
**dropped** and their modules removed, with a promise that each was
"reintroducible on the engine without further breaking changes".

A downstream consumer drives long, unattended voice calls and relies on
those features in production: without them a migrated build does not just
lose nice-to-haves, it fails to compile and — where it would compile —
drops calls. This change reinstates the genuinely-missing capabilities on
the engine.

## Scope: what's missing vs. what merely moved

The deferred items split into two kinds. Only the first is in scope here.

### In scope — capabilities the engine cannot currently perform

These are not present anywhere in the engine; a consumer cannot reach them
under any spelling. Each must be implemented.

| # | Capability | Why it's genuinely missing |
|---|------------|----------------------------|
| 1 | **In-dialog re-INVITE with 2xx ACK** | `Ua::send_in_dialog` exists but never ACKs a 2xx. A re-INVITE is an INVITE transaction (RFC 3261 §13/§14) whose 2xx **must** be ACKed by the TU, or the peer retransmits and ultimately tears the dialog down. No code path does this. *Foundation for #4 and #5.* |
| 2 | **`User-Agent` header** | Not emitted on any outbound request; the engine has no product-token plumbing. |
| 3 | **DTMF over SIP INFO** | No way to send an in-dialog `INFO`; `dtmf_info.rs` was removed. Inbound `INFO` is blindly auto-answered `200` and dropped. |
| 4 | **Hold / resume re-INVITE** | No `a=sendonly`/`a=inactive`/`a=sendrecv` SDP builder, no `o=` version bump, no re-INVITE call control. |
| 5 | **Session timers (RFC 4028)** | No `Session-Expires`/`Min-SE`/`Supported: timer` negotiation, no refresh/watchdog loop; `session_timer.rs` was removed. |
| 6 | **Surfacing inbound in-dialog requests** | The router auto-answers every in-dialog request (re-INVITE / INFO) with a bare `200 OK` and discards it. A peer's session-timer **refresh** re-INVITE needs an SDP answer + watchdog reset; an inbound `INFO` DTMF needs to reach the consumer. Neither is reachable. |
| 7 | **CANCEL a pending outbound INVITE** | RFC 3261 §9. The transaction layer routes CANCEL but nothing builds/sends it; a ringing outbound call cannot be cancelled. |
| 8 | **Provisional / terminated state observation** | `await_final` silently skips 1xx and never reports *why* a dialog ended. A "ringing" UX and cancel-while-ringing both need the 1xx stream + a terminated reason. |

### Out of scope — present, only the API shape changed

These capabilities **exist** on the engine; adopting them is a matter of the
consumer changing its calling code, not the crate adding anything. Per the
instruction driving this change, they are deliberately left alone:

- The inbound-call types renamed (`Callee` / `PendingCall` / `AcceptedCall`
  → `IncomingCall` → `accept()` → `Call`).
- The outbound-call types renamed (`PendingDial` / `AcceptedDial` →
  `Caller::dial() -> Call`).
- The exact `DialogState` enum spelling and `TransactionHandle` /
  `DispatchOutcome` types. (The *capabilities* they carried — provisional
  observation, cancel, inbound in-dialog surfacing — are in scope as #6–#8;
  only their old type names are not restored verbatim.)

## Engine seams these build on

The relevant primitives already exist (`stack/dialog.rs`, `stack/ua.rs`,
`stack/response.rs`):

- `Dialog::new_request(method) -> Request` — composes an in-dialog request
  with a fresh Via branch, incremented `CSeq`, and the captured route set.
- `Dialog::ack_2xx(invite_cseq) -> Request` — builds the out-of-transaction
  ACK for a 2xx (already used by the initial INVITE in `Ua::call`).
- `Ua::send_in_dialog(peer, request) -> Option<Response>` — sends a
  caller-built request and awaits its final response (no ACK).
- `Ua::answer(key, response)` + `build_response(request, status, to_tag,
  contact, body)` — answer an inbound server transaction with any
  status/body. Reusable for re-INVITE / INFO answers.
- `Ua::next_incoming() -> Incoming { key, request, peer }` and the router in
  `ua.rs` that currently auto-answers in-dialog requests in
  `endpoint.rs::route_inbound`.

## Design, phase by phase

Each phase lands as its own commit, green on all four gates, with tests in
the same commit (per `CLAUDE.md`).

### Phase 1 — in-dialog re-INVITE seam (foundation)

Add `Ua::reinvite(peer, dialog, headers, body) -> Option<Response>`:
build `dialog.new_request(Method::Invite)`, attach the extra headers and
SDP body, send, await the final response, and **on a 2xx send the ACK**
(`dialog.ack_2xx(cseq_of(&reinvite))` via `send_out_of_dialog`). Non-2xx
finals are returned as-is (no ACK; the transaction's own ACK covers them).
`Ua::send_in_dialog` stays for non-INVITE in-dialog requests (BYE/INFO).

Expose on the public `Call` as `pub(crate)`-flavored helpers the feature
phases call: `Call::reinvite(...)` and `Call::send_info(...)`.

Tests: loopback in `stack::ua` — a re-INVITE gets a 200, the test peer
observes the ACK; a rejected re-INVITE (e.g. 488) returns the status and
sends no ACK.

### Phase 2 — `User-Agent` header

Carry an optional product token on the `Ua` (set at bind time) and inject a
`User-Agent` header in the shared request builders (`build_invite`,
`build_register`, `Dialog::new_request`). Restore the public entry point as
`SipEndpoint::new_with_app(account, product, cancel)` with `new` delegating
to it with `None`. A `None` token emits no header (byte-identical to today).

Tests: `build_invite` / `build_register` include `User-Agent: <product>`
when set and omit it when `None`.

### Phase 3 — DTMF over SIP INFO

Restore `dtmf_info.rs`. The pure parts return verbatim: `CONTENT_TYPE`,
`build_info_body`, `content_type_header`, `InfoOutcome` (+ `is_accepted`
/ `should_stop`), and `classify(Option<rsip::Response>) -> InfoOutcome`
(`classify` already takes exactly what `send_in_dialog` returns). Replace
the two `rsipstack` send functions with one `Call::send_dtmf_info(digit,
duration_ms) -> InfoOutcome` over the Phase-1 INFO seam. The existing tests
(body format, classifier) port unchanged.

### Phase 4 — hold / resume re-INVITE

Generalize the SDP builder: `build_sdp_with(local_ip, rtp_port, direction,
version)` where `direction ∈ {SendRecv, SendOnly, Inactive}` controls the
`a=` attribute and `version` feeds `o=wavekat 0 <version> …` (RFC 3264
requires the same session-id and an **incremented** version on each
re-offer). `build_sdp` becomes `build_sdp_with(.., SendRecv, 0)`.

`Call` tracks an SDP `o=` version and current direction; `Call::set_hold(
on: bool)` builds the next re-offer (sendonly on hold, sendrecv on resume),
sends it via the Phase-1 re-INVITE seam, and only flips local audio gating
once the peer 2xxs. A non-2xx final surfaces the server's reason (status)
without changing local state.

Tests: SDP builder emits the right `a=` line and a monotonic `o=` version;
`set_hold` round-trips direction state; rejection leaves state unchanged
(driven by a loopback peer in `tests/`).

### Phase 5 — session timers (RFC 4028)

Restore `session_timer.rs`. Almost all of it is pure `rsip` + tokio and
returns verbatim: `Refresher`, `SessionExpires` (parse/build), `min_se_in`,
`supports_timer`, `SessionTimer` (`refresh_after`/`expiry_after`),
`negotiate_uac` / `negotiate_uas`, `SessionTimerOutcome`, the
`SessionDialogOps` trait, and `session_timer_loop` (with its full
paused-clock test suite). The only change: drop the two
`impl SessionDialogOps for ClientInviteDialog/ServerInviteDialog` and
implement the trait for the engine call handle instead — `refresh` =
Phase-1 re-INVITE, `send_bye` = in-dialog BYE.

Negotiate in `Caller::dial` (UAC, from the 2xx) and `IncomingCall::accept`
(UAS, from the INVITE, echoing `Session-Expires` + optional `Require:
timer` in the 200). Expose the negotiated `SessionTimer` on `Call` so the
consumer can spawn `session_timer_loop`. The UAC-refresher path is fully
functional on Phases 1–5; the **watchdog** path that resets on a peer
refresh depends on Phase 6 (the peer's refresh re-INVITE must be surfaced).

### Phase 6 — inbound in-dialog surfacing + CANCEL + provisional states

The deepest, most invasive phase; may be split into sub-commits.

- **Surface inbound in-dialog requests.** Instead of `route_inbound`
  blindly auto-answering, deliver in-dialog re-INVITE / INFO to the owning
  `Call` (keyed by dialog id) as events the consumer can read, so a peer
  session refresh can be answered with SDP + the watchdog pinged, and an
  inbound INFO DTMF body reaches the consumer. Requests with no matching
  dialog keep the safe auto-`200` fallback.
- **CANCEL a pending INVITE.** Track the in-flight INVITE branch and add a
  cancel path (RFC 3261 §9: same branch/Call-ID, `CSeq` method `CANCEL`),
  so a ringing outbound call can be aborted before answer.
- **Provisional + terminated observation.** Surface 1xx (notably `180
  Ringing`) and a terminated reason on the call's event stream, replacing
  the silent `await_final` skip for callers that opt into the stream.

This phase is where the old `DialogState` UX is reconstructed in spirit
(not by name) on the engine.

## Testing

Per `CLAUDE.md`: every phase ships unit tests in the same commit; pure
helpers (SDP direction/version, INFO body, session-timer math/negotiation)
are tested directly, and the dialog-coupled paths get loopback coverage in
`stack::ua` or an `#[ignore]`-free loopback test in `tests/` where no
external server is needed. All four gates (`fmt`, `clippy -D warnings`,
`test`, `doc`) stay green at every commit.

## Status checklist

- [ ] Phase 1 — in-dialog re-INVITE seam (ACK the 2xx)
- [ ] Phase 2 — `User-Agent` header
- [ ] Phase 3 — DTMF over SIP INFO
- [ ] Phase 4 — hold / resume re-INVITE
- [ ] Phase 5 — session timers (RFC 4028)
- [ ] Phase 6 — inbound in-dialog surfacing + CANCEL + provisional states
