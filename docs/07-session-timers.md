# Session timers (RFC 4028) — plan

Date: 2026-06-06

## Why

A long-running call whose dialog has silently died (peer crashed, NAT
binding dropped, proxy lost state) lives forever today: nothing on the
signaling path ever re-validates the dialog, so the consumer keeps
streaming RTP into the void. For an attended softphone a human notices;
an unattended consumer (voice bot, AI agent) does not — session timers
bound that window. RFC 4028 does this with a periodic refresh
(re-INVITE) plus a watchdog: if no refresh lands before the negotiated
session interval lapses, the call is torn down with BYE.

## What rsipstack 0.4 gives us (verified against 0.4.14/0.4.15 sources)

- `InviteOption.headers: Option<Vec<rsip::Header>>` — extra headers are
  appended verbatim to the outbound INVITE, so we **can** advertise
  `Supported: timer` + `Session-Expires` on the initial INVITE.
- `ClientInviteDialog::reinvite(headers, body)` and
  `ServerInviteDialog::reinvite(headers, body)` send an in-dialog
  re-INVITE and return `Result<Option<rsip::Response>>` (`Ok(None)` when
  the dialog is not confirmed). The transaction layer auto-sends the ACK
  for the 2xx, so a refresh is a single call from our side. Both roles
  can therefore act as the refresher.
- An **inbound** re-INVITE driven through `dialog.handle()` (i.e. via
  `SipEndpoint::dispatch_in_dialog`) surfaces as
  `DialogState::Updated(id, request, TransactionHandle)` on the dialog's
  state stream. rsipstack does **not** auto-answer it: whoever pumps
  `state_rx` must reply through the `TransactionHandle` (otherwise
  rsipstack replies `501` after the transaction timeout). That pump
  lives in the consumer, so the crate cannot transparently observe
  peer refreshes — the consumer signals them to the watchdog (see
  below).
- rsip 0.4 has no typed `Session-Expires` / `Min-SE` headers; they
  parse into `rsip::Header::Other(name, value)`. We parse/build the
  values manually, matching the crate's minimal-parsing style (SDP, RTP
  header).

## Design

New module `session_timer.rs` with three layers, plus thin wiring in
`caller.rs` / `callee.rs`.

### 1. Pure negotiation logic (fully unit-tested)

- `SessionExpires { interval_secs, refresher: Option<Refresher> }` with
  `parse` / `header_value` / `header()` round-trip (`;refresher=uac|uas`
  param, case-insensitive, compact form `x` accepted on parse).
- `min_se_in(&Headers) -> Option<u32>`, `session_expires_in(&Headers)`,
  `supports_timer(&Headers)` (token scan of `Supported` / compact `k`).
- `SessionTimer { interval_secs, we_are_refresher }` with the RFC 4028
  §10 schedule:
  - refresher: send a refresh at `interval / 2`;
  - non-refresher: if no refresh arrived, send BYE at
    `interval - min(32s, interval / 3)`.
- `negotiate_uac(&Headers)` — UAC side, from the 2xx: no
  `Session-Expires` → no timer; `refresher=uas` → peer refreshes, we
  watchdog; `refresher=uac` or (defensively) missing → we refresh.
- `negotiate_uas(&Headers)` — UAS side, from the INVITE: interval is
  floored at `max(90, Min-SE)` (RFC 4028 absolute minimum). Refresher:
  honor the request's `refresher` param when the peer advertised
  `Supported: timer`, defaulting to `uac` (peer refreshes); when the
  peer did **not** advertise timer support (e.g. proxy-inserted
  `Session-Expires`), we must refresh and must not `Require: timer`.
  Returns the `SessionExpires` to echo in the 2xx plus whether to add
  `Require: timer`.

### 2. `session_timer_loop` (Registrar::keepalive_loop shape)

`session_timer_loop(dialog, timer, refresh_body, peer_refreshed, cancel)
-> SessionTimerOutcome`, `select!`-ing on sleep / `CancellationToken`:

- **We are refresher**: every `interval/2`, send a refresh re-INVITE
  (`Supported: timer`, `Session-Expires: N;refresher=uac`, repeating our
  SDP so the offer is a no-op per RFC 3264). A 2xx resets the clock and
  adopts a server-granted `Session-Expires` if present; a non-2xx or
  transport error sends BYE and returns `RefreshFailed`; `Ok(None)`
  (dialog no longer confirmed) returns `DialogGone`.
- **Peer is refresher (watchdog)**: sleep until the expiry deadline;
  each `peer_refreshed.notify_one()` (a `tokio::sync::Notify` pinged by
  the consumer when it answers the peer's refresh re-INVITE) resets the
  deadline. If the deadline lapses, send BYE and return `Expired`.

The loop is generic over a small `SessionDialogOps` trait
(`refresh` / `send_bye`) implemented for both `ClientInviteDialog` and
`ServerInviteDialog` — this keeps the timing logic unit-testable with
tokio's paused clock and a mock dialog, with no live SIP server.

### 3. Wiring

- `caller.rs`: outbound INVITEs always advertise `Supported: timer` and
  `Session-Expires: 1800` (RFC 4028 default; no `refresher` param — the
  UAS picks). `PendingDial::on_confirmed` parses the 2xx via
  `negotiate_uac` and exposes `AcceptedDial.session_timer:
  Option<SessionTimer>`.
- `callee.rs`: `Callee::handle_pending` parses the INVITE via
  `negotiate_uas` and exposes `PendingCall.session_timer:
  Option<UasSessionTimer>`. `PendingCall::accept` echoes the negotiated
  `Session-Expires` (plus `Supported: timer`, and `Require: timer` when
  the peer supports it) in the 200 OK, and `AcceptedCall.session_timer:
  Option<SessionTimer>` carries the result.
- The consumer spawns `session_timer_loop` with the accepted dialog and
  its `CancellationToken`; on the watchdog side it answers
  `DialogState::Updated` re-INVITEs via the carried `TransactionHandle`
  and pings the `Notify`. Module docs show both wirings.

## Testing

- Unit tests (same module): header parse/build round-trips, param and
  case handling, malformed inputs, `Min-SE`/90s floor, refresher-role
  selection for both UAC and UAS negotiation, interval math
  (`interval/2` refresh, `interval - min(32, interval/3)` expiry), and
  the full loop against a mock `SessionDialogOps` under
  `start_paused` time: refresh cadence, granted-interval adoption,
  refresh failure → BYE, watchdog expiry → BYE, notify-resets-deadline,
  cancellation.
- Loopback integration tests (not `#[ignore]`d, same shape as
  `tests/caller_dial.rs`): negotiation end-to-end (INVITE carries the
  headers, callee negotiates, 200 OK echoes, caller parses) and one
  real refresh re-INVITE answered through the `TransactionHandle`.
- One `#[ignore]`d wall-clock test (~60 s) driving the watchdog → BYE
  path over real loopback dialogs.

## Deferred (explicitly out of scope)

- **UPDATE-based refreshes** (RFC 4028 allows UPDATE; rsipstack has
  `dialog.update()`, but re-INVITE is universally supported and one
  mechanism is enough). We also don't advertise `Allow: UPDATE`.
- **422 (Session Interval Too Small) retry** on the initial INVITE. We
  request the RFC default 1800 s and never send `Min-SE`, so a 422
  requires a server demanding >30 min intervals — vanishingly rare. A
  422 today simply fails the dial like any other non-2xx.
- **UAS-initiated timers**: if the inbound INVITE carries no
  `Session-Expires`, we do not insert one in the 2xx (allowed by the
  RFC, skipped for now) — `session_timer` is simply `None`.
- **Auto-answering peer refresh re-INVITEs inside the crate.** The
  state stream (and thus the `TransactionHandle`) is owned by the
  consumer's pump, so the crate can't answer without taking over that
  loop. The consumer replies 200 (echoing `Session-Expires`) and pings
  the watchdog's `Notify` — documented with an example.
- **Configurable requested interval** on `Caller`. Constant 1800 s
  until a consumer needs otherwise.
- **Re-negotiation on mid-call role flip**: a refresh 2xx claiming
  `refresher=uas` mid-call is ignored (we keep refreshing — safe, just
  possibly redundant).
