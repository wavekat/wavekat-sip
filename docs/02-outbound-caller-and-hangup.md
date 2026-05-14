# 02 — Outbound `Caller` + local-hangup ergonomics

> Status: planning · Date: 2026-05-15 · Target release: v0.0.10

This note is the upstream half of a feature being designed in `wavekat-voice` — see [`wavekat-voice/docs/15-active-call-history-and-outbound.md`](https://github.com/wavekat/wavekat-voice/blob/main/docs/15-active-call-history-and-outbound.md). That doc plans an in-call UI, durable call history, and **outbound dialing** for the desktop product. The outbound half can't ship until this crate exposes a way to place an INVITE; this note specifies what that surface should look like.

The other two `wavekat-voice` features (active-call screen, call history) **do not need anything new from this crate** — `ServerInviteDialog::bye()` already supports user-initiated hangup on inbound calls, and `DialogState::Terminated(_, TerminatedReason)` already supplies enough information to populate a per-call disposition. We just need to call that out so consumers don't reinvent it. See [§3](#3-local-hangup-on-inbound-already-supported-document-it).

## TL;DR

Three additions:

1. **`Caller` + `PendingDial` + accepted/answered handles** — a `Callee`-shaped module for outbound. `Caller::dial(target)` sends INVITE, returns a `PendingDial` whose `state_rx` surfaces early progress (`Trying`, `EarlyMedia`, `Confirmed`, `Terminated`). On `Confirmed` the consumer gets an `AcceptedCall` of the same shape we already have for inbound, so the audio/RTP layer in `wavekat-voice` doesn't branch on direction.
2. **`PendingDial::cancel()`** — sends `CANCEL` if the early dialog is still pre-answer. Maps to "user hit End on the dialing screen before the remote picked up."
3. **Documentation polish** — `AcceptedCall.dialog.bye().await` (already present via `ServerInviteDialog::bye`) is the local-hangup path for *both* directions. Add a short paragraph and a code sample to `callee.rs`'s module-level docs and to the new `caller.rs`, so consumers don't write their own.

Plus a cleanup: `docs/01-port-plan.md` lists `caller` under "v0.0.3 (in flight)" which is stale. Roll the unshipped pieces into a v0.0.10 column and delete the v0.0.3 one as part of this PR.

## Why now

The deferral in `wavekat-voice` docs 10 and 12 — "outbound is post-MVP" — has been reversed in doc 15. The reasoning there: bundling outbound with the active-call screen and hangup endpoint costs the marginal price of `Caller` plus a UI sheet, because every other piece (current-call hook, call-screen route, hangup wire path) is already being built. The bottleneck is now this crate.

`Callee` shipped in v0.0.7 + v0.0.8 with a deliberately UI-friendly two-phase API (`handle_pending` → `accept` / `reject`) so that an Electron renderer can show a ringing card before committing to a `200 OK`. Outbound has the symmetric need: the renderer should show a "Dialing…" screen while the INVITE is in flight, and only commit to streaming audio when the remote answers. `rsipstack::DialogLayer::do_invite` exists, but it returns `(ClientInviteDialog, Option<Response>)` synchronously at the *end* of the transaction — the UI has nothing to render between "user clicked Call" and "call is up." We need to split that the way `handle_pending` split the inbound path.

## 1. The `Caller` module

Mirror `Callee`'s shape so the daemon's code reads the same on both sides.

```rust
// crates/wavekat-sip/src/caller.rs

pub struct Caller {
    account: SipAccount,
    endpoint: Arc<SipEndpoint>,
}

impl Caller {
    pub fn new(account: SipAccount, endpoint: Arc<SipEndpoint>) -> Self { … }

    /// Place an outbound INVITE to `target`. Returns a [`PendingDial`]
    /// the consumer pumps for state updates while the UI shows a
    /// "Dialing…" / "Ringing…" surface. On `Confirmed`, transitions
    /// to an [`AcceptedCall`] via [`PendingDial::on_confirmed`].
    ///
    /// `target` is a SIP URI (`sip:alice@example.com`) or a plain
    /// number that the caller will format into a SIP URI using the
    /// account's domain. Number normalization (E.164, country codes)
    /// stays out of this crate — that's a consumer concern.
    pub async fn dial(&self, target: rsip::Uri) -> Result<PendingDial, BoxError> { … }
}
```

### The pending-dial handle

```rust
/// An outbound INVITE that's on the wire. The client transaction is
/// running; final response has not been received yet.
///
/// Pump `state_rx` for early progress:
/// - `Trying` (100) — proxy acknowledged
/// - `Calling` (180/183) — remote is ringing
/// - `Confirmed` — remote picked up; call [`on_confirmed`] to get the
///   [`AcceptedCall`] with the negotiated SDP answer
/// - `Terminated(_, reason)` — call ended before / after pickup; see
///   [`TerminatedReason`] for the cause (`UasBusy`, `UasDecline`,
///   `Timeout`, `ProxyError`, …)
pub struct PendingDial {
    pub dialog: ClientInviteDialog,
    pub state_rx: DialogStateReceiver,
    local_ip: IpAddr,
    /// Carried so [`on_confirmed`] can build the [`RemoteMedia`] from
    /// the SDP answer without the consumer re-parsing.
    answer_rx: oneshot::Receiver<Vec<u8>>,
}

impl PendingDial {
    /// CANCEL the INVITE. Idempotent; safe to call after the dialog
    /// has already confirmed or terminated (logs and returns Ok).
    /// Maps to the user hitting "End" on the dialing screen.
    pub async fn cancel(&self) -> Result<(), BoxError> { … }

    /// Bind a local RTP socket, parse the negotiated SDP answer,
    /// return the [`AcceptedCall`]. Call once `state_rx` yielded
    /// `Confirmed`. Calling before that is an error.
    pub async fn on_confirmed(self) -> Result<AcceptedCall, BoxError> { … }
}
```

### Sharing `AcceptedCall`

The existing `AcceptedCall` in `callee.rs` is a `ServerInviteDialog`-flavoured struct. The outbound version needs a `ClientInviteDialog` instead. Two options:

- **Option A — generic `AcceptedCall<D>`** parameterised over `ServerInviteDialog | ClientInviteDialog`. Clean but invasive: every downstream usage signature has to choose.
- **Option B — split into `AcceptedCall` (inbound, unchanged) and `AcceptedDial` (outbound, ClientInviteDialog).** No breaking change to the existing type; consumer-side code branches on direction via a small enum if it wants direction-agnostic handling. **Recommended.**

Rationale for B: today there is exactly one consumer (`wavekat-voice`), and that consumer's `LiveCall::start` in `call_audio.rs` only uses `accepted.remote_media`, `accepted.rtp_socket`, and `accepted.local_rtp_addr` — *not* the dialog field's concrete type. So a tiny `enum CallDialog { Inbound(ServerInviteDialog), Outbound(ClientInviteDialog) }` (or a trait with `bye() -> impl Future`) lets the consumer hold "the live call's dialog" without branching, and `wavekat-sip` stays free of generics noise.

Either choice is acceptable; ship whichever has the smaller diff against current tests.

## 2. SDP answer plumbing

`build_sdp` and `parse_sdp` are already in `sdp.rs` and already symmetric:

- Outbound: `Caller::dial` constructs an SDP **offer** (`build_sdp(local_ip, rtp_port)`), then `do_invite` ships it as the request body. `PendingDial::on_confirmed` parses the SDP **answer** from the final 200 OK with `parse_sdp` — same code path the inbound `accept` uses today, just on the other side of the wire.
- The local RTP socket is bound **at `on_confirmed` time** (mirroring inbound's `PendingCall::accept`), not at `dial` time. Otherwise a cancelled dial leaves a socket bound until drop, and we can't write the test that asserts no socket is held during the pre-answer window.

## 3. Local hangup on inbound — already supported, document it

This is a documentation-only change; the API exists.

`AcceptedCall.dialog` is a `ServerInviteDialog`, and `ServerInviteDialog::bye()` is a one-line async call. The current `callee.rs` module docs allude to it (`/// Call .bye().await to hang up locally.` on the `dialog` field) but don't show a usage snippet. Add one to the module-level doc:

```rust
//! ## Hanging up a connected call
//!
//! `AcceptedCall.dialog` is a [`ServerInviteDialog`]. To hang up
//! locally (user hit "End call" in the UI):
//!
//! ```ignore
//! accepted.dialog.bye().await?;
//! ```
//!
//! The dialog state machine then transitions to
//! `Terminated(_, TerminatedReason::UasBye)` on `state_rx`, so a
//! single watcher pumping `state_rx` handles both local and remote
//! hangup with the same code path.
```

The outbound `caller.rs` gets the same paragraph with `accepted.dialog.bye().await?` against `ClientInviteDialog::bye` (which already exists in rsipstack — same name, different concrete type).

**Why not add a `hangup()` shortcut in this crate?** It would just be a one-line forward to `dialog.bye()`. Wrappers that add no behavior over the underlying call are a maintenance tax — they hide what's happening and have to be kept in sync. The right move is a docstring with a one-line snippet, not a new function.

## 4. Wire-level behavior

For the `Caller`:

- **Digest auth**: the outbound INVITE must replay against a `401 Unauthorized` or `407 Proxy Authentication Required` with a `Authorization` / `Proxy-Authorization` header derived from the account credentials. `Registrar` already does this for REGISTER; the same `compute_digest_response` helper applies. If `rsipstack::do_invite` already retries on auth (verify before implementing) — use it. Otherwise factor the helper out of `registrar.rs`.
- **CSeq**: `dial` uses a fresh dialog-scoped CSeq; CANCEL re-uses the INVITE's CSeq number with method `CANCEL` (RFC 3261 §9.1). `rsipstack` handles this; don't re-derive.
- **Retransmits**: INVITE retransmits and Timer A/B handling are `rsipstack`'s job; no work here.
- **Provisional responses**: pass `100 Trying`, `180 Ringing`, `183 Session Progress` through the `state_rx` without translation. The consumer maps these to UI states ("Calling…" vs. "Ringing…") — the crate doesn't impose a vocabulary.
- **Final responses**:
  - `2xx` → `Confirmed` on `state_rx`; consumer calls `on_confirmed` to get `AcceptedCall`. ACK is sent automatically by the dialog layer.
  - `3xx` → out of scope for v1; treat as `Terminated(_, ProxyError(status))`. (REDIRECT handling could be added later as a separate doc.)
  - `4xx`–`6xx` → `Terminated(_, reason)` with the `TerminatedReason` variant rsipstack already maps (`UasBusy` for 486, `UasDecline` for 603, `UasOther(status)` for the rest).

## 5. Tests

Per `CLAUDE.md`'s "every change that adds or modifies public surface must land with a unit test":

- **`caller::tests::dial_builds_invite_with_account_uri`** — `Caller::dial` produces an INVITE whose `To`/`From`/`Request-URI` are correctly composed from `SipAccount` + target. Pure-function test; mock or capture the transport.
- **`caller::tests::cancel_after_terminated_is_idempotent`** — invoke `cancel()` on a `PendingDial` whose `state_rx` has already yielded `Terminated`; expect `Ok(())` and no panic.
- **`caller::tests::on_confirmed_parses_remote_media_from_answer`** — feed a synthetic 200 OK SDP body, assert the returned `AcceptedCall` has the expected `remote_media.addr` / `port` / `payload_type`.
- **Integration test (`#[ignore]`d)** — `tests/caller_against_asterisk.rs`: dial a fixed extension on a local Asterisk, assert state transitions land in order, hang up, assert `Terminated(_, UasBye)` fires. Mirrors the inbound integration test pattern from `01-port-plan.md`. Run manually; not in CI.

If `rsipstack`'s `do_invite` proves too opinionated to test in isolation (it pulls the dialog layer + transport), add an `#[ignore]`'d test instead of skipping — the rule from `CLAUDE.md` is "the exception should be visible."

## 6. Release plan

Target **v0.0.10**. Single release that ships:

- `caller` module (new public API)
- Module-doc additions to `callee` and `caller` covering local hangup
- `docs/01-port-plan.md` cleanup (delete stale "v0.0.3 (in flight)" section, move `caller` to v0.0.10)

Once v0.0.10 is on crates.io, `wavekat-voice` bumps its `wavekat-sip` dep from `0.0.9` → `0.0.10` and implements step 5 of doc 15's migration order (`POST /calls/dial` + `OutgoingCall` event + dial sheet).

No breaking changes are required; this is purely additive. `Callee`, `Registrar`, `SipEndpoint`, `rtp::send_loop`, `AcceptedCall` (inbound) all keep their current public shapes.

## 7. Out of scope (this crate, this release)

- **Number normalization** (E.164 prefixing, country-code defaulting). Consumer concern.
- **Address book / contacts.** Consumer concern.
- **REFER / transfer.** Separate design pass.
- **Hold / re-INVITE.** Separate design pass; will need API on both `Caller`-side and `Callee`-side dialogs.
- **Outbound recording or transcript taps.** Belongs in the consumer's audio pipeline — `wavekat-voice` is already planning the recording slice as M3.

## 8. Doc 01 cleanup (do this in the same PR)

`docs/01-port-plan.md` today says:

```
## Landing in v0.0.3 (in flight)
| `callee`    | implemented   | …
| `caller`    | not started   | …

## Pending
### `caller` — outbound INVITE
…
```

That table is two releases stale. `callee` shipped in v0.0.7 + v0.0.8 (deferred-decision API in #13). Update the table to read:

```
## Shipped in v0.0.7 / v0.0.8
| `callee` | `handle_pending` / `accept_transaction` / `reject_transaction`. … |

## Landing in v0.0.10 (this doc)
| `caller` | `Caller::dial` → `PendingDial` (state_rx) → `AcceptedCall`. CANCEL pre-answer; BYE via dialog. |
```

And drop the `### caller — outbound INVITE` stub from `Pending` since it's been replaced by this doc.
