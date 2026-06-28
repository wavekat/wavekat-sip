# From-scratch SIP stack (internal `stack` module) — plan

Date: 2026-06-27

## Why

Today the crate's call control (transactions, dialogs, transport, digest
auth) is provided by an external SIP stack. That bet was the right one
to get a working softphone quickly — it spared us RFC 3261 §17 timers,
dialog matching, and ACK/CANCEL races. But three problems have surfaced:

1. **We don't control our own bugs.** A real, call-breaking defect — an
   in-dialog re-INVITE's 2xx ACK addressed straight to the Contact
   instead of through the dialog route set — bites hold/resume through a
   proxy/SBC. We are already carrying a local patch for it. Every such
   fix is gated on an upstream we don't own.

2. **The stack leaks through our public API.** `Caller`, `Callee`, and
   `session_timer` expose the underlying stack's `ClientInviteDialog`,
   `ServerInviteDialog`, and `DialogStateReceiver` directly. Any change
   to that stack — including a version bump — is a *breaking* change for
   downstream consumers. The current major-version line of the upstream
   stack is a hard fork of its own message layer (it dropped the `rsip`
   crate and vendored its own SIP types), so even a routine upgrade is a
   breaking migration that touches every module here — and it still
   ships the re-INVITE ACK bug.

3. **We carry far more than we use.** The upstream stack is a general
   SIP toolkit (proxy/SBC roles, benchmark binaries, TLS, examples). We
   drive a narrow UA path: REGISTER, outbound INVITE, inbound INVITE,
   re-INVITE (hold/resume + session-timer refresh), BYE, CANCEL, INFO,
   OPTIONS. A purpose-built engine for *that* surface is small.

This plan proposes a **clean-room** SIP transaction/dialog/transport
engine, written from the ground up against our actual needs — **not** a
copy or fork of any existing stack — living as an **internal module**
inside `wavekat-sip`, exposed to consumers only through our own public
types.

**One crate, on purpose.** `wavekat-sip` stays a single crate. A Rust
user who wants SIP depends on `wavekat-sip` and nothing else — no
choice between a "stack" crate and an "API" crate, no version-matching
across two crates. The engine is an implementation detail behind the
crate boundary, not a separate published artifact.

## Non-goals

- **Not** a general SIP library. No proxy, registrar-server, B2BUA, or
  SBC roles. We are a User Agent only.
- **Not** a rewrite of SIP *message* parsing. We keep the crates.io
  `rsip` crate for `Uri`/`Request`/`Response`/headers/digest math: it is
  pure, stateless parsing with no product value to reimplement, and a
  hand-rolled RFC 3261 grammar is a large, bug-prone slog. We write only
  the **stateful** layer (transactions, dialogs, transport, auth
  orchestration) that sits on top of `rsip`.
- **Not** a big-bang replacement. The existing stack stays wired (via a
  `[patch.crates-io]` bridge to a locally-fixed fork) until our engine
  reaches parity on each flow, one flow at a time.
- **No** new dependencies that touch audio, files, or LLM APIs — this
  crate is SIP signaling + transport only, same scope rule as
  `wavekat-sip`.

## Scope — what the engine must do

Derived from the flows `wavekat-sip` actually drives today:

### Transport
- UDP bind + send/receive loop (primary path).
- TCP outbound connections (framing per RFC 3261 §7.5 — Content-Length
  delimited).
- Source-address selection (already solved in `endpoint.rs::detect_local_ip`;
  reuse).
- Inbound message demux to the right transaction / dialog.

### Transactions (RFC 3261 §17)
- **Client INVITE** FSM: Calling → Proceeding → Completed → Terminated,
  timers A (retransmit), B (timeout), D (wait for retransmits).
- **Server INVITE** FSM: Proceeding → Completed → Confirmed → Terminated,
  timers G, H, I; ACK absorption for non-2xx; 2xx ACK handled at the
  dialog/TU layer (separate transaction).
- **Non-INVITE client/server** FSM (REGISTER, BYE, INFO, OPTIONS,
  CANCEL): Trying → Proceeding → Completed → Terminated, timers E, F, K.
- Via `branch` generation (RFC 3261 magic cookie), CSeq handling,
  retransmission on unreliable transports only.

### Dialogs (RFC 3261 §12)
- Dialog creation from 2xx (UAC) and from request + local tag (UAS).
- Dialog ID = Call-ID + local tag + remote tag; matching of in-dialog
  requests to existing dialogs.
- **Route set** capture from Record-Route (establishing response) and
  reuse on every in-dialog request — including the case the upstream bug
  got wrong: a re-INVITE 2xx with no Record-Route must reuse the stored
  dialog route set, not fall back to the Contact.
- Remote target (Contact) tracking; local/remote CSeq.
- State machine: Calling → Early → Confirmed → (Updated)\* → Terminated,
  with explicit terminated reasons (UAC/UAS BYE, CANCEL, decline, busy,
  timeout) so consumers can render call outcomes.

### Call control (the TU surface we expose)
- Outbound INVITE with SDP offer; CANCEL; ACK for 2xx; BYE; re-INVITE
  (carrying new SDP for hold/resume and session-timer refresh); INFO
  (DTMF); OPTIONS keepalive.
- Inbound INVITE accept (200 + SDP answer) / reject (4xx–6xx with
  Reason); inbound BYE/INFO/OPTIONS/re-INVITE handling.

### Authentication (RFC 3261 §22 + RFC 2617 / 8760)
- Digest challenge/response on 401/407, MD5 and SHA-256, `qop=auth`,
  nonce/cnonce/nc. Reuse `rsip`'s digest primitives where they exist;
  own only the challenge→retry orchestration.

### Out of initial scope (add only if a flow needs it)
- TLS/WSS transport, IPv6-only edge cases beyond what UDP/TCP give us,
  forking/multiple early dialogs per INVITE, PRACK/100rel, UPDATE method
  (we refresh via re-INVITE), SUBSCRIBE/NOTIFY/PUBLISH.

## Where it lives — one crate, internal module

`wavekat-sip` stays a single crate. The engine is a private module
subtree; only `wavekat-sip`'s existing public types appear in the API:

```
crates/wavekat-sip/src/
  stack/              # new: clean-room SIP engine, pub(crate) only
    mod.rs            #   engine entry point + the trait surface (below)
    transport.rs      #   UDP/TCP bind, serve loop, inbound demux
    transaction.rs    #   RFC 3261 §17 client/server FSMs + timers
    dialog.rs         #   RFC 3261 §12 dialog state, route set, matching
    auth.rs           #   digest challenge -> retry orchestration
  endpoint.rs         # existing: re-pointed at stack::*
  caller.rs           # existing: wraps stack dialog handles
  callee.rs           # existing
  registrar.rs        # existing
  session_timer.rs    # existing (already trait-abstracted)
  sdp.rs  rtp/  ...    # unchanged
```

Rationale:

- **One crate for consumers (decisive).** A Rust user who wants SIP uses
  `wavekat-sip` and only `wavekat-sip` — no choosing between an "API"
  crate and a "stack" crate, no cross-crate version matching. The engine
  is an internal detail, not a separate published artifact. This also
  matches the crate's existing "single-crate workspace" structure.
- **Concern separation without a crate split.** The engine is a focused
  module *subtree* (`stack/transport.rs`, `transaction.rs`, `dialog.rs`,
  `auth.rs`), each file one concern under the >300-line rule — the same
  discipline a separate crate would give, at module granularity.
- **It stops the leak for good — and this is a `pub` question, not a
  crate question.** Keep every engine type `pub(crate)`; expose only
  `wavekat-sip`'s own wrapper types. The engine then never appears in
  `wavekat_sip::*` signatures, so evolving or replacing it is no longer
  a breaking change for downstream consumers (motivation 2 above). A
  second crate was never required for this; module privacy delivers it.
- **Engine-level tests still fit.** Unit tests live at the bottom of each
  `stack/*.rs` (per project policy); RFC-conformance and interop suites
  live in `wavekat-sip`'s `tests/` (the `#[ignore]`'d integration tier).

## The boundary — the public API wraps the engine, never exposes it

The key design rule: the engine lives behind a **small internal
trait/type surface** (`stack::mod`), and `wavekat-sip`'s public types
(`Caller`, `Callee`, `PendingDial`, …) wrap it. The engine is
swappable and never leaks into `wavekat_sip::*`. Sketch (names
provisional, all `pub(crate)`):

- `Endpoint` — bind transport, serve loop, yield inbound transactions.
- `ClientInvite` / `ServerInvite` — the two dialog handles, with
  `bye()`, `cancel()`, `reinvite(headers, body)`, `info(...)`,
  `accept(...)`, `reject(...)`, `state()`.
- `DialogEvents` — async stream of dialog state transitions
  (`Calling`/`Early`/`Confirmed`/`Updated`/`Terminated{reason}`).
- Re-export the `rsip` message types we already pass around, so SDP/
  header construction in `sdp.rs` and `registrar.rs` is unchanged.

`session_timer.rs` already abstracts over a `SessionDialogOps` trait for
exactly this reason; that pattern generalizes to the whole surface.

## Migration — phased, behind the bridge

Parity is reached one flow at a time. Until a flow is at parity it keeps
running on the existing stack via `[patch.crates-io]` → locally-fixed
fork.

1. **Phase 0 — unblock now.** Keep the existing stack; point it at the
   locally-patched fork via `[patch.crates-io]` so hold/resume works
   today. (Separately: upstream the re-INVITE ACK fix.)
2. **Phase 1 — transport + transactions.** UDP/TCP, the three
   transaction FSMs, Via/branch/CSeq, retransmission. Conformance tests
   against the timer tables. No dialog layer yet.
3. **Phase 2 — REGISTER.** Non-INVITE client transaction + digest
   orchestration end-to-end. Swap `Registrar`'s internals to the new
   engine; `Registrar`'s public API is unchanged.
4. **Phase 3 — outbound INVITE.** Client INVITE + dialog creation +
   2xx ACK + BYE/CANCEL. Swap `Caller`; keep its public type names,
   re-pointed at engine-backed wrappers.
5. **Phase 4 — inbound INVITE.** Server INVITE + accept/reject. Swap
   `Callee`.
6. **Phase 5 — re-INVITE + INFO.** Hold/resume, session-timer refresh,
   DTMF INFO. This is where the upstream bug lived; the route-set reuse
   is a first-class requirement here with a direct regression test.
7. **Phase 6 — remove the old dependency.** Drop the external stack and
   the `[patch]` once every flow is at parity and the external stack's
   types no longer appear anywhere in `wavekat_sip::*`. `wavekat-sip`
   remains a single crate throughout — no crate is added or published at
   any phase.

Each phase lands with its own tests in the same PR (per project policy),
and updates `RFC-COVERAGE.md` to point at the new engine instead of the
external stack.

## Risks & honest caveats

- **This is the hard core.** Transaction timers, ACK absorption, dialog
  matching, CANCEL/re-INVITE races, and digest edge cases are exactly
  where homegrown SIP stacks bleed. The phased approach with the bridge
  is the mitigation: never lose a working call path, validate each flow
  against the real server before cutting over.
- **Interop surface is wide.** Proxies/SBCs (Kamailio, FreeSWITCH,
  Plivo, etc.) vary in Record-Route, loose vs. strict routing, and
  `;lr` quirks. Keep an `#[ignore]`'d integration suite in `tests/`
  exercising each against a real endpoint.
- **Effort is non-trivial.** This is weeks, not days. It is justified by
  owning our bug-fix loop and permanently de-leaking the public API — not
  by a single fix, which the `[patch]` bridge already delivers.

## Open questions

- Internal module path: `stack/` subtree as sketched, vs. a flatter
  `stack.rs` + a few siblings. (Either way it stays `pub(crate)` inside
  the one crate.)
- Async runtime surface: keep the current `tokio` + `CancellationToken`
  shape, or define a thinner internal abstraction.
- How much of `rsip`'s digest helpers to reuse vs. own.
- Feature-gating: should the engine sit behind a default-on feature so
  the old-stack path can be A/B-compiled during migration, or is the
  `[patch]` bridge enough?

## Decision sought

Approve (a) keeping `wavekat-sip` a **single crate** with the engine as
an internal `pub(crate)` module, (b) keeping `rsip` for messages while
writing the stateful engine from scratch, and (c) the phased,
bridge-backed migration order above. Implementation starts at Phase 1
only after sign-off.
