# 16 · Cutover: drop `rsipstack`, run on the in-house engine

> Status: Done · Phase 8 (final) of the own-SIP-stack plan (`docs/08`).

## What changed

The public wrappers were re-pointed off `rsipstack` and onto the clean-room
engine built across phases 1–7 (`docs/09`–`docs/15`). `rsipstack` is removed
from `Cargo.toml` and no longer appears in the dependency tree. `rsip` (SIP
message types) is the only SIP crate left.

This is a **breaking** API change — accepted deliberately: the old wrappers
exposed `rsipstack` types (`DialogState`, `TransactionHandle`, `DialogId`, …)
across the public surface, so they could not survive the dependency's removal.

## New public surface

The engine is internal (`pub(crate) mod stack`). The public API is a thin layer
over the `Ua` router (`stack::ua`):

- **`SipEndpoint::new(account, cancel) -> Arc<Self>`** — binds the UDP
  transport, starts the engine, resolves the next-hop server (RFC 3263 subset),
  and spawns an **inbound router** that drains `Ua::next_incoming()`:
  - a fresh `INVITE` (no `To` tag) → an `IncomingCall` on
    `next_incoming_call()`;
  - any in-dialog request (`BYE` / `OPTIONS` / `INFO` / re-`INVITE`) →
    auto-answered `200 OK`;
  - the 2xx `ACK` → absorbed.
- **`Caller::dial(target) -> Call`** — binds an RTP socket, offers G.711 SDP,
  places the INVITE, answers a single `401`/`407` digest challenge, and parses
  the SDP answer from the 2xx.
- **`IncomingCall::accept() -> Call`** / **`reject(status)`** — answers `200 OK`
  with an SDP answer (building a UAS dialog), or sends a non-2xx final.
- **`Call`** — the established-call handle (`remote_media`, `rtp_socket`,
  `local_rtp_addr`); `hangup()` sends an in-dialog `BYE`.
- **`Registrar`** — `register()` / `keepalive_loop()` / `unregister()` /
  `diagnostics()` over `Ua::register`, preserving `RegistrarDiagnostics`.
- **`re_exports`** now exposes only `rsip` types (`Header`, `Headers`, `Method`,
  `StatusCode`, `Uri`).

Two small engine additions landed to support the wrappers:

- `stack/response.rs` — `build_response()`, a UAS response builder (echoes
  Via/From/Call-ID/CSeq, adds a local `To` tag, optional Contact + body).
- `stack::transaction::gen_tag()` — opaque dialog-tag generator.

## Feature deltas (deferred to follow-ups on the new API)

To land the cutover as one coherent change, these `rsipstack`-coupled features
were dropped for now and their modules removed. Each is reintroducible on the
engine without further breaking changes:

- **Session timers (RFC 4028)** — `session_timer.rs` removed. The engine
  auto-answers in-dialog re-INVITEs; periodic refresh is not yet driven.
- **DTMF over SIP INFO** — `dtmf_info.rs` removed. In-band RTP telephone-event
  DTMF (`rtp::dtmf`) is unaffected.
- **Hold / resume re-INVITE** — not yet wired on the new `Call`.
- **DialogState streaming / cancel-while-ringing** — the old `DialogState`
  receiver UX is gone; `dial()` resolves directly to an answered `Call`.
- **`User-Agent` header** — not currently emitted.

## Tests

- The old `rsipstack`-based integration tests were removed.
- `tests/end_to_end_call.rs` (new) drives the **public** API over loopback on
  the in-house engine: one endpoint dials another, the callee accepts with an
  SDP answer, the caller confirms negotiated media, and hangs up with a BYE the
  callee's router auto-answers. No external SIP server required.
- The engine's own loopback coverage (`stack::ua`) continues to exercise
  REGISTER-with-digest and the full INVITE/200/ACK/BYE flow.

All four gates pass with zero warnings; `rsipstack` is absent from `Cargo.lock`.
