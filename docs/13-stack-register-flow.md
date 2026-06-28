# Internal `stack` engine, Phase 5 — REGISTER flow (first composed flow)

> Status: implemented · Date: 2026-06-27

Adds `src/stack/registration.rs` — the first *composed* flow on the
clean-room stack, and the first end-to-end proof it works over the wire.
Continues [08-own-sip-stack.md](08-own-sip-stack.md).

## What landed

- `build_register(cfg, cseq, local_addr)` — compose a REGISTER (Via with
  a fresh branch + sent-by, From/To/Contact, CSeq, Call-ID, Expires).
- `drive_register(engine, peer, events, cfg, cseq)` — send the REGISTER
  through the engine, answer a single `401`/`407` with `auth::build_retry`,
  and report a `RegisterOutcome` (`Registered{expires}` / `Unauthorized` /
  `Failed(status)` / `TimedOut` / `EngineStopped`).

This stitches together every prior phase: the non-INVITE client
transaction (§17.1.2), the UDP engine, and the digest orchestration. It
is the logic the migrated `Registrar` will sit on.

## Tests

3 tests, two of them **full loopback round-trips against a fake
registrar**:

- `register_succeeds_after_digest_challenge` — the fake registrar
  challenges the first REGISTER (401 + `WWW-Authenticate`) and accepts the
  second once it carries `Authorization`; the flow reports
  `Registered { expires: 60 }`.
- `rejected_credentials_yield_unauthorized` — a registrar that always
  challenges yields `Unauthorized` after one retry (no auth loop).
- `build_register_has_expected_shape` — header/CSeq/tag/expires checks.

These are real SIP messages on real UDP sockets, parsed by `rsip` on the
server side — the strongest evidence yet that the engine interoperates.

## Note on event routing

`drive_register` consumes the engine's event stream directly and assumes
it is the only flow in flight. The migrated endpoint will add a small
per-transaction/per-dialog router so REGISTER, calls, and keepalives
share one engine — that router is the heart of the next phase.

## Next

Wire the public wrappers (`Registrar`/`Caller`/`Callee`) and a new
engine-backed endpoint onto these flows, replace the `rsipstack`
re-exports with crate-owned types, and drop the dependency.
