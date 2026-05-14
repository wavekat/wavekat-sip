# wavekat-sip — project instructions

## Scope

This crate is **SIP signaling + RTP transport only**. Things that belong
elsewhere:

- Audio device I/O, codec, jitter buffering, recording → the consuming
  application or future dedicated crates.
- Account persistence (TOML files, keychain) → application layer.
- Call orchestration, AI pipeline, business logic → consuming application.

If a new module touches `cpal`, file paths, or LLM APIs, it is in the wrong
crate. Push back to the consumer.

## Structure

Single-crate workspace at `crates/wavekat-sip/`. Modules:

- `account.rs` — runtime `SipAccount` + `Transport`.
- `endpoint.rs` — shared `SipEndpoint` (transport + dialog layer).
- `sdp.rs` — minimal SDP offer/answer for G.711.
- `rtp.rs` — `RtpHeader` parser + receive loop.
- `registrar.rs` — REGISTER + digest auth + keepalive.

Planned (see `docs/01-port-plan.md`):

- `caller.rs` — outbound INVITE wrapper.
- `callee.rs` — inbound INVITE accept/reject.

## Testing

- Every module must have unit tests at the bottom of the file.
- **Every change that adds or modifies public surface must land with a
  unit test in the same PR.** "It's mostly glue over rsipstack" is not
  an exemption — if the function is too entangled for a pure unit test,
  add an `#[ignore]`'d integration test in `tests/` in the same PR.
  Deferring tests to a follow-up is not acceptable.
- Test pure functions first: parsers, builders, helpers.
- Round-trip tests where applicable (e.g. `build_sdp` ↔ `parse_sdp`).
- Integration tests requiring a SIP server go in `tests/` and are `#[ignore]`.
- No `unwrap()` in library code — only in tests.

## Code quality

Before merging, all four must pass with zero warnings:

```sh
cargo fmt --all --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo doc --no-deps -p wavekat-sip --all-features
```

Use `thiserror` for typed errors. Use
`Box<dyn std::error::Error + Send + Sync>` at async task boundaries
(`tokio::spawn`). Add `///` doc comments on public structs and functions.

Keep modules focused — one concern per module, split if >300 lines.
Minimise external crates — prefer manual parsing for simple formats (SDP,
RTP header).

## Conventions

- Plan docs go in `docs/` with date-prefixed names: `YYYYMMDD-<slug>.md`
  (no dashes in the date) for time-sensitive plans, or `NN-<topic>.md` for
  evergreen design docs.
- Each non-trivial change gets a plan doc before implementation.
