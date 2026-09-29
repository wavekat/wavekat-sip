# Honouring `423 Interval Too Brief` on REGISTER — plan

> Status: planned · Date: 2026-09-29

## The bug

A registrar is free to refuse a registration whose lifetime is shorter
than its configured minimum. RFC 3261 §10.3 step 7 says it rejects with
`423 (Interval Too Brief)` and **MUST** include a `Min-Expires` header
naming the shortest lifetime it will accept. §10.2.8 then puts the ball
in the UAC's court:

> If a UAC receives a 423 (Interval Too Brief) response, it MAY retry
> the registration after making the expiration interval of all contact
> addresses in the REGISTER request equal to or greater than the
> expiration interval within the Min-Expires header field of the 423
> response.

This crate never reads that header. `Ua::register` classifies anything
that is not a 2xx and not a `401`/`407` as
`RegisterOutcome::Failed(status)`, so a `423` surfaces as an opaque
`registration failed: 423 Interval Too Brief` and the registration never
completes. The only way out today is for a human to raise the
configured `expires` by hand until the server stops complaining — which
is a value the server already told us.

## The fix

Read `Min-Expires`, retry once at that lifetime, and remember it so the
next refresh asks for the right value the first time.

### Where the two halves live

The split follows the existing layering — `stack` is mechanism, the
public wrappers are policy:

- **`stack/registration.rs`** — a `min_expires(&Response)` reader beside
  the existing `granted_expires`, and a new
  `RegisterOutcome::IntervalTooBrief { min_expires }` variant.
- **`stack/ua.rs`** — map a `423` that carries a usable `Min-Expires` to
  that variant. A `423` *without* one violates §10.3 and leaves nothing
  to adjust to, so it stays `Failed(423)`.
- **`registrar.rs`** — owns the retry. `Registrar` keeps the learned
  floor in its state, raises the requested lifetime to
  `max(configured, floor)` on every subsequent register, and retries a
  `423` once.

Doing the retry in `Registrar` rather than inside `Ua::register` is
deliberate:

- The learned floor has to outlive the single attempt to be useful on
  the next refresh, and `Registrar` is what owns per-account state.
- The retry becomes a genuinely fresh REGISTER with its own `CSeq` and
  its own challenge cycle. Re-sending the previous `Authorization`
  header under a new `CSeq` would reuse the `qop`/`nc=1` pair a server
  is entitled to treat as a replay.
- `Ua::register` keeps its documented shape: one attempt, one challenge.

### Guard rails

- **Never bump an unregister.** `unregister` sends `Expires: 0`; a
  registrar has no business `423`-ing that (§10.3 only rejects a
  *non-zero* interval below its minimum), and bumping it would recreate
  the binding we asked to remove. `expires == 0` never retries.
- **Retry once.** A second `423` — or one naming a `Min-Expires` that is
  not actually larger than what we just asked for — fails the attempt
  instead of looping.
- **No invented ceiling.** Whatever the registrar demands is what we
  ask for; the lifetime that actually governs the binding is the
  `Expires` in its own `200 OK`, which we already read.

### Surface

`RegistrarDiagnostics` gains `min_expires: Option<u32>` so a consumer
can show *why* the effective lifetime differs from the configured one
(and, if it wants, size its own refresh interval from
`negotiated_expires` rather than a hardcoded value). This adds a field
to a public struct — a breaking change for anyone constructing or
exhaustively destructuring it, which only `diagnostics()` does.

`refresh_secs` is deliberately left alone: how often the consumer wants
to re-register is its call, and re-registering more often than the
granted lifetime is wasteful but never wrong.

## Tests

- `stack/registration.rs` — `min_expires` reads the header; absent and
  unparsable headers read `None`.
- `registrar.rs` — the retry policy as a pure function: bump when the
  floor is higher, refuse a second bump, refuse to bump an unregister,
  refuse a floor that is not an increase; and the requested lifetime is
  `max(configured, learned floor)`.
- `stack/ua.rs` — a `423 Min-Expires: 3600` over loopback yields
  `IntervalTooBrief { min_expires: 3600 }`; a `423` with no
  `Min-Expires` stays `Failed`.
- `tests/register_refresh.rs` — the whole loop through the
  public `Registrar` against a fake registrar that `423`s the first
  REGISTER and `200`s the second: `register()` succeeds, the second
  REGISTER on the wire carries `Expires: 3600`, and the diagnostics
  report the learned floor.

## Doc updates

`RFC-COVERAGE.md`'s §10 row gains the `423`/`Min-Expires` behaviour.
