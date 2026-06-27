# Internal `stack` engine, Phase 2 — transport + async runner

> Status: implemented · Date: 2026-06-27

Builds on [09-stack-transactions.md](09-stack-transactions.md). Adds the
UDP transport and the async **engine** that drives the sans-IO §17 state
machines over a real socket — the half of "Phase 1: transport +
transactions" in [08-own-sip-stack.md](08-own-sip-stack.md) that the
first slice deferred.

Still entirely `pub(crate)`; nothing here appears in `wavekat_sip::*`.

## What landed

`src/stack/`:

```
transport.rs   SIP (de)serialization (via rsip) + a bound UDP socket
engine.rs      the async runner: one task owns the socket, the
               transaction table and the timers; Command/Event API
transaction/mod.rs   + Transaction dispatch enum, Reliability::from(Transport)
```

### `transport.rs`

`parse`/`serialize` delegate to `rsip` (we own only socket plumbing).
`UdpTransport` binds a `tokio` UDP socket, sends one message per
datagram, and `recv`s the next *parseable* message — malformed datagrams
are dropped (trace-logged) so one bad packet can't stall the engine. UDP
is `Reliability::Unreliable`; TCP framing is a later addition (kept out
of the initial cut per the plan).

### `engine.rs`

A single task `select!`s over three sources and owns all mutable state,
so there are no locks:

- **inbound datagrams** → demuxed by `TransactionKey` to an existing
  transaction, or used to open a new server transaction (INVITE →
  server-INVITE machine, else server-non-INVITE). An ACK matching no
  transaction is surfaced as `UnmatchedRequest` — it's the 2xx ACK, a
  dialog concern.
- **fired timers** → looked up and fed back into the owning machine.
- **TU commands** (`Command`) → start a client transaction, hand a
  server transaction its response, or send out-of-dialog (the 2xx ACK).

Each machine returns `TxAction`s, which the runner applies: send bytes,
arm/cancel a timer, or publish an `Event` (`IncomingRequest`,
`Response`, `UnmatchedRequest`, `TimedOut`, `Terminated`) up to the TU.

**Timers without handles.** Arming a timer bumps a per-`(transaction,
TimerId)` generation and spawns a `tokio::time::sleep` tagged with it; a
fired timer is ignored unless its generation still matches. So
`StopTimer` and re-arming are just increments — no `DelayQueue`, no
handle bookkeeping, and a terminated transaction's stale timers are
dropped for free.

## Tests

49 stack tests (41 sans-IO + 8 new). The new ones run on **loopback UDP
sockets** with shrunk timers (`start_with_timers`, T1 = 1 ms) so soak and
timeout timers fire in milliseconds:

- transport: parse/serialize round-trip, garbage rejection, two-socket
  send/recv, malformed-then-valid recovery, response round-trip;
- engine: a client transaction delivering a 200 then terminating; an
  inbound INVITE opening a server transaction and emitting the TU's 486
  to the wire; and a silent peer driving Timer F to `TimedOut` +
  `Terminated`.

## Next

Dialog layer (§12 route sets, dialog matching, the 2xx-ACK path that
`UnmatchedRequest` feeds), digest orchestration, then migrating
`Registrar`/`Caller`/`Callee` onto the engine and dropping the external
stack — the remaining phases in
[08-own-sip-stack.md](08-own-sip-stack.md).
