# Internal `stack` engine, Phase 1 — transaction layer

> Status: implemented · Date: 2026-06-27

Implements the first slice of the clean-room engine planned in
[08-own-sip-stack.md](08-own-sip-stack.md): the RFC 3261 §17 transaction
state machines. This is the conformance-critical "hard core" the plan
flags — the timers, retransmissions and ACK absorption where homegrown
SIP stacks bleed — so it lands first, fully unit-tested, ahead of the
transport runner and dialog layer.

Everything here is `pub(crate)` inside the single `wavekat-sip` crate and
appears in no public signature, per the plan's one-crate, no-leak rule.

## What landed

`src/stack/`:

```
mod.rs                       engine entry point + build-status doc
transaction/
  mod.rs                     Reliability, Timers (T1/T2/T4), TimerId,
                             TxAction, TransactionKey (demux), gen_branch,
                             build_non_2xx_ack
  client_invite.rs           §17.1.1  Calling/Proceeding/Completed
  client_non_invite.rs       §17.1.2  Trying/Proceeding/Completed
  server_invite.rs           §17.2.1  Proceeding/Completed/Confirmed
  server_non_invite.rs       §17.2.2  Trying/Proceeding/Completed
```

All four machines are driven, because our UA drives all four:

| Machine | Methods |
|---------|---------|
| Client INVITE | outbound INVITE |
| Client non-INVITE | REGISTER, BYE, CANCEL, INFO, OPTIONS |
| Server INVITE | inbound INVITE |
| Server non-INVITE | inbound BYE, INFO, OPTIONS, CANCEL |

Only what we use: no PRACK/100rel, no UPDATE (we refresh via re-INVITE),
no forking/multiple early dialogs, no TLS-specific timing — matching the
plan's non-goals.

## Design — sans-IO

The machines never touch a socket or the clock. Each maps an input event
to an ordered list of actions the caller must perform:

- **Events in:** a received `rsip` message, a fired `TimerId`, or (server
  side) a response the TU wants to send.
- **Actions out (`TxAction`):** `Send`, `StartTimer{id, after}`,
  `StopTimer`, `DeliverResponse`/`DeliverRequest` (hand up to the TU),
  `TimedOut`, `Terminated`.

A later phase adds a thin transport runner that owns the UDP/TCP socket
and a timer wheel and simply applies whatever actions come back. Until
then the design pays off immediately: the timer-heavy core is tested by
feeding events and asserting on the action list and the exact timer
durations — the RFC §17 timer tables checked directly, with no sleeping
and no flakiness.

### Timers

`Timers { t1, t2, t4 }` defaults to the RFC's 500 ms / 4 s / 5 s; tests
shrink nothing (durations are asserted symbolically), and a future
runner can tune T1 to a measured RTT. A single `Reliability` bit
(UDP = `Unreliable`, TCP = `Reliable`) selects every timer that differs
between transports: the retransmit timers (A, E, G) run only on
unreliable transports, and the post-final soak timers (D, I, J, K)
collapse to zero on reliable ones, so those transactions terminate
immediately instead of lingering.

### The re-INVITE ACK bug, structurally avoided

The defect that motivated the whole effort — a non-2xx ACK addressed to
the Contact instead of through the transaction — cannot occur here:
`build_non_2xx_ack` reuses the INVITE's own top `Via` (same branch),
`From`, `Call-ID`, request-URI and `CSeq` number, takes `To` (with the
remote tag) from the response, and copies the request's `Route` set. The
2xx ACK is deliberately *not* this machine's job — on a 2xx the client
INVITE transaction hands the response up and terminates, leaving the ACK
and dialog routing to the (future) dialog/TU layer, where the route set
will live.

## Tests

41 unit tests at the bottoms of the `stack/` files cover, per machine:
initial send + timer arming, retransmit backoff and caps (A doubles;
E/G double capped at T2), the timeout timers (B/F/H), provisional →
proceeding transitions, final-response handling, ACK absorption
(server INVITE → Confirmed), the soak timers (D/I/J/K), and the
reliable-transport fast paths. Shared helpers cover `gen_branch`
(magic-cookie prefix + uniqueness), `TransactionKey` matching
(ACK folds onto INVITE, CANCEL does not), and the non-2xx ACK builder.

## Not in this slice

Transport sockets + serve loop / inbound demux, the dialog layer
(§12 route sets, dialog matching), digest orchestration, and wiring the
existing wrappers onto the engine. Those are the next phases in
[08-own-sip-stack.md](08-own-sip-stack.md); the external stack stays
wired until each flow reaches parity.
