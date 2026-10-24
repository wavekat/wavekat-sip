# Stream keepalive: CRLF pings on TCP and TLS — plan

> Status: implemented · Date: 2026-10-24

## The need

A TCP or TLS connection to a registrar is opened once and then carries
everything: requests, responses, and the inbound INVITEs that make a UA
reachable behind NAT. It sits idle between refreshes, and idle connections
don't last:

- **Home routers and carrier NATs forget them.** Many drop an idle TCP mapping
  after a few minutes, well under the 2 h 4 min RFC 5382 asks for. Neither end
  is told. The registrar's next INVITE goes nowhere, and the UA learns the
  connection is gone only when its next REGISTER refresh times out.
- **A dead connection looks alive.** With nothing to write, nothing fails. The
  UA can't tell a quiet connection from a dead one until it next sends.

A consumer can rebuild its endpoint when a refresh fails, but with a long
registration that is a long time to be unreachable. A registrar that grants
`Expires: 3600` means up to an hour, or two hours for a consumer that waits
for a second failure before rebuilding.

RFC-COVERAGE lists this as known gap 2: "a dropped TCP or TLS connection is
not re-established and we do not send RFC 5626 §3.5.1 CRLF keepalives".

## The design

RFC 5626 §3.5.1 defines a keepalive for connection-oriented transports. The
client sends a double CRLF (a "ping") between messages, and a registrar that
supports it answers with a single CRLF (a "pong"). The framer already skips
bare CRLFs, so neither side confuses them with a message.

`StreamTransport` gains a keepalive task alongside its read task:

1. **Ping on an interval.** Every 30 s, write `\r\n\r\n` through the same
   write half and mutex that messages use, so a ping never lands inside a
   message. Four bytes every 30 s keeps the connection busy enough that NAT
   devices with short idle timeouts keep the mapping.
2. **A failed write closes the connection.** If the ping can't be written,
   the connection is gone. The same applies to a message write that fails in
   `send_to`.
3. **A missing pong closes the connection, but only from a registrar that
   pongs.** The framer now counts the bare CRLFs it skips. If the peer has
   ever answered with one, a ping that gets no answer within 10 s (the figure
   RFC 5626 §4.4.1 uses) means the connection is dead. A peer that has never
   ponged is never judged by its silence, because many registrars simply
   don't implement the pong and their connections are fine.

"Closes the connection" means the read task stops. Its channel to `recv()`
closes, and the engine stops exactly as it does when the peer closes the
connection, so the consumer sees the endpoint end through the existing
signals: `SipEndpoint::next_incoming_call()` returns `None`, and pending
transactions end with `engine stopped`. Before this change, a dead connection
produced neither signal until the next refresh timed out.

### What this doesn't do

- **Reconnect in place.** A new connection has a new source port, so every
  binding and dialog route that named the old one is stale. Rebuilding the
  endpoint, then re-registering, is the consumer's job, and it already gets
  the signal it needs. Reconnecting inside the crate would mean
  re-registering from the transport layer and re-targeting live dialogs. That
  is a larger change for a later plan.
- **Answer the registrar's pings.** RFC 5626 also lets the server ping. We
  count those as proof of life but don't answer them. No registrar we know
  of relies on a client pong.
- **Make the interval configurable.** 30 s and 10 s are internal constants.
  The `Flow-Timer` header (RFC 5626 §4.4.1) could set them per registrar.
  Neither needs public API until someone asks.

## Code

- `stack/keepalive.rs` (new): the interval and timeout as a
  `StreamKeepalive` value, and the ping task. It is a separate module because
  `stream.rs` is already over the size rule.
- `stack/framing.rs`: `Framer` counts the keepalive CRLFs it skips
  (`take_keepalives`).
- `stack/stream.rs`: a `CancellationToken` that the read task watches. The
  keepalive task and a failed `send_to` cancel it, and `Drop` cancels it and
  stops the keepalive task.
- `stack/transport.rs`: `TransportSetup` carries the keepalive
  (`Some(default)` from `From<Transport>` and in `SipEndpoint`). Tests pass
  millisecond intervals through it.

No public API changes, so this is a patch release.

## Tests

- Framer: keepalive CRLFs are counted, between and before messages.
- Stream:
  - An idle connection is pinged.
  - A peer that ponged and then goes silent gets its connection closed, and
    `recv()` ends.
  - A peer that never pongs keeps its connection.
  - Dropping the transport stops the pings.
