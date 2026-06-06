# DTMF receive — decode incoming RFC 4733 telephone-event

## Motivation

The crate can send RFC 4733 DTMF (`rtp::dtmf::send_dtmf_burst`) but cannot
decode it. Consumers that listen for keypad input (IVR-style flows, AI
agents reacting to digits) currently have to hand-roll decoding this crate
already understands on the send path. This adds the receive half so the
two sides round-trip within the crate.

## Design

New module `src/rtp/dtmf_recv.rs` (`dtmf.rs` is already ~365 lines of
non-test code; the >300-line rule says split rather than grow it).

### Payload parser

`parse_event_payload(&[u8]) -> Option<DtmfEventPayload>` — the inverse of
`build_event_payload`. `DtmfEventPayload` carries the raw fields: `event`
code, `end` (E bit), 6-bit `volume`, 16-bit `duration_ticks` (8 kHz).
Plus `DtmfDigit::from_event_code` in `dtmf.rs`, the inverse of
`event_code` (returns `None` for codes ≥ 16 — flash-hook etc.).

### Receiver

`DtmfReceiver::new(payload_type)` + `push(&mut self, packet: &[u8]) ->
Option<DtmfEvent>`. Consumers construct one per call with the negotiated
PT from `RemoteMedia::dtmf_payload_type` and feed every inbound RTP
datagram from the media socket through `push`.

**Why raw datagram bytes rather than a pre-parsed `RtpHeader`?** A single
integration point: the consumer's receive loop hands over each datagram
wholesale and acts on `Some`. Taking `(header, payload)` invites slicing
mistakes (`header_len()` off-by-CSRC) and saves only a 12-byte re-parse,
which is negligible next to a UDP recv. Non-RTP, wrong-PT, and audio
packets all simply return `None`.

**Dedup.** All packets of one event share the event-start RTP timestamp
(RFC 4733 §2.5.1.2), so the receiver keys the in-progress event by
`(SSRC, timestamp, event code)`:

- First packet matching no active event → emit `DtmfEvent::Pressed` once.
  The marker bit is *not* required, so a lost marker packet still
  registers the press (the redundant copies carry the same key).
- Further packets with the same key (start redundancy, 20 ms
  continuations, end redundancy, out-of-order copies) → no emission,
  except the first end packet, which emits `DtmfEvent::Released` with the
  final `duration_ticks`.
- Same SSRC but a timestamp at-or-before the active event's start
  (wrapping comparison) → stragglers from a past event, dropped.
- A newer timestamp → next digit; the previous event is abandoned (its
  end packets were lost) and a fresh `Pressed` is emitted. Back-to-back
  digits chain timestamps exactly like `send_dtmf_burst` produces.
- An SSRC change is a new stream (e.g. after re-INVITE) and resets state.

`Released` is best-effort: if every end packet of a burst is lost, the
consumer still got the `Pressed` — which is the actionable signal — and
just never learns the duration.

## Tests

Unit tests at the bottom of `dtmf_recv.rs`:

- payload parse ↔ `build_event_payload` round-trip (all 16 digits, E bit,
  volume, duration); short-buffer rejection.
- Full burst round-trip over a loopback socket: capture real
  `send_dtmf_burst` output, feed it to the receiver, assert exactly one
  `Pressed` + one `Released` with the right duration.
- Synthetic-burst tests (same packet shape, no sleeps): redundancy dedup,
  marker-packet-lost, all-end-packets-lost followed by a new digit,
  interleaved audio packets ignored, wrong PT ignored, non-DTMF event
  codes ignored, two chained digits emit two presses, out-of-order
  straggler dropped.
- `from_event_code` round-trip test in `dtmf.rs`.
