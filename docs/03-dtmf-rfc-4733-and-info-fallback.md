# 03 — DTMF: RFC 4733 telephone-event + SIP INFO fallback

> Status: in-progress · Date: 2026-05-25

A SIP softphone that can't send touch-tones is stuck the moment a call
reaches an IVR ("press 1 for sales"), a conference PIN, or a voicemail
prompt. This crate ships SIP signaling + RTP transport, so DTMF is on
us — the consumer hands us digits, we put them on the wire.

This note covers the design that lands across three releases:

| Release | Slice |
|---------|-------|
| 0.0.11 (this PR) | SDP negotiates `telephone-event/8000` (PT 101). `RemoteMedia` exposes the negotiated DTMF payload type. |
| 0.0.12 | RFC 4733 event-packet writer + `send_dtmf(digit)` on the live dialog handle. |
| 0.0.13 | SIP INFO (`application/dtmf-relay`) fallback when the answer omits `telephone-event`. |

## Background — the three transports

There are three ways a SIP endpoint can send DTMF:

1. **RFC 4733 telephone-event (in-band RTP, out-of-band semantically).**
   A separate RTP payload type (PT 101 by convention) carries
   event packets — one digit per event with begin / continue / end
   markers — interleaved on the same RTP stream as the audio codec.
   Negotiated in SDP. **What virtually every IP-PBX and softphone uses
   today.**
2. **SIP INFO with `application/dtmf-relay`.** A SIP request (not RTP)
   sent inside the dialog. Older, simpler, widely supported but not
   universally. Some carriers reject it.
3. **In-band audio tones.** Synthesize the 697/1209 Hz pair and mix it
   into the outbound audio. Works through any path but is fragile —
   VAD, PLC, low-bitrate transcoding, and CNG can all mangle the tone.

We do (1) as the primary and (2) as the fallback. We never do (3) —
the failure modes aren't worth the breadth of compatibility.

## Slice 1 (this PR) — SDP negotiation

Today's SDP offer / answer advertises only G.711:

```
m=audio 5004 RTP/AVP 0 8
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
```

After this PR it becomes:

```
m=audio 5004 RTP/AVP 0 8 101
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
```

- `101` is the *de facto* dynamic payload type for telephone-event.
  Any value in 96-127 is legal — we pick 101 because it's the value
  every other softphone picks, which keeps inter-op clean.
- `a=fmtp:101 0-15` advertises support for the standard event codes
  (digits `0`-`9`, `*`, `#`, A-D).

### Parser changes

`RemoteMedia` grows one field:

```rust
pub struct RemoteMedia {
    pub addr: IpAddr,
    pub port: u16,
    pub payload_type: u8,
    /// Payload type the remote offered (or accepted) for RFC 4733
    /// `telephone-event/8000`. `None` if the remote did not advertise
    /// it — consumers should then fall back to SIP INFO for DTMF.
    pub dtmf_payload_type: Option<u8>,
}
```

The parser walks `m=audio`'s payload-type list and resolves each one
against the `a=rtpmap:<pt> <name>/<rate>` lines. If any of them is
`telephone-event/8000`, that PT goes into `dtmf_payload_type`. The
audio `payload_type` is still the *first* PT listed (the preferred
codec), preserving today's behavior — we don't suddenly pick 101 as
the "preferred codec."

### What this does *not* do

- Doesn't send any DTMF. Slice 2 wires `send_dtmf` to the writer.
- Doesn't fall back to INFO. Slice 3 adds the INFO sender.
- Doesn't decode inbound telephone-event packets — the consumer's
  audio-decode path already needs to switch on `RtpHeader::payload_type`
  per packet; this PR just makes "PT 101 = DTMF, don't feed to G.711
  decode" possible to express by exposing the negotiated PT.

## Slice 2 (next PR) — RFC 4733 event-packet writer

A telephone-event packet is a normal RTP packet with the negotiated PT
and a 4-byte payload:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     event     |E|R| volume    |          duration             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

State machine per press (digit, hold ≈ 160 ms):

- **3 initial packets** — `E=0`, same RTP timestamp, sequence numbers
  incrementing, duration `160`.
- **Continuation packets every 20 ms** — `E=0`, duration grows by 160
  each tick.
- **3 end packets** — `E=1`, same final duration. Sent back-to-back.

The initial-3 and end-3 repetitions are loss resilience: a single
dropped packet must not lose the digit or, worse, leave it "stuck on."

Public surface:

```rust
impl AcceptedCall { pub async fn send_dtmf(&self, digit: DtmfDigit); }
impl AcceptedDial { pub async fn send_dtmf(&self, digit: DtmfDigit); }
```

Both delegate to a small queue drained by the same send loop that
ships audio. When a DTMF burst is mid-flight, audio frames continue
to be sent in parallel (no muting) — the receive side handles the
slight bandwidth bump cleanly.

## Slice 3 (next-next PR) — SIP INFO fallback

When `RemoteMedia.dtmf_payload_type.is_none()`, `send_dtmf` falls back
to a SIP INFO request inside the dialog:

```
INFO sip:carrier@example.com SIP/2.0
...
CSeq: <next> INFO
Content-Type: application/dtmf-relay
Content-Length: 22

Signal=5
Duration=160
```

`Signal` is the digit char. `Duration` is in milliseconds. Dialog
CSeq / route set / contact are reused.

If we get a 415 (unsupported) back, we log it once and stop trying
for this dialog — the press technically failed but the consumer
already updated its UI optimistically. Same failure mode as a real
phone on a broken trunk.

## Public API after all three slices

```rust
// sdp::RemoteMedia
pub struct RemoteMedia {
    pub addr: IpAddr,
    pub port: u16,
    pub payload_type: u8,
    pub dtmf_payload_type: Option<u8>,
}

// rtp::dtmf (new module)
pub const DTMF_DEFAULT_PT: u8 = 101;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtmfDigit { D0, D1, D2, D3, D4, D5, D6, D7, D8, D9, Star, Pound, A, B, C, D }

impl DtmfDigit {
    pub fn from_char(c: char) -> Option<Self>;
    pub fn as_char(self) -> char;
    pub fn event_code(self) -> u8; // 0-15 per RFC 4733
}

// On the live call handles
impl AcceptedCall { pub async fn send_dtmf(&self, digit: DtmfDigit) -> Result<(), SendDtmfError>; }
impl AcceptedDial { pub async fn send_dtmf(&self, digit: DtmfDigit) -> Result<(), SendDtmfError>; }
```

## Tests

- **Slice 1**: SDP round-trip — `build_sdp(...)` followed by
  `parse_sdp(...)` produces `dtmf_payload_type = Some(101)`. An
  answer without `a=rtpmap:101 telephone-event/8000` parses with
  `dtmf_payload_type = None`. Out-of-order rtpmap lines, mixed-case
  parameter names, and the optional `a=fmtp:101 0-15` line are all
  exercised.
- **Slice 2**: byte-exact event packet — pressing `5` for 100 ms
  produces a sequence of `(event=5, E=0, volume=10, duration=160)` →
  `(duration=320)` → ... → `(E=1, duration=N)` packets with the
  3× initial and 3× end repetition.
- **Slice 3**: INFO request body is exactly `Signal=5\nDuration=160`,
  CSeq increments correctly, dialog state is otherwise untouched.

## Out of scope

- **Receiving DTMF.** Parsing inbound telephone-event packets so the
  consumer's UI can show "the remote pressed 5" is a future slice.
  For now the consumer's RTP receive path must skip packets where
  `header.payload_type == media.dtmf_payload_type` (so they don't
  reach G.711 decode); whether to surface them is the consumer's
  call.
- **DTMF over WebRTC data channel.** Not in scope; WebRTC isn't on
  this crate's roadmap.
- **Per-digit `Volume` overrides.** The writer fixes `volume = 10`
  (per RFC 4733 §2.5.2.3, in dBm0). If a consumer needs to vary
  volume per call, add a parameter later.
