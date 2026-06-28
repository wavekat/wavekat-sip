# RFC coverage

> Status: living document · Last audited: 2026-06-28 (deferred features reinstated — see `docs/17`)

What standards this crate's **public API** implements, which parts of
each, and what is knowingly absent. The yardstick is the surface a
consumer can actually reach through `wavekat_sip::*`.

Since `docs/16`, the SIP transaction/dialog/transport machinery is a
from-scratch in-house engine (internal `stack` module; see `docs/08`–`docs/16`).
The only SIP crate dependency is [`rsip`], used for message types. There is no
longer an "underlying stack" with extra latent capabilities — what the engine
does is exactly what this document lists.

[`rsip`]: https://crates.io/crates/rsip

## Implemented

### RFC 3261 — SIP: Session Initiation Protocol (partial)

| Area | Coverage | Public surface |
|------|----------|----------------|
| §10 Registrations | REGISTER, digest-auth retry on 401/407, re-registration on an interval, unregister (`Expires: 0`), outcome classification (registered / unauthorized / failed / timed out) | `Registrar` |
| §13.2 UAC INVITE | Outbound INVITE with SDP offer, follows provisional responses to a final, answers one digest challenge, parses the SDP answer from the 2xx, sends the 2xx ACK; provisional statuses can be observed (`dial_with_progress`) | `Caller::dial`, `Call` |
| §9 CANCEL | Cancel a still-ringing outbound INVITE (CANCEL after the first provisional; resolves `487 Request Terminated`) | `Caller::dial_cancellable` |
| §13.3 UAS INVITE | Automatic `100 Trying`, deferred accept (`200 OK` + SDP answer) or reject (non-2xx final, e.g. `486`/`603`) | `SipEndpoint::next_incoming_call`, `IncomingCall` |
| §14 Re-INVITE | Outbound in-dialog re-INVITE with SDP re-offer and the mandatory 2xx ACK, used for hold/resume and session refresh | `Call::set_hold`, `Call::session_handle` |
| §15 Terminating | BYE — local hangup via the call handle; an inbound in-dialog BYE is auto-answered `200 OK` by the endpoint router | `Call::hangup`, `SipEndpoint` |
| §12 Dialogs | Dialog establishment with route-set capture/reuse (UAC reverses Record-Route, UAS keeps order), in-dialog request composition addressed to the route set | internal (`Call`) |
| §12.2.2 In-dialog requests | Outbound in-dialog re-INVITE / INFO carrying a body. Inbound re-INVITE / INFO are auto-answered `200 OK` by default, or surfaced to the owning `Call` when it opts in (to answer a session refresh / peer hold, or read INFO DTMF); BYE / OPTIONS stay auto-answered | `Call`, `Call::inbound_requests`, `SipEndpoint` router |
| §8.1.1.4 Call-ID | Random Call-ID generation | `Caller`, `Registrar` |
| §17 Transactions | Full RFC 3261 §17 client/server INVITE & non-INVITE state machines with T1/T2/T4 timers and UDP retransmission | internal (`stack::transaction`) |
| §20.41 User-Agent | Optional product token emitted on every outbound request | `SipEndpoint::new_with_app` |
| §22 Authentication | Digest challenge/response as a client, on both REGISTER and INVITE | `Registrar`, `Caller` (credentials threaded internally) |

Not covered from RFC 3261: acting as a proxy/registrar/redirect server,
SIPS/TLS (§26.2), and multicast (§18.1.1). Provisional responses are
observed but not acknowledged reliably (PRACK / 100rel is RFC 3262, below).

### RFC 3264 — SDP offer/answer model (minimal subset)

Single `m=audio` line, one round of offer/answer:

- Offer generated at `dial` time (`build_sdp`), answer parsed from the
  2xx (`parse_sdp`) — UAC direction.
- Offer parsed from the inbound INVITE, answer generated in the 200 OK
  — UAS direction.

Hold/resume **is** supported: `Call::set_hold` sends a re-INVITE with an
`a=sendonly`/`a=sendrecv` re-offer and a bumped `o=` version (§5),
`build_sdp_with` exposing the direction + version. Still absent: multiple
media descriptions, `a=inactive` two-way hold as a first-class call state
(the `MediaDirection::Inactive` variant exists but `set_hold` only toggles
sendonly/sendrecv), and rejected-stream (`port 0`) handling. Inbound
re-INVITE re-offers are auto-answered `200 OK` without a renegotiated SDP
answer body — see the gap noted in `docs/17`.

### RFC 8866 (ex-4566) — SDP (minimal subset)

`build_sdp` emits and `parse_sdp` reads exactly the subset telephony
G.711 interop needs: `v=`, `o=`, `s=`, `c=` (IN IP4/IP6), `t=`,
`m=audio … RTP/AVP …`, `a=rtpmap`, `a=fmtp`, `a=sendrecv`. Everything
else in SDP is ignored on parse and never emitted.

### RFC 3550 — RTP (partial, no RTCP)

- Fixed-header parsing: version check, padding/extension/marker flags,
  CSRC count (and `header_len` accounting), PT, seq, timestamp, SSRC —
  `RtpHeader::parse`.
- Sending: codec-agnostic packetizer with per-packet seq increment
  (wrapping), timestamp advance by `samples_per_frame`, fixed
  SSRC/PT — `send_loop`, `RtpSendConfig`.
- Symmetric use of one socket for send + receive (shared `Arc<UdpSocket>`,
  in the spirit of RFC 4961).

Not covered: **RTCP entirely** (SR/RR, SDES, BYE, jitter/loss
statistics), header-extension parsing beyond the flag, CSRC list
contents, padding removal, SSRC collision detection. `receive_rtp` is
a debug/smoke-test loop that traces headers; real receive paths are
expected to live in the consumer (parsing headers with
`RtpHeader::parse`).

### RFC 3551 — RTP/AVP profile (G.711 only)

Static payload types 0 (PCMU) and 8 (PCMA); dynamic range 96–127
honored when the remote maps `telephone-event` somewhere other
than 101. No other codecs are negotiated or named.

### RFC 4733 — DTMF events over RTP (send and receive)

Send side:

- Event codes 0–15 (`0`–`9`, `*`, `#`, `A`–`D`) — `DtmfDigit`.
- 4-byte event payload (E bit, 6-bit volume with clamping, duration in
  8 kHz ticks) — `build_event_payload`.
- Burst transmission: marker on first packet, threefold start/end
  redundancy (§2.5.1.4), 20 ms continuation cadence, event-start
  timestamp shared across the burst (§2.5.1.2), monotonic seq/ts
  chaining across digits — `send_dtmf_burst`.
- Separate-SSRC stream per §2.6.2.
- SDP negotiation of `telephone-event/8000` (offer + answer detection,
  `a=fmtp 0-15`); the 16000 Hz clock variant is deliberately not
  selected — `DTMF_DEFAULT_PT`, `RemoteMedia::dtmf_payload_type`.

Receive side:

- Payload decoding (event code, E bit, volume, duration) —
  `parse_event_payload`, `DtmfEventPayload`.
- Stateful per-stream decoder that turns raw RTP packets into
  exactly-once `Pressed` / `Released { duration_ticks }` events,
  deduplicating the redundant burst packets (by SSRC + event-start
  timestamp + event code) and tolerating loss, reordering, and SSRC
  changes — `DtmfReceiver`, `DtmfEvent`. Feed it every packet matching
  the negotiated `dtmf_payload_type` from the consumer's receive loop.

Not covered: tones (§3), trunk/line events beyond DTMF, RFC 2198
redundancy encoding. (RFC 2833 is the obsoleted predecessor — we
implement the 4733 revision.)

### RFC 3263 — Locating SIP servers (SRV subset)

- SRV lookup (`_sip._udp.` / `_sip._tcp.` per the account transport)
  with RFC 2782 priority ordering and weighted-random selection within
  a priority — `resolve_sip_server`, `order_candidates`, `SrvRecord`.
- §4.1 short-circuits: an explicit port or an IP-literal server skips
  SRV entirely and resolves A/AAAA directly (or uses the literal as
  is), keeping the pre-SRV behavior byte-identical for those accounts.
- No-SRV-records fallback to A/AAAA on the bare host at the default
  port; SRV-target resolution failure does *not* fall back (per the
  RFC).

Not covered: NAPTR (§4.1 transport selection starts from the account's
configured transport instead), `_sips._tcp` / TLS targets, and failover
across multiple SRV targets on connection failure — only the first
candidate is used today.

### RFC 4028 — Session timers

- Header logic: `Session-Expires` (with `;refresher=uac|uas`) and `Min-SE`
  parse/build, `Supported`/`Require: timer` — `SessionExpires`,
  `min_se_in`, `supports_timer`.
- Negotiation: `negotiate_uac` (from the 2xx) and `negotiate_uas` (from the
  INVITE, echoing the agreed interval + `Require: timer` in the 200). The
  outbound INVITE advertises `Supported: timer` + a 30-minute
  `Session-Expires` by default.
- Runtime: `session_timer_loop` drives the §10 schedule — the refresher
  sends a refresh re-INVITE every `interval/2`; the non-refresher runs a
  BYE watchdog at `interval − min(32 s, interval/3)`. Surfaced via
  `Call::session_timer()` + `Call::session_handle()`.

Both roles work: the watchdog resets on the peer's refresh re-INVITE,
which the consumer receives via `Call::inbound_requests` (answer it with a
fresh SDP + echoed `Session-Expires`, then ping the loop's `Notify`).

### RFC 6086 (ex-2976) — SIP INFO (DTMF relay)

Outbound `INFO` with the Cisco `application/dtmf-relay` body
(`Signal=…\nDuration=…`) as a DTMF fallback when the remote did not
negotiate RFC 4733 `telephone-event` — `Call::send_dtmf_info`,
`build_info_body`, `InfoOutcome` (incl. the `415 Unsupported Media Type`
stop signal). Inbound `INFO` is still auto-answered `200 OK` and not yet
surfaced (see `docs/17`).

### RFC 3515 — REFER (blind call transfer)

Outbound in-dialog `REFER` with a `Refer-To` target — `Call::blind_transfer`
returns once the transferee accepts (`202 Accepted`). The implicit
subscription's transfer-progress `NOTIFY`s (a `message/sipfrag` status line,
RFC 3420) are surfaced on `Call::inbound_requests`, and `parse_sipfrag_status`
/ `is_final_sipfrag` read the result so the consumer can tear its own leg down
once the target answers. Inbound `REFER` / `NOTIFY` route to the owning `Call`
(rather than being auto-answered) so a consumer can accept/reject a
peer-initiated transfer or follow the sipfrag.

Still absent: `Replaces` (RFC 3891, attended transfer) and `Referred-By`
(RFC 3892) — `blind_transfer` sends neither; and acting on an *inbound* REFER
(auto-dialing the target on the consumer's behalf) is left to the consumer.

## Not implemented

NAT traversal and media security, in particular, are fully delegated
to the network (the crate assumes a reachable, routable RTP path —
typically a PBX/SBC on the same network or a trunk that latches):

| RFC | What it is | Status |
|-----|------------|--------|
| 3581 | Symmetric response routing (`rport`) | Not currently added to outgoing Via; responses route to the Via sent-by address. |
| 3311 | UPDATE method | Not exposed |
| 3326 | Reason header | Not emitted or parsed |
| 3891 / 3892 | Replaces, Referred-By (attended transfer) | Not implemented (blind transfer via REFER **is** — see RFC 3515 above) |
| 3428 | MESSAGE (pager-mode IM) | Not implemented |
| 6665 (ex-3265) | SUBSCRIBE/NOTIFY event framework | Not implemented |
| 3856 / 3863 | Presence, PIDF | Not implemented |
| 5626 / 5627 | Outbound connection reuse, GRUU | Not implemented |
| 3711 / 5763 / 5764 | SRTP, DTLS-SRTP | No media encryption |
| 8489 / 8445 / 8656 | STUN, ICE, TURN | No NAT traversal; local address discovery is a UDP-connect trick only |
| 3605 / 5761 | RTCP attribute in SDP, RTP/RTCP mux | No RTCP at all |
| 7587 et al. | Wideband codecs (Opus, …) | G.711 only by design (see scope in `CLAUDE.md`) |
| 3262 | PRACK / 100rel | Provisional responses are not acknowledged reliably |
| 7118 | SIP over WebSocket | Not exposed (`Transport` is UDP/TCP only) |

### Transports

The engine currently implements a **UDP** transport only. The `Transport`
enum still carries a `Tcp` variant (and the transaction timers collapse their
retransmission soak for a reliable transport), but a TCP transport
implementation is not yet wired into the engine. TLS and WebSocket are out of
scope.

## Known gaps worth closing first

Ranked by how soon a real deployment trips over them:

1. **`rport` (RFC 3581)** — needed for responses to come back through NAT/PAT;
   add `;rport` to outgoing Via and honor it on responses.
2. **TCP transport** — the `Transport::Tcp` variant is currently inert.
3. **RTCP receiver reports** — without them, neither side gets loss or jitter
   feedback; fine on a LAN, blind over the open internet.
4. **TLS transport (SIPS)** — credentials currently ride plaintext except for
   the digest exchange itself.
5. **SRV failover (RFC 3263)** — we order the candidates correctly but only ever
   try the first; a dead primary should fall through to the next target.
