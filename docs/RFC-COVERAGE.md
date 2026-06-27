# RFC coverage

> Status: living document · Last audited: 2026-06-27 (post-v0.0.15 main)

What standards this crate's **public API** implements, which parts of
each, and what is knowingly absent. The yardstick is the surface a
consumer can actually reach through `wavekat_sip::*` — capabilities
that exist in the underlying [`rsipstack`] but are not exposed here are
listed under [Not exposed](#in-the-underlying-stack-but-not-exposed),
not under "implemented".

[`rsipstack`]: https://crates.io/crates/rsipstack

## Implemented

### RFC 3261 — SIP: Session Initiation Protocol (partial)

| Area | Coverage | Public surface |
|------|----------|----------------|
| §10 Registrations | REGISTER, digest-auth retry on 401/407, re-registration driven by the server-granted `Expires`, unregister (`Expires: 0`), permanent-vs-transient failure classification | `Registrar` |
| §9 Cancelling | CANCEL for a pending outbound INVITE (idempotent once settled) | `PendingDial::cancel` |
| §13.2 UAC INVITE | Outbound INVITE with SDP offer, early dialog states (`Calling` / `Early` / `Confirmed` / `Terminated`), digest credentials | `Caller::dial`, `PendingDial`, `AcceptedDial` |
| §13.3 UAS INVITE | `100 Trying`, deferred accept/reject, `487` auto-reply to pre-answer CANCEL, non-2xx final rejects (`486`, `603`, …) | `Callee`, `PendingCall`, `AcceptedCall` |
| §15 Terminating | BYE in both directions — local hangup via the dialog handle, remote BYE surfaced as `Terminated` on the state channel | `dialog.bye()`, `DialogStateReceiver` |
| §12.2.2 In-dialog requests | Route inbound in-dialog transactions to their dialog; `481 Call/Transaction Does Not Exist` when nothing matches, `501 Not Implemented` for non-INVITE dialog kinds | `SipEndpoint::dispatch_in_dialog`, `DispatchOutcome` |
| §20.41 User-Agent | Library product token plus optional consumer-prepended app token, most-significant-first per RFC 7231 §5.5.3 | `SipEndpoint::new_with_app` |
| §8.1.1.4 Call-ID | Random-prefix Call-ID generation (suffix overridden from rsipstack's default) | `SipEndpoint::new` |
| §18 Transports | UDP and TCP | `Transport` |
| §22 Authentication | Digest challenge/response as a client, on both REGISTER and INVITE | `Registrar`, `Caller` (credentials threaded internally) |

Not covered from RFC 3261: acting as a proxy/registrar/redirect
server, SIPS/TLS (§26.2), multicast (§18.1.1), `OPTIONS` self-handling
(inbound OPTIONS outside a dialog is left to the consumer via the
incoming-transaction stream).

### RFC 3264 — SDP offer/answer model (minimal subset)

Single `m=audio` line, initial offer/answer plus a directional re-offer
for call hold:

- Offer generated at `dial` time (`build_sdp`), answer parsed from the
  2xx (`parse_sdp`) — UAC direction.
- Offer parsed from the inbound INVITE, answer generated in the 200 OK
  — UAS direction.
- **Hold/resume re-INVITE** — re-offer the stream with an explicit
  direction attribute (`a=sendonly` to hold, `a=sendrecv` to resume,
  `a=inactive` for a both-ways pause) and parse the answer back.
  `build_sdp_with_direction`, `MediaDirection`, `reoffer_media`,
  `AcceptedCall::set_hold` / `AcceptedDial::set_hold`. The parsed
  direction is exposed on `RemoteMedia::direction`, and
  `MediaDirection::responding` gives the attribute to answer a
  peer-initiated hold with.

The hold re-offer keeps the same connection address, port, and codecs —
only the direction moves. What plays on the RTP stream while held
(silence, music-on-hold) is the consumer's audio concern, not signaling.

Not covered: *answering* a peer-initiated hold re-INVITE is left to the
consumer (the inbound re-INVITE surfaces on the dialog state stream;
this crate supplies the parsed direction and the `responding()` helper
but does not auto-answer). No multiple media descriptions, no
rejected-stream (`port 0`) handling.

### RFC 8866 (ex-4566) — SDP (minimal subset)

`build_sdp` emits and `parse_sdp` reads exactly the subset telephony
G.711 interop needs: `v=`, `o=`, `s=`, `c=` (IN IP4/IP6), `t=`,
`m=audio … RTP/AVP …`, `a=rtpmap`, `a=fmtp`, and a direction attribute
(`a=sendrecv` / `a=sendonly` / `a=recvonly` / `a=inactive`). Everything
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

### SIP INFO method (RFC 6086 / ex-2976) — DTMF relay only

Sending in-dialog `INFO` carrying `application/dtmf-relay`
(`Signal=` / `Duration=`, the Cisco de-facto body — not itself an RFC
format) on both client and server dialogs, with 2xx / 415 / other
outcome classification — `send_dtmf_info_client`,
`send_dtmf_info_server`, `InfoOutcome`.

Not covered: the RFC 6086 Info Package negotiation framework
(`Recv-Info`), and surfacing *inbound* INFO bodies to the consumer —
an incoming INFO is absorbed by the dialog state machine via
`dispatch_in_dialog` but its payload is not exposed.

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

### RFC 4028 — Session timers (partial)

- `Session-Expires` / `Min-SE` / `Supported: timer` parsing and
  building (manual, header-shape tolerant) — `SessionExpires`,
  `Refresher`, `session_expires_in`, `min_se_in`, `supports_timer`.
- Outbound INVITEs advertise `Supported: timer` +
  `Session-Expires: 1800`; the negotiated result is surfaced as
  `AcceptedDial::session_timer` (UAC, from the 2xx) and
  `PendingCall::session_timer` / `AcceptedCall::session_timer` (UAS,
  echoed into the 200 OK with `Require: timer` when the caller asked).
- 90 s `Min-SE` floor (§4) — `MIN_SESSION_EXPIRES_SECS`.
- `session_timer_loop` drives one confirmed dialog in either role:
  refresher sends re-INVITE refreshes at interval/2 (repeating the
  original SDP — a no-op offer per RFC 3264); non-refresher runs the
  expiry watchdog and tears the call down with BYE if no refresh lands
  in time — `SessionTimerOutcome`.

Not covered: UPDATE-based refreshes (re-INVITE only), `422 Session
Interval Too Small` retry, initiating timers as the UAS when the
caller didn't offer them, and answering the *peer's* refresh
re-INVITEs in-crate — the consumer answers those from its dialog-state
pump and pings the loop's `peer_refreshed` notifier.

### RFC 3581 — Symmetric response routing (`rport`)

Client side only, inherited from the underlying stack: every request
we send carries `;rport` in its Via, so responses come back to the
source port. We do not implement the server-side behavior (we are not
a proxy).

## Not implemented

NAT traversal and media security, in particular, are fully delegated
to the network (the crate assumes a reachable, routable RTP path —
typically a PBX/SBC on the same network or a trunk that latches):

| RFC | What it is | Status |
|-----|------------|--------|
| 3311 | UPDATE method | Not exposed |
| 3326 | Reason header | Not emitted or parsed |
| 3515 / 3891 / 3892 | REFER, Replaces, Referred-By (call transfer) | Not implemented |
| 3428 | MESSAGE (pager-mode IM) | Not implemented |
| 6665 (ex-3265) | SUBSCRIBE/NOTIFY event framework | Matching dialogs answered `501 Not Implemented` |
| 3856 / 3863 | Presence, PIDF | Not implemented |
| 5626 / 5627 | Outbound connection reuse, GRUU | Not implemented |
| 3711 / 5763 / 5764 | SRTP, DTLS-SRTP | No media encryption |
| 8489 / 8445 / 8656 | STUN, ICE, TURN | No NAT traversal; local address discovery is a UDP-connect trick only |
| 3605 / 5761 | RTCP attribute in SDP, RTP/RTCP mux | No RTCP at all |
| 7587 et al. | Wideband codecs (Opus, …) | G.711 only by design (see scope in `CLAUDE.md`) |
| 7118 | SIP over WebSocket | Not exposed (`Transport` is UDP/TCP only) |

## In the underlying stack but not exposed

`rsipstack` ships these, but `wavekat-sip` does not surface them — a
consumer holding only this crate's API cannot reach them:

- **TLS and WebSocket transports** — `Transport` deliberately offers
  `Udp | Tcp` only.
- **RFC 3262 PRACK / 100rel** — provisional responses are surfaced as
  dialog states but never acknowledged reliably.
- **Proxy / registrar server roles** — this crate is a UA toolkit.

If a consumer needs one of these, the path is to widen this crate's
API (new `Transport` variant, etc.), not to reach into `rsipstack`
directly — the `re_exports` module pins the only upstream types we
consider public.

## Known gaps worth closing first

Ranked by how soon a real deployment trips over them:

1. **RTCP receiver reports** — without them, neither side gets loss or
   jitter feedback; fine on a LAN, blind over the open internet.
2. **TLS transport (SIPS)** — credentials currently ride plaintext
   except for the digest exchange itself.
3. **422 retry + UPDATE refreshes (RFC 4028)** — a server that rejects
   our 1800 s `Session-Expires` with `422` currently just gets no
   timer; UPDATE would refresh without touching media.
4. **SRV failover (RFC 3263)** — we order the candidates correctly but
   only ever try the first; a dead primary should fall through to the
   next target.
