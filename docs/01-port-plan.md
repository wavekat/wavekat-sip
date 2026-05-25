# 01 — Roadmap

> Status: in-progress · Date: 2026-05-13

This crate extracts the SIP signaling and RTP transport pieces from an
earlier softphone prototype into a focused, reusable SDK.

## Shipped in v0.0.1

| Module      | Notes                                                                |
|-------------|----------------------------------------------------------------------|
| `account`   | Runtime `SipAccount` + `Transport`. Persistence is app-layer.        |
| `endpoint`  | Shared SIP endpoint: bound transport, dialog layer, incoming stream. |
| `sdp`       | Minimal G.711 offer/answer (PCMU + PCMA, sendrecv).                  |
| `rtp`       | `RtpHeader::parse` + debug `receive_rtp` loop.                       |

## Shipped in v0.0.7 / v0.0.8

| Module   | Notes                                                                                                                                |
|----------|--------------------------------------------------------------------------------------------------------------------------------------|
| `callee` | `handle_pending` / `accept_transaction` / `reject_transaction` returning `AcceptedCall` (dialog, RTP socket, remote media, state RX). |

## Shipped in v0.0.9

| Module      | Notes                                                                                  |
|-------------|----------------------------------------------------------------------------------------|
| `rtp`       | `send_loop` — codec-agnostic packetizer: payload bytes in (mpsc), RTP on the wire out. |
| `registrar` | REGISTER + digest auth retry + keepalive + unregister.                                 |

## Landing in v0.0.10

| Module   | Notes                                                                                                                                                                                            |
|----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `caller` | `Caller::dial(target)` → `PendingDial` (state_rx) → `AcceptedDial` on `Confirmed`. `PendingDial::cancel` for pre-answer CANCEL; `accepted.dialog.bye().await` for BYE. See `docs/02-…` for shape. |

## Landing next — DTMF, slice 1 of 3

Version pin TBD — held until all three slices land so a single
release ships the complete RFC 4733 + SIP INFO surface. See
[doc 03](03-dtmf-rfc-4733-and-info-fallback.md) for the full plan.

| Module | Notes |
|--------|-------|
| `sdp`  | Advertises `telephone-event/8000` (PT 101) in offers/answers; `RemoteMedia.dtmf_payload_type` exposes the negotiated PT (or `None`) so consumers can route DTMF to RFC 4733 or fall back to SIP INFO. |

## Landing next — DTMF, slice 2 of 3

| Module     | Notes |
|------------|-------|
| `rtp::dtmf`| RFC 4733 event-packet construction (`build_event_payload`, `build_rtp_dtmf_packet`) plus `send_dtmf_burst` — the async transmit helper that drives the 3× initial / continuation / 3× end packet pattern on its own RTP stream (separate SSRC, per RFC 4733 §2.6.2). `DtmfDigit` enum + `from_char` / `as_char` / `event_code`. |

## Landing in v0.0.13

| Module      | Notes |
|-------------|-------|
| `dtmf_info` | SIP `INFO` fallback for DTMF when the SDP answer omits `telephone-event/8000`. `build_info_body` produces the `application/dtmf-relay` body (`Signal=X\nDuration=N`). `send_dtmf_info_client` / `send_dtmf_info_server` wrap the rsipstack `dialog.info()` call with the right `Content-Type` and surface a typed `InfoOutcome` (Accepted / UnsupportedMedia / OtherFailure / DialogNotConfirmed) so the consumer can stop retrying after a 415. |

## Pending

### Integration tests against a SIP server

Add an `#[ignore]`d integration test in `tests/` that registers against
a local Asterisk and places a call. Run manually; not in CI.

## Out of scope

- Audio device I/O (cpal), codec (G.711 / Opus encode-decode), jitter
  buffer, recording, WAV writer.
- File / keychain account persistence.
- Call orchestration, AI pipeline, business logic.

These belong in the consuming application, not in this crate.
