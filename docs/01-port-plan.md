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

## Shipped in v0.0.9

| Module | Notes                                                                                  |
|--------|----------------------------------------------------------------------------------------|
| `rtp`  | `send_loop` — codec-agnostic packetizer: payload bytes in (mpsc), RTP on the wire out. |
| `registrar` | REGISTER + digest auth retry + keepalive + unregister.               |

## Landing in v0.0.3 (in flight)

| Module      | Status        | Notes                                                                |
|-------------|---------------|----------------------------------------------------------------------|
| `callee`    | implemented   | `accept_transaction` / `reject_transaction` returning `AcceptedCall` (dialog, RTP socket, remote media, state receiver). No audio. |
| `caller`    | not started   | `Caller::invite(target)` returning `(Dialog, RemoteMedia, Arc<UdpSocket>)`. |

## Pending

### `caller` — outbound INVITE

`Caller::invite(target)` returns `(Dialog, RemoteMedia, Arc<UdpSocket>)`
and lets the consumer drive RTP themselves. A higher-level helper can sit
on top for the common case.

### Integration tests

Once `caller` lands, add an `#[ignore]`d integration test in `tests/` that
registers against a local Asterisk and places a call. Run manually; not in
CI.

## Out of scope

- Audio device I/O (cpal), codec (G.711 / Opus encode-decode), jitter
  buffer, recording, WAV writer.
- File / keychain account persistence.
- Call orchestration, AI pipeline, business logic.

These belong in the consuming application, not in this crate.
