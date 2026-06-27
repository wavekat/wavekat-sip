# Call hold / resume (RFC 3264 re-INVITE) — plan

Date: 2026-06-27

## Why

A softphone needs to put a live call on hold and pick it back up. The
table-stakes version a user expects is *signaled* hold: the far end is
told the call is parked, so it can stop sending audio and play its own
music-on-hold, and the dialog stays healthy throughout.

Before this change the crate could only renegotiate media for an RFC
4028 session refresh — a re-INVITE that repeats the *same* SDP. A
consumer that wanted hold had two bad options: hand-roll the SDP +
re-INVITE itself (signaling logic leaking into the application layer,
which this crate exists to absorb), or fake it with a purely local audio
gate that the far end never learns about (no music-on-hold, no "the
other side knows"). This change gives the consumer a first-class hold
primitive so the signaling stays here.

## What RFC 3264 says

Hold is an offer/answer re-negotiation of an existing stream's
*direction* attribute (§5.1, §6.1):

- Normal call: `a=sendrecv`.
- To hold, the holding party re-offers the stream as `a=sendonly` ("I'll
  keep sending — typically silence or music — but you should stop"). The
  held party answers `a=recvonly`.
- `a=inactive` parks both directions (used when neither side should send,
  e.g. both ends hold).
- Resume re-offers `a=sendrecv`.

The connection address, port, and codecs are unchanged across the
re-offer — only the direction attribute moves — so the RTP five-tuple
and any session timer survive the transition.

## What the underlying stack gives us

`ClientInviteDialog` / `ServerInviteDialog` both expose
`reinvite(headers, body) -> Result<Option<Response>>`, already wrapped by
this crate's `SessionDialogOps::refresh` (used by the session-timer
loop). Hold reuses exactly that seam — the only differences from a
session refresh are (a) the offer carries a one-directional `a=` line and
(b) the 2xx answer is parsed back so the caller can observe what the peer
agreed to. No new rsipstack surface is needed.

## Public surface added

- **`sdp::MediaDirection`** — `SendRecv` / `SendOnly` / `RecvOnly` /
  `Inactive`, with `attr()` (the wire token), `parse()`, and
  `responding()` (the direction to answer a peer's offer with). Defaults
  to `SendRecv`.
- **`sdp::build_sdp_with_direction(local_ip, rtp_port, direction)`** —
  the existing `build_sdp` body with an explicit direction line.
  `build_sdp` now delegates to it with `SendRecv`, so its output is
  unchanged.
- **`sdp::RemoteMedia::direction`** — the parsed direction of a remote
  SDP (default `SendRecv` when no `a=` line is present), so a consumer
  can also *detect* a peer-initiated hold.
- **`hold::reoffer_media(dialog, local_rtp_addr, direction)`** — sends
  the directional re-INVITE over any `SessionDialogOps` dialog and
  returns the re-parsed answer: `Ok(Some(media))` on a 2xx with SDP,
  `Ok(None)` on a 2xx without (the signal still landed), `Err` on a
  non-2xx or an unconfirmed dialog.
- **`AcceptedCall::set_hold(held)` / `AcceptedDial::set_hold(held)`** —
  thin convenience wrappers over `reoffer_media` (`sendonly` to hold,
  `sendrecv` to resume) for the common case where the consumer holds an
  accepted call.

## Out of scope (consumer's job)

What flows on the RTP stream while held — silence, a tone, music-on-hold
— is audio, not signaling, so it stays with the consumer (this crate is
codec- and audio-I/O-agnostic by design). Answering a *peer-initiated*
hold re-INVITE is left to the consumer too: the inbound re-INVITE
surfaces on the dialog state stream, `RemoteMedia::direction` reports the
offered direction, and `MediaDirection::responding()` gives the
attribute to answer with. A single shared media stream is assumed (one
`m=audio`), matching the rest of the crate.

## Testing

`sdp.rs` covers the direction round-trip (build → parse for all four
directions), the absent-attribute default, and `responding()`. `hold.rs`
unit-tests `reoffer_media` against a scripted `SessionDialogOps` mock
(same pattern as the session-timer tests): asserts the offer carries the
right direction at the right port, parses the peer's answer, maps a bare
2xx to `Ok(None)`, and errors on a non-2xx / unconfirmed dialog. No live
SIP server needed.
