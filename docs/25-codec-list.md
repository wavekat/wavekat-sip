# 25 — Choose the codecs a call may use

> Status: implemented

## Problem

The codec menu is fixed. `Caller::dial` always offers Opus, G.722, PCMU
and PCMA, and `IncomingCall::accept` takes Opus if offered, else the
peer's first codec we know. A consumer has no way to say which codecs it
can actually encode and decode. That was tolerable while every consumer
could handle every codec, but with G.722 added (PR #70)
an app that only has G.711 would now have G.722 negotiated under it, and
an app that wants a different order (G.722 before Opus, or G.711 only on
one line) cannot get it.

## Design

A `CodecList` — the codecs this side may use, in order of preference —
set once on the `SipEndpoint` and read by both directions.

- `CodecList::new(iter)` checks the list: not empty, no codec twice,
  Opus at a dynamic payload type (96–127). `CodecList::default()` is
  today's menu: Opus (111), G.722, PCMU, PCMA.
- `SipEndpoint::set_codecs(list)` / `SipEndpoint::codecs()`. A plain
  setter on the shared endpoint (behind a `std::sync::Mutex`, like the
  other registries) keeps the existing constructors unchanged.
- **Offer** (`Caller::dial`): `build_sdp_offer_with(ip, port, &list)`
  lists exactly those codecs, in that order. Opus rides the payload type
  given in the list. `telephone-event/8000` is always offered;
  `telephone-event/48000` only when Opus is.
- **Answer** (`IncomingCall::accept`): `CodecList::select(&offer)` picks
  the first codec in **our** list that the offer also contains (Opus at
  the offer's payload type). Nothing in common → `488`, as before.
- `RemoteMedia` gains `codecs`: every codec we know on the `m=` line, in
  the peer's order. `select` needs the whole set, not just the first.

`build_sdp_offer`, `CodecMenu::Full` and `select_codec` keep working and
mean "the default list".

## Behaviour change

Answer selection now follows our order instead of the peer's. With the
default list that means:

- G.722 is chosen over G.711 even when the peer lists G.711 first
  (`m=audio … 8 9` → G.722, was PCMA).
- PCMU is chosen over PCMA when the peer offers both
  (`m=audio … 8 0` → PCMU, was PCMA).

Opus still wins wherever it appears. A consumer that wants the peer's
G.711 variant can list only that one.

Why our order and not the peer's (both are allowed by RFC 3264, and
stacks differ: PJSIP and FreeSWITCH default to the peer's): the order
the application chooses is the call quality its users get. If a peer
that lists G.711 first could override it, an app that put G.722 first
would still sound narrowband on many lines, and "most preferred first"
would not mean what it says. There is no switch for the peer's order;
add one only if a consumer needs it.

## Not done

- `AudioCodec` stays exhaustive. `#[non_exhaustive]` would let future
  codecs land without a breaking release, but it would also stop the
  compiler from pointing consumers at the new codec they must now
  handle. With an explicit list, a consumer is safe either way; the
  compile error is the more useful signal.
- No per-call override. One list per endpoint covers the cases we know
  of; `build_sdp_offer_with` and `CodecList::select` are public for
  anyone building bodies by hand.
