# Internal `stack` engine, Phase 4 — dialog layer

> Status: implemented · Date: 2026-06-27

Adds `src/stack/dialog.rs` — RFC 3261 §12 dialogs: the state that turns an
INVITE/2xx into a relationship through which BYE, re-INVITE and INFO are
sent. Continues [08-own-sip-stack.md](08-own-sip-stack.md).

## What landed

- `Dialog::uac(invite, response, local_contact)` — build the caller-side
  dialog from the INVITE we sent and the establishing response (2xx, or a
  1xx-with-tag early dialog).
- `Dialog::uas(invite, local_tag, local_contact)` — build the callee-side
  dialog from an inbound INVITE and the tag we answer with.
- `Dialog::new_request(method)` — the next in-dialog request: incremented
  CSeq, Request-URI = remote target, From/To with the right tags, a fresh
  Via branch, our Contact, and the replayed route set.
- `DialogId` (Call-ID + local tag + remote tag) and
  `DialogId::from_request` to route inbound in-dialog requests.

## The route-set bug, fixed by construction

The defect that motivated the clean-room engine: an in-dialog re-INVITE
addressed straight to the Contact instead of through the stored route
set, breaking hold/resume behind a proxy/SBC. Here it **cannot** recur:

- the route set is captured **once** at establishment (UAC: the response's
  `Record-Route`, reversed; UAS: the request's, in order);
- `new_request` replays it as `Route` headers on **every** in-dialog
  request, with the remote target as the Request-URI — the two are never
  conflated, and a later re-INVITE 2xx with no `Record-Route` cannot
  erase it.

A dedicated test (`route_set_is_replayed_on_every_request`) guards this:
a second in-dialog request still carries the captured route set.

## Tests

5 unit tests: UAC dialog identity/target capture; an in-dialog BYE using
the target + reversed route set + correct tags + advancing CSeq; the
route-set regression guard; UAS party orientation + inbound-request
matching; and early (1xx) vs confirmed (2xx) state.

## Scope

Loose routing (`;lr`) only — universal in modern proxies; strict routing
(legacy) is out of scope per the plan. UDP transport in the Via.

## Next

With transactions, transport/engine, auth and dialogs in place, the
remaining work is wiring: migrate `Registrar`, `Caller` and `Callee` onto
the engine + dialog layer behind their existing public types, replace the
`rsipstack` re-exports with crate-owned types, and drop the dependency.
