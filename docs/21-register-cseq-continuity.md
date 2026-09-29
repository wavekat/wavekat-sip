# REGISTER `CSeq` continuity across challenged refreshes — plan

> Status: planned · Date: 2026-09-29

Found while testing [20-register-interval-too-brief.md](20-register-interval-too-brief.md),
but a separate bug with a separate root cause.

## The bug

RFC 3261 §10.2:

> The UA MUST increment the CSeq value by one for each REGISTER request
> with the same Call-ID.

We do not. `Registrar` keeps one `CSeq` counter and raises it by one per
attempt, while `Ua::register` quietly spends a *second* number whenever it
answers a `401`/`407`: `auth::build_retry` bumps the `CSeq` because the
retry is a new request (§8.1.3.5), and nothing reports that back. The
counter and the wire drift by one per challenge answered.

Against a registrar that challenges every REGISTER — which is to say,
every real provider — the sequence on the wire is:

```
attempt 1:  CSeq 1 (401)  →  CSeq 2 (200)
attempt 2:  CSeq 2 (401)  →  CSeq 3 (200)     ← 2 reused
attempt 3:  CSeq 3 (401)  →  CSeq 4 (200)     ← 3 reused
```

Every refresh opens by replaying the number its predecessor's
authenticated REGISTER already used. A registrar that enforces the
ordering answers `500 Server Internal Error` (or drops the request), so
the refresh fails and the binding lapses; one that does not enforce it
challenges us again and hides the bug. That is why this has gone
unnoticed — and why it is worth fixing before the `423` retry adds a
third REGISTER to an attempt.

## The fix

Report the sequence number that actually reached the wire, and resume
from it. This is already the pattern on the call path: `cseq_of(&request)`
reads the `CSeq` back off the request that was sent, which is how
`ack_2xx` gets the right number after a challenged INVITE.

- **`stack/registration.rs`** — a `RegisterAttempt { outcome, last_cseq }`
  return type, so one attempt reports both what it reached and where it
  left the sequence.
- **`stack/ua.rs`** — `register` returns that instead of a bare
  `RegisterOutcome`, reading `last_cseq` off the last request it sent.
- **`registrar.rs`** — carry it forward:
  `state.cseq = state.cseq.max(attempt.last_cseq)`.

`max` rather than plain assignment: the counter must never go backwards,
whatever an attempt reports.

Nothing public changes — `RegisterAttempt` is internal to the `stack`
module, and `Registrar`'s surface is unaffected.

## Tests

- `stack/ua.rs` — the existing challenged register asserts the attempt
  reports the retry's `CSeq` (2), not the one handed in (1).
- `tests/register_refresh.rs` — two challenged refreshes against a fake
  registrar: the four REGISTERs on the wire must carry strictly
  increasing `CSeq`s. This is the test that caught it.
