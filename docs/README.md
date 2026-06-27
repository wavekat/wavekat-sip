# docs/

Two kinds of documents live here:

- **Plan docs** — `NN-<topic>.md`, numbered in the order they were
  written. Each captures the design of one change at the time it was
  made and is *not* updated afterwards; the code and later docs
  supersede it. Numbering may have gaps.
- **Living docs** — `UPPERCASE.md`, maintained in place and expected
  to stay accurate. Re-audit them when the public surface changes.

## Living docs

| Doc | What it tracks |
|-----|----------------|
| [RFC-COVERAGE.md](RFC-COVERAGE.md) | Which RFCs the crate's public API implements, which parts, and what is knowingly absent |

## Plan docs

| Doc | Change |
|-----|--------|
| [01-port-plan.md](01-port-plan.md) | Initial roadmap for the crate |
| [02-outbound-caller-and-hangup.md](02-outbound-caller-and-hangup.md) | Outbound `Caller` + local-hangup ergonomics |
| [03-dtmf-rfc-4733-and-info-fallback.md](03-dtmf-rfc-4733-and-info-fallback.md) | DTMF sending: RFC 4733 telephone-event + SIP INFO fallback |
| [05-dtmf-receive.md](05-dtmf-receive.md) | DTMF receiving: decoding incoming telephone-event packets |
| [06-srv-lookup.md](06-srv-lookup.md) | RFC 3263 SRV-based server location |
| [07-session-timers.md](07-session-timers.md) | RFC 4028 session timers |
| [08-own-sip-stack.md](08-own-sip-stack.md) | Clean-room SIP transaction/dialog/transport engine as an internal `stack` module |
