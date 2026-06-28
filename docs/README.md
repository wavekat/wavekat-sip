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
| [09-stack-transactions.md](09-stack-transactions.md) | `stack` engine Phase 1: the RFC 3261 §17 transaction state machines (sans-IO) |
| [10-stack-transport-engine.md](10-stack-transport-engine.md) | `stack` engine Phase 2: UDP transport + the async runner that drives the §17 machines |
| [11-stack-auth.md](11-stack-auth.md) | `stack` engine Phase 3: digest authentication challenge→retry orchestration |
| [12-stack-dialog.md](12-stack-dialog.md) | `stack` engine Phase 4: RFC 3261 §12 dialogs + route-set reuse (the bug fix) |
| [13-stack-register-flow.md](13-stack-register-flow.md) | `stack` engine Phase 5: REGISTER-with-digest, the first composed end-to-end flow |
| [14-stack-call-flow.md](14-stack-call-flow.md) | `stack` engine Phase 6: outbound INVITE call flow (place / answer / ACK / BYE) |
| [15-stack-ua-router.md](15-stack-ua-router.md) | `stack` engine Phase 7: UA router so one engine serves register + many calls |
| [16-drop-rsipstack.md](16-drop-rsipstack.md) | `stack` engine Phase 8 (final): re-point the public wrappers onto the engine and remove the `rsipstack` dependency |
| [17-reinstate-deferred-features.md](17-reinstate-deferred-features.md) | Re-add the call features deferred by the cutover (re-INVITE seam, User-Agent, DTMF INFO, hold/resume, session timers, inbound surfacing + CANCEL) on the engine |
