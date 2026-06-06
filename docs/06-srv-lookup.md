# RFC 3263 SRV-based server location

Date: 2026-06-06

## Problem

`Caller::dial` resolves the account's SIP server with a plain A/AAAA
lookup (`tokio::net::lookup_host` in `resolve_server`,
`src/caller.rs`). An account pointing at a bare provider domain that
only publishes `_sip._udp` SRV records — no A/AAAA on the apex — cannot
be dialed: the lookup fails before the INVITE ever leaves.

## Plan

Add a new `src/resolve.rs` module implementing an honest **subset** of
RFC 3263 server location, and wire `Caller::dial` through it.

### What the subset covers

1. **Skip SRV when the target is already pinned** (RFC 3263 §4.1): if
   the account has an explicit `port` configured, or `server` is an IP
   literal, resolve A/AAAA directly (IP literals short-circuit without
   any DNS). This is exactly today's behavior and stays the default
   path — existing setups do not change.
2. **SRV otherwise**: query `_sip._udp.<host>` (UDP transport) or
   `_sip._tcp.<host>` (TCP transport) where `<host>` is
   `SipAccount::server()` (the `server` field, falling back to
   `domain`). Order the records per RFC 2782: ascending priority, then
   weighted-random selection without replacement inside each priority
   class (zero-weight records ordered first for selection, as the RFC
   prescribes). Resolve each target host to an address with the
   SRV-provided port; first success wins. A target of `"."` means
   "service decidedly not available" (RFC 2782) and is skipped.
3. **Fallback**: if the SRV query returns no records (NXDOMAIN or an
   empty answer), fall back to A/AAAA on the bare host at the default
   port (5060) — byte-for-byte today's behavior.

### What the subset deliberately omits

- **NAPTR** (RFC 3263 §4.1 step 1). We derive the transport from the
  account's configured `transport` instead of discovering it via NAPTR.
- **TLS / `_sips._tcp`**. The crate only supports UDP/TCP today.
- **Full failover semantics**. We return the first candidate that
  resolves rather than handing the whole ordered list to the transport
  layer for per-request retry. `rsipstack`'s `InviteOption.destination`
  takes a single address.
- **Robustness deviation**: a *failed* SRV query (e.g. SERVFAIL,
  timeout) is treated like an empty answer and falls back to A/AAAA,
  with a debug log. Strict RFC 3263 would distinguish; falling back
  guarantees the new code path is never worse than today's behavior.
  Conversely, if SRV records *do* exist but none of their targets
  resolve, we do **not** fall back to A/AAAA (per RFC 3263).

### Module layout

`src/resolve.rs` — one concern: SIP server location.

- `SrvRecord` — `(priority, weight, port, target)`, public.
- `order_candidates(&[SrvRecord], seed: u64) -> Vec<SrvRecord>` —
  **pure** RFC 2782 ordering. The weighted choice uses a tiny embedded
  SplitMix64 PRNG seeded by the caller, so unit tests are fully
  deterministic and need no DNS and no `rand` dependency.
- `location_plan(&SipAccount) -> LocationPlan` (private, pure) — the
  skip-SRV decision: `Direct { host, port }` vs
  `Srv { name, host, port }`.
- `trait Dns` (private) — two async methods, `srv` and `lookup`. The
  real implementation does SRV via `hickory-resolver` and A/AAAA via
  `tokio::net::lookup_host` (the system resolver — same call today's
  code makes, so the direct and fallback paths keep identical
  semantics, including `/etc/hosts`). A mock implementation drives the
  unit tests for the decision rules and the fallback path.
- `resolve_sip_server(&SipAccount) -> Result<Option<SocketAddr>, _>` —
  public async entry point. `Caller::dial`'s `resolve_server` delegates
  to it.

### Dependency decision

CLAUDE.md says minimize external crates, but SRV needs a real DNS
client — `lookup_host` (getaddrinfo) cannot query SRV. `rsipstack`
0.4.x already depends on `hickory-resolver` 0.25 through its default
`srv_lookup` feature, so declaring `hickory-resolver = "0.25"` (default
features = `system-config` + `tokio`, the same set rsipstack enables)
adds **zero new crates** to the dependency tree. We use it directly
rather than going through `rsipstack::resolver::SipResolver` because
the latter's selection logic is not seedable (untestable ordering) and
its constructor panics (`expect`) on resolver-config errors, which
violates this crate's no-`unwrap()` rule.

### Out of scope / unchanged

`detect_local_ip` in `src/endpoint.rs` still resolves
`server:port` through the OS resolver (a `UdpSocket::connect`). That is
acceptable for now — it only needs *a* route to pick a source IP, not
the actual SIP target — and is left unchanged (a code comment marks
this). Note the consequence: a domain with SRV records but **no**
A/AAAA on the bare host will still fail at `SipEndpoint::new`. Fixing
that needs an async, SRV-aware bind path and is deferred; this change
fixes the dial path, which also covers the common case where the apex
has an A record (for the provider's website) but SIP listens elsewhere.

## Tests

Unit tests in `src/resolve.rs` (no network):

- `order_candidates`: priority ordering, weighted distribution with
  seeded RNG (statistical over a fixed seed range), all-zero-weight
  classes, mixed zero/non-zero weights, single record, determinism for
  a fixed seed, empty input.
- `location_plan`: explicit port → direct; IP literal (v4 and v6) →
  direct; bare domain → SRV with `_sip._udp.` label; TCP transport →
  `_sip._tcp.`; `server` falling back to `domain`.
- `resolve_with` + mock DNS: direct IP literal makes no DNS calls;
  direct hostname resolves at the configured port; empty SRV answer
  falls back to A/AAAA at 5060; SRV query error falls back; SRV records
  resolve the target at the SRV port; failed first candidate falls
  through to the second; `"."` targets are skipped; SRV-present but
  unresolvable targets do not fall back.

Live-DNS coverage goes to `tests/srv_resolution.rs` as `#[ignore]`'d
integration tests.
