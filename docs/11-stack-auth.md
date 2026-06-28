# Internal `stack` engine, Phase 3 — digest auth orchestration

> Status: implemented · Date: 2026-06-27

Adds `src/stack/auth.rs` — the digest challenge→retry orchestration the
engine needs for REGISTER (and any challenged request). Continues
[08-own-sip-stack.md](08-own-sip-stack.md).

## What we own vs. reuse

The digest **math** (HA1/HA2, MD5/SHA-256/SHA-512, `qop=auth` with
`cnonce`/`nc`) is `rsip`'s `DigestGenerator`. Reimplementing it has no
product value and is easy to get subtly wrong, so we reuse it — per the
plan's non-goal of not rewriting message-layer primitives.

We own only the **orchestration**:

- `build_retry(original, response, creds)` — given the request we sent
  and the `401`/`407` we got back, produce the retried request: a fresh
  `Via` branch and incremented `CSeq` (it's a new transaction), the
  original otherwise, plus the credential header.
- `401` → `WWW-Authenticate` answered with `Authorization`; `407` →
  `Proxy-Authenticate` answered with `Proxy-Authorization`.
- `qop=auth` handling: a fresh client nonce (`cnonce`, generated with the
  same no-`rand` seeded-hash trick as branch values) and `nc=1`.

## Tests

7 unit tests: retry adds the credential header with a bumped CSeq and a
fresh branch; the computed response self-verifies via `DigestGenerator`
(catches qop/cnonce/algorithm mixups) for both `qop=auth` and no-qop; the
wire form carries the expected params; `407` uses `Proxy-Authorization`;
and a non-challenge response yields no retry.

## Known limitation

`rsip` spells the algorithm token `SHA256` (no hyphen) for both parsing
and `Display`, where RFC 7616 uses `SHA-256`. So SHA-256 interop with a
strict server is limited by `rsip`, not by this layer. **MD5 — the
near-universal SIP digest — is fully correct.** Since we own the
orchestration, the token can be normalized here later if a SHA-256
deployment needs it.

## Next

The dialog layer (§12 route sets + matching), then migrating `Registrar`
(REGISTER + this auth path), `Caller` and `Callee` onto the engine, and
finally dropping the external stack.
