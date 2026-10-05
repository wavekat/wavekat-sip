# Probe a registrar without signing in: `Registrar::probe` — plan

> Status: planned · Date: 2026-10-05

## The need

A consumer setting up an account often doesn't know which transport the
provider listens on. The account may be on UDP when the provider only answers
TCP, or on TLS pointed at the plain-SIP port. The only way to find out today
is a full `Registrar::register()` on each transport. That's the wrong tool for
the job:

- **It sends the password every time.** With a wrong password, checking three
  transports means three refused logins. Registrars commonly ban a source
  address after 3–5 of those (fail2ban on Asterisk, PBX intrusion detection),
  so a user checking their setup can lock themselves out.
- **It creates a binding.** A successful REGISTER binds a contact. Calls fork
  to it until it expires or is removed. On a registrar that allows one contact
  per AOR, it can also push out a working device.

What the consumer actually wants to know first is cheaper: *is a SIP registrar
listening on this transport and port?*

## The design

RFC 3261 §10.2.3 defines a REGISTER with no `Contact` header as a **binding
query**. The registrar answers with the current bindings and can't add or
remove one. Sent without credentials, any final response answers the
question:

- `401`/`407`: the registrar is there and wants credentials (the usual answer);
- `200`: there, and it doesn't authenticate queries;
- `403`, `404`, even `400`: there, and refusing.

The challenge is **reported, not answered**, so no credentials go on the wire
and nothing happens that a registrar could count as a failed login.

### API

A backward-compatible addition:

```rust
pub enum RegisterProbe {
    Answered { status: u16 },
    TimedOut,
    EngineStopped,
}

impl Registrar {
    pub async fn probe(&self) -> Result<RegisterProbe, BoxError>;
}
```

`RegisterProbe` is re-exported from the crate root.

### Implementation

- `stack/registration.rs`: `build_register_query` builds the request
  `build_register` builds, then drops `Contact` and `Expires`. Via (with
  `rport`), From tag, Call-ID and CSeq are unchanged. The Via transport still
  comes from the configured contact, so a TCP query says `SIP/2.0/TCP`.
- `stack/ua.rs`: `Ua::register_query` sends it once (`start_client` +
  `await_final`) and maps the first final response to `Answered`. No challenge
  loop.
- `registrar.rs`: `Registrar::probe` takes the next CSeq from the
  registration state and uses the registrar's Call-ID, so a `register()`
  afterwards keeps §10.2 sequencing (doc 21). The probe isn't a registration
  attempt, so it doesn't touch `diagnostics()` (no count, status or error).

Timeouts are the transaction's own (Timer F, 64·T1). A consumer that wants a
shorter answer wraps the call in its own timeout and cancels the endpoint's
token.

## Tests

- `build_register_query` omits `Contact` and `Expires` and keeps the rest.
- `Ua::register_query` against a UDP peer that challenges: `Answered { 401 }`,
  exactly one request on the wire, with no `Authorization`, `Contact` or
  `Expires`.
- `200` and `403` both come back as `Answered`.
- No answer: `TimedOut`.
- Over TCP (`tests/register_probe.rs`): a probe followed by a real
  `register()` shares one Call-ID with a strictly increasing CSeq, only the
  signed retry carries `Authorization`, and the probe leaves the diagnostics
  counters untouched. A `403` is reported as answered.

## Not in scope

- `OPTIONS` pings. Many registrars ignore an out-of-dialog OPTIONS from an
  unregistered source, while every registrar answers a REGISTER.
- Answering the challenge. That's what `register()` is for.
