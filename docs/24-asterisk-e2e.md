# End-to-end tests against Asterisk — plan

> Status: implemented · Date: 2026-10-24

## The need

Every integration test under `tests/` talks to a SIP peer we wrote: a second
`SipEndpoint`, or a hand-rolled listener that answers what the test expects.
That proves the crate agrees with itself, not that a real registrar accepts
what it sends. The differences that hurt are the ones a hand-written peer
can't show:

- how a real server answers a REGISTER on each transport;
- whether it routes an inbound call back down a TCP connection we opened;
- whether it answers an RFC 5626 keepalive ping;
- what our side sees when the server restarts.

## The design

**Asterisk 22 (PJSIP), the certified LTS line, in Docker.** It is the
registrar people most often run themselves.

- **Image:** `andrius/asterisk:22.8-cert4_debian-trixie`. It is multi-arch,
  so it runs the same on an arm64 laptop and an amd64 CI runner. The tag is
  pinned in the `Makefile`, so a new Asterisk release changes nothing until
  a commit moves it.
- **Config:** `e2e/asterisk/` is mounted over the image's defaults:
  - Two accounts, `alice` and `bob`, on UDP and TCP port 5060.
  - Extension `600` answers and echoes.
  - Extension `alice` rings alice.
  - Contacts are rewritten to the request's source (`rewrite_contact`,
    `force_rport`), because the tests reach Asterisk through Docker's port
    mapping.

**The tests**, in `tests/asterisk.rs`, are `#[ignore]`d like every other test
that needs a server (see `CLAUDE.md`) and run one at a time:

| Test | What it pins |
|---|---|
| `registers_over_udp`, `registers_over_tcp` | A REGISTER with digest is accepted on each transport |
| `a_wrong_password_is_refused` | A bad password is a refusal, not a timeout |
| `an_echo_call_connects_and_hangs_up_over_udp` / `_tcp` | INVITE with digest, G.711 answer, BYE |
| `an_inbound_call_arrives_down_the_tcp_connection` | Asterisk sends alice's INVITE (and the BYE) down her TCP connection |
| `asterisk_does_not_answer_keepalive_pings` | PJSIP doesn't pong. The stream keepalive must never judge it by silence (`docs/23-stream-keepalive.md`); if Asterisk starts ponging, this fails |
| `restarting_asterisk_ends_a_tcp_endpoint` | A server restart ends the endpoint promptly: `next_incoming_call()` returns `None` |

**Running it:** `make e2e-asterisk` starts the container, waits for
`core waitfullybooted`, runs the file, prints Asterisk's log if a test
failed, and removes the container. `make asterisk-up` / `asterisk-down` leave
it running for debugging. The tests read `WAVEKAT_E2E_SIP_HOST`,
`WAVEKAT_E2E_SIP_PORT` and `WAVEKAT_E2E_ASTERISK_CONTAINER`.

**CI:** the `E2E (Asterisk)` workflow runs on GitHub-hosted `ubuntu-latest`,
on every PR and every push to `main`. The main CI's self-hosted runners are
containers with no Docker daemon, and hosted minutes are free for a public
repo. It is a separate check, so a problem with the image or with Docker
can't hide a failure in the main one.

## One Docker quirk the restart test works around

Datagrams sent to a mapped UDP port while its container is restarting can
leave Docker's port mapping pointing at the old container. UDP to that port
then goes nowhere for a while, even after Asterisk is back; TCP is
unaffected. So the restart test waits for Asterisk with `docker exec … core
waitfullybooted` and a TCP sign-in, never with UDP, and it sorts last.

## Not covered yet

- **TLS.** This needs a certificate for the container and a pinned
  fingerprint on our side.
- **Media.** RTP isn't mapped, so the echo call checks signalling only.
- **Other registrars.** FreeSWITCH and Kamailio could join with the same
  shape: config in `e2e/<name>/`, a test file, and a Makefile target.
