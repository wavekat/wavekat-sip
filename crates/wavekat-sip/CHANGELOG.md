# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/wavekat/wavekat-sip/compare/v0.1.0...v0.1.1) - 2026-06-28

### Added

- blind call transfer via REFER (RFC 3515) ([#45](https://github.com/wavekat/wavekat-sip/pull/45))

### Added

- blind call transfer (RFC 3515): `Call::blind_transfer` sends an in-dialog
  `REFER` with `Refer-To`; transfer-progress `NOTIFY`s (a `message/sipfrag`
  status line) arrive on `Call::inbound_requests` and are parsed with
  `parse_sipfrag_status` / `is_final_sipfrag`. Inbound `REFER` / `NOTIFY` now
  route to the owning `Call` instead of being auto-answered.

## [0.1.0](https://github.com/wavekat/wavekat-sip/compare/v0.0.15...v0.1.0) - 2026-06-28

### Added

- [**breaking**] in-house SIP engine, full call lifecycle ([#43](https://github.com/wavekat/wavekat-sip/pull/43))

## [0.0.15](https://github.com/wavekat/wavekat-sip/compare/v0.0.14...v0.0.15) - 2026-06-06

### Added

- add RFC 4028 session timers ([#37](https://github.com/wavekat/wavekat-sip/pull/37))
- resolve SIP servers via DNS SRV ([#35](https://github.com/wavekat/wavekat-sip/pull/35))
- decode incoming RFC 4733 DTMF ([#34](https://github.com/wavekat/wavekat-sip/pull/34))

## [0.0.14](https://github.com/wavekat/wavekat-sip/compare/v0.0.13...v0.0.14) - 2026-06-06

### Added

- let consumers prepend an app product token to the User-Agent ([#31](https://github.com/wavekat/wavekat-sip/pull/31))

## [0.0.13](https://github.com/wavekat/wavekat-sip/compare/v0.0.12...v0.0.13) - 2026-06-06

### Fixed

- refresh REGISTER on the server-granted Expires ([#30](https://github.com/wavekat/wavekat-sip/pull/30))

### Other

- link wavekat.com from README ([#28](https://github.com/wavekat/wavekat-sip/pull/28))

## [0.0.12](https://github.com/wavekat/wavekat-sip/compare/v0.0.11...v0.0.12) - 2026-06-03

### Fixed

- surface permanent REGISTER rejections instead of retrying forever ([#27](https://github.com/wavekat/wavekat-sip/pull/27))

## [0.0.11](https://github.com/wavekat/wavekat-sip/compare/v0.0.10...v0.0.11) - 2026-05-26

### Added

- *(dtmf-info)* SIP INFO fallback for application/dtmf-relay ([#25](https://github.com/wavekat/wavekat-sip/pull/25))
- *(rtp)* RFC 4733 DTMF event-packet writer + send_dtmf_burst ([#24](https://github.com/wavekat/wavekat-sip/pull/24))
- *(sdp)* advertise + parse RFC 4733 telephone-event (DTMF) ([#23](https://github.com/wavekat/wavekat-sip/pull/23))

### Other

- add stars chart to README ([#20](https://github.com/wavekat/wavekat-sip/pull/20))

## [0.0.10](https://github.com/wavekat/wavekat-sip/compare/v0.0.9...v0.0.10) - 2026-05-14

### Added

- *(caller)* add outbound Caller + PendingDial + AcceptedDial ([#19](https://github.com/wavekat/wavekat-sip/pull/19))

### Other

- plan outbound Caller + hangup (doc 02) ([#17](https://github.com/wavekat/wavekat-sip/pull/17))

## [0.0.9](https://github.com/wavekat/wavekat-sip/compare/v0.0.8...v0.0.9) - 2026-05-14

### Added

- *(rtp)* add codec-agnostic send_loop ([#15](https://github.com/wavekat/wavekat-sip/pull/15))

## [0.0.8](https://github.com/wavekat/wavekat-sip/compare/v0.0.7...v0.0.8) - 2026-05-14

### Added

- *(callee)* add handle_pending for deferred accept/reject ([#13](https://github.com/wavekat/wavekat-sip/pull/13))

## [0.0.7](https://github.com/wavekat/wavekat-sip/compare/v0.0.6...v0.0.7) - 2026-05-14

### Added

- *(endpoint)* dispatch in-dialog transactions to matching dialog ([#11](https://github.com/wavekat/wavekat-sip/pull/11))

## [0.0.6](https://github.com/wavekat/wavekat-sip/compare/v0.0.5...v0.0.6) - 2026-05-13

### Added

- *(endpoint)* set branded Call-ID suffix instead of restsend.com ([#9](https://github.com/wavekat/wavekat-sip/pull/9))

## [0.0.5](https://github.com/wavekat/wavekat-sip/compare/v0.0.4...v0.0.5) - 2026-05-13

### Fixed

- *(registrar)* return Call-ID value without header prefix in diagnostics ([#7](https://github.com/wavekat/wavekat-sip/pull/7))

## [0.0.4](https://github.com/wavekat/wavekat-sip/compare/v0.0.3...v0.0.4) - 2026-05-13

### Added

- expose REGISTER + endpoint diagnostics ([#5](https://github.com/wavekat/wavekat-sip/pull/5))

## [0.0.3](https://github.com/wavekat/wavekat-sip/compare/v0.0.2...v0.0.3) - 2026-05-13

### Added

- add Callee for inbound INVITE accept/reject ([#3](https://github.com/wavekat/wavekat-sip/pull/3))

## [0.0.2](https://github.com/wavekat/wavekat-sip/compare/v0.0.1...v0.0.2) - 2026-05-12

### Other

- flesh out crate-level rustdoc landing page ([#2](https://github.com/wavekat/wavekat-sip/pull/2))
- point homepage at crates.io
