# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
