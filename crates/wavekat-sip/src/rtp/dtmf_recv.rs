//! RFC 4733 DTMF (`telephone-event`) reception and decoding — the
//! inverse of [`crate::rtp::dtmf`].
//!
//! A remote digit press arrives as a burst of small RTP packets: three
//! redundant start copies (the first carrying the marker bit), a 20 ms
//! continuation cadence, and three redundant end copies with the `E`
//! bit set. [`DtmfReceiver`] collapses that burst back into at most one
//! [`DtmfEvent::Pressed`] and one [`DtmfEvent::Released`] per press, so
//! consumers reacting to keypad input (IVR-style flows, AI agents) see
//! each digit exactly once.
//!
//! ## Example
//!
//! ```no_run
//! use wavekat_sip::rtp::dtmf_recv::{DtmfEvent, DtmfReceiver};
//!
//! # async fn ex(socket: tokio::net::UdpSocket) -> std::io::Result<()> {
//! // PT from the negotiated SDP — `RemoteMedia::dtmf_payload_type`.
//! let mut dtmf = DtmfReceiver::new(101);
//! let mut buf = [0u8; 2048];
//! loop {
//!     let (len, _from) = socket.recv_from(&mut buf).await?;
//!     match dtmf.push(&buf[..len]) {
//!         Some(DtmfEvent::Pressed { digit }) => {
//!             println!("remote pressed {}", digit.as_char());
//!         }
//!         Some(DtmfEvent::Released { .. }) | None => {
//!             // None covers audio packets too — route them to the
//!             // decoder as usual.
//!         }
//!     }
//! }
//! # }
//! ```

use crate::rtp::dtmf::DtmfDigit;
use crate::rtp::RtpHeader;

/// A parsed 4-byte RFC 4733 event payload — the inverse of
/// [`crate::rtp::dtmf::build_event_payload`].
///
/// Layout (RFC 4733 §2.5.2):
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     event     |E|R| volume    |          duration             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtmfEventPayload {
    /// Event code. 0-15 are the DTMF digits (see
    /// [`DtmfDigit::from_event_code`]); higher codes are other
    /// telephony events (flash-hook, fax tones, …).
    pub event: u8,
    /// `E` (end) flag — set on the final packets of a burst.
    pub end: bool,
    /// Power in dBm0, 0-63 (lower magnitude = louder).
    pub volume: u8,
    /// How long the event has been going so far, in RTP timestamp
    /// ticks at 8 kHz (divide by 8 for milliseconds).
    pub duration_ticks: u16,
}

/// Parse the 4-byte RFC 4733 event payload from `buf`.
///
/// Returns `None` if `buf` is shorter than 4 bytes. Extra trailing
/// bytes are ignored — RFC 4733 permits a packet to report several
/// already-ended events at once, but senders (including this crate's
/// [`crate::rtp::dtmf::send_dtmf_burst`]) put one event per packet in
/// practice, so only the first is decoded.
pub fn parse_event_payload(buf: &[u8]) -> Option<DtmfEventPayload> {
    if buf.len() < 4 {
        return None;
    }
    Some(DtmfEventPayload {
        event: buf[0],
        // Bit 7 = E (end), bit 6 = R (reserved), bits 0-5 = volume.
        end: buf[1] & 0x80 != 0,
        volume: buf[1] & 0x3F,
        duration_ticks: u16::from_be_bytes([buf[2], buf[3]]),
    })
}

/// A decoded change in remote keypad state, produced by
/// [`DtmfReceiver::push`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DtmfEvent {
    /// A new digit press was observed. Emitted exactly once per press,
    /// on the first packet of the burst that arrives — redundant start
    /// copies, continuations, and retransmissions never repeat it.
    Pressed {
        /// The digit being pressed.
        digit: DtmfDigit,
    },
    /// The press ended. Emitted at most once per press, on the first
    /// end (`E=1`) packet that arrives *after* the press was reported.
    /// Best-effort: if every end packet of a burst is lost, the press
    /// stays reported but its release (and duration) is never known.
    Released {
        /// The digit that was released.
        digit: DtmfDigit,
        /// Total press length in RTP timestamp ticks at 8 kHz
        /// (divide by 8 for milliseconds).
        duration_ticks: u16,
    },
}

/// The event currently being tracked. All packets of one RFC 4733
/// event share the event-*start* RTP timestamp (§2.5.1.2), so the
/// `(SSRC, timestamp, event)` triple identifies a press uniquely.
#[derive(Debug, Clone, Copy)]
struct ActiveEvent {
    ssrc: u32,
    timestamp: u32,
    event: u8,
    /// Whether `Released` has already been emitted for this press.
    released: bool,
}

/// Stateful decoder that collapses RFC 4733 packet bursts into one
/// [`DtmfEvent::Pressed`] (and at most one [`DtmfEvent::Released`])
/// per digit press.
///
/// Construct one per call with the negotiated `telephone-event`
/// payload type ([`crate::RemoteMedia::dtmf_payload_type`]) and feed
/// every datagram from the media socket through [`DtmfReceiver::push`]
/// — audio packets, wrong payload types, and non-RTP datagrams all
/// come back as `None`.
///
/// Loss tolerance: the marker packet is not required (any redundant
/// start copy registers the press), lost end packets degrade only the
/// `Released` signal, and out-of-order stragglers from an already-seen
/// or earlier event are dropped by timestamp comparison.
#[derive(Debug)]
pub struct DtmfReceiver {
    payload_type: u8,
    active: Option<ActiveEvent>,
}

impl DtmfReceiver {
    /// Create a receiver that decodes packets whose RTP payload type
    /// equals `payload_type` (typically 101 — take the negotiated
    /// value from [`crate::RemoteMedia::dtmf_payload_type`]).
    pub fn new(payload_type: u8) -> Self {
        Self {
            payload_type,
            active: None,
        }
    }

    /// Feed one inbound RTP datagram (header + payload, as received
    /// off the socket).
    ///
    /// Returns `Some` only on a state change: the first packet of a
    /// new press yields [`DtmfEvent::Pressed`]; the first end packet
    /// of that press yields [`DtmfEvent::Released`]. Everything else —
    /// redundant copies, 20 ms continuations, audio packets, other
    /// payload types, non-digit telephone events, malformed or
    /// out-of-order data — returns `None`.
    pub fn push(&mut self, packet: &[u8]) -> Option<DtmfEvent> {
        let header = RtpHeader::parse(packet)?;
        if header.payload_type != self.payload_type {
            return None;
        }
        let payload = parse_event_payload(packet.get(header.header_len()..)?)?;
        // Codes ≥ 16 are flash-hook / fax events — not keypad digits.
        let digit = DtmfDigit::from_event_code(payload.event)?;

        if let Some(active) = &mut self.active {
            let same_event = active.ssrc == header.ssrc
                && active.timestamp == header.timestamp
                && active.event == payload.event;
            if same_event {
                if payload.end && !active.released {
                    active.released = true;
                    return Some(DtmfEvent::Released {
                        digit,
                        duration_ticks: payload.duration_ticks,
                    });
                }
                // Redundant start copy, continuation, duplicate end,
                // or an out-of-order packet of the same press.
                return None;
            }
            // A different SSRC is a different stream (e.g. after a
            // re-INVITE) — its timeline is unrelated, accept as new.
            // On the *same* SSRC, anything at or before the active
            // event's start timestamp is a straggler from the past.
            if active.ssrc == header.ssrc && !timestamp_newer(header.timestamp, active.timestamp) {
                return None;
            }
            // Newer timestamp on the same SSRC: the next digit. If the
            // previous press never got its end packets they were lost;
            // the press itself was already reported, so just move on.
        }

        self.active = Some(ActiveEvent {
            ssrc: header.ssrc,
            timestamp: header.timestamp,
            event: payload.event,
            released: false,
        });
        Some(DtmfEvent::Pressed { digit })
    }
}

/// `true` iff RTP timestamp `a` is strictly newer than `b` under
/// RFC 3550 wrapping arithmetic (a forward distance below half the
/// u32 range).
fn timestamp_newer(a: u32, b: u32) -> bool {
    let forward = a.wrapping_sub(b);
    forward != 0 && forward < 0x8000_0000
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::dtmf::{
        build_event_payload, build_rtp_dtmf_packet, send_dtmf_burst, DtmfBurstConfig,
    };

    const PT: u8 = 101;
    const SSRC: u32 = 0xDEAD_BEEF;

    #[test]
    fn parse_round_trips_with_build() {
        for code in 0u8..16 {
            for end in [false, true] {
                let built = build_event_payload(code, end, 10, 800);
                let parsed = parse_event_payload(&built).expect("4 bytes parse");
                assert_eq!(parsed.event, code);
                assert_eq!(parsed.end, end);
                assert_eq!(parsed.volume, 10);
                assert_eq!(parsed.duration_ticks, 800);
            }
        }
    }

    #[test]
    fn parse_extracts_volume_and_extreme_durations() {
        let p = parse_event_payload(&build_event_payload(11, true, 63, u16::MAX)).unwrap();
        assert_eq!(p.event, 11);
        assert!(p.end);
        assert_eq!(p.volume, 63);
        assert_eq!(p.duration_ticks, u16::MAX);

        let p = parse_event_payload(&build_event_payload(0, false, 0, 0)).unwrap();
        assert!(!p.end);
        assert_eq!(p.volume, 0);
        assert_eq!(p.duration_ticks, 0);
    }

    #[test]
    fn parse_rejects_short_buffer() {
        assert_eq!(parse_event_payload(&[]), None);
        assert_eq!(parse_event_payload(&[5]), None);
        assert_eq!(parse_event_payload(&[5, 0x0A, 0x00]), None);
    }

    /// Generate the packets of one burst exactly the way
    /// `send_dtmf_burst` does (3 marker'd/redundant starts, growing
    /// continuations, 3 redundant ends) without the wall-clock sleeps.
    fn synth_burst(
        digit: DtmfDigit,
        ssrc: u32,
        start_seq: u16,
        timestamp: u32,
        total_ticks: u16,
    ) -> Vec<[u8; 16]> {
        let event = digit.event_code();
        let mut out = Vec::new();
        let mut seq = start_seq;
        let mut dur = 160u16;
        for i in 0..3 {
            let payload = build_event_payload(event, false, 10, dur);
            out.push(build_rtp_dtmf_packet(
                PT,
                i == 0,
                seq,
                timestamp,
                ssrc,
                payload,
            ));
            seq = seq.wrapping_add(1);
        }
        for _ in 1..total_ticks {
            dur += 160;
            let payload = build_event_payload(event, false, 10, dur);
            out.push(build_rtp_dtmf_packet(
                PT, false, seq, timestamp, ssrc, payload,
            ));
            seq = seq.wrapping_add(1);
        }
        for _ in 0..3 {
            let payload = build_event_payload(event, true, 10, dur);
            out.push(build_rtp_dtmf_packet(
                PT, false, seq, timestamp, ssrc, payload,
            ));
            seq = seq.wrapping_add(1);
        }
        out
    }

    /// Feed packets and collect every emitted event.
    fn feed(rx: &mut DtmfReceiver, packets: &[[u8; 16]]) -> Vec<DtmfEvent> {
        packets.iter().filter_map(|p| rx.push(p)).collect()
    }

    #[test]
    fn full_burst_emits_one_press_and_one_release() {
        // 5 ticks = 100 ms press: 3 + 4 + 3 = 10 packets in, 2 events out.
        let mut rx = DtmfReceiver::new(PT);
        let events = feed(&mut rx, &synth_burst(DtmfDigit::D5, SSRC, 100, 5000, 5));
        assert_eq!(
            events,
            vec![
                DtmfEvent::Pressed {
                    digit: DtmfDigit::D5
                },
                DtmfEvent::Released {
                    digit: DtmfDigit::D5,
                    duration_ticks: 800,
                },
            ]
        );
    }

    #[test]
    fn redundant_start_copies_do_not_repeat_the_press() {
        // Only the three redundant start packets — no continuations or
        // ends yet. Exactly one Pressed.
        let mut rx = DtmfReceiver::new(PT);
        let burst = synth_burst(DtmfDigit::Star, SSRC, 0, 0, 5);
        let events = feed(&mut rx, &burst[..3]);
        assert_eq!(
            events,
            vec![DtmfEvent::Pressed {
                digit: DtmfDigit::Star
            }]
        );
    }

    #[test]
    fn lost_marker_packet_still_registers_the_press() {
        // Drop packet 0 (the only one carrying the marker bit); the
        // redundant copies carry the same (ssrc, ts, event) key.
        let mut rx = DtmfReceiver::new(PT);
        let burst = synth_burst(DtmfDigit::D7, SSRC, 100, 5000, 5);
        let events = feed(&mut rx, &burst[1..]);
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0],
            DtmfEvent::Pressed {
                digit: DtmfDigit::D7
            }
        );
    }

    #[test]
    fn lost_end_packets_then_next_digit_emits_both_presses() {
        // All three end packets of the first burst are lost; the next
        // digit's start (chained timestamp) must still come through,
        // and the first press must not be re-emitted or "stuck".
        let mut rx = DtmfReceiver::new(PT);
        let mut burst1 = synth_burst(DtmfDigit::D1, SSRC, 0, 0, 5);
        burst1.truncate(burst1.len() - 3); // drop the E=1 trio
        let burst2 = synth_burst(DtmfDigit::D2, SSRC, 7, 800, 5);

        let mut events = feed(&mut rx, &burst1);
        events.extend(feed(&mut rx, &burst2));
        assert_eq!(
            events,
            vec![
                DtmfEvent::Pressed {
                    digit: DtmfDigit::D1
                },
                DtmfEvent::Pressed {
                    digit: DtmfDigit::D2
                },
                DtmfEvent::Released {
                    digit: DtmfDigit::D2,
                    duration_ticks: 800,
                },
            ]
        );
    }

    #[test]
    fn interleaved_audio_packets_are_ignored() {
        let mut rx = DtmfReceiver::new(PT);
        let burst = synth_burst(DtmfDigit::Pound, SSRC, 0, 0, 2);

        // A PCMU (PT=0) audio packet on the same socket.
        let mut audio = vec![0u8; 12 + 160];
        audio[0] = 0x80;
        audio[1] = 0; // PT 0 = PCMU
        audio[8..12].copy_from_slice(&0xAAAA_AAAAu32.to_be_bytes());

        let mut events = Vec::new();
        for (i, pkt) in burst.iter().enumerate() {
            events.extend(rx.push(pkt));
            if i % 2 == 0 {
                assert_eq!(rx.push(&audio), None, "audio must not decode");
            }
        }
        assert_eq!(events.len(), 2, "one press + one release despite audio");
    }

    #[test]
    fn wrong_payload_type_is_ignored() {
        // A well-formed telephone-event burst on PT 96 must not decode
        // when the negotiated PT is 101.
        let mut rx = DtmfReceiver::new(PT);
        let event = build_event_payload(5, false, 10, 160);
        let pkt = build_rtp_dtmf_packet(96, true, 0, 0, SSRC, event);
        assert_eq!(rx.push(&pkt), None);
    }

    #[test]
    fn non_digit_event_codes_are_ignored() {
        // Event 16 = flash-hook: valid RFC 4733, not a DTMF digit.
        let mut rx = DtmfReceiver::new(PT);
        let event = build_event_payload(16, false, 10, 160);
        let pkt = build_rtp_dtmf_packet(PT, true, 0, 0, SSRC, event);
        assert_eq!(rx.push(&pkt), None);
    }

    #[test]
    fn malformed_packets_are_ignored() {
        let mut rx = DtmfReceiver::new(PT);
        assert_eq!(rx.push(&[]), None);
        assert_eq!(rx.push(&[0u8; 11]), None, "short of an RTP header");
        // Valid header, truncated event payload (2 of 4 bytes).
        let full = build_rtp_dtmf_packet(PT, true, 0, 0, SSRC, [5, 0x0A, 0, 160]);
        assert_eq!(rx.push(&full[..14]), None);
    }

    #[test]
    fn two_back_to_back_digits_emit_two_presses() {
        // "5" then "7" with chained seq/timestamp, exactly as two
        // send_dtmf_burst calls produce them.
        let mut rx = DtmfReceiver::new(PT);
        let burst1 = synth_burst(DtmfDigit::D5, SSRC, 0, 0, 2); // 2 ticks → next ts 320
        let burst2 = synth_burst(DtmfDigit::D7, SSRC, 7, 320, 2);

        let mut events = feed(&mut rx, &burst1);
        events.extend(feed(&mut rx, &burst2));
        assert_eq!(
            events,
            vec![
                DtmfEvent::Pressed {
                    digit: DtmfDigit::D5
                },
                DtmfEvent::Released {
                    digit: DtmfDigit::D5,
                    duration_ticks: 320,
                },
                DtmfEvent::Pressed {
                    digit: DtmfDigit::D7
                },
                DtmfEvent::Released {
                    digit: DtmfDigit::D7,
                    duration_ticks: 320,
                },
            ]
        );
    }

    #[test]
    fn out_of_order_straggler_from_previous_event_is_dropped() {
        let mut rx = DtmfReceiver::new(PT);
        let burst1 = synth_burst(DtmfDigit::D5, SSRC, 0, 0, 2);
        let burst2 = synth_burst(DtmfDigit::D7, SSRC, 7, 320, 2);

        assert_eq!(feed(&mut rx, &burst1).len(), 2);
        // Second digit starts...
        assert_eq!(
            rx.push(&burst2[0]),
            Some(DtmfEvent::Pressed {
                digit: DtmfDigit::D7
            })
        );
        // ...then a late duplicate end of the *first* digit arrives.
        let straggler = burst1.last().unwrap();
        assert_eq!(rx.push(straggler), None, "straggler must not re-press 5");
        // The second digit's own end still comes through.
        let events = feed(&mut rx, &burst2[1..]);
        assert_eq!(
            events,
            vec![DtmfEvent::Released {
                digit: DtmfDigit::D7,
                duration_ticks: 320,
            }]
        );
    }

    #[test]
    fn ssrc_change_starts_a_fresh_stream() {
        // After a re-INVITE the remote may pick a new SSRC with an
        // unrelated (possibly "older") timestamp; that must not be
        // mistaken for a straggler.
        let mut rx = DtmfReceiver::new(PT);
        assert_eq!(
            feed(&mut rx, &synth_burst(DtmfDigit::D9, SSRC, 0, 90_000, 2)).len(),
            2
        );
        let events = feed(&mut rx, &synth_burst(DtmfDigit::D3, 0x1234_5678, 0, 100, 2));
        assert_eq!(
            events[0],
            DtmfEvent::Pressed {
                digit: DtmfDigit::D3
            }
        );
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn first_seen_end_packet_still_reports_the_press() {
        // Every start and continuation packet lost — only the end trio
        // arrives. The press is the actionable signal, so the first
        // end packet reports Pressed and a redundant copy completes it
        // with Released.
        let mut rx = DtmfReceiver::new(PT);
        let burst = synth_burst(DtmfDigit::D8, SSRC, 0, 0, 5);
        let ends = &burst[burst.len() - 3..];
        let events = feed(&mut rx, ends);
        assert_eq!(
            events,
            vec![
                DtmfEvent::Pressed {
                    digit: DtmfDigit::D8
                },
                DtmfEvent::Released {
                    digit: DtmfDigit::D8,
                    duration_ticks: 800,
                },
            ]
        );
    }

    #[test]
    fn timestamp_newer_handles_wraparound() {
        assert!(timestamp_newer(1, 0));
        assert!(!timestamp_newer(0, 1));
        assert!(!timestamp_newer(5, 5));
        // Wrap: 100 is newer than (u32::MAX - 100).
        assert!(timestamp_newer(100, u32::MAX - 100));
        assert!(!timestamp_newer(u32::MAX - 100, 100));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn round_trips_with_send_dtmf_burst_over_loopback() {
        // The real send path over a loopback socket: capture all 10
        // packets of a 100 ms "5" press and feed them to the receiver.
        use std::sync::Arc;
        use tokio::net::UdpSocket;

        let sender = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = receiver.local_addr().unwrap();

        let cfg = DtmfBurstConfig {
            payload_type: PT,
            ssrc: SSRC,
            initial_seq: 100,
            initial_timestamp: 5000,
            hold_duration_ms: 100, // 5 ticks → 10 packets
            volume_dbm0: 10,
        };
        let send = tokio::spawn(send_dtmf_burst(sender, remote, cfg, DtmfDigit::D5));

        let mut rx = DtmfReceiver::new(PT);
        let mut events = Vec::new();
        let mut buf = [0u8; 64];
        for _ in 0..10 {
            let (n, _) = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                receiver.recv_from(&mut buf),
            )
            .await
            .expect("packet arrived in time")
            .expect("recv ok");
            events.extend(rx.push(&buf[..n]));
        }
        send.await.unwrap().unwrap();

        assert_eq!(
            events,
            vec![
                DtmfEvent::Pressed {
                    digit: DtmfDigit::D5
                },
                DtmfEvent::Released {
                    digit: DtmfDigit::D5,
                    duration_ticks: 800, // 100 ms at 8 kHz
                },
            ]
        );
    }
}
