//! RFC 4733 DTMF (`telephone-event`) packet construction and transmission.
//!
//! A DTMF "press" rides RTP as a sequence of small (4-byte payload)
//! event packets. The first three carry the marker bit and a short
//! initial duration; continuation packets follow every 20 ms with a
//! growing duration field; three end packets with the `E` bit set
//! close out the burst. The three-fold redundancy at the start and end
//! protects against single-packet loss; without it, a dropped marker
//! could silently swallow the digit, and a dropped end could leave it
//! "stuck on" at the receiver.
//!
//! ## Why a separate SSRC
//!
//! RFC 4733 §2.6.2 explicitly allows telephone-event to ride either
//! the audio SSRC (interleaved) or its own SSRC (a separate RTP
//! stream). We pick the latter: it lets DTMF be sent without
//! coordinating the sequence-number / timestamp counter with the
//! audio send loop, keeps both code paths simple, and is what the
//! receiver demuxes by payload type anyway. Pick a fresh random SSRC
//! per call and keep it stable for that call's lifetime.
//!
//! ## Example
//!
//! ```no_run
//! use std::net::SocketAddr;
//! use std::sync::Arc;
//! use tokio::net::UdpSocket;
//! use wavekat_sip::rtp::dtmf::{send_dtmf_burst, DtmfBurstConfig, DtmfDigit};
//!
//! # async fn ex(socket: Arc<UdpSocket>, remote: SocketAddr) -> std::io::Result<()> {
//! let mut seq = 1_000u16;
//! let mut ts = 0_u32;
//! let cfg = DtmfBurstConfig {
//!     payload_type: 101,
//!     ssrc: 0xDEAD_BEEF,
//!     initial_seq: seq,
//!     initial_timestamp: ts,
//!     hold_duration_ms: 160,
//!     volume_dbm0: 10,
//! };
//! let (next_seq, next_ts) =
//!     send_dtmf_burst(socket, remote, cfg, DtmfDigit::D5).await?;
//! seq = next_seq;
//! ts = next_ts;
//! # Ok(())
//! # }
//! ```
//!
//! [`send_dtmf_burst`] is `async` and `await`s ~20 ms between
//! continuation packets, so a press of `hold_duration_ms = 160`
//! takes roughly 160 ms wall-clock to complete.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};
use tracing::debug;

/// Default volume (dBm0) advertised in each event packet.
///
/// 10 dBm0 is the recommended fall-back per RFC 4733 §2.5.2.3 and the
/// value every major softphone defaults to. The valid range is 0-63
/// (each unit is one dB below the reference; higher = quieter).
pub const DEFAULT_VOLUME_DBM0: u8 = 10;

/// 20 ms at an 8 kHz clock = 160 sample ticks. The RTP timestamp clock
/// for `telephone-event/8000` is 8 kHz regardless of the audio codec.
const TICKS_PER_PACKET: u16 = 160;

/// Inter-packet gap for continuation packets.
const PACKET_INTERVAL: Duration = Duration::from_millis(20);

/// Recommended number of duplicate copies for the first and last
/// packets of a burst (RFC 4733 §2.5.1.4 — redundancy against single
/// packet loss).
const REDUNDANCY: u8 = 3;

/// A single DTMF digit per RFC 4733 §2.5.2.1 event codes 0-15.
///
/// `D0`-`D9`, `Star`, `Pound`, `A`-`D`. The letter variants are vestigial
/// (US AUTOVON keypad) and almost never appear in practice; consumers
/// should typically only expose the digits and `* #` in their UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DtmfDigit {
    D0,
    D1,
    D2,
    D3,
    D4,
    D5,
    D6,
    D7,
    D8,
    D9,
    Star,
    Pound,
    A,
    B,
    C,
    D,
}

impl DtmfDigit {
    /// Parse a digit from one of `0`-`9`, `*`, `#`, or `A`-`D`
    /// (case-insensitive for the letters). Returns `None` for anything
    /// else, including whitespace.
    pub fn from_char(c: char) -> Option<Self> {
        Some(match c {
            '0' => Self::D0,
            '1' => Self::D1,
            '2' => Self::D2,
            '3' => Self::D3,
            '4' => Self::D4,
            '5' => Self::D5,
            '6' => Self::D6,
            '7' => Self::D7,
            '8' => Self::D8,
            '9' => Self::D9,
            '*' => Self::Star,
            '#' => Self::Pound,
            'a' | 'A' => Self::A,
            'b' | 'B' => Self::B,
            'c' | 'C' => Self::C,
            'd' | 'D' => Self::D,
            _ => return None,
        })
    }

    /// The canonical character for this digit, e.g. `5` for `D5`,
    /// `*` for `Star`, `A` (uppercase) for `A`.
    pub fn as_char(self) -> char {
        match self {
            Self::D0 => '0',
            Self::D1 => '1',
            Self::D2 => '2',
            Self::D3 => '3',
            Self::D4 => '4',
            Self::D5 => '5',
            Self::D6 => '6',
            Self::D7 => '7',
            Self::D8 => '8',
            Self::D9 => '9',
            Self::Star => '*',
            Self::Pound => '#',
            Self::A => 'A',
            Self::B => 'B',
            Self::C => 'C',
            Self::D => 'D',
        }
    }

    /// The RFC 4733 §2.5.2.1 event code (0-15) for this digit.
    pub fn event_code(self) -> u8 {
        match self {
            Self::D0 => 0,
            Self::D1 => 1,
            Self::D2 => 2,
            Self::D3 => 3,
            Self::D4 => 4,
            Self::D5 => 5,
            Self::D6 => 6,
            Self::D7 => 7,
            Self::D8 => 8,
            Self::D9 => 9,
            Self::Star => 10,
            Self::Pound => 11,
            Self::A => 12,
            Self::B => 13,
            Self::C => 14,
            Self::D => 15,
        }
    }
}

/// Build the 4-byte RFC 4733 event payload.
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
///
/// - `event`: digit code 0-15 (see [`DtmfDigit::event_code`]).
/// - `E`: end-of-event flag (set on the last packet of a burst).
/// - `R`: reserved (always 0).
/// - `volume`: power in dBm0 (0-63, lower magnitude = louder; see
///   [`DEFAULT_VOLUME_DBM0`]). Clamped to 6 bits.
/// - `duration`: how long the event has been going so far, in RTP
///   timestamp ticks (8 kHz). Grows across continuation packets.
pub fn build_event_payload(event: u8, end: bool, volume: u8, duration_ticks: u16) -> [u8; 4] {
    let mut out = [0u8; 4];
    out[0] = event;
    // Bit 7 = E (end), bit 6 = R (reserved/0), bits 0-5 = volume.
    let end_bit = if end { 0x80 } else { 0x00 };
    out[1] = end_bit | (volume & 0x3F);
    let dur = duration_ticks.to_be_bytes();
    out[2] = dur[0];
    out[3] = dur[1];
    out
}

/// Settings for a single DTMF burst.
///
/// Each press of one digit is one burst. For multi-digit dialing,
/// pace the calls to [`send_dtmf_burst`] yourself — typically with an
/// inter-digit gap of ≥50 ms so the receiver can demarcate them.
#[derive(Debug, Clone, Copy)]
pub struct DtmfBurstConfig {
    /// Negotiated `telephone-event` payload type — typically 101. Get
    /// this from [`crate::RemoteMedia::dtmf_payload_type`]; if it's
    /// `None`, the remote didn't agree to RFC 4733 and DTMF must be
    /// sent via SIP INFO instead.
    pub payload_type: u8,
    /// SSRC for the DTMF stream. Pick a fresh random value per call
    /// (distinct from the audio stream's SSRC, per the module docs).
    pub ssrc: u32,
    /// RTP sequence number for the first packet of this burst. The
    /// returned `(next_seq, _)` tuple is the seq to pass on the next
    /// burst — keep the counter monotonic for the lifetime of the
    /// SSRC, per RFC 3550.
    pub initial_seq: u16,
    /// RTP timestamp for the *start* of the event. All packets in
    /// this burst share this value (RFC 4733 §2.5.1.2 — the start
    /// time of the event being marked, not the time of the packet).
    /// Pass the previous burst's returned `next_ts` for back-to-back
    /// digits — that step keeps the timeline monotonic without
    /// running a clock between presses.
    pub initial_timestamp: u32,
    /// How long to hold the digit, in milliseconds. Typical: 100-200.
    /// The actual on-wire duration field uses 8 kHz ticks; this is
    /// rounded to the nearest whole packet (`PACKET_INTERVAL` = 20 ms).
    pub hold_duration_ms: u32,
    /// Volume in dBm0 (0-63). See [`DEFAULT_VOLUME_DBM0`].
    pub volume_dbm0: u8,
}

/// Build the full RTP packet (12-byte header + 4-byte event payload).
///
/// Exposed for tests and for consumers that want to send DTMF via a
/// transport other than [`send_dtmf_burst`] (for example, batching
/// packets onto a shared send loop).
pub fn build_rtp_dtmf_packet(
    payload_type: u8,
    marker: bool,
    seq: u16,
    timestamp: u32,
    ssrc: u32,
    event_payload: [u8; 4],
) -> [u8; 16] {
    let mut pkt = [0u8; 16];
    // V=2, no padding, no extension, CSRC count = 0.
    pkt[0] = 0x80;
    // Marker bit + payload type.
    let marker_bit = if marker { 0x80 } else { 0x00 };
    pkt[1] = marker_bit | (payload_type & 0x7F);
    pkt[2..4].copy_from_slice(&seq.to_be_bytes());
    pkt[4..8].copy_from_slice(&timestamp.to_be_bytes());
    pkt[8..12].copy_from_slice(&ssrc.to_be_bytes());
    pkt[12..16].copy_from_slice(&event_payload);
    pkt
}

/// Send one digit as a burst of RFC 4733 event packets on the given
/// socket, addressed to `remote`. Returns `(next_seq, next_timestamp)`
/// — the values to thread into the next burst on the same SSRC.
///
/// `next_timestamp` is `initial_timestamp + final_duration_ticks`, so
/// chaining bursts produces a monotonically increasing RTP timeline
/// even when there's no audio on the same SSRC to fill the gaps.
///
/// Network policy: this function `await`s a UDP send per packet plus
/// `sleep`s `PACKET_INTERVAL` between continuation packets. A digit
/// with `hold_duration_ms = 160` therefore takes ≈ 160 ms wall-clock
/// to finish. Cancel by dropping the returned future or by aborting
/// the surrounding task — partial bursts are valid RTP (the receiver
/// will see the missing end as packet loss and stop the tone).
pub async fn send_dtmf_burst(
    socket: Arc<UdpSocket>,
    remote: SocketAddr,
    config: DtmfBurstConfig,
    digit: DtmfDigit,
) -> Result<(u16, u32), std::io::Error> {
    let event = digit.event_code();
    let volume = config.volume_dbm0.min(0x3F);

    debug!(
        "DTMF burst '{}' → {remote} (PT={}, SSRC=0x{:08X}, hold={}ms)",
        digit.as_char(),
        config.payload_type,
        config.ssrc,
        config.hold_duration_ms,
    );

    // Total packets in the press: at least the 3 initial + 3 end.
    // Continuation packets fill in the middle every 20 ms.
    let total_packets = config.hold_duration_ms.div_ceil(20).max(1) as u16;
    let total_duration_ticks = total_packets.saturating_mul(TICKS_PER_PACKET);

    let mut seq = config.initial_seq;
    let mut current_duration = TICKS_PER_PACKET;

    // Marker bit + first three copies — `E=0`, duration = one tick.
    // All three share the marker'd timestamp; the receiver de-dupes by
    // seq/duration but treats the first arrival as the start of the
    // event.
    for i in 0..REDUNDANCY {
        let payload = build_event_payload(event, false, volume, current_duration);
        let marker = i == 0;
        let pkt = build_rtp_dtmf_packet(
            config.payload_type,
            marker,
            seq,
            config.initial_timestamp,
            config.ssrc,
            payload,
        );
        socket.send_to(&pkt, remote).await?;
        seq = seq.wrapping_add(1);
    }

    // Continuation packets — one per 20 ms tick, growing duration.
    // `total_packets - 1` because the initial trio already covered the
    // first tick.
    for _ in 1..total_packets {
        sleep(PACKET_INTERVAL).await;
        current_duration = current_duration.saturating_add(TICKS_PER_PACKET);
        let payload = build_event_payload(event, false, volume, current_duration);
        let pkt = build_rtp_dtmf_packet(
            config.payload_type,
            false,
            seq,
            config.initial_timestamp,
            config.ssrc,
            payload,
        );
        socket.send_to(&pkt, remote).await?;
        seq = seq.wrapping_add(1);
    }

    // Three end packets — `E=1`, final duration. Sent back-to-back at
    // this tick boundary; no sleep between them.
    for _ in 0..REDUNDANCY {
        let payload = build_event_payload(event, true, volume, current_duration);
        let pkt = build_rtp_dtmf_packet(
            config.payload_type,
            false,
            seq,
            config.initial_timestamp,
            config.ssrc,
            payload,
        );
        socket.send_to(&pkt, remote).await?;
        seq = seq.wrapping_add(1);
    }

    let next_timestamp = config
        .initial_timestamp
        .wrapping_add(total_duration_ticks as u32);
    Ok((seq, next_timestamp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digit_from_char_round_trips() {
        for d in [
            DtmfDigit::D0,
            DtmfDigit::D1,
            DtmfDigit::D2,
            DtmfDigit::D3,
            DtmfDigit::D4,
            DtmfDigit::D5,
            DtmfDigit::D6,
            DtmfDigit::D7,
            DtmfDigit::D8,
            DtmfDigit::D9,
            DtmfDigit::Star,
            DtmfDigit::Pound,
            DtmfDigit::A,
            DtmfDigit::B,
            DtmfDigit::C,
            DtmfDigit::D,
        ] {
            assert_eq!(DtmfDigit::from_char(d.as_char()), Some(d), "digit {d:?}");
        }
    }

    #[test]
    fn digit_event_codes_match_rfc_4733() {
        // Spot-check the spec assignments — these are wire-visible and a
        // typo would scramble every IVR's "you pressed 7" response.
        assert_eq!(DtmfDigit::D0.event_code(), 0);
        assert_eq!(DtmfDigit::D9.event_code(), 9);
        assert_eq!(DtmfDigit::Star.event_code(), 10);
        assert_eq!(DtmfDigit::Pound.event_code(), 11);
        assert_eq!(DtmfDigit::A.event_code(), 12);
        assert_eq!(DtmfDigit::D.event_code(), 15);
    }

    #[test]
    fn digit_from_char_rejects_non_dtmf() {
        for c in [' ', 'e', 'E', '+', '-', '\n'] {
            assert_eq!(DtmfDigit::from_char(c), None, "should reject {c:?}");
        }
    }

    #[test]
    fn digit_from_char_accepts_letters_case_insensitive() {
        assert_eq!(DtmfDigit::from_char('a'), Some(DtmfDigit::A));
        assert_eq!(DtmfDigit::from_char('A'), Some(DtmfDigit::A));
        assert_eq!(DtmfDigit::from_char('d'), Some(DtmfDigit::D));
        assert_eq!(DtmfDigit::from_char('D'), Some(DtmfDigit::D));
    }

    #[test]
    fn event_payload_byte_layout() {
        // event=5, E=0, volume=10, duration=160 — typical first packet
        // of pressing "5".
        let p = build_event_payload(5, false, 10, 160);
        assert_eq!(p[0], 5);
        // 0x0A = 10; E and R both 0.
        assert_eq!(p[1], 0x0A);
        assert_eq!(p[2..4], 160u16.to_be_bytes());

        // E bit set on the last packet of a burst.
        let end = build_event_payload(5, true, 10, 1280);
        // E bit (0x80) plus volume 10.
        assert_eq!(end[1], 0x8A);
        assert_eq!(end[2..4], 1280u16.to_be_bytes());
    }

    #[test]
    fn event_payload_clamps_volume_to_6_bits() {
        // A consumer passing volume=100 (out of the 0-63 range) must not
        // bleed into the E or R bits — the volume field is 6 bits.
        let p = build_event_payload(5, false, 0xFF, 160);
        // Top two bits must be zero (E=0, R=0); bottom six = volume.
        assert_eq!(p[1] & 0xC0, 0x00);
        assert_eq!(p[1] & 0x3F, 0x3F);
    }

    #[test]
    fn rtp_dtmf_packet_header_shape() {
        // Single packet build: V=2, marker set, PT=101, seq/ts/ssrc as
        // given, event payload appended verbatim.
        let event = build_event_payload(5, false, 10, 160);
        let pkt = build_rtp_dtmf_packet(101, true, 1000, 12345, 0xCAFE_BABE, event);

        assert_eq!(pkt[0], 0x80); // V=2, P=0, X=0, CC=0
        assert_eq!(pkt[1], 0x80 | 101); // marker | PT 101
        assert_eq!(&pkt[2..4], &1000u16.to_be_bytes());
        assert_eq!(&pkt[4..8], &12345u32.to_be_bytes());
        assert_eq!(&pkt[8..12], &0xCAFE_BABEu32.to_be_bytes());
        assert_eq!(&pkt[12..16], &event);
    }

    /// Bind a pair of UDP sockets on loopback. Returns (sender, receiver).
    async fn loopback_pair() -> (Arc<UdpSocket>, UdpSocket) {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        (Arc::new(a), b)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn burst_packet_count_and_durations() {
        // A 100 ms press at 20 ms per tick is 5 ticks. With 3 initial
        // duplicates and 3 end duplicates we expect:
        //   3 (initial, dur=160)
        // + 4 (continuation, dur=320, 480, 640, 800)
        // + 3 (end, dur=800, E=1)
        // = 10 packets. The continuation count is `total_packets - 1`
        // because the initial trio already covered the first tick.
        let (sender, receiver) = loopback_pair().await;
        let remote = receiver.local_addr().unwrap();

        let cfg = DtmfBurstConfig {
            payload_type: 101,
            ssrc: 0xDEAD_BEEF,
            initial_seq: 100,
            initial_timestamp: 5000,
            hold_duration_ms: 100,
            volume_dbm0: 10,
        };

        let handle = tokio::spawn(send_dtmf_burst(sender, remote, cfg, DtmfDigit::D5));

        let mut buf = [0u8; 64];
        let mut packets: Vec<[u8; 4]> = Vec::new();
        let mut markers: Vec<bool> = Vec::new();
        let mut seqs: Vec<u16> = Vec::new();
        for _ in 0..10 {
            let (n, _) =
                tokio::time::timeout(Duration::from_millis(500), receiver.recv_from(&mut buf))
                    .await
                    .expect("packet arrived in time")
                    .expect("recv ok");
            assert_eq!(n, 16, "DTMF packets are 12 + 4 bytes");
            markers.push(buf[1] & 0x80 != 0);
            seqs.push(u16::from_be_bytes([buf[2], buf[3]]));
            let mut payload = [0u8; 4];
            payload.copy_from_slice(&buf[12..16]);
            packets.push(payload);
        }

        let (next_seq, next_ts) = handle.await.unwrap().unwrap();
        assert_eq!(next_seq, 100 + 10);
        // 5 ticks × 160 = 800
        assert_eq!(next_ts, 5000 + 800);

        // Sequence numbers strictly increasing by 1 from initial_seq.
        for (i, s) in seqs.iter().enumerate() {
            assert_eq!(*s, 100 + i as u16, "packet {i}");
        }

        // First packet has marker; nothing else does. (Per RFC 4733
        // §2.5.1.1 the marker rides only on the first packet of the
        // talkspurt.)
        assert!(markers[0], "marker on first packet");
        for (i, m) in markers.iter().enumerate().skip(1) {
            assert!(!m, "no marker on packet {i}");
        }

        // Each payload's first byte = event code 5.
        for p in &packets {
            assert_eq!(p[0], 5);
        }

        // Initial three: E=0, dur=160.
        for p in &packets[0..3] {
            assert_eq!(p[1] & 0x80, 0, "E bit clear on initial");
            assert_eq!(u16::from_be_bytes([p[2], p[3]]), 160);
        }

        // Continuation 4 packets: E=0, dur grows 320, 480, 640, 800.
        let expected_durations = [320u16, 480, 640, 800];
        for (p, &dur) in packets[3..7].iter().zip(expected_durations.iter()) {
            assert_eq!(p[1] & 0x80, 0, "E bit clear on continuation");
            assert_eq!(u16::from_be_bytes([p[2], p[3]]), dur);
        }

        // End three: E=1, dur=800 (the final tick).
        for p in &packets[7..10] {
            assert_eq!(p[1] & 0x80, 0x80, "E bit set on end packet");
            assert_eq!(u16::from_be_bytes([p[2], p[3]]), 800);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn chained_bursts_keep_timestamp_monotonic() {
        // Pressing "5" then "7" back-to-back must produce a continuous
        // RTP timeline on the same SSRC, with the second burst's
        // timestamps starting where the first left off.
        let (sender, receiver) = loopback_pair().await;
        let remote = receiver.local_addr().unwrap();

        let cfg1 = DtmfBurstConfig {
            payload_type: 101,
            ssrc: 0xCAFE_F00D,
            initial_seq: 0,
            initial_timestamp: 0,
            hold_duration_ms: 40, // 2 ticks → 3 init + 1 cont + 3 end = 7 packets
            volume_dbm0: 10,
        };

        let receiver_task = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            let mut count = 0;
            while count < 14 {
                let (_n, _) =
                    tokio::time::timeout(Duration::from_millis(500), receiver.recv_from(&mut buf))
                        .await
                        .unwrap()
                        .unwrap();
                count += 1;
            }
        });

        let (s1, t1) = send_dtmf_burst(sender.clone(), remote, cfg1, DtmfDigit::D5)
            .await
            .unwrap();
        // 7 packets, 2 ticks × 160 = 320.
        assert_eq!(s1, 7);
        assert_eq!(t1, 320);

        let cfg2 = DtmfBurstConfig {
            initial_seq: s1,
            initial_timestamp: t1,
            ..cfg1
        };
        let (s2, t2) = send_dtmf_burst(sender, remote, cfg2, DtmfDigit::D7)
            .await
            .unwrap();
        assert_eq!(s2, 14);
        assert_eq!(t2, 640);

        receiver_task.await.unwrap();
    }
}
