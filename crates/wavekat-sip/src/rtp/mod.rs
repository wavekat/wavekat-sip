//! RTP header parsing, a debug receive loop, a codec-agnostic send loop,
//! and RFC 4733 DTMF (`telephone-event`) in both directions.
//!
//! This module intentionally stops at the wire: it parses RTP headers
//! (RFC 3550), exposes a debug-friendly receive loop, packetizes
//! caller-supplied payloads onto the wire via [`send_loop`], ships
//! DTMF bursts via [`dtmf::send_dtmf_burst`], and decodes inbound
//! digit presses via [`dtmf_recv::DtmfReceiver`]. Decoding audio
//! payloads (G.711, Opus, …), jitter buffering, audio device routing,
//! and pacing are consumer-layer concerns and live outside this crate.

pub mod dtmf;
pub mod dtmf_recv;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Parsed RTP packet header (RFC 3550, 12 bytes minimum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpHeader {
    pub version: u8,
    pub padding: bool,
    pub extension: bool,
    pub csrc_count: u8,
    pub marker: bool,
    pub payload_type: u8,
    pub sequence: u16,
    pub timestamp: u32,
    pub ssrc: u32,
}

impl RtpHeader {
    /// Parse an RTP header from a buffer. Returns `None` if the buffer is
    /// too short or the version field is not 2.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }

        let version = (buf[0] >> 6) & 0x03;
        if version != 2 {
            return None;
        }

        let padding = (buf[0] >> 5) & 0x01 != 0;
        let extension = (buf[0] >> 4) & 0x01 != 0;
        let csrc_count = buf[0] & 0x0F;
        let marker = (buf[1] >> 7) & 0x01 != 0;
        let payload_type = buf[1] & 0x7F;
        let sequence = u16::from_be_bytes([buf[2], buf[3]]);
        let timestamp = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

        Some(Self {
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            sequence,
            timestamp,
            ssrc,
        })
    }

    /// Total header length in bytes (12 + 4 * CSRC count).
    pub fn header_len(&self) -> usize {
        12 + 4 * self.csrc_count as usize
    }
}

/// Human-friendly name for a static RTP payload type.
fn payload_type_name(pt: u8) -> &'static str {
    match pt {
        0 => "PCMU",
        8 => "PCMA",
        _ => "unknown",
    }
}

/// Receive RTP packets on the given socket and trace their headers until
/// cancelled. Useful for smoke-testing inbound media without wiring up an
/// audio path.
pub async fn receive_rtp(socket: UdpSocket, cancel: CancellationToken) {
    let mut buf = [0u8; 2048];
    let mut count = 0u64;

    let local = socket
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "<unknown>".into());
    info!("RTP receiver started on {local}");

    loop {
        select! {
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, from)) => {
                        if let Some(header) = RtpHeader::parse(&buf[..len]) {
                            count += 1;
                            let payload_len = len.saturating_sub(header.header_len());
                            debug!(
                                "RTP #{} | PT={} ({}) | TS={} | SSRC=0x{:08X} | {} bytes from {}",
                                header.sequence,
                                header.payload_type,
                                payload_type_name(header.payload_type),
                                header.timestamp,
                                header.ssrc,
                                payload_len,
                                from,
                            );

                            if count.is_multiple_of(100) {
                                info!("Received {count} RTP packets so far");
                            }
                        } else {
                            warn!("Non-RTP packet ({len} bytes) from {from}");
                        }
                    }
                    Err(e) => {
                        warn!("RTP recv error: {e}");
                        break;
                    }
                }
            }
            _ = cancel.cancelled() => break,
        }
    }

    info!("RTP receiver stopped. Total packets: {count}");
}

/// Initial RTP state when starting a `send_loop`. Hold it across calls
/// only if you intend to resume a stream — for a fresh call, pick a new
/// `ssrc` and fresh `seq` / `timestamp` (random per RFC 3550 §5.1).
#[derive(Debug, Clone, Copy)]
pub struct RtpSendConfig {
    /// Static RTP payload type — 0 for PCMU, 8 for PCMA, etc.
    pub payload_type: u8,
    /// Synchronization source. One per call; pick fresh randomness so
    /// the remote can distinguish streams that re-use the same 5-tuple.
    pub ssrc: u32,
    /// Initial RTP sequence number. Wraps at u16 by spec.
    pub initial_seq: u16,
    /// Initial RTP timestamp. The clock domain is the *codec's* sample
    /// rate — 8000 Hz for G.711 — not the audio device rate.
    pub initial_timestamp: u32,
    /// Amount to advance the RTP timestamp per packet. For 20 ms G.711
    /// frames that's 160 (= 8 kHz × 20 ms).
    pub samples_per_frame: u32,
}

/// Forward pre-encoded payloads out as RTP packets.
///
/// Each payload received on `payloads` becomes one RTP packet sent to
/// `remote`. Sequence and timestamp counters advance by 1 and
/// `samples_per_frame` respectively per packet; SSRC and payload type
/// stay fixed for the lifetime of the loop.
///
/// **Pacing is the caller's job.** This loop sends as soon as a payload
/// arrives; if the consumer pushes 20 ms G.711 frames as fast as it can
/// encode them, the remote will hear chipmunk audio. Push at the
/// codec's packetization cadence (a `tokio::time::interval` ticking the
/// encoder is the usual shape).
///
/// `socket` is `Arc`-shared so the receive side can keep using the same
/// bound port — RFC 3550 expects RTP send and receive to share a 5-tuple.
///
/// The loop exits when `cancel` is triggered, when `payloads` closes,
/// or when a send fails (typically a closed socket).
pub async fn send_loop(
    socket: Arc<UdpSocket>,
    remote: SocketAddr,
    config: RtpSendConfig,
    mut payloads: mpsc::Receiver<Vec<u8>>,
    cancel: CancellationToken,
) {
    let mut seq = config.initial_seq;
    let mut ts = config.initial_timestamp;
    let mut count: u64 = 0;
    let mut packet = Vec::with_capacity(12 + 256);

    let local = socket
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "<unknown>".into());
    info!(
        "RTP sender started {local} → {remote} (PT={}, SSRC=0x{:08X})",
        config.payload_type, config.ssrc
    );

    loop {
        select! {
            _ = cancel.cancelled() => break,
            maybe = payloads.recv() => {
                let Some(payload) = maybe else { break };
                packet.clear();
                // V=2, no padding, no extension, CSRC count = 0.
                packet.push(0x80);
                // Marker bit stays 0 — first-packet marker semantics are
                // codec-specific and the caller can encode them into the
                // payload stream if/when needed.
                packet.push(config.payload_type & 0x7F);
                packet.extend_from_slice(&seq.to_be_bytes());
                packet.extend_from_slice(&ts.to_be_bytes());
                packet.extend_from_slice(&config.ssrc.to_be_bytes());
                packet.extend_from_slice(&payload);

                if let Err(err) = socket.send_to(&packet, remote).await {
                    warn!("RTP send error: {err}");
                    break;
                }
                count += 1;
                seq = seq.wrapping_add(1);
                ts = ts.wrapping_add(config.samples_per_frame);

                if count.is_multiple_of(100) {
                    debug!("sent {count} RTP packets");
                }
            }
        }
    }

    info!("RTP sender stopped. Total packets: {count}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_packet(version: u8, pt: u8, seq: u16, ts: u32, ssrc: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 12];
        buf[0] = (version << 6) & 0xC0; // version, no padding/ext/csrc
        buf[1] = pt & 0x7F; // no marker, payload type
        buf[2..4].copy_from_slice(&seq.to_be_bytes());
        buf[4..8].copy_from_slice(&ts.to_be_bytes());
        buf[8..12].copy_from_slice(&ssrc.to_be_bytes());
        buf
    }

    #[test]
    fn parse_minimum_header() {
        let buf = make_packet(2, 0, 1234, 5678, 0xDEADBEEF);
        let h = RtpHeader::parse(&buf).unwrap();
        assert_eq!(h.version, 2);
        assert_eq!(h.payload_type, 0);
        assert_eq!(h.sequence, 1234);
        assert_eq!(h.timestamp, 5678);
        assert_eq!(h.ssrc, 0xDEADBEEF);
        assert_eq!(h.csrc_count, 0);
        assert_eq!(h.header_len(), 12);
    }

    #[test]
    fn parse_rejects_short_buffer() {
        let buf = vec![0u8; 11];
        assert!(RtpHeader::parse(&buf).is_none());
    }

    #[test]
    fn parse_rejects_wrong_version() {
        let buf = make_packet(1, 0, 0, 0, 0);
        assert!(RtpHeader::parse(&buf).is_none());
    }

    #[test]
    fn parse_extracts_marker_bit() {
        let mut buf = make_packet(2, 8, 0, 0, 0);
        buf[1] |= 0x80; // set marker
        let h = RtpHeader::parse(&buf).unwrap();
        assert!(h.marker);
        assert_eq!(h.payload_type, 8); // PCMA
    }

    #[test]
    fn header_len_accounts_for_csrcs() {
        let mut buf = make_packet(2, 0, 0, 0, 0);
        // Set CSRC count to 3, then extend buffer so length check passes.
        buf[0] |= 0x03;
        buf.extend(std::iter::repeat_n(0u8, 12));
        let h = RtpHeader::parse(&buf).unwrap();
        assert_eq!(h.csrc_count, 3);
        assert_eq!(h.header_len(), 24);
    }

    #[test]
    fn payload_type_names() {
        assert_eq!(payload_type_name(0), "PCMU");
        assert_eq!(payload_type_name(8), "PCMA");
        assert_eq!(payload_type_name(127), "unknown");
    }

    /// Bind a pair of UDP sockets on loopback. Returns (sender, receiver)
    /// with each one's `connect`/`send_to` target derivable from the
    /// other's `local_addr()`.
    async fn loopback_pair() -> (UdpSocket, UdpSocket) {
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        (a, b)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_loop_packetizes_payloads_into_rtp() {
        // One payload in, one wire packet out — header shaped per
        // RtpSendConfig, payload appended verbatim.
        let (sender, receiver) = loopback_pair().await;
        let remote = receiver.local_addr().unwrap();
        let sender = Arc::new(sender);

        let (tx, rx) = mpsc::channel::<Vec<u8>>(4);
        let cancel = CancellationToken::new();

        let task = tokio::spawn({
            let sender = sender.clone();
            let cancel = cancel.clone();
            async move {
                send_loop(
                    sender,
                    remote,
                    RtpSendConfig {
                        payload_type: 0, // PCMU
                        ssrc: 0xCAFEBABE,
                        initial_seq: 1000,
                        initial_timestamp: 5000,
                        samples_per_frame: 160,
                    },
                    rx,
                    cancel,
                )
                .await;
            }
        });

        // The payload is the 160-byte G.711 shape, but the loop is
        // codec-agnostic — what matters is that those bytes appear
        // verbatim after the 12-byte header.
        let payload: Vec<u8> = (0..160).map(|i| i as u8).collect();
        tx.send(payload.clone()).await.unwrap();

        let mut buf = [0u8; 2048];
        let (n, from) = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            receiver.recv_from(&mut buf),
        )
        .await
        .expect("receiver got packet in time")
        .expect("recv_from ok");

        assert_eq!(from, sender.local_addr().unwrap());
        assert_eq!(n, 12 + 160);

        let header = RtpHeader::parse(&buf[..n]).expect("parses as RTP");
        assert_eq!(header.version, 2);
        assert_eq!(header.payload_type, 0);
        assert_eq!(header.sequence, 1000);
        assert_eq!(header.timestamp, 5000);
        assert_eq!(header.ssrc, 0xCAFEBABE);
        assert_eq!(header.csrc_count, 0);
        assert!(!header.marker);
        assert!(!header.padding);
        assert!(!header.extension);

        assert_eq!(&buf[12..n], &payload[..]);

        cancel.cancel();
        let _ = task.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_loop_advances_seq_and_timestamp_per_packet() {
        // Regression guard: a future refactor that "simplifies" the
        // counters (e.g. forgets wrapping_add, or advances ts by 1
        // instead of samples_per_frame) breaks interop without this test.
        let (sender, receiver) = loopback_pair().await;
        let remote = receiver.local_addr().unwrap();
        let sender = Arc::new(sender);

        let (tx, rx) = mpsc::channel::<Vec<u8>>(8);
        let cancel = CancellationToken::new();

        let task = tokio::spawn({
            let sender = sender.clone();
            let cancel = cancel.clone();
            async move {
                send_loop(
                    sender,
                    remote,
                    RtpSendConfig {
                        payload_type: 8, // PCMA
                        ssrc: 0xDEADBEEF,
                        initial_seq: u16::MAX, // exercise wrap on second packet
                        initial_timestamp: 100,
                        samples_per_frame: 160,
                    },
                    rx,
                    cancel,
                )
                .await;
            }
        });

        for i in 0..3u8 {
            tx.send(vec![i; 4]).await.unwrap();
        }

        let mut headers = Vec::new();
        let mut buf = [0u8; 2048];
        for _ in 0..3 {
            let (n, _) = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                receiver.recv_from(&mut buf),
            )
            .await
            .unwrap()
            .unwrap();
            headers.push(RtpHeader::parse(&buf[..n]).unwrap());
        }

        // seq: MAX, 0 (wrap), 1
        assert_eq!(headers[0].sequence, u16::MAX);
        assert_eq!(headers[1].sequence, 0);
        assert_eq!(headers[2].sequence, 1);

        // ts advances by samples_per_frame each step
        assert_eq!(headers[0].timestamp, 100);
        assert_eq!(headers[1].timestamp, 260);
        assert_eq!(headers[2].timestamp, 420);

        // PT pinned across packets
        for h in &headers {
            assert_eq!(h.payload_type, 8);
            assert_eq!(h.ssrc, 0xDEADBEEF);
        }

        cancel.cancel();
        let _ = task.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_loop_exits_when_payload_channel_closes() {
        // Producer-driven shutdown: dropping the sender half of the
        // mpsc must let send_loop return on its own, so the consumer
        // doesn't have to remember to fire `cancel` for the happy path
        // of "encoder finished, nothing more to send."
        let (sender, _receiver) = loopback_pair().await;
        let remote = "127.0.0.1:9".parse().unwrap();
        let sender = Arc::new(sender);

        let (tx, rx) = mpsc::channel::<Vec<u8>>(1);
        let cancel = CancellationToken::new();

        let task = tokio::spawn({
            let sender = sender.clone();
            let cancel = cancel.clone();
            async move {
                send_loop(
                    sender,
                    remote,
                    RtpSendConfig {
                        payload_type: 0,
                        ssrc: 1,
                        initial_seq: 0,
                        initial_timestamp: 0,
                        samples_per_frame: 160,
                    },
                    rx,
                    cancel,
                )
                .await;
            }
        });

        drop(tx);

        tokio::time::timeout(std::time::Duration::from_millis(500), task)
            .await
            .expect("send_loop exited within timeout")
            .expect("task did not panic");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_loop_exits_on_cancel() {
        // Cancel-driven shutdown for the "we're done with this call"
        // path — the producer may still be alive (the encoder task is
        // shared across calls) but this dialog's loop must stop.
        let (sender, _receiver) = loopback_pair().await;
        let remote = "127.0.0.1:9".parse().unwrap();
        let sender = Arc::new(sender);

        let (_tx, rx) = mpsc::channel::<Vec<u8>>(1);
        let cancel = CancellationToken::new();

        let task = tokio::spawn({
            let sender = sender.clone();
            let cancel = cancel.clone();
            async move {
                send_loop(
                    sender,
                    remote,
                    RtpSendConfig {
                        payload_type: 0,
                        ssrc: 1,
                        initial_seq: 0,
                        initial_timestamp: 0,
                        samples_per_frame: 160,
                    },
                    rx,
                    cancel,
                )
                .await;
            }
        });

        cancel.cancel();
        tokio::time::timeout(std::time::Duration::from_millis(500), task)
            .await
            .expect("send_loop exited within timeout")
            .expect("task did not panic");
    }
}
