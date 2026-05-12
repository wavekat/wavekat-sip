//! RTP header parsing and a basic receive loop.
//!
//! This module intentionally stops at the wire: it parses RTP headers
//! (RFC 3550) and exposes a debug-friendly receive loop. Decoding payloads
//! (G.711, Opus, …), jitter buffering, and audio device routing are
//! consumer-layer concerns and live outside this crate.

use tokio::net::UdpSocket;
use tokio::select;
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
}
