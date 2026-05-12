//! Minimal SDP offer/answer for G.711 telephony audio.

use std::net::IpAddr;

/// Build a minimal SDP body for bidirectional audio (G.711 PCMU + PCMA).
///
/// Suitable as both the offer (sent in an outbound INVITE) and the answer
/// (sent in a 200 OK to an inbound INVITE).
pub fn build_sdp(local_ip: IpAddr, rtp_port: u16) -> Vec<u8> {
    format!(
        "v=0\r\n\
         o=wavekat 0 0 IN IP4 {local_ip}\r\n\
         s=wavekat-sip\r\n\
         c=IN IP4 {local_ip}\r\n\
         t=0 0\r\n\
         m=audio {rtp_port} RTP/AVP 0 8\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:8 PCMA/8000\r\n\
         a=sendrecv\r\n"
    )
    .into_bytes()
}

/// Remote media info extracted from an SDP body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteMedia {
    /// Remote IP from the `c=` line.
    pub addr: IpAddr,
    /// Remote RTP port from the `m=audio` line.
    pub port: u16,
    /// First (preferred) RTP payload type from the `m=audio` line.
    pub payload_type: u8,
}

/// Parse the connection address, audio port, and preferred codec from an
/// SDP body.
pub fn parse_sdp(sdp_bytes: &[u8]) -> Result<RemoteMedia, String> {
    let sdp = std::str::from_utf8(sdp_bytes).map_err(|e| format!("SDP not UTF-8: {e}"))?;

    let mut addr: Option<IpAddr> = None;
    let mut port: Option<u16> = None;
    let mut payload_type: Option<u8> = None;

    for line in sdp.lines() {
        let line = line.trim();

        // c=IN IP4 10.0.0.1
        if line.starts_with("c=IN IP4 ") || line.starts_with("c=IN IP6 ") {
            if let Some(ip_str) = line.split_whitespace().nth(2) {
                addr = ip_str.parse().ok();
            }
        }

        // m=audio 20000 RTP/AVP 0 8
        // The first payload type after RTP/AVP is the preferred codec.
        if line.starts_with("m=audio ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                port = parts[1].parse().ok();
            }
            if parts.len() >= 4 {
                payload_type = parts[3].parse().ok();
            }
        }
    }

    match (addr, port, payload_type) {
        (Some(addr), Some(port), Some(pt)) => Ok(RemoteMedia {
            addr,
            port,
            payload_type: pt,
        }),
        (None, _, _) => Err("No connection address (c=) in SDP".to_string()),
        (_, None, _) => Err("No audio media line (m=audio) in SDP".to_string()),
        (_, _, None) => Err("No payload type in m=audio line".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn build_sdp_contains_required_fields() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let sdp = build_sdp(ip, 5004);
        let text = String::from_utf8(sdp).unwrap();

        assert!(text.contains("v=0\r\n"));
        assert!(text.contains("c=IN IP4 10.0.0.1\r\n"));
        assert!(text.contains("m=audio 5004 RTP/AVP 0 8\r\n"));
        assert!(text.contains("a=sendrecv\r\n"));
        assert!(text.contains("a=rtpmap:0 PCMU/8000\r\n"));
        assert!(text.contains("a=rtpmap:8 PCMA/8000\r\n"));
    }

    #[test]
    fn parse_sdp_extracts_addr_port_and_codec() {
        let sdp = b"v=0\r\nc=IN IP4 192.168.1.100\r\nm=audio 20000 RTP/AVP 0\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(media.addr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(media.port, 20000);
        assert_eq!(media.payload_type, 0); // PCMU
    }

    #[test]
    fn parse_sdp_extracts_first_codec_when_multiple() {
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 8 0 101\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(media.payload_type, 8); // PCMA is first/preferred
    }

    #[test]
    fn round_trip_build_then_parse() {
        let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5));
        let sdp = build_sdp(ip, 8000);
        let media = parse_sdp(&sdp).unwrap();
        assert_eq!(media.addr, ip);
        assert_eq!(media.port, 8000);
        assert_eq!(media.payload_type, 0); // PCMU is first in our SDP
    }

    #[test]
    fn parse_sdp_missing_connection_line() {
        let sdp = b"v=0\r\nm=audio 20000 RTP/AVP 0\r\n";
        let err = parse_sdp(sdp).unwrap_err();
        assert!(err.contains("connection address"));
    }

    #[test]
    fn parse_sdp_missing_media_line() {
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\n";
        let err = parse_sdp(sdp).unwrap_err();
        assert!(err.contains("audio media"));
    }

    #[test]
    fn parse_sdp_invalid_utf8() {
        let sdp = &[0xFF, 0xFE, 0xFD];
        let err = parse_sdp(sdp).unwrap_err();
        assert!(err.contains("UTF-8"));
    }
}
