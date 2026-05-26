//! Minimal SDP offer/answer for G.711 telephony audio plus RFC 4733
//! `telephone-event` (DTMF) negotiation.

use std::net::IpAddr;

/// The de-facto dynamic RTP payload type for `telephone-event/8000`.
///
/// Any value in 96-127 is legal under RFC 3551, but ~every softphone
/// and PBX in the field picks 101 — matching that keeps inter-op
/// boring and predictable.
pub const DTMF_DEFAULT_PT: u8 = 101;

/// Build a minimal SDP body for bidirectional G.711 audio with RFC 4733
/// telephone-event (DTMF) advertised at payload type 101.
///
/// Suitable as both the offer (sent in an outbound INVITE) and the answer
/// (sent in a 200 OK to an inbound INVITE). The G.711 codecs stay
/// listed first so the remote still selects PCMU/PCMA as the audio
/// codec; the 101 entry adds DTMF support without changing the
/// preferred audio choice.
pub fn build_sdp(local_ip: IpAddr, rtp_port: u16) -> Vec<u8> {
    format!(
        "v=0\r\n\
         o=wavekat 0 0 IN IP4 {local_ip}\r\n\
         s=wavekat-sip\r\n\
         c=IN IP4 {local_ip}\r\n\
         t=0 0\r\n\
         m=audio {rtp_port} RTP/AVP 0 8 {DTMF_DEFAULT_PT}\r\n\
         a=rtpmap:0 PCMU/8000\r\n\
         a=rtpmap:8 PCMA/8000\r\n\
         a=rtpmap:{DTMF_DEFAULT_PT} telephone-event/8000\r\n\
         a=fmtp:{DTMF_DEFAULT_PT} 0-15\r\n\
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
    /// Payload type the remote offered (or accepted) for RFC 4733
    /// `telephone-event/8000`. `None` if the remote did not advertise
    /// it — consumers should fall back to SIP INFO for DTMF in that
    /// case.
    pub dtmf_payload_type: Option<u8>,
}

/// Parse the connection address, audio port, preferred codec, and
/// (optionally) the negotiated DTMF payload type from an SDP body.
pub fn parse_sdp(sdp_bytes: &[u8]) -> Result<RemoteMedia, String> {
    let sdp = std::str::from_utf8(sdp_bytes).map_err(|e| format!("SDP not UTF-8: {e}"))?;

    let mut addr: Option<IpAddr> = None;
    let mut port: Option<u16> = None;
    let mut audio_pts: Vec<u8> = Vec::new();
    // PTs whose rtpmap names them as `telephone-event/8000`.
    let mut dtmf_candidate_pts: Vec<u8> = Vec::new();

    for line in sdp.lines() {
        let line = line.trim();

        // c=IN IP4 10.0.0.1
        if line.starts_with("c=IN IP4 ") || line.starts_with("c=IN IP6 ") {
            if let Some(ip_str) = line.split_whitespace().nth(2) {
                addr = ip_str.parse().ok();
            }
        }

        // m=audio 20000 RTP/AVP 0 8 101
        // The first payload type after RTP/AVP is the preferred codec;
        // the rest may include telephone-event.
        if line.starts_with("m=audio ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                port = parts[1].parse().ok();
            }
            // Skip "m=audio", port, "RTP/AVP" — payload types start at index 3.
            for pt_str in parts.iter().skip(3) {
                if let Ok(pt) = pt_str.parse::<u8>() {
                    audio_pts.push(pt);
                }
            }
        }

        // a=rtpmap:101 telephone-event/8000
        if let Some(rest) = line.strip_prefix("a=rtpmap:") {
            // <pt> <name>/<rate>[/params]
            let mut sp = rest.splitn(2, char::is_whitespace);
            let pt_str = sp.next().unwrap_or("");
            let mapping = sp.next().unwrap_or("");
            if let Ok(pt) = pt_str.parse::<u8>() {
                let name_lc = mapping.split('/').next().unwrap_or("").to_ascii_lowercase();
                let rate = mapping.split('/').nth(1).unwrap_or("");
                if name_lc == "telephone-event" && rate == "8000" {
                    dtmf_candidate_pts.push(pt);
                }
            }
        }
    }

    // DTMF must both be named in an rtpmap *and* listed on the m=audio line
    // for the negotiation to be valid. If either is missing, treat DTMF as
    // not negotiated.
    let dtmf_payload_type = dtmf_candidate_pts
        .into_iter()
        .find(|pt| audio_pts.contains(pt));

    let payload_type = audio_pts.first().copied();

    match (addr, port, payload_type) {
        (Some(addr), Some(port), Some(pt)) => Ok(RemoteMedia {
            addr,
            port,
            payload_type: pt,
            dtmf_payload_type,
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
        assert!(text.contains("m=audio 5004 RTP/AVP 0 8 101\r\n"));
        assert!(text.contains("a=sendrecv\r\n"));
        assert!(text.contains("a=rtpmap:0 PCMU/8000\r\n"));
        assert!(text.contains("a=rtpmap:8 PCMA/8000\r\n"));
        assert!(text.contains("a=rtpmap:101 telephone-event/8000\r\n"));
        assert!(text.contains("a=fmtp:101 0-15\r\n"));
    }

    #[test]
    fn parse_sdp_extracts_addr_port_and_codec() {
        let sdp = b"v=0\r\nc=IN IP4 192.168.1.100\r\nm=audio 20000 RTP/AVP 0\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(media.addr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(media.port, 20000);
        assert_eq!(media.payload_type, 0);
        // No rtpmap for telephone-event → no DTMF advertised.
        assert_eq!(media.dtmf_payload_type, None);
    }

    #[test]
    fn parse_sdp_extracts_first_codec_when_multiple() {
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 8 0 101\r\n\
                    a=rtpmap:101 telephone-event/8000\r\n";
        let media = parse_sdp(sdp).unwrap();
        // First PT in the m= line is still the preferred audio codec — adding
        // telephone-event must not change which codec the consumer thinks the
        // remote wants for voice.
        assert_eq!(media.payload_type, 8); // PCMA is first/preferred
        assert_eq!(media.dtmf_payload_type, Some(101));
    }

    #[test]
    fn round_trip_build_then_parse() {
        let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5));
        let sdp = build_sdp(ip, 8000);
        let media = parse_sdp(&sdp).unwrap();
        assert_eq!(media.addr, ip);
        assert_eq!(media.port, 8000);
        assert_eq!(media.payload_type, 0); // PCMU is first in our SDP
        assert_eq!(media.dtmf_payload_type, Some(DTMF_DEFAULT_PT));
    }

    #[test]
    fn parse_sdp_picks_dtmf_pt_from_rtpmap_not_constant() {
        // Some remotes negotiate telephone-event on a different dynamic PT
        // (96-127). The parser must follow the rtpmap, not assume 101.
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 0 96\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:96 telephone-event/8000\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(media.dtmf_payload_type, Some(96));
    }

    #[test]
    fn parse_sdp_ignores_telephone_event_at_wrong_rate() {
        // RFC 4733 also defines telephone-event/16000 for wideband; we only
        // ship the 8000 Hz clock domain, so a 16000 entry must not be
        // selected.
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 0 101\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:101 telephone-event/16000\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(media.dtmf_payload_type, None);
    }

    #[test]
    fn parse_sdp_rejects_telephone_event_not_listed_on_m_line() {
        // rtpmap names PT 101 but the m=audio line doesn't include it →
        // not actually negotiated, must be ignored.
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 0\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:101 telephone-event/8000\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(media.dtmf_payload_type, None);
    }

    #[test]
    fn parse_sdp_handles_mixed_case_telephone_event() {
        // Some stacks emit "Telephone-Event" or "TELEPHONE-EVENT". Case
        // matching at the rtpmap level shouldn't reject those.
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 0 101\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:101 Telephone-Event/8000\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(media.dtmf_payload_type, Some(101));
    }

    #[test]
    fn parse_sdp_handles_telephone_event_without_fmtp() {
        // `a=fmtp:101 0-15` is optional; many stacks omit it. Absence must
        // not gate negotiation.
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 0 101\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:101 telephone-event/8000\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(media.dtmf_payload_type, Some(101));
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
