//! SDP offer/answer for telephony audio — Opus (RFC 7587) preferred,
//! G.711 fallback — plus RFC 4733 `telephone-event` (DTMF) negotiation.
//!
//! The crate stays codec-agnostic: nothing here encodes or decodes
//! audio. This module only *negotiates* — which codec, at which payload
//! type, with which DTMF clock — and reports the result as
//! [`AudioCodec`] / [`DtmfSpec`] for the consumer to act on.
//!
//! ## Offer, answer, re-offer
//!
//! - **Initial offer** ([`build_sdp_offer`]): the full menu, Opus first
//!   (`opus/48000/2` with `useinbandfec=1`), then PCMU/PCMA, plus
//!   `telephone-event` at both the 8 kHz and 48 kHz clocks so whichever
//!   codec the peer picks it finds a matching-clock DTMF entry.
//! - **Answer**: a real RFC 3264 intersection — echo back *only* the
//!   codec we selected from the offer (via [`select_codec`] /
//!   [`select_dtmf`]), at the offer's own payload-type numbers, built
//!   with [`CodecMenu::Pinned`].
//! - **Mid-call re-offers** (hold/resume, session refresh): also
//!   [`CodecMenu::Pinned`] to the already-negotiated codec. Re-offering
//!   the full menu would let the peer switch codecs mid-call, which the
//!   consumer's audio path (encoder state, sample rates, recording) is
//!   not prepared for; pinning makes that structurally impossible.
//!
//! ## The Opus wire constants
//!
//! The rtpmap for Opus is always `opus/48000/2` (RFC 7587 §4.1) — the
//! 48 kHz clock and the 2 channels are wire-format constants, not a
//! description of the stream (the actual audio is typically mono
//! wideband). Opus also has no static payload type: it rides the
//! dynamic range, [`OPUS_DEFAULT_PT`] (111) being only what *we* offer.
//! The negotiated number comes out of [`parse_sdp`] per call.

use std::net::IpAddr;

/// The de-facto dynamic RTP payload type for `telephone-event/8000`.
///
/// Any value in 96-127 is legal under RFC 3551, but ~every softphone
/// and PBX in the field picks 101 — matching that keeps inter-op
/// boring and predictable.
pub const DTMF_DEFAULT_PT: u8 = 101;

/// The dynamic payload type we offer for `telephone-event/48000` —
/// DTMF at the Opus RTP clock. RFC 4733 §2.1 wants the event clock to
/// match the audio stream's, so peers that select Opus commonly expect
/// (and some only accept) telephone-event at 48 kHz. Offered alongside
/// the classic 8 kHz entry; the answerer picks one.
pub const DTMF_WIDEBAND_DEFAULT_PT: u8 = 110;

/// The dynamic payload type we offer for Opus. There is no static
/// assignment — 111 is the field's de-facto default (same spirit as 101
/// for telephone-event). The peer may counter with any number; always
/// use the negotiated value from [`parse_sdp`], never this constant,
/// when talking to the wire.
pub const OPUS_DEFAULT_PT: u8 = 111;

/// RTP timestamp clock for Opus — pinned to 48 kHz by RFC 7587 §4.1
/// regardless of the actual encode rate. (G.711's clock is 8 kHz.)
pub const OPUS_RTP_CLOCK_RATE: u32 = 48_000;

const G711_RTP_CLOCK_RATE: u32 = 8_000;

/// Media direction (RFC 4566 `a=` attribute), used to put a call on hold
/// and take it off again per RFC 3264 §8.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaDirection {
    /// Send and receive media — the normal, active state (`a=sendrecv`).
    SendRecv,
    /// Send only, do not receive — places the peer on hold (`a=sendonly`).
    SendOnly,
    /// Neither send nor receive — a full two-way hold (`a=inactive`).
    Inactive,
}

impl MediaDirection {
    /// The `a=` attribute line value (no `a=` prefix, no CRLF).
    pub fn attribute(&self) -> &'static str {
        match self {
            MediaDirection::SendRecv => "sendrecv",
            MediaDirection::SendOnly => "sendonly",
            MediaDirection::Inactive => "inactive",
        }
    }
}

/// An audio codec this stack can negotiate, with its wire identity.
///
/// This is negotiation metadata, not a codec implementation — encode
/// and decode stay with the consumer (`wavekat-core` provides G.711 and
/// Opus codecs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioCodec {
    /// G.711 μ-law — static RTP payload type 0.
    Pcmu,
    /// G.711 A-law — static RTP payload type 8.
    Pcma,
    /// Opus at a **dynamic** payload type — whatever this side of the
    /// negotiation chose. The number alone is not self-describing the
    /// way 0/8 are; it only means Opus in the context of the SDP body
    /// that mapped it.
    Opus {
        /// The negotiated dynamic payload type (96-127 in practice).
        payload_type: u8,
    },
}

impl AudioCodec {
    /// The RTP payload-type number this codec rides on.
    pub fn payload_type(&self) -> u8 {
        match self {
            AudioCodec::Pcmu => 0,
            AudioCodec::Pcma => 8,
            AudioCodec::Opus { payload_type } => *payload_type,
        }
    }

    /// The RTP timestamp clock rate: 8 kHz for G.711, always 48 kHz for
    /// Opus (a wire constant — see the module docs).
    pub fn rtp_clock_rate(&self) -> u32 {
        match self {
            AudioCodec::Pcmu | AudioCodec::Pcma => G711_RTP_CLOCK_RATE,
            AudioCodec::Opus { .. } => OPUS_RTP_CLOCK_RATE,
        }
    }

    /// The `a=rtpmap:` encoding string (`<name>/<clock>[/<channels>]`).
    fn rtpmap_encoding(&self) -> &'static str {
        match self {
            AudioCodec::Pcmu => "PCMU/8000",
            AudioCodec::Pcma => "PCMA/8000",
            AudioCodec::Opus { .. } => "opus/48000/2",
        }
    }
}

/// One negotiated `telephone-event` entry: its payload type and clock.
///
/// The clock matters beyond the SDP line — RFC 4733 duration fields and
/// burst pacing count in ticks of this clock (160 per 20 ms at 8 kHz,
/// 960 at 48 kHz), so it must be threaded into
/// [`crate::rtp::dtmf::DtmfBurstConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DtmfSpec {
    /// The negotiated dynamic payload type.
    pub payload_type: u8,
    /// The event clock rate from the rtpmap (8000 classic, 48000
    /// alongside Opus).
    pub clock_rate: u32,
}

/// Which audio codecs an SDP body advertises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecMenu {
    /// The full initial-offer menu: Opus (preferred, at
    /// [`OPUS_DEFAULT_PT`]) then PCMU/PCMA, with `telephone-event` at
    /// both clocks. Use for initial offers only.
    Full,
    /// Exactly one codec (plus optionally one `telephone-event` entry)
    /// — the shape of every answer and every post-negotiation re-offer.
    /// Pinning re-offers to the negotiated codec is what keeps a
    /// hold/resume or session-refresh re-INVITE from renegotiating the
    /// codec out from under a live audio path.
    Pinned {
        /// The negotiated audio codec, echoed at its negotiated payload
        /// type.
        codec: AudioCodec,
        /// The negotiated `telephone-event` entry, if any.
        dtmf: Option<DtmfSpec>,
    },
}

/// Build the initial SDP offer: the full codec menu ([`CodecMenu::Full`]),
/// `a=sendrecv`, `o=` version 0.
///
/// Answers and re-offers must **not** use this — see [`CodecMenu`] and
/// [`build_sdp_with`].
pub fn build_sdp_offer(local_ip: IpAddr, rtp_port: u16) -> Vec<u8> {
    build_sdp_with(
        local_ip,
        rtp_port,
        CodecMenu::Full,
        MediaDirection::SendRecv,
        0,
    )
}

/// Build an SDP body with an explicit codec `menu`, media `direction`,
/// and `o=` session `version`.
///
/// RFC 3264 §5 requires every re-offer to keep the same session id but
/// **increment** the `o=` version; hold/resume re-INVITEs feed the bumped
/// version here and flip `direction` between [`MediaDirection::SendRecv`]
/// and [`MediaDirection::SendOnly`]/[`MediaDirection::Inactive`] — with
/// the menu pinned to the negotiated codec ([`CodecMenu::Pinned`]).
pub fn build_sdp_with(
    local_ip: IpAddr,
    rtp_port: u16,
    menu: CodecMenu,
    direction: MediaDirection,
    version: u32,
) -> Vec<u8> {
    // Collect the m= line payload types and the a= lines per menu.
    let mut pts: Vec<String> = Vec::new();
    let mut attrs: Vec<String> = Vec::new();

    match menu {
        CodecMenu::Full => {
            pts.extend([
                OPUS_DEFAULT_PT.to_string(),
                "0".into(),
                "8".into(),
                DTMF_DEFAULT_PT.to_string(),
                DTMF_WIDEBAND_DEFAULT_PT.to_string(),
            ]);
            attrs.push(format!("a=rtpmap:{OPUS_DEFAULT_PT} opus/48000/2"));
            attrs.push(format!("a=fmtp:{OPUS_DEFAULT_PT} useinbandfec=1"));
            attrs.push("a=rtpmap:0 PCMU/8000".into());
            attrs.push("a=rtpmap:8 PCMA/8000".into());
            attrs.push(format!("a=rtpmap:{DTMF_DEFAULT_PT} telephone-event/8000"));
            attrs.push(format!("a=fmtp:{DTMF_DEFAULT_PT} 0-15"));
            attrs.push(format!(
                "a=rtpmap:{DTMF_WIDEBAND_DEFAULT_PT} telephone-event/{OPUS_RTP_CLOCK_RATE}"
            ));
            attrs.push(format!("a=fmtp:{DTMF_WIDEBAND_DEFAULT_PT} 0-15"));
        }
        CodecMenu::Pinned { codec, dtmf } => {
            let pt = codec.payload_type();
            pts.push(pt.to_string());
            attrs.push(format!("a=rtpmap:{pt} {}", codec.rtpmap_encoding()));
            if matches!(codec, AudioCodec::Opus { .. }) {
                attrs.push(format!("a=fmtp:{pt} useinbandfec=1"));
            }
            if let Some(DtmfSpec {
                payload_type,
                clock_rate,
            }) = dtmf
            {
                pts.push(payload_type.to_string());
                attrs.push(format!(
                    "a=rtpmap:{payload_type} telephone-event/{clock_rate}"
                ));
                attrs.push(format!("a=fmtp:{payload_type} 0-15"));
            }
        }
    }

    let pt_list = pts.join(" ");
    let attr_lines = attrs.join("\r\n");
    let dir = direction.attribute();
    format!(
        "v=0\r\n\
         o=wavekat 0 {version} IN IP4 {local_ip}\r\n\
         s=wavekat-sip\r\n\
         c=IN IP4 {local_ip}\r\n\
         t=0 0\r\n\
         m=audio {rtp_port} RTP/AVP {pt_list}\r\n\
         {attr_lines}\r\n\
         a={dir}\r\n"
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
    /// First (preferred) RTP payload type from the `m=audio` line, raw.
    /// Kept for logging/diagnostics; consumers should act on [`codec`]
    /// (`Self::codec`), which resolves dynamic payload types.
    pub payload_type: u8,
    /// The first payload type on the `m=audio` line that resolves to a
    /// codec this stack knows (static 0/8, or a dynamic PT whose rtpmap
    /// names `opus/48000` or PCMU/PCMA). `None` when the body offers
    /// nothing we understand.
    ///
    /// When parsed from an **answer** this *is* the negotiated codec.
    /// When parsed from an **offer** it is only the peer's first
    /// preference — the selection is ours to make ([`select_codec`]).
    /// [`crate::IncomingCall::accept`] rewrites this field to the codec
    /// it actually selected, so on an established [`crate::Call`] it is
    /// always the negotiated codec.
    pub codec: Option<AudioCodec>,
    /// The payload type Opus rides on, if Opus appears **anywhere** in
    /// the menu (not just first). This is what lets the answer side
    /// prefer Opus over a peer that offers `0 8 111`.
    pub opus_payload_type: Option<u8>,
    /// Every `telephone-event` entry on the `m=audio` line, in offer
    /// order, with its clock. Use [`Self::dtmf`] for "the one that goes
    /// with the negotiated codec".
    pub dtmf_events: Vec<DtmfSpec>,
}

impl RemoteMedia {
    /// The `telephone-event` entry to use with the negotiated codec:
    /// the one whose clock matches the codec's RTP clock, else the
    /// first offered. `None` if the remote advertised no
    /// telephone-event at all — fall back to SIP INFO for DTMF then.
    pub fn dtmf(&self) -> Option<DtmfSpec> {
        match self.codec {
            Some(codec) => select_dtmf(self, codec),
            None => self.dtmf_events.first().copied(),
        }
    }
}

/// Pick the audio codec for an answer, per the WaveKat policy: **prefer
/// Opus wherever it appears in the offer, else the peer's first G.711**.
/// Returns `None` when the offer contains nothing this stack knows —
/// the SIP-correct response then is `488 Not Acceptable Here`.
pub fn select_codec(offer: &RemoteMedia) -> Option<AudioCodec> {
    offer
        .opus_payload_type
        .map(|payload_type| AudioCodec::Opus { payload_type })
        .or(offer.codec)
}

/// Pick the `telephone-event` entry to answer with, given the selected
/// audio codec: matching clock first (RFC 4733 §2.1 wants the event
/// clock to follow the audio stream's), else the first offered entry.
pub fn select_dtmf(offer: &RemoteMedia, codec: AudioCodec) -> Option<DtmfSpec> {
    let clock = codec.rtp_clock_rate();
    offer
        .dtmf_events
        .iter()
        .copied()
        .find(|d| d.clock_rate == clock)
        .or_else(|| offer.dtmf_events.first().copied())
}

/// Parse the connection address, audio port, codec menu, and
/// `telephone-event` entries from an SDP body.
pub fn parse_sdp(sdp_bytes: &[u8]) -> Result<RemoteMedia, String> {
    let sdp = std::str::from_utf8(sdp_bytes).map_err(|e| format!("SDP not UTF-8: {e}"))?;

    let mut addr: Option<IpAddr> = None;
    let mut port: Option<u16> = None;
    let mut audio_pts: Vec<u8> = Vec::new();
    // Every parsed a=rtpmap: line — (pt, lowercased encoding name, clock).
    let mut rtpmaps: Vec<(u8, String, u32)> = Vec::new();

    for line in sdp.lines() {
        let line = line.trim();

        // c=IN IP4 10.0.0.1
        if line.starts_with("c=IN IP4 ") || line.starts_with("c=IN IP6 ") {
            if let Some(ip_str) = line.split_whitespace().nth(2) {
                addr = ip_str.parse().ok();
            }
        }

        // m=audio 20000 RTP/AVP 111 0 8 101
        // The first payload type after RTP/AVP is the preferred codec;
        // the rest may include more codecs and telephone-event.
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

        // a=rtpmap:111 opus/48000/2
        // a=rtpmap:101 telephone-event/8000
        if let Some(rest) = line.strip_prefix("a=rtpmap:") {
            // <pt> <name>/<rate>[/params]
            let mut sp = rest.splitn(2, char::is_whitespace);
            let pt_str = sp.next().unwrap_or("");
            let mapping = sp.next().unwrap_or("");
            if let Ok(pt) = pt_str.parse::<u8>() {
                let name_lc = mapping.split('/').next().unwrap_or("").to_ascii_lowercase();
                if let Ok(rate) = mapping.split('/').nth(1).unwrap_or("").parse::<u32>() {
                    rtpmaps.push((pt, name_lc, rate));
                }
            }
        }
    }

    let rtpmap_for = |pt: u8| rtpmaps.iter().find(|(p, _, _)| *p == pt);

    // Resolve one m=-line payload type to a codec. An explicit rtpmap
    // wins over the static assignment (RFC 8866 allows remapping);
    // without one, only the static 0/8 numbers are self-describing.
    let resolve = |pt: u8| -> Option<AudioCodec> {
        match rtpmap_for(pt) {
            Some((_, name, rate)) => match (name.as_str(), *rate) {
                ("opus", OPUS_RTP_CLOCK_RATE) => Some(AudioCodec::Opus { payload_type: pt }),
                ("pcmu", G711_RTP_CLOCK_RATE) => Some(AudioCodec::Pcmu),
                ("pcma", G711_RTP_CLOCK_RATE) => Some(AudioCodec::Pcma),
                _ => None,
            },
            None => match pt {
                0 => Some(AudioCodec::Pcmu),
                8 => Some(AudioCodec::Pcma),
                _ => None,
            },
        }
    };

    let codec = audio_pts.iter().copied().find_map(resolve);
    let opus_payload_type = audio_pts
        .iter()
        .copied()
        .find(|&pt| matches!(resolve(pt), Some(AudioCodec::Opus { .. })));

    // telephone-event must both be named in an rtpmap *and* listed on
    // the m=audio line for the negotiation to be valid — at any clock
    // rate (8000 classic, 48000 alongside Opus, 16000 exists in the
    // wild too). The clock is recorded because duration math depends
    // on it.
    let dtmf_events: Vec<DtmfSpec> = audio_pts
        .iter()
        .filter_map(|&pt| match rtpmap_for(pt) {
            Some((_, name, rate)) if name == "telephone-event" => Some(DtmfSpec {
                payload_type: pt,
                clock_rate: *rate,
            }),
            _ => None,
        })
        .collect();

    let payload_type = audio_pts.first().copied();

    match (addr, port, payload_type) {
        (Some(addr), Some(port), Some(pt)) => Ok(RemoteMedia {
            addr,
            port,
            payload_type: pt,
            codec,
            opus_payload_type,
            dtmf_events,
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

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    #[test]
    fn offer_contains_required_fields_opus_first() {
        let sdp = build_sdp_offer(ip(), 5004);
        let text = String::from_utf8(sdp).unwrap();

        assert!(text.contains("v=0\r\n"));
        assert!(text.contains("c=IN IP4 10.0.0.1\r\n"));
        // Opus leads the menu; G.711 follows for fallback; both DTMF
        // clocks are on the table.
        assert!(text.contains("m=audio 5004 RTP/AVP 111 0 8 101 110\r\n"));
        assert!(text.contains("a=rtpmap:111 opus/48000/2\r\n"));
        assert!(text.contains("a=fmtp:111 useinbandfec=1\r\n"));
        assert!(text.contains("a=rtpmap:0 PCMU/8000\r\n"));
        assert!(text.contains("a=rtpmap:8 PCMA/8000\r\n"));
        assert!(text.contains("a=rtpmap:101 telephone-event/8000\r\n"));
        assert!(text.contains("a=fmtp:101 0-15\r\n"));
        assert!(text.contains("a=rtpmap:110 telephone-event/48000\r\n"));
        assert!(text.contains("a=fmtp:110 0-15\r\n"));
        assert!(text.contains("a=sendrecv\r\n"));
        assert!(text.contains("o=wavekat 0 0 IN IP4 10.0.0.1\r\n"));
    }

    #[test]
    fn build_sdp_with_sets_direction_and_version() {
        let menu = CodecMenu::Pinned {
            codec: AudioCodec::Pcmu,
            dtmf: Some(DtmfSpec {
                payload_type: 101,
                clock_rate: 8000,
            }),
        };

        let hold = String::from_utf8(build_sdp_with(
            ip(),
            5004,
            menu,
            MediaDirection::SendOnly,
            1,
        ))
        .unwrap();
        assert!(hold.contains("o=wavekat 0 1 IN IP4 10.0.0.1\r\n"));
        assert!(hold.contains("a=sendonly\r\n"));
        assert!(!hold.contains("a=sendrecv\r\n"));

        let resume = String::from_utf8(build_sdp_with(
            ip(),
            5004,
            menu,
            MediaDirection::SendRecv,
            2,
        ))
        .unwrap();
        assert!(resume.contains("o=wavekat 0 2 IN IP4 10.0.0.1\r\n"));
        assert!(resume.contains("a=sendrecv\r\n"));

        let inactive = String::from_utf8(build_sdp_with(
            ip(),
            5004,
            menu,
            MediaDirection::Inactive,
            3,
        ))
        .unwrap();
        assert!(inactive.contains("a=inactive\r\n"));
    }

    #[test]
    fn pinned_g711_reoffer_contains_only_the_negotiated_codec() {
        // A hold re-INVITE after a PCMA call must not re-open the Opus
        // (or PCMU) negotiation.
        let menu = CodecMenu::Pinned {
            codec: AudioCodec::Pcma,
            dtmf: Some(DtmfSpec {
                payload_type: 101,
                clock_rate: 8000,
            }),
        };
        let text = String::from_utf8(build_sdp_with(
            ip(),
            5004,
            menu,
            MediaDirection::SendOnly,
            1,
        ))
        .unwrap();
        assert!(text.contains("m=audio 5004 RTP/AVP 8 101\r\n"));
        assert!(text.contains("a=rtpmap:8 PCMA/8000\r\n"));
        assert!(!text.contains("opus"));
        assert!(!text.contains("PCMU"));
    }

    #[test]
    fn pinned_opus_reoffer_keeps_the_negotiated_pt_and_dtmf_clock() {
        // The peer negotiated Opus at *its* PT (96, not our default 111)
        // and telephone-event at the 48 kHz clock. Re-offers must echo
        // those exact numbers.
        let menu = CodecMenu::Pinned {
            codec: AudioCodec::Opus { payload_type: 96 },
            dtmf: Some(DtmfSpec {
                payload_type: 97,
                clock_rate: 48000,
            }),
        };
        let text = String::from_utf8(build_sdp_with(
            ip(),
            5004,
            menu,
            MediaDirection::SendOnly,
            1,
        ))
        .unwrap();
        assert!(text.contains("m=audio 5004 RTP/AVP 96 97\r\n"));
        assert!(text.contains("a=rtpmap:96 opus/48000/2\r\n"));
        assert!(text.contains("a=fmtp:96 useinbandfec=1\r\n"));
        assert!(text.contains("a=rtpmap:97 telephone-event/48000\r\n"));
        assert!(!text.contains("111"));
        assert!(!text.contains("PCMU"));
        assert!(!text.contains("PCMA"));
    }

    #[test]
    fn pinned_without_dtmf_omits_telephone_event() {
        let menu = CodecMenu::Pinned {
            codec: AudioCodec::Pcmu,
            dtmf: None,
        };
        let text = String::from_utf8(build_sdp_with(
            ip(),
            5004,
            menu,
            MediaDirection::SendRecv,
            0,
        ))
        .unwrap();
        assert!(text.contains("m=audio 5004 RTP/AVP 0\r\n"));
        assert!(!text.contains("telephone-event"));
    }

    #[test]
    fn parse_sdp_extracts_addr_port_and_codec() {
        let sdp = b"v=0\r\nc=IN IP4 192.168.1.100\r\nm=audio 20000 RTP/AVP 0\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(media.addr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(media.port, 20000);
        assert_eq!(media.payload_type, 0);
        assert_eq!(media.codec, Some(AudioCodec::Pcmu));
        assert_eq!(media.opus_payload_type, None);
        // No rtpmap for telephone-event → no DTMF advertised.
        assert_eq!(media.dtmf(), None);
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
        assert_eq!(media.codec, Some(AudioCodec::Pcma));
        assert_eq!(
            media.dtmf(),
            Some(DtmfSpec {
                payload_type: 101,
                clock_rate: 8000
            })
        );
    }

    #[test]
    fn parse_sdp_resolves_dynamic_opus_pt() {
        // Opus has no static PT — the peer picked 96, and only the
        // rtpmap says what 96 means.
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 96 0 101\r\n\
                    a=rtpmap:96 opus/48000/2\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:101 telephone-event/8000\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(media.payload_type, 96);
        assert_eq!(media.codec, Some(AudioCodec::Opus { payload_type: 96 }));
        assert_eq!(media.opus_payload_type, Some(96));
    }

    #[test]
    fn parse_sdp_finds_opus_even_when_not_first() {
        // Peer prefers PCMU but also offers Opus. `codec` reports their
        // preference; `opus_payload_type` is what lets our answer side
        // still pick Opus.
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 0 8 111\r\n\
                    a=rtpmap:111 opus/48000/2\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(media.codec, Some(AudioCodec::Pcmu));
        assert_eq!(media.opus_payload_type, Some(111));
    }

    #[test]
    fn parse_sdp_skips_unknown_dynamic_pt_to_next_known_codec() {
        // First PT is something we don't speak (G.729 at 18); the
        // resolved codec must be the next understood one, while the raw
        // first PT stays observable.
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 18 8 0\r\n\
                    a=rtpmap:18 G729/8000\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(media.payload_type, 18);
        assert_eq!(media.codec, Some(AudioCodec::Pcma));
    }

    #[test]
    fn parse_sdp_no_known_codec_yields_none() {
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 18\r\n\
                    a=rtpmap:18 G729/8000\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(media.codec, None);
        assert_eq!(select_codec(&media), None);
    }

    #[test]
    fn round_trip_build_offer_then_parse() {
        let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 5));
        let sdp = build_sdp_offer(ip, 8000);
        let media = parse_sdp(&sdp).unwrap();
        assert_eq!(media.addr, ip);
        assert_eq!(media.port, 8000);
        // Opus leads our own offer.
        assert_eq!(media.payload_type, OPUS_DEFAULT_PT);
        assert_eq!(
            media.codec,
            Some(AudioCodec::Opus {
                payload_type: OPUS_DEFAULT_PT
            })
        );
        // Both DTMF clocks parse back, and the Opus-matched pick is the
        // 48 kHz one.
        assert_eq!(media.dtmf_events.len(), 2);
        assert_eq!(
            media.dtmf(),
            Some(DtmfSpec {
                payload_type: DTMF_WIDEBAND_DEFAULT_PT,
                clock_rate: 48000
            })
        );
    }

    #[test]
    fn round_trip_pinned_answer_then_parse() {
        // Build the answer shape accept() sends and confirm the caller
        // side parses the negotiated codec back out of it.
        let menu = CodecMenu::Pinned {
            codec: AudioCodec::Opus { payload_type: 111 },
            dtmf: Some(DtmfSpec {
                payload_type: 110,
                clock_rate: 48000,
            }),
        };
        let sdp = build_sdp_with(ip(), 8000, menu, MediaDirection::SendRecv, 0);
        let media = parse_sdp(&sdp).unwrap();
        assert_eq!(media.codec, Some(AudioCodec::Opus { payload_type: 111 }));
        assert_eq!(
            media.dtmf(),
            Some(DtmfSpec {
                payload_type: 110,
                clock_rate: 48000
            })
        );
    }

    #[test]
    fn select_codec_prefers_opus_anywhere_in_the_offer() {
        // Peer's m= line prefers PCMU but lists Opus later — our policy
        // still picks Opus, at the peer's PT.
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 0 8 102\r\n\
                    a=rtpmap:102 opus/48000/2\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(
            select_codec(&media),
            Some(AudioCodec::Opus { payload_type: 102 })
        );
    }

    #[test]
    fn select_codec_falls_back_to_g711_without_opus() {
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 8 0\r\n";
        let media = parse_sdp(sdp).unwrap();
        // No Opus in the offer → the peer's first G.711, no Opus in the
        // answer.
        assert_eq!(select_codec(&media), Some(AudioCodec::Pcma));
    }

    #[test]
    fn select_dtmf_matches_the_codec_clock() {
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 111 0 101 110\r\n\
                    a=rtpmap:111 opus/48000/2\r\n\
                    a=rtpmap:101 telephone-event/8000\r\n\
                    a=rtpmap:110 telephone-event/48000\r\n";
        let media = parse_sdp(sdp).unwrap();
        // Opus selected → the 48 kHz event entry, even though the 8 kHz
        // one is listed first.
        assert_eq!(
            select_dtmf(&media, AudioCodec::Opus { payload_type: 111 }),
            Some(DtmfSpec {
                payload_type: 110,
                clock_rate: 48000
            })
        );
        // G.711 selected → the 8 kHz entry.
        assert_eq!(
            select_dtmf(&media, AudioCodec::Pcmu),
            Some(DtmfSpec {
                payload_type: 101,
                clock_rate: 8000
            })
        );
    }

    #[test]
    fn select_dtmf_falls_back_to_any_clock() {
        // Peer paired Opus with only an 8 kHz telephone-event (common
        // with older stacks). Better to use it at its own clock than to
        // degrade to SIP INFO.
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 111 101\r\n\
                    a=rtpmap:111 opus/48000/2\r\n\
                    a=rtpmap:101 telephone-event/8000\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(
            select_dtmf(&media, AudioCodec::Opus { payload_type: 111 }),
            Some(DtmfSpec {
                payload_type: 101,
                clock_rate: 8000
            })
        );
    }

    #[test]
    fn parse_sdp_accepts_telephone_event_at_48k() {
        // The regression this whole DTMF rework exists for: a peer that
        // pairs Opus with telephone-event/48000 must not be reported as
        // "no DTMF" (which silently degrades to SIP INFO).
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 111 110\r\n\
                    a=rtpmap:111 opus/48000/2\r\n\
                    a=rtpmap:110 telephone-event/48000\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(
            media.dtmf(),
            Some(DtmfSpec {
                payload_type: 110,
                clock_rate: 48000
            })
        );
    }

    #[test]
    fn parse_sdp_records_telephone_event_at_any_clock() {
        // RFC 4733 also defines other clocks (16000 for wideband
        // codecs). We record the advertised clock instead of rejecting
        // it — using the peer's entry at its own clock beats degrading
        // to SIP INFO.
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 0 101\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:101 telephone-event/16000\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(
            media.dtmf(),
            Some(DtmfSpec {
                payload_type: 101,
                clock_rate: 16000
            })
        );
    }

    #[test]
    fn parse_sdp_picks_dtmf_pt_from_rtpmap_not_constant() {
        // Some remotes negotiate telephone-event on a different dynamic PT
        // (96-127). The parser must follow the rtpmap, not assume 101.
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 0 96\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:96 telephone-event/8000\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(
            media.dtmf(),
            Some(DtmfSpec {
                payload_type: 96,
                clock_rate: 8000
            })
        );
    }

    #[test]
    fn parse_sdp_rejects_telephone_event_not_listed_on_m_line() {
        // rtpmap names PT 101 but the m=audio line doesn't include it →
        // not actually negotiated, must be ignored.
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 0\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:101 telephone-event/8000\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(media.dtmf(), None);
    }

    #[test]
    fn parse_sdp_handles_mixed_case_telephone_event() {
        // Some stacks emit "Telephone-Event" or "TELEPHONE-EVENT". Case
        // matching at the rtpmap level shouldn't reject those.
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 0 101\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:101 Telephone-Event/8000\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(
            media.dtmf(),
            Some(DtmfSpec {
                payload_type: 101,
                clock_rate: 8000
            })
        );
    }

    #[test]
    fn parse_sdp_handles_telephone_event_without_fmtp() {
        // `a=fmtp:101 0-15` is optional; many stacks omit it. Absence must
        // not gate negotiation.
        let sdp = b"v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 5000 RTP/AVP 0 101\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:101 telephone-event/8000\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert!(media.dtmf().is_some());
    }

    #[test]
    fn parse_sdp_g711_only_body_still_parses_as_before() {
        // Regression guard: the pre-Opus wire shape (what every 0.1.x
        // peer and most PBXes send) must keep parsing identically.
        let sdp = b"v=0\r\n\
                    o=wavekat 0 0 IN IP4 10.0.0.2\r\n\
                    s=wavekat-sip\r\n\
                    c=IN IP4 10.0.0.2\r\n\
                    t=0 0\r\n\
                    m=audio 5004 RTP/AVP 0 8 101\r\n\
                    a=rtpmap:0 PCMU/8000\r\n\
                    a=rtpmap:8 PCMA/8000\r\n\
                    a=rtpmap:101 telephone-event/8000\r\n\
                    a=fmtp:101 0-15\r\n\
                    a=sendrecv\r\n";
        let media = parse_sdp(sdp).unwrap();
        assert_eq!(media.payload_type, 0);
        assert_eq!(media.codec, Some(AudioCodec::Pcmu));
        assert_eq!(media.opus_payload_type, None);
        assert_eq!(
            media.dtmf(),
            Some(DtmfSpec {
                payload_type: 101,
                clock_rate: 8000
            })
        );
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

    #[test]
    fn audio_codec_wire_identities() {
        assert_eq!(AudioCodec::Pcmu.payload_type(), 0);
        assert_eq!(AudioCodec::Pcma.payload_type(), 8);
        assert_eq!(AudioCodec::Opus { payload_type: 96 }.payload_type(), 96);
        assert_eq!(AudioCodec::Pcmu.rtp_clock_rate(), 8000);
        assert_eq!(AudioCodec::Pcma.rtp_clock_rate(), 8000);
        // RFC 7587 §4.1: the Opus RTP clock is 48 kHz no matter what.
        assert_eq!(
            AudioCodec::Opus { payload_type: 96 }.rtp_clock_rate(),
            48000
        );
    }
}
