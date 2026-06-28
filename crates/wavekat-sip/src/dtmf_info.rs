//! SIP INFO fallback transport for DTMF (`application/dtmf-relay`).
//!
//! When the SDP answer omits `telephone-event/8000`
//! ([`crate::RemoteMedia::dtmf_payload_type`] is `None`), the remote
//! hasn't agreed to RFC 4733 — but most legacy PBXes still accept DTMF
//! via SIP `INFO` requests inside the dialog with the
//! `application/dtmf-relay` body originally defined by Cisco. This
//! module builds that body, classifies the response, and is driven by
//! [`crate::Call::send_dtmf_info`].
//!
//! ## Wire format
//!
//! ```text
//! INFO sip:carrier@example.com SIP/2.0
//! ...
//! Content-Type: application/dtmf-relay
//! Content-Length: 22
//!
//! Signal=5
//! Duration=160
//! ```
//!
//! `Signal` is the digit character (`0`-`9`, `*`, `#`, `A`-`D`).
//! `Duration` is in milliseconds (typical: 100-200). Lines are
//! separated by a single `\n` per the de-facto format — no CR.
//!
//! ## When to call
//!
//! Use [`crate::Call::send_dtmf_info`] only after confirming the remote
//! did not negotiate `telephone-event/8000`. If RFC 4733 is available,
//! prefer [`crate::send_dtmf_burst`] — it's what every modern carrier
//! expects and the wire footprint is smaller. A 415 (Unsupported Media
//! Type) response means the remote rejects this transport too; surface
//! it to the user as "this trunk doesn't accept touch-tones" and stop
//! trying ([`InfoOutcome::should_stop`]).

use rsip::{Header, StatusCode};
use tracing::warn;

use crate::rtp::dtmf::DtmfDigit;

/// MIME type for the DTMF body carried in the `INFO` request.
pub const CONTENT_TYPE: &str = "application/dtmf-relay";

/// Build the `application/dtmf-relay` body for one DTMF press.
///
/// Returns a `String` like `"Signal=5\nDuration=160"`. No trailing
/// newline. The consumer wraps this in `Vec<u8>` to send.
pub fn build_info_body(digit: DtmfDigit, duration_ms: u32) -> String {
    format!("Signal={}\nDuration={duration_ms}", digit.as_char())
}

/// Build the `Content-Type: application/dtmf-relay` header to attach to
/// the `INFO` request.
pub fn content_type_header() -> Header {
    Header::ContentType(CONTENT_TYPE.into())
}

/// Possible outcomes of one INFO-DTMF attempt.
#[derive(Debug)]
pub enum InfoOutcome {
    /// The remote returned a 2xx response. Press accepted.
    Accepted(StatusCode),
    /// The remote returned 415 (Unsupported Media Type) — it does not
    /// accept `application/dtmf-relay`. Consumers should stop sending
    /// further INFO presses on this dialog and surface a user-facing
    /// error.
    UnsupportedMedia,
    /// The remote returned a non-2xx, non-415 response. Logged but
    /// not retried — same observable effect as packet loss.
    OtherFailure(StatusCode),
    /// No final response arrived (e.g. the dialog already ended).
    DialogNotConfirmed,
}

impl InfoOutcome {
    /// `true` if the press was accepted by the remote.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted(_))
    }

    /// `true` if the remote signalled this transport is unusable and
    /// further presses on this dialog should not be attempted.
    pub fn should_stop(&self) -> bool {
        matches!(self, Self::UnsupportedMedia)
    }
}

/// Classify the engine's in-dialog `INFO` result into an [`InfoOutcome`].
///
/// `None` (no final response) maps to [`InfoOutcome::DialogNotConfirmed`];
/// the common cause is that the call has already ended.
pub(crate) fn classify(response: Option<rsip::Response>) -> InfoOutcome {
    let Some(r) = response else {
        return InfoOutcome::DialogNotConfirmed;
    };
    let code = r.status_code.code();
    if (200..300).contains(&code) {
        InfoOutcome::Accepted(r.status_code)
    } else if code == 415 {
        warn!(
            "remote rejected application/dtmf-relay (415); \
             stop sending INFO DTMF on this dialog"
        );
        InfoOutcome::UnsupportedMedia
    } else {
        warn!(status = %r.status_code, "INFO DTMF failed");
        InfoOutcome::OtherFailure(r.status_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_format_matches_application_dtmf_relay() {
        // Cisco's original spec — `Signal=<char>\nDuration=<ms>`. No CR,
        // no trailing newline. Verbatim wire bytes get checked here
        // because any deviation can quietly break a PBX's parser.
        let body = build_info_body(DtmfDigit::D5, 160);
        assert_eq!(body, "Signal=5\nDuration=160");
    }

    #[test]
    fn body_uses_digit_canonical_char_for_star_pound() {
        assert_eq!(
            build_info_body(DtmfDigit::Star, 100),
            "Signal=*\nDuration=100"
        );
        assert_eq!(
            build_info_body(DtmfDigit::Pound, 100),
            "Signal=#\nDuration=100"
        );
    }

    #[test]
    fn body_uppercases_letter_digits() {
        // RFC 4733 digit codes 12-15 correspond to the AUTOVON A/B/C/D
        // keys; `DtmfDigit::as_char` returns uppercase. The body must
        // carry that uppercase form so any remote that whitelists the
        // letters case-sensitively still accepts the press.
        assert_eq!(build_info_body(DtmfDigit::A, 160), "Signal=A\nDuration=160");
        assert_eq!(build_info_body(DtmfDigit::D, 160), "Signal=D\nDuration=160");
    }

    #[test]
    fn content_type_header_is_application_dtmf_relay() {
        let h = content_type_header();
        let s = h.to_string();
        assert!(
            s.contains(CONTENT_TYPE),
            "header should contain {CONTENT_TYPE}, got {s:?}"
        );
    }

    #[test]
    fn classify_2xx_response_is_accepted() {
        let resp = make_response(200);
        match classify(Some(resp)) {
            InfoOutcome::Accepted(code) => assert_eq!(code.code(), 200),
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[test]
    fn classify_415_response_is_unsupported_media() {
        let resp = make_response(415);
        assert!(matches!(
            classify(Some(resp)),
            InfoOutcome::UnsupportedMedia
        ));
    }

    #[test]
    fn classify_500_response_is_other_failure() {
        let resp = make_response(500);
        match classify(Some(resp)) {
            InfoOutcome::OtherFailure(code) => assert_eq!(code.code(), 500),
            other => panic!("expected OtherFailure, got {other:?}"),
        }
    }

    #[test]
    fn classify_none_response_is_dialog_not_confirmed() {
        // The engine returns `None` when no final response arrives; treat
        // that as a distinct outcome so the consumer can refresh its UI
        // rather than retry.
        assert!(matches!(classify(None), InfoOutcome::DialogNotConfirmed));
    }

    #[test]
    fn outcome_helpers() {
        let accepted = InfoOutcome::Accepted(StatusCode::from(200u16));
        assert!(accepted.is_accepted());
        assert!(!accepted.should_stop());

        let unsupported = InfoOutcome::UnsupportedMedia;
        assert!(!unsupported.is_accepted());
        assert!(unsupported.should_stop());

        let other = InfoOutcome::OtherFailure(StatusCode::from(500u16));
        assert!(!other.is_accepted());
        assert!(!other.should_stop());
    }

    /// Minimal rsip::Response builder for the classifier tests. The
    /// classifier only inspects `status_code`, so the rest stays empty.
    fn make_response(code: u16) -> rsip::Response {
        rsip::Response {
            status_code: StatusCode::from(code),
            version: rsip::Version::V2,
            headers: rsip::Headers::default(),
            body: Vec::new(),
        }
    }
}
