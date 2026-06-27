//! Call hold / resume via RFC 3264 re-INVITE.
//!
//! A confirmed call is put on hold by re-offering its media stream with
//! a one-directional [`MediaDirection`] (`SendOnly` to hold while still
//! sending — typically silence or music-on-hold — or `Inactive` to pause
//! both ways) inside a re-INVITE, and resumed by re-offering `SendRecv`.
//! Unlike a *local* mute that just stops feeding the wire, this tells the
//! far end it's on hold, so it can stop sending and play its own
//! music-on-hold.
//!
//! The re-INVITE reuses the same dialog seam as RFC 4028 session
//! refreshes ([`SessionDialogOps`]); the only differences are the media
//! direction in the offer and that the answer is parsed back so the
//! caller can observe the remote's response. This crate owns the
//! signaling; what to *send* on the RTP stream while held (silence,
//! music) is the consumer's audio concern.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rsip::{Header, StatusCode};
use rsipstack::dialog::client_dialog::ClientInviteDialog;
use rsipstack::dialog::server_dialog::ServerInviteDialog;

use crate::sdp::{build_sdp_with_direction, parse_sdp, MediaDirection, RemoteMedia};
use crate::session_timer::SessionDialogOps;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Re-offer a confirmed call's media in `direction` via a re-INVITE,
/// returning the remote's re-parsed media answer.
///
/// This is the primitive behind call hold: pass [`MediaDirection::SendOnly`]
/// (or [`MediaDirection::Inactive`]) to hold and [`MediaDirection::SendRecv`]
/// to resume. The SDP re-offer keeps the same RTP port and codecs as the
/// original call — only the `a=<direction>` attribute changes — so the
/// dialog and any session timer stay healthy across the transition.
///
/// `local_rtp_addr` is the address advertised in the original SDP (an
/// [`AcceptedCall`](crate::AcceptedCall) / [`AcceptedDial`](crate::AcceptedDial)
/// exposes it as `local_rtp_addr`); re-advertising it unchanged keeps the
/// remote sending to the same socket.
///
/// `session_version` is the RFC 3264 §8 `o=` line version for this
/// re-offer — it **must increase** on each successive re-offer within the
/// dialog (the initial offer/answer was `0`, so pass `1`, `2`, … here).
/// A static version is the classic hold→resume interop failure: a carrier
/// SBC accepts the hold but rejects the resume with `500` because the
/// body changed while the version did not. [`HoldHandle`] keeps the
/// counter so callers don't have to; reach for this primitive directly
/// only if you own the monotonicity yourself.
///
/// Returns:
/// - `Ok(Some(media))` — the peer answered `200 OK` with an SDP body,
///   re-parsed here (its direction reflects what the peer agreed to,
///   e.g. `RecvOnly` answering our `SendOnly`).
/// - `Ok(None)` — the peer answered `200 OK` with no SDP body (some
///   stacks omit it when nothing else changed). The hold/resume was
///   still signaled; the existing media parameters stand.
/// - `Err` — the dialog was no longer confirmed (nothing sent) or the
///   peer rejected the re-INVITE with a non-2xx final response.
pub async fn reoffer_media<D: SessionDialogOps>(
    dialog: &D,
    local_rtp_addr: SocketAddr,
    direction: MediaDirection,
    session_version: u64,
) -> Result<Option<RemoteMedia>, BoxError> {
    let body = build_sdp_with_direction(
        local_rtp_addr.ip(),
        local_rtp_addr.port(),
        direction,
        session_version,
    );
    let headers = vec![Header::ContentType("application/sdp".into())];

    let resp = dialog
        .refresh(headers, Some(body))
        .await?
        .ok_or("re-INVITE not sent: dialog is no longer confirmed")?;

    if resp.status_code != StatusCode::OK {
        return Err(format!(
            "re-INVITE for media change rejected: {}{}",
            resp.status_code,
            rejection_detail(&resp.headers),
        )
        .into());
    }

    if resp.body.is_empty() {
        return Ok(None);
    }
    parse_sdp(&resp.body).map(Some).map_err(Into::into)
}

/// Pull the human-meaningful "why" out of a non-2xx re-INVITE response
/// so a rejection logs something a person can act on instead of a bare
/// status code. SIP servers that refuse a media change usually say why
/// in a `Warning` header (RFC 3261 §20.43, e.g. `399 sbc "Codec
/// negotiation failed"`) or a `Reason` header (RFC 3326); we surface
/// whichever are present, formatted as ` (Warning: …; Reason: …)`, or an
/// empty string when the response carries neither.
fn rejection_detail(headers: &rsip::Headers) -> String {
    let mut parts: Vec<String> = Vec::new();
    for header in headers.iter() {
        match header {
            // The typed `Warning` Display already renders as
            // `Warning: <code> <agent> "<text>"`, so don't re-prefix it.
            Header::Warning(w) => parts.push(w.to_string()),
            Header::Other(name, value) if name.eq_ignore_ascii_case("Reason") => {
                parts.push(format!("Reason: {value}"))
            }
            _ => {}
        }
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join("; "))
    }
}

/// Advance a call-scoped `o=` version counter and return the value to
/// stamp on the next re-offer. The counter holds the *last used* version
/// (seeded to `0` for the initial offer/answer), so this returns `1` on
/// the first call, `2` on the next, … — a strictly increasing series, as
/// RFC 3264 §8 requires across re-offers within one dialog.
fn next_session_version(counter: &AtomicU64) -> u64 {
    counter.fetch_add(1, Ordering::Relaxed) + 1
}

/// The media direction to re-offer for a hold (`true`) or resume
/// (`false`): standard RFC 3264 call hold is `sendonly` — we keep the
/// stream and feed it silence/music while asking the peer to stop —
/// resumed with `sendrecv`.
pub fn hold_direction(held: bool) -> MediaDirection {
    if held {
        MediaDirection::SendOnly
    } else {
        MediaDirection::SendRecv
    }
}

/// A cheap, cloneable handle that can place one confirmed call on hold /
/// resume it via [`reoffer_media`], without borrowing the
/// [`AcceptedCall`](crate::AcceptedCall) / [`AcceptedDial`](crate::AcceptedDial)
/// it came from.
///
/// Both inner dialog types are `Clone`, so a consumer can snapshot this
/// under whatever lock guards its live-call table, *release the lock*,
/// and only then await the re-INVITE round-trip — re-INVITE latency is a
/// full SIP transaction and must not be held across a contended lock.
///
/// Obtain one from [`AcceptedCall::hold_handle`](crate::AcceptedCall::hold_handle)
/// or [`AcceptedDial::hold_handle`](crate::AcceptedDial::hold_handle).
///
/// The shared `session_version` counter is what makes successive
/// hold/resume re-offers RFC 3264 §8-compliant: every handle minted for
/// one call clones the *same* `Arc<AtomicU64>`, so a hold (version 1) and
/// the resume that follows it (version 2) advance one monotonic series
/// even though each request snapshots a fresh handle. A per-handle
/// counter would reset to the same value each time and reintroduce the
/// static-version bug, so this Arc is deliberately call-scoped.
#[derive(Clone)]
pub struct HoldHandle {
    dialog: HoldDialog,
    local_rtp_addr: SocketAddr,
    /// Call-scoped monotonic `o=` version source (initial SDP was `0`).
    session_version: Arc<AtomicU64>,
}

#[derive(Clone)]
enum HoldDialog {
    Server(ServerInviteDialog),
    Client(ClientInviteDialog),
}

impl HoldHandle {
    /// Build a handle for an inbound (server-side) call's dialog.
    ///
    /// `session_version` is the call-scoped monotonic `o=` version
    /// counter (the [`AcceptedCall`](crate::AcceptedCall) owns it, seeded
    /// to `0` to match its initial SDP answer); all handles minted for
    /// one call must share the same `Arc` so re-offer versions advance
    /// across requests rather than resetting.
    pub fn for_server(
        dialog: ServerInviteDialog,
        local_rtp_addr: SocketAddr,
        session_version: Arc<AtomicU64>,
    ) -> Self {
        Self {
            dialog: HoldDialog::Server(dialog),
            local_rtp_addr,
            session_version,
        }
    }

    /// Build a handle for an outbound (client-side) call's dialog. See
    /// [`Self::for_server`] for the `session_version` contract.
    pub fn for_client(
        dialog: ClientInviteDialog,
        local_rtp_addr: SocketAddr,
        session_version: Arc<AtomicU64>,
    ) -> Self {
        Self {
            dialog: HoldDialog::Client(dialog),
            local_rtp_addr,
            session_version,
        }
    }

    /// Place the call on hold (`held = true`, re-offer `sendonly`) or
    /// resume it (`held = false`, re-offer `sendrecv`). Same return-value
    /// contract as [`reoffer_media`].
    ///
    /// Each call bumps the shared `o=` version first, so the offer
    /// carries a strictly higher RFC 3264 §8 version than the previous
    /// one (initial SDP was `0`, so the first re-offer is `1`).
    pub async fn set_hold(&self, held: bool) -> Result<Option<RemoteMedia>, BoxError> {
        let direction = hold_direction(held);
        // 1, 2, 3, … across this call's hold/resume requests (the initial
        // offer/answer occupied 0).
        let version = next_session_version(&self.session_version);
        match &self.dialog {
            HoldDialog::Server(d) => {
                reoffer_media(d, self.local_rtp_addr, direction, version).await
            }
            HoldDialog::Client(d) => {
                reoffer_media(d, self.local_rtp_addr, direction, version).await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsip::Headers;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    /// Scripted mock dialog: records the SDP body of each re-INVITE and
    /// replies with a canned response. Mirrors the `MockDialog` pattern
    /// in `session_timer.rs`, trimmed to what hold needs.
    struct MockDialog {
        bodies: Mutex<Vec<Vec<u8>>>,
        reply: Mutex<Option<Result<Option<rsip::Response>, String>>>,
    }

    impl MockDialog {
        fn new(reply: Result<Option<rsip::Response>, String>) -> Self {
            Self {
                bodies: Mutex::new(Vec::new()),
                reply: Mutex::new(Some(reply)),
            }
        }

        fn last_body(&self) -> String {
            String::from_utf8(self.bodies.lock().unwrap().last().cloned().unwrap()).unwrap()
        }
    }

    impl SessionDialogOps for MockDialog {
        async fn refresh(
            &self,
            _headers: Vec<Header>,
            body: Option<Vec<u8>>,
        ) -> Result<Option<rsip::Response>, BoxError> {
            self.bodies.lock().unwrap().push(body.unwrap_or_default());
            self.reply
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .map_err(Into::into)
        }

        async fn send_bye(&self) -> Result<(), BoxError> {
            Ok(())
        }
    }

    fn response(code: u16, body: Vec<u8>) -> rsip::Response {
        rsip::Response {
            status_code: StatusCode::from(code),
            version: rsip::Version::V2,
            headers: Headers::default(),
            body,
        }
    }

    fn addr() -> SocketAddr {
        SocketAddr::new(Ipv4Addr::new(10, 0, 0, 7).into(), 40000)
    }

    #[tokio::test]
    async fn hold_offers_sendonly_and_parses_answer() {
        // Peer answers our sendonly hold with recvonly, the usual mirror.
        let answer = build_sdp_with_direction(
            Ipv4Addr::new(203, 0, 113, 9).into(),
            8000,
            MediaDirection::RecvOnly,
            1,
        );
        let dialog = MockDialog::new(Ok(Some(response(200, answer))));

        let media = reoffer_media(&dialog, addr(), MediaDirection::SendOnly, 1)
            .await
            .unwrap()
            .expect("answer had SDP");

        // We offered sendonly at our own RTP port…
        let offered = dialog.last_body();
        assert!(offered.contains("a=sendonly\r\n"));
        assert!(offered.contains("m=audio 40000 RTP/AVP 0 8 101\r\n"));
        // …with the re-offer's `o=` version (1, one past the initial 0)…
        assert!(offered.contains("o=wavekat 0 1 IN IP4 10.0.0.7\r\n"));
        // …and read the peer's recvonly answer back.
        assert_eq!(media.direction, MediaDirection::RecvOnly);
        assert_eq!(media.port, 8000);
    }

    #[tokio::test]
    async fn resume_offers_sendrecv() {
        let answer = build_sdp_with_direction(
            Ipv4Addr::new(203, 0, 113, 9).into(),
            8000,
            MediaDirection::SendRecv,
            2,
        );
        let dialog = MockDialog::new(Ok(Some(response(200, answer))));

        reoffer_media(&dialog, addr(), MediaDirection::SendRecv, 2)
            .await
            .unwrap();
        let offered = dialog.last_body();
        assert!(offered.contains("a=sendrecv\r\n"));
        // A resume after one hold carries version 2 — strictly greater
        // than the hold's 1, as RFC 3264 §8 requires.
        assert!(offered.contains("o=wavekat 0 2 IN IP4 10.0.0.7\r\n"));
    }

    #[tokio::test]
    async fn empty_2xx_body_is_ok_none() {
        // A bare 200 OK (no SDP) still confirms the hold; media stands.
        let dialog = MockDialog::new(Ok(Some(response(200, Vec::new()))));
        let out = reoffer_media(&dialog, addr(), MediaDirection::SendOnly, 1)
            .await
            .unwrap();
        assert_eq!(out, None);
    }

    #[tokio::test]
    async fn non_2xx_is_error() {
        // 488 Not Acceptable Here — the peer refused the media change.
        let dialog = MockDialog::new(Ok(Some(response(488, Vec::new()))));
        let err = reoffer_media(&dialog, addr(), MediaDirection::SendOnly, 1)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("488"));
    }

    #[tokio::test]
    async fn unconfirmed_dialog_is_error() {
        // refresh() returns None when the dialog is no longer confirmed.
        let dialog = MockDialog::new(Ok(None));
        let err = reoffer_media(&dialog, addr(), MediaDirection::SendOnly, 1)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no longer confirmed"));
    }

    #[test]
    fn hold_direction_maps_held_to_sendonly() {
        assert_eq!(hold_direction(true), MediaDirection::SendOnly);
        assert_eq!(hold_direction(false), MediaDirection::SendRecv);
    }

    #[test]
    fn rejection_detail_surfaces_warning_and_reason() {
        use rsip::headers::{UntypedHeader, Warning};

        // No diagnostic headers → no trailing detail (the bare status
        // code already carries everything we know).
        assert_eq!(rejection_detail(&Headers::default()), "");

        // A Warning header (RFC 3261 §20.43) is the usual "why" an SBC
        // attaches to a refused media change.
        let mut warned = Headers::default();
        warned.push(Header::Warning(Warning::new(
            "399 sbc \"Codec negotiation failed\"",
        )));
        assert_eq!(
            rejection_detail(&warned),
            " (Warning: 399 sbc \"Codec negotiation failed\")"
        );

        // Warning + Reason (RFC 3326) are joined, in header order.
        let mut both = warned.clone();
        both.push(Header::Other(
            "Reason".into(),
            "SIP;cause=500;text=\"internal\"".into(),
        ));
        assert_eq!(
            rejection_detail(&both),
            " (Warning: 399 sbc \"Codec negotiation failed\"; Reason: SIP;cause=500;text=\"internal\")"
        );
    }

    #[test]
    fn session_version_increases_across_reoffers() {
        // Regression: a hold then a resume must carry strictly increasing
        // `o=` versions (1, then 2) one past the initial answer's 0. The
        // earlier static-version offer made carrier SBCs 500 the resume.
        let counter = AtomicU64::new(0);
        let versions: Vec<u64> = (0..4).map(|_| next_session_version(&counter)).collect();
        assert_eq!(versions, vec![1, 2, 3, 4]);
    }
}
