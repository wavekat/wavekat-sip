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
) -> Result<Option<RemoteMedia>, BoxError> {
    let body = build_sdp_with_direction(local_rtp_addr.ip(), local_rtp_addr.port(), direction);
    let headers = vec![Header::ContentType("application/sdp".into())];

    let resp = dialog
        .refresh(headers, Some(body))
        .await?
        .ok_or("re-INVITE not sent: dialog is no longer confirmed")?;

    if resp.status_code != StatusCode::OK {
        return Err(format!("re-INVITE for media change rejected: {}", resp.status_code).into());
    }

    if resp.body.is_empty() {
        return Ok(None);
    }
    parse_sdp(&resp.body).map(Some).map_err(Into::into)
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
#[derive(Clone)]
pub struct HoldHandle {
    dialog: HoldDialog,
    local_rtp_addr: SocketAddr,
}

#[derive(Clone)]
enum HoldDialog {
    Server(ServerInviteDialog),
    Client(ClientInviteDialog),
}

impl HoldHandle {
    /// Build a handle for an inbound (server-side) call's dialog.
    pub fn for_server(dialog: ServerInviteDialog, local_rtp_addr: SocketAddr) -> Self {
        Self {
            dialog: HoldDialog::Server(dialog),
            local_rtp_addr,
        }
    }

    /// Build a handle for an outbound (client-side) call's dialog.
    pub fn for_client(dialog: ClientInviteDialog, local_rtp_addr: SocketAddr) -> Self {
        Self {
            dialog: HoldDialog::Client(dialog),
            local_rtp_addr,
        }
    }

    /// Place the call on hold (`held = true`, re-offer `sendonly`) or
    /// resume it (`held = false`, re-offer `sendrecv`). Same return-value
    /// contract as [`reoffer_media`].
    pub async fn set_hold(&self, held: bool) -> Result<Option<RemoteMedia>, BoxError> {
        let direction = hold_direction(held);
        match &self.dialog {
            HoldDialog::Server(d) => reoffer_media(d, self.local_rtp_addr, direction).await,
            HoldDialog::Client(d) => reoffer_media(d, self.local_rtp_addr, direction).await,
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
        );
        let dialog = MockDialog::new(Ok(Some(response(200, answer))));

        let media = reoffer_media(&dialog, addr(), MediaDirection::SendOnly)
            .await
            .unwrap()
            .expect("answer had SDP");

        // We offered sendonly at our own RTP port…
        let offered = dialog.last_body();
        assert!(offered.contains("a=sendonly\r\n"));
        assert!(offered.contains("m=audio 40000 RTP/AVP 0 8 101\r\n"));
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
        );
        let dialog = MockDialog::new(Ok(Some(response(200, answer))));

        reoffer_media(&dialog, addr(), MediaDirection::SendRecv)
            .await
            .unwrap();
        assert!(dialog.last_body().contains("a=sendrecv\r\n"));
    }

    #[tokio::test]
    async fn empty_2xx_body_is_ok_none() {
        // A bare 200 OK (no SDP) still confirms the hold; media stands.
        let dialog = MockDialog::new(Ok(Some(response(200, Vec::new()))));
        let out = reoffer_media(&dialog, addr(), MediaDirection::SendOnly)
            .await
            .unwrap();
        assert_eq!(out, None);
    }

    #[tokio::test]
    async fn non_2xx_is_error() {
        // 488 Not Acceptable Here — the peer refused the media change.
        let dialog = MockDialog::new(Ok(Some(response(488, Vec::new()))));
        let err = reoffer_media(&dialog, addr(), MediaDirection::SendOnly)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("488"));
    }

    #[tokio::test]
    async fn unconfirmed_dialog_is_error() {
        // refresh() returns None when the dialog is no longer confirmed.
        let dialog = MockDialog::new(Ok(None));
        let err = reoffer_media(&dialog, addr(), MediaDirection::SendOnly)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no longer confirmed"));
    }

    #[test]
    fn hold_direction_maps_held_to_sendonly() {
        assert_eq!(hold_direction(true), MediaDirection::SendOnly);
        assert_eq!(hold_direction(false), MediaDirection::SendRecv);
    }
}
