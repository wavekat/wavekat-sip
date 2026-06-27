//! RFC 4028 session timers — keep long calls from outliving a dead dialog.
//!
//! Without session timers, a call whose dialog silently died (peer
//! crashed, NAT binding dropped, proxy lost state) lives forever:
//! nothing on the signaling path re-validates the dialog, so an
//! unattended consumer (voice bot, AI agent) keeps streaming RTP into
//! the void. RFC 4028 bounds that window: one side periodically
//! refreshes the session with a re-INVITE, and the other side tears the
//! call down with BYE if no refresh arrives before the negotiated
//! session interval lapses.
//!
//! This module has three layers:
//!
//! 1. **Pure header logic** — [`SessionExpires`] parse/build for the
//!    `Session-Expires` header (with its `;refresher=uac|uas` param),
//!    [`min_se_in`] for `Min-SE`, and [`supports_timer`] for the
//!    `Supported: timer` option tag. rsip 0.4 has no typed variants for
//!    these, so they are parsed manually from
//!    [`rsip::Header::Other`] — same style as the crate's SDP and RTP
//!    parsing.
//! 2. **Negotiation** — [`negotiate_uac`] (from a 2xx response, caller
//!    side) and [`negotiate_uas`] (from an INVITE, callee side) decide
//!    the [`SessionTimer`]: the negotiated interval and whether *we*
//!    are the refresher. [`SessionTimer::refresh_after`] /
//!    [`SessionTimer::expiry_after`] give the RFC 4028 §10 schedule.
//! 3. **Runtime** — [`session_timer_loop`], shaped like
//!    [`crate::Registrar::keepalive_loop`]: a `select!` over sleeps and
//!    a [`CancellationToken`] that either sends the periodic refresh
//!    re-INVITE (when we are the refresher) or watches for the peer's
//!    refreshes and sends BYE when the session lapses.
//!
//! # Wiring it up
//!
//! [`crate::Caller`] and [`crate::IncomingCall`] negotiate for you:
//! [`crate::Call::session_timer`] carries the result. Drive the loop
//! against the call's shareable dialog handle
//! ([`crate::Call::session_handle`]) so it runs alongside the audio path:
//!
//! ```ignore
//! if let Some(timer) = call.session_timer() {
//!     let handle = call.session_handle();
//!     let refreshed = std::sync::Arc::new(tokio::sync::Notify::new());
//!     let sdp = build_sdp(local_ip, rtp_port); // repeat our offer
//!     tokio::spawn(async move {
//!         let outcome =
//!             session_timer_loop(&handle, timer, Some(sdp), refreshed, cancel).await;
//!         tracing::info!(?outcome, "session timer finished");
//!     });
//! }
//! ```
//!
//! When the **peer** is the refresher, its refresh re-INVITEs arrive as
//! inbound in-dialog requests. The consumer answers them with an SDP
//! answer (echoing `Session-Expires`) and pings `refreshed` so the
//! watchdog deadline resets.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use rsip::prelude::UntypedHeader;
use rsip::Header;
use tokio::select;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Smallest session interval we will run a timer at, in seconds.
/// RFC 4028 §4 fixes 90 s as the absolute minimum (and the default
/// `Min-SE`); anything shorter would churn re-INVITEs.
pub const MIN_SESSION_EXPIRES_SECS: u32 = 90;

/// Session interval requested on outbound INVITEs, in seconds — the
/// RFC 4028 recommended default of 30 minutes.
pub const DEFAULT_SESSION_EXPIRES_SECS: u32 = 1800;

/// Cap on how far *before* the session expiry the non-refresher fires
/// its BYE watchdog (RFC 4028 §10: `min(32 s, interval / 3)`).
const MAX_EXPIRY_HEADROOM_SECS: u32 = 32;

/// Which side of the original INVITE transaction performs refreshes —
/// the value space of the `Session-Expires` `refresher` parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refresher {
    /// The party that sent the request refreshes.
    Uac,
    /// The party that answered the request refreshes.
    Uas,
}

impl Refresher {
    /// Canonical lowercase parameter value (`"uac"` / `"uas"`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Refresher::Uac => "uac",
            Refresher::Uas => "uas",
        }
    }

    fn parse(s: &str) -> Result<Self, String> {
        if s.eq_ignore_ascii_case("uac") {
            Ok(Refresher::Uac)
        } else if s.eq_ignore_ascii_case("uas") {
            Ok(Refresher::Uas)
        } else {
            Err(format!("invalid refresher value {s:?} (want uac|uas)"))
        }
    }
}

/// Parsed `Session-Expires` header value: interval in seconds plus the
/// optional `refresher` parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionExpires {
    /// Session interval in seconds.
    pub interval_secs: u32,
    /// Who refreshes, if pinned. `None` means "answerer's choice".
    pub refresher: Option<Refresher>,
}

impl SessionExpires {
    /// Parse a `Session-Expires` header *value* (not the full header
    /// line), e.g. `"1800"` or `"1800;refresher=uas"`. Parameter names
    /// and values are case-insensitive; unknown parameters are ignored
    /// per RFC 4028 §4.
    pub fn parse(value: &str) -> Result<Self, String> {
        let mut parts = value.split(';');
        let interval = parts.next().unwrap_or("").trim();
        let interval_secs: u32 = interval
            .parse()
            .map_err(|e| format!("invalid Session-Expires interval {interval:?}: {e}"))?;
        let mut refresher = None;
        for param in parts {
            if let Some((name, val)) = param.split_once('=') {
                if name.trim().eq_ignore_ascii_case("refresher") {
                    refresher = Some(Refresher::parse(val.trim())?);
                }
            }
        }
        Ok(Self {
            interval_secs,
            refresher,
        })
    }

    /// Serialize back to a header value, e.g. `"1800;refresher=uac"`.
    pub fn header_value(&self) -> String {
        match self.refresher {
            Some(r) => format!("{};refresher={}", self.interval_secs, r.as_str()),
            None => self.interval_secs.to_string(),
        }
    }

    /// Build the untyped `Session-Expires` header (rsip 0.4 has no
    /// typed variant).
    pub fn header(&self) -> Header {
        Header::Other("Session-Expires".into(), self.header_value())
    }
}

/// `Supported: timer` — advertise RFC 4028 support on a request or
/// response.
pub fn supported_timer_header() -> Header {
    Header::Supported("timer".into())
}

/// `Require: timer` — placed in a 2xx by the answerer when the offerer
/// advertised timer support (RFC 4028 §9).
pub fn require_timer_header() -> Header {
    Header::Require("timer".into())
}

/// Find the value of the first untyped header matching any of `names`
/// (case-insensitive).
fn other_header_value<'a>(headers: &'a rsip::Headers, names: &[&str]) -> Option<&'a str> {
    headers.iter().find_map(|h| match h {
        Header::Other(name, value) if names.iter().any(|n| name.eq_ignore_ascii_case(n)) => {
            Some(value.as_str())
        }
        _ => None,
    })
}

/// Extract and parse the `Session-Expires` header (long or compact `x`
/// form) from a header list. Malformed values are logged and treated as
/// absent — a broken peer header must not kill the call.
pub fn session_expires_in(headers: &rsip::Headers) -> Option<SessionExpires> {
    let raw = other_header_value(headers, &["Session-Expires", "x"])?;
    match SessionExpires::parse(raw) {
        Ok(se) => Some(se),
        Err(e) => {
            warn!("ignoring malformed Session-Expires header: {e}");
            None
        }
    }
}

/// Extract the `Min-SE` interval (seconds) from a header list, ignoring
/// any generic parameters. Malformed values are treated as absent.
pub fn min_se_in(headers: &rsip::Headers) -> Option<u32> {
    let raw = other_header_value(headers, &["Min-SE"])?;
    let interval = raw.split(';').next().unwrap_or("").trim();
    match interval.parse() {
        Ok(v) => Some(v),
        Err(e) => {
            warn!("ignoring malformed Min-SE header {raw:?}: {e}");
            None
        }
    }
}

fn has_timer_token(value: &str) -> bool {
    value
        .split(',')
        .any(|tag| tag.trim().eq_ignore_ascii_case("timer"))
}

/// `true` if any `Supported` header (typed, untyped, or compact `k`
/// form) carries the `timer` option tag.
pub fn supports_timer(headers: &rsip::Headers) -> bool {
    headers.iter().any(|h| match h {
        Header::Supported(s) => has_timer_token(s.value()),
        Header::Other(name, value)
            if name.eq_ignore_ascii_case("Supported") || name.eq_ignore_ascii_case("k") =>
        {
            has_timer_token(value)
        }
        _ => false,
    })
}

/// Negotiated session-timer state for one dialog, from our side's
/// perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionTimer {
    /// Negotiated session interval in seconds.
    pub interval_secs: u32,
    /// `true` if we send the periodic refresh re-INVITEs; `false` if we
    /// only watch for the peer's refreshes and BYE on expiry.
    pub we_are_refresher: bool,
}

impl SessionTimer {
    /// When the refresher sends its refresh: half the session interval
    /// after the last refresh (RFC 4028 §10).
    pub fn refresh_after(&self) -> Duration {
        Duration::from_secs(u64::from(self.interval_secs / 2))
    }

    /// When the non-refresher gives up and sends BYE: the session
    /// interval minus `min(32 s, interval / 3)` after the last refresh
    /// (RFC 4028 §10).
    pub fn expiry_after(&self) -> Duration {
        let headroom = (self.interval_secs / 3).min(MAX_EXPIRY_HEADROOM_SECS);
        Duration::from_secs(u64::from(self.interval_secs.saturating_sub(headroom)))
    }
}

/// UAC-side negotiation: decide the [`SessionTimer`] from the 2xx
/// response to our INVITE.
///
/// Returns `None` when the response carries no `Session-Expires` — the
/// answerer declined (or doesn't support) session timers, so no timer
/// runs. When the (mandatory per RFC 4028 §9) `refresher` parameter is
/// missing we defensively take the refresher role ourselves: refreshing
/// when the peer also refreshes is redundant but harmless, while *not*
/// refreshing when the peer expects us to would drop the call.
///
/// The interval is floored at [`MIN_SESSION_EXPIRES_SECS`] so a bogus
/// tiny grant can't spin the refresh loop.
pub fn negotiate_uac(response_headers: &rsip::Headers) -> Option<SessionTimer> {
    let se = session_expires_in(response_headers)?;
    Some(SessionTimer {
        interval_secs: se.interval_secs.max(MIN_SESSION_EXPIRES_SECS),
        we_are_refresher: !matches!(se.refresher, Some(Refresher::Uas)),
    })
}

/// UAS-side negotiation result: the timer to run plus what to put in
/// our 2xx so the peer agrees on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UasSessionTimer {
    /// Timer state from our (UAS) perspective.
    pub timer: SessionTimer,
    /// `Session-Expires` to echo in the 2xx (interval + pinned
    /// refresher).
    pub echo: SessionExpires,
    /// `true` if the peer advertised `Supported: timer`, in which case
    /// the 2xx must also carry `Require: timer` (RFC 4028 §9).
    pub require_timer: bool,
}

/// UAS-side negotiation: decide the session timer from an inbound
/// INVITE's headers.
///
/// Returns `None` when the INVITE carries no `Session-Expires` — we do
/// not insert timers into sessions the caller didn't ask for (allowed
/// by RFC 4028, deliberately deferred; see
/// `docs/07-session-timers.md`).
///
/// The interval is floored at `max(90, Min-SE)`. The refresher is the
/// request's `refresher` parameter when the peer advertised timer
/// support, defaulting to `uac` (peer refreshes). When the peer did
/// *not* advertise `Supported: timer` — e.g. a proxy inserted the
/// `Session-Expires` — the peer cannot refresh, so we take the
/// refresher role and skip `Require: timer`.
pub fn negotiate_uas(invite_headers: &rsip::Headers) -> Option<UasSessionTimer> {
    let se = session_expires_in(invite_headers)?;
    let floor = min_se_in(invite_headers)
        .unwrap_or(0)
        .max(MIN_SESSION_EXPIRES_SECS);
    let interval_secs = se.interval_secs.max(floor);
    let peer_supports = supports_timer(invite_headers);
    let refresher = if peer_supports {
        se.refresher.unwrap_or(Refresher::Uac)
    } else {
        Refresher::Uas
    };
    Some(UasSessionTimer {
        timer: SessionTimer {
            interval_secs,
            we_are_refresher: refresher == Refresher::Uas,
        },
        echo: SessionExpires {
            interval_secs,
            refresher: Some(refresher),
        },
        require_timer: peer_supports,
    })
}

/// The dialog operations [`session_timer_loop`] needs, abstracted so
/// the loop's timing logic stays unit-testable without a live dialog.
///
/// Implemented for [`crate::Call`]'s shareable session handle over the
/// engine's in-dialog re-INVITE / BYE.
pub trait SessionDialogOps {
    /// Send a session-refresh re-INVITE with the given extra headers
    /// and (typically SDP) body. Returns the final response, or
    /// `Ok(None)` if the dialog is no longer confirmed.
    fn refresh(
        &self,
        headers: Vec<Header>,
        body: Option<Vec<u8>>,
    ) -> impl Future<Output = Result<Option<rsip::Response>, BoxError>> + Send;

    /// Hang up the dialog with BYE.
    fn send_bye(&self) -> impl Future<Output = Result<(), BoxError>> + Send;
}

/// How [`session_timer_loop`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionTimerOutcome {
    /// The [`CancellationToken`] fired — the call ended through the
    /// normal path (local/remote BYE) and the loop just stood down.
    Cancelled,
    /// We were the watchdog and no refresh arrived before the session
    /// interval lapsed. A BYE was sent (best effort).
    Expired,
    /// We were the refresher and a refresh re-INVITE failed (non-2xx or
    /// transport error). A BYE was sent (best effort).
    RefreshFailed,
    /// The dialog was no longer confirmed when we tried to refresh —
    /// it already terminated through another path. No BYE needed.
    DialogGone,
}

/// Drive RFC 4028 session keepalive for one confirmed dialog. Runs
/// until cancelled or the session dies; same shape as
/// [`crate::Registrar::keepalive_loop`].
///
/// - When `timer.we_are_refresher`, sends a refresh re-INVITE every
///   `interval / 2` carrying `refresh_body` (repeat the SDP you sent
///   when the call was set up — an identical offer is a no-op per
///   RFC 3264). A 2xx resets the clock (adopting any `Session-Expires`
///   the peer granted); failure tears the call down with BYE.
/// - Otherwise runs the expiry watchdog: every
///   `peer_refreshed.notify_one()` resets the deadline, and if the
///   deadline lapses the call is torn down with BYE. The consumer pings
///   `peer_refreshed` after answering the peer's refresh re-INVITE.
///
/// All failures are folded into the returned [`SessionTimerOutcome`];
/// the loop never panics and never returns early without standing the
/// session down.
pub async fn session_timer_loop<D: SessionDialogOps>(
    dialog: &D,
    timer: SessionTimer,
    refresh_body: Option<Vec<u8>>,
    peer_refreshed: Arc<Notify>,
    cancel: CancellationToken,
) -> SessionTimerOutcome {
    let mut interval_secs = timer.interval_secs.max(MIN_SESSION_EXPIRES_SECS);
    if timer.we_are_refresher {
        loop {
            let current = SessionTimer {
                interval_secs,
                we_are_refresher: true,
            };
            select! {
                _ = tokio::time::sleep(current.refresh_after()) => {}
                _ = cancel.cancelled() => return SessionTimerOutcome::Cancelled,
            }

            // In this refresh re-INVITE we are the UAC of the new
            // transaction, so the refresher param says `uac`.
            let headers = vec![
                supported_timer_header(),
                SessionExpires {
                    interval_secs,
                    refresher: Some(Refresher::Uac),
                }
                .header(),
            ];
            match dialog.refresh(headers, refresh_body.clone()).await {
                Ok(Some(resp)) if resp.status_code.kind() == rsip::StatusCodeKind::Successful => {
                    // Adopt a re-granted interval (a peer may shorten or
                    // lengthen mid-call), floored to avoid a hot loop.
                    if let Some(granted) = session_expires_in(&resp.headers) {
                        interval_secs = granted.interval_secs.max(MIN_SESSION_EXPIRES_SECS);
                    }
                    debug!(interval_secs, "session refresh accepted");
                }
                Ok(Some(resp)) => {
                    warn!(
                        status = %resp.status_code,
                        "session refresh rejected; hanging up"
                    );
                    if let Err(e) = dialog.send_bye().await {
                        warn!("BYE after rejected refresh failed: {e}");
                    }
                    return SessionTimerOutcome::RefreshFailed;
                }
                Ok(None) => {
                    debug!("dialog no longer confirmed; session timer standing down");
                    return SessionTimerOutcome::DialogGone;
                }
                Err(e) => {
                    warn!("session refresh error: {e}; hanging up");
                    if let Err(e) = dialog.send_bye().await {
                        warn!("BYE after failed refresh failed: {e}");
                    }
                    return SessionTimerOutcome::RefreshFailed;
                }
            }
        }
    } else {
        let current = SessionTimer {
            interval_secs,
            we_are_refresher: false,
        };
        loop {
            select! {
                _ = tokio::time::sleep(current.expiry_after()) => {
                    info!(
                        interval_secs,
                        "session lapsed without refresh; sending BYE"
                    );
                    if let Err(e) = dialog.send_bye().await {
                        warn!("BYE after session expiry failed: {e}");
                    }
                    return SessionTimerOutcome::Expired;
                }
                _ = peer_refreshed.notified() => {
                    debug!("peer refreshed session; watchdog deadline reset");
                }
                _ = cancel.cancelled() => return SessionTimerOutcome::Cancelled,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // ---- SessionExpires parse / build ----

    #[test]
    fn parse_bare_interval() {
        let se = SessionExpires::parse("1800").unwrap();
        assert_eq!(se.interval_secs, 1800);
        assert_eq!(se.refresher, None);
    }

    #[test]
    fn parse_with_refresher_param() {
        let se = SessionExpires::parse("1800;refresher=uas").unwrap();
        assert_eq!(se.interval_secs, 1800);
        assert_eq!(se.refresher, Some(Refresher::Uas));
        let se = SessionExpires::parse("90;refresher=uac").unwrap();
        assert_eq!(se.refresher, Some(Refresher::Uac));
    }

    #[test]
    fn parse_is_case_insensitive_and_whitespace_tolerant() {
        let se = SessionExpires::parse(" 600 ; Refresher = UAS ").unwrap();
        assert_eq!(se.interval_secs, 600);
        assert_eq!(se.refresher, Some(Refresher::Uas));
    }

    #[test]
    fn parse_ignores_unknown_params() {
        let se = SessionExpires::parse("1800;foo=bar;refresher=uac;baz").unwrap();
        assert_eq!(se.refresher, Some(Refresher::Uac));
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(SessionExpires::parse("").is_err());
        assert!(SessionExpires::parse("soon").is_err());
        assert!(SessionExpires::parse("1800;refresher=bogus").is_err());
        assert!(SessionExpires::parse("-5").is_err());
    }

    #[test]
    fn header_value_round_trips() {
        for se in [
            SessionExpires {
                interval_secs: 1800,
                refresher: None,
            },
            SessionExpires {
                interval_secs: 90,
                refresher: Some(Refresher::Uac),
            },
            SessionExpires {
                interval_secs: 7200,
                refresher: Some(Refresher::Uas),
            },
        ] {
            let parsed = SessionExpires::parse(&se.header_value()).unwrap();
            assert_eq!(parsed, se, "round-trip via {:?}", se.header_value());
        }
    }

    #[test]
    fn header_builds_untyped_session_expires() {
        let h = SessionExpires {
            interval_secs: 1800,
            refresher: Some(Refresher::Uac),
        }
        .header();
        assert_eq!(h.to_string(), "Session-Expires: 1800;refresher=uac");
    }

    // ---- header extraction ----

    fn headers(items: Vec<Header>) -> rsip::Headers {
        let mut h = rsip::Headers::default();
        for item in items {
            h.push(item);
        }
        h
    }

    #[test]
    fn session_expires_in_finds_header_case_insensitively() {
        let h = headers(vec![Header::Other(
            "session-expires".into(),
            "600;refresher=uas".into(),
        )]);
        let se = session_expires_in(&h).unwrap();
        assert_eq!(se.interval_secs, 600);
        assert_eq!(se.refresher, Some(Refresher::Uas));
    }

    #[test]
    fn session_expires_in_accepts_compact_form() {
        // RFC 4028 §4 defines `x` as the compact form of Session-Expires.
        let h = headers(vec![Header::Other("x".into(), "300".into())]);
        assert_eq!(
            session_expires_in(&h),
            Some(SessionExpires {
                interval_secs: 300,
                refresher: None
            })
        );
    }

    #[test]
    fn session_expires_in_absent_or_malformed_is_none() {
        assert_eq!(session_expires_in(&headers(vec![])), None);
        let h = headers(vec![Header::Other("Session-Expires".into(), "soon".into())]);
        assert_eq!(session_expires_in(&h), None);
    }

    #[test]
    fn min_se_in_parses_and_ignores_params() {
        let h = headers(vec![Header::Other("Min-SE".into(), "120".into())]);
        assert_eq!(min_se_in(&h), Some(120));
        let h = headers(vec![Header::Other("min-se".into(), "240;lr".into())]);
        assert_eq!(min_se_in(&h), Some(240));
        assert_eq!(min_se_in(&headers(vec![])), None);
        let h = headers(vec![Header::Other("Min-SE".into(), "never".into())]);
        assert_eq!(min_se_in(&h), None);
    }

    #[test]
    fn supports_timer_scans_typed_untyped_and_compact() {
        assert!(supports_timer(&headers(vec![supported_timer_header()])));
        assert!(supports_timer(&headers(vec![Header::Supported(
            "100rel, timer".into()
        )])));
        assert!(supports_timer(&headers(vec![Header::Other(
            "k".into(),
            "timer".into()
        )])));
        assert!(supports_timer(&headers(vec![Header::Other(
            "Supported".into(),
            "TIMER".into()
        )])));
        assert!(!supports_timer(&headers(vec![])));
        assert!(!supports_timer(&headers(vec![Header::Supported(
            "100rel".into()
        )])));
        // `timer` must be a whole option tag, not a substring.
        assert!(!supports_timer(&headers(vec![Header::Supported(
            "timers".into()
        )])));
    }

    // ---- interval math (RFC 4028 §10) ----

    #[test]
    fn refresh_fires_at_half_the_interval() {
        let t = SessionTimer {
            interval_secs: 1800,
            we_are_refresher: true,
        };
        assert_eq!(t.refresh_after(), Duration::from_secs(900));
        let t = SessionTimer {
            interval_secs: 90,
            we_are_refresher: true,
        };
        assert_eq!(t.refresh_after(), Duration::from_secs(45));
    }

    #[test]
    fn expiry_keeps_min_of_32s_or_a_third_headroom() {
        // Long interval: headroom caps at 32 s.
        let t = SessionTimer {
            interval_secs: 1800,
            we_are_refresher: false,
        };
        assert_eq!(t.expiry_after(), Duration::from_secs(1768));
        // Short interval: a third of 90 s = 30 s < 32 s.
        let t = SessionTimer {
            interval_secs: 90,
            we_are_refresher: false,
        };
        assert_eq!(t.expiry_after(), Duration::from_secs(60));
    }

    // ---- negotiation: UAC side ----

    #[test]
    fn uac_no_session_expires_means_no_timer() {
        assert_eq!(negotiate_uac(&headers(vec![])), None);
    }

    #[test]
    fn uac_refresher_uas_means_peer_refreshes() {
        let h = headers(vec![Header::Other(
            "Session-Expires".into(),
            "1800;refresher=uas".into(),
        )]);
        assert_eq!(
            negotiate_uac(&h),
            Some(SessionTimer {
                interval_secs: 1800,
                we_are_refresher: false
            })
        );
    }

    #[test]
    fn uac_refresher_uac_or_missing_means_we_refresh() {
        let h = headers(vec![Header::Other(
            "Session-Expires".into(),
            "600;refresher=uac".into(),
        )]);
        assert!(negotiate_uac(&h).unwrap().we_are_refresher);
        // RFC 4028 §9 says the 2xx MUST pin the refresher; a peer that
        // omits it gets the defensive default: we refresh.
        let h = headers(vec![Header::Other("Session-Expires".into(), "600".into())]);
        assert!(negotiate_uac(&h).unwrap().we_are_refresher);
    }

    #[test]
    fn uac_floors_tiny_grants_at_90s() {
        let h = headers(vec![Header::Other(
            "Session-Expires".into(),
            "20;refresher=uac".into(),
        )]);
        assert_eq!(negotiate_uac(&h).unwrap().interval_secs, 90);
    }

    // ---- negotiation: UAS side ----

    fn invite_headers(session_expires: &str, min_se: Option<&str>, timer: bool) -> rsip::Headers {
        let mut items = vec![Header::Other(
            "Session-Expires".into(),
            session_expires.into(),
        )];
        if let Some(m) = min_se {
            items.push(Header::Other("Min-SE".into(), m.into()));
        }
        if timer {
            items.push(supported_timer_header());
        }
        headers(items)
    }

    #[test]
    fn uas_no_session_expires_means_no_timer() {
        assert_eq!(
            negotiate_uas(&headers(vec![supported_timer_header()])),
            None
        );
    }

    #[test]
    fn uas_default_makes_supporting_peer_the_refresher() {
        let uas = negotiate_uas(&invite_headers("1800", None, true)).unwrap();
        assert_eq!(uas.timer.interval_secs, 1800);
        assert!(!uas.timer.we_are_refresher, "peer (UAC) should refresh");
        assert_eq!(
            uas.echo,
            SessionExpires {
                interval_secs: 1800,
                refresher: Some(Refresher::Uac)
            }
        );
        assert!(uas.require_timer);
    }

    #[test]
    fn uas_honors_requested_refresher_uas() {
        let uas = negotiate_uas(&invite_headers("1800;refresher=uas", None, true)).unwrap();
        assert!(uas.timer.we_are_refresher, "we (UAS) were asked to refresh");
        assert_eq!(uas.echo.refresher, Some(Refresher::Uas));
    }

    #[test]
    fn uas_without_peer_support_takes_refresher_role() {
        // A proxy inserted Session-Expires but the UAC itself never
        // advertised `Supported: timer` — it can't refresh, so we must,
        // and we must not Require: timer in the 2xx.
        let uas = negotiate_uas(&invite_headers("1800;refresher=uac", None, false)).unwrap();
        assert!(uas.timer.we_are_refresher);
        assert_eq!(uas.echo.refresher, Some(Refresher::Uas));
        assert!(!uas.require_timer);
    }

    #[test]
    fn uas_floors_interval_at_min_se_and_90s() {
        // Requested 30 s with Min-SE 120 → 120 s.
        let uas = negotiate_uas(&invite_headers("30", Some("120"), true)).unwrap();
        assert_eq!(uas.timer.interval_secs, 120);
        assert_eq!(uas.echo.interval_secs, 120);
        // Requested 30 s without Min-SE → RFC floor of 90 s.
        let uas = negotiate_uas(&invite_headers("30", None, true)).unwrap();
        assert_eq!(uas.timer.interval_secs, 90);
    }

    // ---- session_timer_loop against a mock dialog ----

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Event {
        Refresh { session_expires: String },
        Bye,
    }

    /// Scripted mock: pops one canned reply per refresh; records every
    /// call with a timestamp readable under tokio's paused clock.
    struct MockDialog {
        events: Mutex<Vec<(Duration, Event)>>,
        refresh_replies: Mutex<Vec<Result<Option<rsip::Response>, String>>>,
        started: tokio::time::Instant,
    }

    impl MockDialog {
        fn new(refresh_replies: Vec<Result<Option<rsip::Response>, String>>) -> Self {
            Self {
                events: Mutex::new(Vec::new()),
                refresh_replies: Mutex::new(refresh_replies),
                started: tokio::time::Instant::now(),
            }
        }

        fn events(&self) -> Vec<(Duration, Event)> {
            self.events.lock().unwrap().clone()
        }
    }

    fn response(code: u16, extra: Vec<Header>) -> rsip::Response {
        rsip::Response {
            status_code: rsip::StatusCode::from(code),
            version: rsip::Version::V2,
            headers: headers(extra),
            body: Vec::new(),
        }
    }

    impl SessionDialogOps for MockDialog {
        async fn refresh(
            &self,
            hdrs: Vec<Header>,
            _body: Option<Vec<u8>>,
        ) -> Result<Option<rsip::Response>, BoxError> {
            let se = hdrs
                .iter()
                .find_map(|h| match h {
                    Header::Other(name, value) if name == "Session-Expires" => Some(value.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            self.events.lock().unwrap().push((
                self.started.elapsed(),
                Event::Refresh {
                    session_expires: se,
                },
            ));
            let reply = self.refresh_replies.lock().unwrap().remove(0);
            reply.map_err(Into::into)
        }

        async fn send_bye(&self) -> Result<(), BoxError> {
            self.events
                .lock()
                .unwrap()
                .push((self.started.elapsed(), Event::Bye));
            Ok(())
        }
    }

    fn timer(interval_secs: u32, we_are_refresher: bool) -> SessionTimer {
        SessionTimer {
            interval_secs,
            we_are_refresher,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn refresher_sends_refresh_every_half_interval() {
        let dialog = Arc::new(MockDialog::new(vec![
            Ok(Some(response(200, vec![]))),
            Ok(Some(response(200, vec![]))),
            Ok(None), // third tick: dialog gone, loop exits
        ]));
        let cancel = CancellationToken::new();
        let outcome = session_timer_loop(
            &*dialog,
            timer(180, true),
            None,
            Arc::new(Notify::new()),
            cancel,
        )
        .await;
        assert_eq!(outcome, SessionTimerOutcome::DialogGone);

        let events = dialog.events();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].0, Duration::from_secs(90));
        assert_eq!(events[1].0, Duration::from_secs(180));
        assert_eq!(events[2].0, Duration::from_secs(270));
        for (_, e) in &events {
            assert_eq!(
                e,
                &Event::Refresh {
                    session_expires: "180;refresher=uac".into()
                }
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn refresher_adopts_interval_granted_in_refresh_response() {
        // First 200 re-grants a longer interval; the second refresh must
        // fire at the *new* half-interval.
        let regrant = response(
            200,
            vec![Header::Other(
                "Session-Expires".into(),
                "360;refresher=uac".into(),
            )],
        );
        let dialog = Arc::new(MockDialog::new(vec![Ok(Some(regrant)), Ok(None)]));
        let cancel = CancellationToken::new();
        let outcome = session_timer_loop(
            &*dialog,
            timer(180, true),
            None,
            Arc::new(Notify::new()),
            cancel,
        )
        .await;
        assert_eq!(outcome, SessionTimerOutcome::DialogGone);

        let events = dialog.events();
        assert_eq!(events[0].0, Duration::from_secs(90), "first at 180/2");
        assert_eq!(
            events[1].0,
            Duration::from_secs(90 + 180),
            "second at 90 + 360/2 after the re-grant"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn refresher_rejected_refresh_sends_bye() {
        let dialog = Arc::new(MockDialog::new(vec![Ok(Some(response(481, vec![])))]));
        let cancel = CancellationToken::new();
        let outcome = session_timer_loop(
            &*dialog,
            timer(180, true),
            None,
            Arc::new(Notify::new()),
            cancel,
        )
        .await;
        assert_eq!(outcome, SessionTimerOutcome::RefreshFailed);
        let events = dialog.events();
        assert!(matches!(events[0].1, Event::Refresh { .. }));
        assert_eq!(events[1].1, Event::Bye);
    }

    #[tokio::test(start_paused = true)]
    async fn refresher_transport_error_sends_bye() {
        let dialog = Arc::new(MockDialog::new(vec![Err("socket closed".into())]));
        let cancel = CancellationToken::new();
        let outcome = session_timer_loop(
            &*dialog,
            timer(180, true),
            None,
            Arc::new(Notify::new()),
            cancel,
        )
        .await;
        assert_eq!(outcome, SessionTimerOutcome::RefreshFailed);
        assert_eq!(dialog.events().last().unwrap().1, Event::Bye);
    }

    #[tokio::test(start_paused = true)]
    async fn refresher_cancellation_wins_before_first_refresh() {
        let dialog = Arc::new(MockDialog::new(vec![]));
        let cancel = CancellationToken::new();
        cancel.cancel();
        let outcome = session_timer_loop(
            &*dialog,
            timer(180, true),
            None,
            Arc::new(Notify::new()),
            cancel,
        )
        .await;
        assert_eq!(outcome, SessionTimerOutcome::Cancelled);
        assert!(dialog.events().is_empty(), "no refresh, no BYE");
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_sends_bye_when_session_lapses() {
        let dialog = Arc::new(MockDialog::new(vec![]));
        let cancel = CancellationToken::new();
        let outcome = session_timer_loop(
            &*dialog,
            timer(90, false),
            None,
            Arc::new(Notify::new()),
            cancel,
        )
        .await;
        assert_eq!(outcome, SessionTimerOutcome::Expired);
        let events = dialog.events();
        assert_eq!(events.len(), 1);
        // 90 - min(32, 90/3) = 60 s.
        assert_eq!(events[0], (Duration::from_secs(60), Event::Bye));
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_resets_deadline_on_peer_refresh() {
        let dialog = Arc::new(MockDialog::new(vec![]));
        let cancel = CancellationToken::new();
        let refreshed = Arc::new(Notify::new());

        let loop_task = tokio::spawn({
            let dialog = dialog.clone();
            let refreshed = refreshed.clone();
            let cancel = cancel.clone();
            async move { session_timer_loop(&*dialog, timer(90, false), None, refreshed, cancel).await }
        });

        // Just before the 60 s deadline, the peer refreshes.
        tokio::time::sleep(Duration::from_secs(59)).await;
        refreshed.notify_one();
        tokio::task::yield_now().await;
        // Crossing the original deadline must NOT fire the BYE...
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert!(dialog.events().is_empty(), "deadline should have reset");
        // ...but the rearmed deadline (59 + 60 = 119 s) must.
        let outcome = loop_task.await.unwrap();
        assert_eq!(outcome, SessionTimerOutcome::Expired);
        assert_eq!(
            dialog.events(),
            vec![(Duration::from_secs(119), Event::Bye)]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn watchdog_cancellation_stands_down_without_bye() {
        let dialog = Arc::new(MockDialog::new(vec![]));
        let cancel = CancellationToken::new();
        let loop_task = tokio::spawn({
            let dialog = dialog.clone();
            let cancel = cancel.clone();
            async move {
                session_timer_loop(
                    &*dialog,
                    timer(90, false),
                    None,
                    Arc::new(Notify::new()),
                    cancel,
                )
                .await
            }
        });
        tokio::time::sleep(Duration::from_secs(10)).await;
        cancel.cancel();
        assert_eq!(loop_task.await.unwrap(), SessionTimerOutcome::Cancelled);
        assert!(dialog.events().is_empty());
    }
}
