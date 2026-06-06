//! REGISTER + digest auth + keepalive re-registration.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rsip::{
    prelude::HeadersExt, prelude::ToTypedHeader, prelude::UntypedHeader, SipMessage, StatusCode,
    Uri,
};
use rsipstack::{
    dialog::authenticate::{handle_client_authenticate, Credential},
    transaction::{
        key::{TransactionKey, TransactionRole},
        make_call_id, make_tag,
        transaction::Transaction,
    },
};
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::account::SipAccount;
use crate::endpoint::SipEndpoint;

/// Sends `REGISTER` (with digest auth retry) on demand, keeps the
/// registration fresh via a keepalive loop, and unregisters on shutdown.
pub struct Registrar {
    account: SipAccount,
    endpoint: Arc<SipEndpoint>,
    cancel: CancellationToken,
    server_uri: Uri,
    call_id: rsip::headers::CallId,
    seq: std::sync::atomic::AtomicU32,
    contact: tokio::sync::Mutex<Option<rsip::typed::Contact>>,
    /// `Expires` value sent in REGISTER requests (seconds).
    register_expires: u32,
    /// Keepalive re-registration interval (seconds).
    keepalive_secs: u32,
    /// Observable snapshot of REGISTER outcomes. Held under a sync mutex
    /// so [`Registrar::diagnostics`] doesn't need to be async; updates
    /// are short and never block on I/O.
    diag: Mutex<DiagState>,
}

/// Mutable state used to populate [`RegistrarDiagnostics`]. Kept separate
/// from the long-lived registrar fields above so the diagnostics getter
/// can snapshot it under a single lock.
#[derive(Debug, Default)]
struct DiagState {
    contact_uri: Option<String>,
    negotiated_expires: Option<u32>,
    last_status: Option<u16>,
    last_attempt_at: Option<SystemTime>,
    last_success_at: Option<SystemTime>,
    last_error: Option<String>,
    register_count: u64,
    failure_count: u64,
}

/// Snapshot of the registrar's current state. Returned by
/// [`Registrar::diagnostics`]; cheap to clone.
///
/// All timestamps are wall-clock ([`SystemTime`]) so callers can render
/// them as absolute strings without needing a separate uptime reference.
#[derive(Debug, Clone)]
pub struct RegistrarDiagnostics {
    /// SIP server URI we send REGISTER to, e.g. `sip:pbx.example.com:5060`.
    pub server_uri: String,
    /// `Contact` URI advertised in the most recent successful REGISTER.
    /// `None` until the first 200 OK.
    pub contact_uri: Option<String>,
    /// `Call-ID` value used across this registrar's REGISTER dialog. The
    /// bare value only (e.g. `abc123@example.com`) — no `Call-ID:` header
    /// prefix, so callers can render it directly without stripping.
    pub call_id: String,
    /// Next CSeq the registrar will send (current value of the internal
    /// atomic — may have already been incremented past the value used in
    /// the last sent request).
    pub cseq: u32,
    /// `Expires` we ask for. From the registrar's constructor.
    pub configured_expires: u32,
    /// `Expires` the server returned in the most recent 200 OK.
    pub negotiated_expires: Option<u32>,
    /// SIP status of the most recent final response.
    pub last_status: Option<u16>,
    /// When the most recent REGISTER was sent.
    pub last_attempt_at: Option<SystemTime>,
    /// When the most recent 200 OK was received.
    pub last_success_at: Option<SystemTime>,
    /// Most recent failure message (only set when `last_status` indicates
    /// failure or the transaction terminated unexpectedly).
    pub last_error: Option<String>,
    /// Cumulative count of successful REGISTERs since process start.
    pub register_count: u64,
    /// Cumulative count of failed REGISTERs since process start.
    pub failure_count: u64,
}

impl Registrar {
    /// Build a registrar bound to an endpoint.
    ///
    /// `register_expires` is the `Expires` value sent in REGISTERs (typical:
    /// 60–300 seconds). `keepalive_secs` is the *requested* re-registration
    /// cadence (typical: `register_expires` minus a small margin, e.g.
    /// `expires - 10`).
    ///
    /// Note that `keepalive_secs` is only an upper bound on the wait between
    /// re-registrations. Servers routinely grant a shorter `Expires` than we
    /// ask for, so the keepalive loop refreshes shortly before whatever the
    /// server actually granted lapses — see `refresh_interval_secs`.
    pub fn new(
        account: SipAccount,
        endpoint: Arc<SipEndpoint>,
        cancel: CancellationToken,
        register_expires: u32,
        keepalive_secs: u32,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let server_uri: Uri = format!("sip:{}:{}", account.server(), account.port()).try_into()?;
        let call_id = make_call_id(endpoint.inner.option.callid_suffix.as_deref());

        Ok(Self {
            account,
            endpoint,
            cancel,
            server_uri,
            call_id,
            seq: std::sync::atomic::AtomicU32::new(0),
            contact: tokio::sync::Mutex::new(None),
            register_expires,
            keepalive_secs,
            diag: Mutex::new(DiagState::default()),
        })
    }

    /// Snapshot of REGISTER state — local socket, server target, last
    /// status, counters, etc. Cheap to clone; safe to call from any task.
    pub fn diagnostics(&self) -> RegistrarDiagnostics {
        let diag = self.diag.lock().expect("registrar diag mutex poisoned");
        RegistrarDiagnostics {
            server_uri: self.server_uri.to_string(),
            contact_uri: diag.contact_uri.clone(),
            call_id: self.call_id.value().to_string(),
            cseq: self.seq.load(std::sync::atomic::Ordering::Relaxed),
            configured_expires: self.register_expires,
            negotiated_expires: diag.negotiated_expires,
            last_status: diag.last_status,
            last_attempt_at: diag.last_attempt_at,
            last_success_at: diag.last_success_at,
            last_error: diag.last_error.clone(),
            register_count: diag.register_count,
            failure_count: diag.failure_count,
        }
    }

    fn record_attempt(&self) {
        let mut diag = self.diag.lock().expect("registrar diag mutex poisoned");
        diag.last_attempt_at = Some(SystemTime::now());
    }

    fn record_success(&self, status: u16, expires: u32, contact_uri: Option<String>) {
        let mut diag = self.diag.lock().expect("registrar diag mutex poisoned");
        diag.last_status = Some(status);
        diag.last_success_at = Some(SystemTime::now());
        diag.negotiated_expires = Some(expires);
        if let Some(c) = contact_uri {
            diag.contact_uri = Some(c);
        }
        diag.register_count = diag.register_count.saturating_add(1);
        diag.last_error = None;
    }

    fn record_failure(&self, status: Option<u16>, error: String) {
        let mut diag = self.diag.lock().expect("registrar diag mutex poisoned");
        diag.last_status = status;
        diag.last_error = Some(error);
        diag.failure_count = diag.failure_count.saturating_add(1);
    }

    fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
    }

    fn set_seq(&self, val: u32) {
        self.seq.store(val, std::sync::atomic::Ordering::Relaxed);
    }

    /// Send the initial REGISTER.
    ///
    /// Transient failures (request timeout, server-side `5xx`, temporary
    /// unavailability, or a transaction that terminated without a final
    /// response) are retried with a fixed backoff until cancelled — these
    /// are conditions a retry can resolve once the server or network
    /// recovers.
    ///
    /// **Permanent** failures — the server answered and rejected us for a
    /// reason a retry will never fix (bad credentials → `401`/`407`,
    /// `403 Forbidden`, `404 Not Found`, other `4xx`/`6xx`) — return `Err`
    /// immediately. Retrying those would spin forever and hide the cause
    /// from the user; surfacing the error lets the caller put the account
    /// into a visible failed state so the user can correct it.
    pub async fn register(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            info!(
                "Sending REGISTER to {}:{}",
                self.account.server(),
                self.account.port()
            );

            let seq = self.next_seq();
            let contact = self.contact.lock().await.clone();

            let request = self.build_register_request(seq, &contact, self.register_expires)?;
            debug!("REGISTER request:\n{request}");

            self.record_attempt();

            let mut seq_val = seq;
            let final_response = self.send_register_with_auth(request, &mut seq_val).await?;
            self.set_seq(seq_val);

            match final_response {
                Some(resp) if resp.status_code == StatusCode::OK => {
                    let typed_contact: Option<rsip::typed::Contact> =
                        resp.contact_header().ok().and_then(|c| c.typed().ok());

                    let expires = typed_contact
                        .as_ref()
                        .and_then(|c| c.expires())
                        .map(|e| e.seconds().unwrap_or(50))
                        .unwrap_or(50);

                    let contact_str = typed_contact.as_ref().map(|c| c.uri.to_string());
                    self.record_success(200, expires, contact_str);
                    *self.contact.lock().await = typed_contact;

                    info!(
                        "Registered as {}@{} (expires {}s)",
                        self.account.username, self.account.domain, expires
                    );
                    return Ok(());
                }
                Some(resp) => {
                    let code = u16::from(resp.status_code.clone());
                    let msg = format!("registration failed with status {}", resp.status_code);
                    warn!("{msg}");
                    self.record_failure(Some(code), msg.clone());
                    if is_permanent_register_failure(&resp.status_code) {
                        // Retrying can't fix a rejection like this — return
                        // so the caller can surface it instead of looping
                        // silently forever.
                        return Err(msg.into());
                    }
                }
                None => {
                    let msg = "registration transaction terminated unexpectedly".to_string();
                    warn!("{msg}");
                    self.record_failure(None, msg);
                }
            }

            select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(10)) => {}
                _ = self.cancel.cancelled() => {
                    return Err("Cancelled".into());
                }
            }
        }
    }

    /// Re-register loop: sleeps until shortly before the current binding
    /// lapses, then re-REGISTERs. Runs until cancelled.
    ///
    /// The wait is driven by the `Expires` the server actually *granted* in
    /// the last 200 OK, not the value we asked for. Registrars commonly hand
    /// back a shorter lifetime than requested; sleeping the requested cadence
    /// would let the binding expire and leave the account silently
    /// unreachable until the next cycle. See `refresh_interval_secs`.
    pub async fn keepalive_loop(&self) {
        loop {
            // Latest server-granted lifetime (populated by the initial
            // `register()` before this loop starts; refreshed on every
            // successful re-REGISTER below). Fall back to what we asked for
            // if, somehow, we never recorded a grant.
            let granted = self
                .diag
                .lock()
                .expect("registrar diag mutex poisoned")
                .negotiated_expires
                .unwrap_or(self.register_expires);
            let interval =
                refresh_interval_secs(self.register_expires, self.keepalive_secs, granted);
            info!("Re-registering in {interval}s...");

            select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(interval as u64)) => {}
                _ = self.cancel.cancelled() => return,
            }

            if self.cancel.is_cancelled() {
                return;
            }

            let seq = self.next_seq();
            let contact = self.contact.lock().await.clone();

            let request = match self.build_register_request(seq, &contact, self.register_expires) {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("failed to build re-register request: {e}");
                    warn!("{msg}");
                    self.record_failure(None, msg);
                    continue;
                }
            };

            self.record_attempt();

            let mut seq_val = seq;
            match self.send_register_with_auth(request, &mut seq_val).await {
                Ok(Some(resp)) if resp.status_code == StatusCode::OK => {
                    let typed_contact: Option<rsip::typed::Contact> =
                        resp.contact_header().ok().and_then(|c| c.typed().ok());

                    let expires = typed_contact
                        .as_ref()
                        .and_then(|c| c.expires())
                        .map(|e| e.seconds().unwrap_or(50))
                        .unwrap_or(50);

                    let contact_str = typed_contact.as_ref().map(|c| c.uri.to_string());
                    self.record_success(200, expires, contact_str);
                    *self.contact.lock().await = typed_contact;
                    self.set_seq(seq_val);

                    info!(
                        "Re-registered as {}@{} (expires {}s)",
                        self.account.username, self.account.domain, expires
                    );
                }
                Ok(Some(resp)) => {
                    let code = u16::from(resp.status_code.clone());
                    let msg = format!("re-registration failed: {}", resp.status_code);
                    warn!("{msg}");
                    self.record_failure(Some(code), msg);
                    self.set_seq(seq_val);
                }
                Ok(None) => {
                    let msg = "re-registration got no response".to_string();
                    warn!("{msg}");
                    self.record_failure(None, msg);
                    self.set_seq(seq_val);
                }
                Err(e) => {
                    let msg = format!("re-registration error: {e}");
                    warn!("{msg}");
                    self.record_failure(None, msg);
                }
            }
        }
    }

    /// Unregister (Expires: 0).
    pub async fn unregister(&self) {
        info!("Unregistering (Expires: 0)...");

        let seq = self.next_seq();
        let contact = self.contact.lock().await.clone();

        let request = match self.build_register_request(seq, &contact, 0) {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to build unregister request: {e}");
                return;
            }
        };

        let mut seq_val = seq;
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            self.send_register_with_auth(request, &mut seq_val),
        )
        .await
        {
            Ok(Ok(Some(resp))) => info!("Unregister response: {}", resp.status_code),
            Ok(Ok(None)) => warn!("No response to unregister"),
            Ok(Err(e)) => warn!("Unregister failed: {e}"),
            Err(_) => warn!("Unregister timed out"),
        }
    }

    fn build_register_request(
        &self,
        seq: u32,
        contact: &Option<rsip::typed::Contact>,
        expires: u32,
    ) -> Result<rsip::Request, Box<dyn std::error::Error + Send + Sync>> {
        let mut to_uri = self.server_uri.clone();
        to_uri.auth = Some(rsip::auth::Auth {
            user: self.account.username.clone(),
            password: None,
        });

        let to = rsip::typed::To {
            display_name: None,
            uri: to_uri.clone(),
            params: vec![],
        };

        let from = rsip::typed::From {
            display_name: None,
            uri: to_uri,
            params: vec![],
        }
        .with_tag(make_tag());

        let via = self.endpoint.inner.get_via(None, None)?;

        let mut reg_contact = contact.clone().unwrap_or_else(|| {
            let host = via.uri.host_with_port.clone();
            rsip::typed::Contact {
                display_name: None,
                uri: rsip::Uri {
                    auth: Some(rsip::auth::Auth {
                        user: self.account.username.clone(),
                        password: None,
                    }),
                    scheme: Some(rsip::Scheme::Sip),
                    host_with_port: host,
                    params: vec![],
                    headers: vec![],
                },
                params: vec![],
            }
        });

        // Strip contact-level expires param — the Expires header is authoritative.
        reg_contact
            .params
            .retain(|p| !matches!(p, rsip::common::uri::Param::Expires(_)));

        let mut request = self.endpoint.inner.make_request(
            rsip::Method::Register,
            self.server_uri.clone(),
            via,
            from,
            to,
            seq,
            Some(self.call_id.clone()),
        );

        request.headers.unique_push(reg_contact.into());
        request
            .headers
            .unique_push(rsip::headers::Allow::default().into());
        request
            .headers
            .unique_push(rsip::headers::Expires::from(expires).into());

        Ok(request)
    }

    async fn send_register_with_auth(
        &self,
        request: rsip::Request,
        seq: &mut u32,
    ) -> Result<Option<rsip::Response>, Box<dyn std::error::Error + Send + Sync>> {
        let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
        let mut tx = Transaction::new_client(key, request, self.endpoint.inner.clone(), None);
        tx.send().await?;

        let mut auth_sent = false;

        while let Some(msg) = tx.receive().await {
            match msg {
                SipMessage::Response(resp) => match resp.status_code {
                    StatusCode::Trying => {
                        debug!("Received 100 Trying");
                        continue;
                    }
                    StatusCode::Unauthorized | StatusCode::ProxyAuthenticationRequired
                        if !auth_sent =>
                    {
                        debug!("Auth challenge response:\n{resp}");
                        let auth_cred = Credential {
                            username: self.account.auth_username().to_string(),
                            password: self.account.password.clone(),
                            realm: None,
                        };
                        *seq += 1;
                        tx = handle_client_authenticate(*seq, &tx, resp, &auth_cred).await?;
                        debug!("Sending authenticated REGISTER:\n{}", tx.original);
                        tx.send().await?;
                        auth_sent = true;
                        continue;
                    }
                    _ => {
                        debug!("Final response:\n{resp}");
                        return Ok(Some(resp));
                    }
                },
                _ => return Ok(None),
            }
        }
        Ok(None)
    }
}

/// Smallest interval the keepalive loop will ever sleep, in seconds. Guards
/// against a pathologically short server-granted `Expires` turning the loop
/// into a hot re-REGISTER spin.
const MIN_REFRESH_INTERVAL_SECS: u32 = 10;

/// Smallest gap we insist on between a re-REGISTER and the moment the current
/// binding would lapse — one round-trip plus slack — even when the configured
/// margin works out smaller. Keeps us from refreshing right on the edge.
const MIN_REFRESH_MARGIN_SECS: u32 = 5;

/// How long to wait before the next re-REGISTER, given the `Expires` the
/// server granted in the last 200 OK and the locally configured values.
///
/// Servers frequently downgrade the `Expires` we request to a shorter value.
/// Refreshing on the *requested* cadence (`keepalive_secs`) would then fire
/// long after the granted binding had already expired, leaving the account
/// unreachable for the gap. So the interval is driven by what the server
/// actually granted:
///
/// - Refresh `margin` seconds before the granted lifetime lapses, where
///   `margin` is the operator's configured headroom
///   (`register_expires - keepalive_secs`), floored at
///   [`MIN_REFRESH_MARGIN_SECS`] so we never sit right on the edge.
/// - Never wait longer than `keepalive_secs` (covers the rare case of a
///   server granting *more* than we asked for).
/// - Never wait less than [`MIN_REFRESH_INTERVAL_SECS`], so an absurdly short
///   grant can't spin the loop.
///
/// When the server honors the requested `Expires`, this reduces to
/// `keepalive_secs` — identical to the previous fixed-cadence behavior.
fn refresh_interval_secs(register_expires: u32, keepalive_secs: u32, granted_expires: u32) -> u32 {
    let margin = register_expires
        .saturating_sub(keepalive_secs)
        .max(MIN_REFRESH_MARGIN_SECS);
    granted_expires
        .saturating_sub(margin)
        .min(keepalive_secs)
        .max(MIN_REFRESH_INTERVAL_SECS)
}

/// Whether a final REGISTER response is a *permanent* rejection the caller
/// must act on, versus a *transient* condition worth retrying.
///
/// Transient (returns `false`): `408 Request Timeout`, `480 Temporarily
/// Unavailable`, and any `5xx` server-side error — the server (or path) is
/// saying "not right now", which a retry can clear once it recovers.
///
/// Permanent (returns `true`): everything else the server answers with —
/// `401`/`407` (bad credentials after the auth retry), `403 Forbidden`,
/// `404 Not Found`, other `4xx`, and `6xx` global failures. Retrying these
/// never succeeds, so the registrar returns the error to its caller rather
/// than spinning on it forever.
fn is_permanent_register_failure(status: &StatusCode) -> bool {
    let code = status.code();
    let transient = code == 408 || code == 480 || (500..600).contains(&code);
    !transient
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Transport;

    fn make_account() -> SipAccount {
        SipAccount {
            display_name: "Test".to_string(),
            username: "1001".to_string(),
            password: "secret".to_string(),
            domain: "127.0.0.1".to_string(),
            auth_username: None,
            server: Some("127.0.0.1".to_string()),
            port: Some(5060),
            transport: Transport::Udp,
        }
    }

    async fn make_registrar() -> (Registrar, Arc<SipEndpoint>, CancellationToken) {
        let account = make_account();
        let cancel = CancellationToken::new();
        let (endpoint, _incoming) = SipEndpoint::new(&account, cancel.clone()).await.unwrap();
        let endpoint = Arc::new(endpoint);
        let registrar = Registrar::new(account, endpoint.clone(), cancel.clone(), 60, 50).unwrap();
        (registrar, endpoint, cancel)
    }

    #[test]
    fn auth_and_client_rejections_are_permanent() {
        // The server answered "no" for a reason a retry can't fix. These
        // must return from register() so the account lands in a visible
        // failed state instead of the registrar looping forever (the bug
        // this classifier fixes: a wrong password → 401 spun silently).
        for code in [400u16, 401, 403, 404, 407, 410, 486, 600, 603, 604, 606] {
            assert!(
                is_permanent_register_failure(&StatusCode::from(code)),
                "status {code} should be treated as permanent",
            );
        }
    }

    #[test]
    fn timeout_and_server_errors_are_transient() {
        // "Not right now" — worth retrying once the server/path recovers.
        for code in [408u16, 480, 500, 502, 503, 504] {
            assert!(
                !is_permanent_register_failure(&StatusCode::from(code)),
                "status {code} should be treated as transient",
            );
        }
    }

    #[test]
    fn refresh_honors_request_when_server_grants_what_we_asked() {
        // Server returns exactly the requested expiry → behavior is unchanged
        // from the old fixed-cadence loop: wait the configured keepalive.
        assert_eq!(refresh_interval_secs(600, 590, 600), 590);
        assert_eq!(refresh_interval_secs(60, 50, 60), 50);
    }

    #[test]
    fn refresh_shortens_when_server_downgrades_expiry() {
        // The regression: ask for 600 (keepalive 590), server grants 174.
        // Refreshing at 590 would lapse the binding ~7 minutes early. We must
        // refresh before 174s, preserving the operator's 10s margin → 164s.
        assert_eq!(refresh_interval_secs(600, 590, 174), 164);
        assert!(refresh_interval_secs(600, 590, 174) < 174);
        // A moderate downgrade keeps the same margin.
        assert_eq!(refresh_interval_secs(600, 590, 120), 110);
    }

    #[test]
    fn refresh_caps_at_keepalive_when_server_grants_more() {
        // Some servers grant a longer lifetime than requested; we still
        // refresh no later than the configured cadence.
        assert_eq!(refresh_interval_secs(600, 590, 1200), 590);
    }

    #[test]
    fn refresh_floors_short_grants_to_avoid_hot_loop() {
        // A tiny grant must not turn into a busy re-REGISTER spin; the
        // interval is floored even though it then lands after expiry.
        assert_eq!(
            refresh_interval_secs(600, 590, 5),
            MIN_REFRESH_INTERVAL_SECS
        );
        assert_eq!(
            refresh_interval_secs(600, 590, 0),
            MIN_REFRESH_INTERVAL_SECS
        );
    }

    #[test]
    fn refresh_keeps_a_margin_even_with_zero_configured_headroom() {
        // keepalive == register_expires means no configured margin; we still
        // refresh strictly before the granted expiry, not right on it.
        assert_eq!(
            refresh_interval_secs(600, 600, 174),
            174 - MIN_REFRESH_MARGIN_SECS
        );
        assert!(refresh_interval_secs(600, 600, 174) < 174);
    }

    #[tokio::test]
    async fn diagnostics_initial_state() {
        let (registrar, endpoint, _cancel) = make_registrar().await;
        let diag = registrar.diagnostics();

        assert_eq!(diag.server_uri, "sip:127.0.0.1:5060");
        assert!(diag.contact_uri.is_none());
        assert!(!diag.call_id.is_empty());
        // Bare value, no header prefix — callers render this directly.
        assert!(!diag.call_id.starts_with("Call-ID"));
        assert!(!diag.call_id.contains(": "));
        assert_eq!(diag.cseq, 0);
        assert_eq!(diag.configured_expires, 60);
        assert!(diag.negotiated_expires.is_none());
        assert!(diag.last_status.is_none());
        assert!(diag.last_attempt_at.is_none());
        assert!(diag.last_success_at.is_none());
        assert!(diag.last_error.is_none());
        assert_eq!(diag.register_count, 0);
        assert_eq!(diag.failure_count, 0);

        endpoint.shutdown();
    }

    #[tokio::test]
    async fn record_attempt_sets_timestamp() {
        let (registrar, endpoint, _cancel) = make_registrar().await;
        registrar.record_attempt();
        let diag = registrar.diagnostics();
        assert!(diag.last_attempt_at.is_some());
        assert!(diag.last_success_at.is_none());
        endpoint.shutdown();
    }

    #[tokio::test]
    async fn record_success_populates_fields_and_clears_error() {
        let (registrar, endpoint, _cancel) = make_registrar().await;
        registrar.record_failure(Some(401), "auth required".to_string());
        registrar.record_success(200, 120, Some("sip:1001@127.0.0.1:5060".to_string()));

        let diag = registrar.diagnostics();
        assert_eq!(diag.last_status, Some(200));
        assert_eq!(diag.negotiated_expires, Some(120));
        assert_eq!(diag.contact_uri.as_deref(), Some("sip:1001@127.0.0.1:5060"));
        assert!(diag.last_success_at.is_some());
        assert!(diag.last_error.is_none(), "success should clear error");
        assert_eq!(diag.register_count, 1);
        assert_eq!(diag.failure_count, 1, "prior failure count preserved");
        endpoint.shutdown();
    }

    #[tokio::test]
    async fn record_failure_increments_and_keeps_contact() {
        let (registrar, endpoint, _cancel) = make_registrar().await;
        registrar.record_success(200, 120, Some("sip:1001@127.0.0.1:5060".to_string()));
        registrar.record_failure(Some(503), "service unavailable".to_string());

        let diag = registrar.diagnostics();
        assert_eq!(diag.last_status, Some(503));
        assert_eq!(diag.last_error.as_deref(), Some("service unavailable"));
        assert_eq!(diag.failure_count, 1);
        assert_eq!(diag.register_count, 1);
        assert_eq!(
            diag.contact_uri.as_deref(),
            Some("sip:1001@127.0.0.1:5060"),
            "failure should not wipe last-known contact"
        );
        endpoint.shutdown();
    }

    #[tokio::test]
    async fn record_failure_without_status_preserves_none() {
        let (registrar, endpoint, _cancel) = make_registrar().await;
        registrar.record_failure(None, "transaction terminated".to_string());

        let diag = registrar.diagnostics();
        assert!(diag.last_status.is_none());
        assert_eq!(diag.last_error.as_deref(), Some("transaction terminated"));
        assert_eq!(diag.failure_count, 1);
        endpoint.shutdown();
    }
}
