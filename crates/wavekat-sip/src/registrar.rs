//! REGISTER + digest auth + keepalive re-registration.

use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rsip::{prelude::HeadersExt, prelude::ToTypedHeader, SipMessage, StatusCode, Uri};
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
    /// `Call-ID` used across this registrar's REGISTER dialog.
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
    /// 60–300 seconds). `keepalive_secs` is how long to wait between
    /// re-registrations (typical: `register_expires` minus a small margin,
    /// e.g. `expires - 10`).
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
            call_id: self.call_id.to_string(),
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

    /// Send the initial REGISTER. Retries on failure until cancelled.
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
                    self.record_failure(Some(code), msg);
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

    /// Re-register loop: sleeps `keepalive_secs`, then re-REGISTERs.
    /// Runs until cancelled.
    pub async fn keepalive_loop(&self) {
        loop {
            let keepalive_secs = self.keepalive_secs;
            info!("Re-registering in {keepalive_secs}s...");

            select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(keepalive_secs as u64)) => {}
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
