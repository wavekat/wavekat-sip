//! REGISTER + digest auth + keepalive re-registration.

use std::sync::Arc;

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
        })
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

                    *self.contact.lock().await = typed_contact;

                    info!(
                        "Registered as {}@{} (expires {}s)",
                        self.account.username, self.account.domain, expires
                    );
                    return Ok(());
                }
                Some(resp) => {
                    warn!("Registration failed with status {}", resp.status_code);
                }
                None => {
                    warn!("Registration transaction terminated unexpectedly");
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
                    warn!("Failed to build re-register request: {e}");
                    continue;
                }
            };

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

                    *self.contact.lock().await = typed_contact;
                    self.set_seq(seq_val);

                    info!(
                        "Re-registered as {}@{} (expires {}s)",
                        self.account.username, self.account.domain, expires
                    );
                }
                Ok(Some(resp)) => {
                    warn!("Re-registration failed: {}", resp.status_code);
                    self.set_seq(seq_val);
                }
                Ok(None) => {
                    warn!("Re-registration got no response");
                    self.set_seq(seq_val);
                }
                Err(e) => {
                    warn!("Re-registration error: {e}");
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
