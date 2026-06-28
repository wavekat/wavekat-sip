//! REGISTER + digest auth + keepalive re-registration, over the engine.
//!
//! [`Registrar::register`] composes a REGISTER, sends it through the engine,
//! answers a `401`/`407` digest challenge, and records the outcome.
//! [`Registrar::keepalive_loop`] re-registers on an interval until cancelled;
//! [`Registrar::unregister`] sends `Expires: 0`.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::account::SipAccount;
use crate::endpoint::SipEndpoint;
use crate::stack::registration::{RegisterConfig, RegisterOutcome};
use crate::stack::transaction::gen_tag;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A point-in-time snapshot of a [`Registrar`]'s status, for UIs/telemetry.
#[derive(Debug, Clone)]
pub struct RegistrarDiagnostics {
    pub server_uri: String,
    pub contact_uri: Option<String>,
    pub call_id: String,
    pub cseq: u32,
    pub configured_expires: u32,
    pub negotiated_expires: Option<u32>,
    pub last_status: Option<u16>,
    pub last_attempt_at: Option<SystemTime>,
    pub last_success_at: Option<SystemTime>,
    pub last_error: Option<String>,
    pub register_count: u64,
    pub failure_count: u64,
}

/// Mutable registration state behind a mutex.
struct State {
    cseq: u32,
    negotiated_expires: Option<u32>,
    last_status: Option<u16>,
    last_attempt_at: Option<SystemTime>,
    last_success_at: Option<SystemTime>,
    last_error: Option<String>,
    register_count: u64,
    failure_count: u64,
}

/// Registers an account and keeps the registration fresh.
pub struct Registrar {
    account: SipAccount,
    endpoint: Arc<SipEndpoint>,
    cancel: CancellationToken,
    expires: u32,
    refresh_secs: u64,
    call_id: String,
    from_tag: String,
    contact: String,
    state: Mutex<State>,
}

impl Registrar {
    /// Build a registrar. `expires` is the requested lifetime; `refresh_secs`
    /// is how often [`keepalive_loop`](Self::keepalive_loop) re-registers.
    pub fn new(
        account: SipAccount,
        endpoint: Arc<SipEndpoint>,
        cancel: CancellationToken,
        expires: u32,
        refresh_secs: u64,
    ) -> Result<Self, BoxError> {
        let contact = format!("sip:{}@{}", account.username, endpoint.local_addr());
        Ok(Self {
            account,
            endpoint,
            cancel,
            expires,
            refresh_secs,
            call_id: format!("{}@wavekat.com", gen_tag()),
            from_tag: gen_tag(),
            contact,
            state: Mutex::new(State {
                cseq: 0,
                negotiated_expires: None,
                last_status: None,
                last_attempt_at: None,
                last_success_at: None,
                last_error: None,
                register_count: 0,
                failure_count: 0,
            }),
        })
    }

    fn config(&self, expires: u32) -> Result<RegisterConfig, BoxError> {
        Ok(RegisterConfig {
            registrar_uri: format!("sip:{}", self.account.domain).try_into()?,
            aor: format!("sip:{}@{}", self.account.username, self.account.domain).try_into()?,
            contact: self.contact.clone().try_into()?,
            from_tag: self.from_tag.clone(),
            call_id: self.call_id.clone(),
            expires,
            username: self.account.auth_username().to_string(),
            password: self.account.password.clone(),
        })
    }

    /// Register once with the configured lifetime.
    pub async fn register(&self) -> Result<(), BoxError> {
        self.register_with(self.expires).await
    }

    async fn register_with(&self, expires: u32) -> Result<(), BoxError> {
        let cseq = {
            let mut state = self.state.lock().await;
            state.cseq += 1;
            state.last_attempt_at = Some(SystemTime::now());
            state.cseq
        };

        let cfg = self.config(expires)?;
        let outcome = self
            .endpoint
            .ua()
            .register(&cfg, self.endpoint.server(), cseq)
            .await;

        let mut state = self.state.lock().await;
        match outcome {
            RegisterOutcome::Registered { expires } => {
                state.negotiated_expires = Some(expires);
                state.last_status = Some(200);
                state.last_success_at = Some(SystemTime::now());
                state.last_error = None;
                state.register_count += 1;
                info!(expires, "registered");
                Ok(())
            }
            RegisterOutcome::Unauthorized => {
                state.last_status = Some(401);
                state.last_error = Some("authentication failed".into());
                state.failure_count += 1;
                Err("registration rejected: authentication failed".into())
            }
            RegisterOutcome::Failed(status) => {
                state.last_status = Some(status.code());
                state.last_error = Some(format!("server returned {status}"));
                state.failure_count += 1;
                Err(format!("registration failed: {status}").into())
            }
            RegisterOutcome::TimedOut => {
                state.last_error = Some("timed out".into());
                state.failure_count += 1;
                Err("registration timed out".into())
            }
            RegisterOutcome::EngineStopped => Err("engine stopped".into()),
        }
    }

    /// Re-register every `refresh_secs` until the cancel token fires.
    pub async fn keepalive_loop(&self) {
        loop {
            if let Err(e) = self.register().await {
                warn!("keepalive register failed: {e}");
            }
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(self.refresh_secs)) => {}
            }
        }
    }

    /// De-register by sending `Expires: 0`.
    pub async fn unregister(&self) {
        if let Err(e) = self.register_with(0).await {
            warn!("unregister failed: {e}");
        }
    }

    /// Snapshot the current diagnostics.
    pub async fn diagnostics(&self) -> RegistrarDiagnostics {
        let state = self.state.lock().await;
        RegistrarDiagnostics {
            server_uri: format!("sip:{}", self.account.domain),
            contact_uri: Some(self.contact.clone()),
            call_id: self.call_id.clone(),
            cseq: state.cseq,
            configured_expires: self.expires,
            negotiated_expires: state.negotiated_expires,
            last_status: state.last_status,
            last_attempt_at: state.last_attempt_at,
            last_success_at: state.last_success_at,
            last_error: state.last_error.clone(),
            register_count: state.register_count,
            failure_count: state.failure_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::Transport;

    fn account() -> SipAccount {
        SipAccount {
            display_name: "T".into(),
            username: "1001".into(),
            password: "secret".into(),
            domain: "example.com".into(),
            auth_username: None,
            server: Some("127.0.0.1".into()),
            port: Some(5060),
            transport: Transport::Udp,
        }
    }

    #[test]
    fn register_config_uris_follow_account() {
        let acct = account();
        let cfg = RegisterConfig {
            registrar_uri: format!("sip:{}", acct.domain).try_into().unwrap(),
            aor: format!("sip:{}@{}", acct.username, acct.domain)
                .try_into()
                .unwrap(),
            contact: "sip:1001@10.0.0.1:5060".try_into().unwrap(),
            from_tag: "t".into(),
            call_id: "c".into(),
            expires: 60,
            username: acct.auth_username().to_string(),
            password: acct.password.clone(),
        };
        assert_eq!(cfg.registrar_uri.to_string(), "sip:example.com");
        assert_eq!(cfg.aor.to_string(), "sip:1001@example.com");
        assert_eq!(cfg.username, "1001");
    }
}
