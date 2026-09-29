//! REGISTER + digest auth + keepalive re-registration, over the engine.
//!
//! [`Registrar::register`] composes a REGISTER, sends it through the engine,
//! answers a `401`/`407` digest challenge, and records the outcome. A
//! registrar that rejects the lifetime as too brief (`423`, RFC 3261 §10.2.8)
//! is answered with one retry at the `Min-Expires` it named, and that floor is
//! remembered so later refreshes ask for it outright.
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
use crate::stack::transaction::{contact_uri, gen_tag};

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
    pub min_expires: Option<u32>,
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
    /// Shortest lifetime this registrar has said it accepts, learned from a
    /// `423`'s `Min-Expires`.
    min_expires: Option<u32>,
    last_status: Option<u16>,
    last_attempt_at: Option<SystemTime>,
    last_success_at: Option<SystemTime>,
    last_error: Option<String>,
    register_count: u64,
    failure_count: u64,
}

/// The lifetime to request: the configured one, raised to a `Min-Expires`
/// floor the registrar has already named. Asking below a floor we have been
/// told about only earns another `423`.
fn requested_expires(configured: u32, floor: Option<u32>) -> u32 {
    match floor {
        Some(floor) => configured.max(floor),
        None => configured,
    }
}

/// The lifetime to retry a `423` at, or `None` to let the rejection stand.
///
/// `requested` is what was just asked for, `min_expires` what the registrar
/// answered with. There is no retry when one has already been made (a
/// registrar that refuses its own minimum keeps its answer rather than
/// spinning us), when the request was an unregister (`Expires: 0` — RFC 3261
/// §10.3 step 7 only rejects a non-zero interval, and obeying such a `423`
/// would re-create the binding we asked to remove), or when the named minimum
/// is not an increase and the retry would repeat the same request.
fn retry_expires(requested: u32, min_expires: u32, retried: bool) -> Option<u32> {
    if retried || requested == 0 || min_expires <= requested {
        return None;
    }
    Some(min_expires)
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
        let contact = contact_uri(
            &account.username,
            endpoint.local_addr(),
            endpoint.transport(),
        );
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
                min_expires: None,
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

    /// Register once, at the configured lifetime — raised to this registrar's
    /// minimum if a `423` has already named one.
    pub async fn register(&self) -> Result<(), BoxError> {
        let expires = {
            let state = self.state.lock().await;
            requested_expires(self.expires, state.min_expires)
        };
        self.register_with(expires).await
    }

    /// Send one REGISTER, its `CSeq` taken from the registration state.
    async fn attempt(&self, expires: u32) -> Result<RegisterOutcome, BoxError> {
        let cseq = {
            let mut state = self.state.lock().await;
            state.cseq += 1;
            state.last_attempt_at = Some(SystemTime::now());
            state.cseq
        };

        let cfg = self.config(expires)?;
        let attempt = self
            .endpoint
            .ua()
            .register(&cfg, self.endpoint.server(), cseq)
            .await;

        // Answering a digest challenge puts a second REGISTER on the wire at
        // the next sequence number. RFC 3261 §10.2 forbids reusing a `CSeq`
        // within one `Call-ID`, so carry the wire's number forward instead of
        // our own — otherwise the next refresh replays a number the registrar
        // has already seen, and a registrar that checks rejects it.
        {
            let mut state = self.state.lock().await;
            state.cseq = state.cseq.max(attempt.last_cseq);
        }
        Ok(attempt.outcome)
    }

    /// Register for `requested` seconds, answering a `423 Interval Too Brief`
    /// with one fresh REGISTER at the lifetime the registrar named (RFC 3261
    /// §10.2.8) — a new transaction with its own `CSeq` and its own challenge
    /// cycle, not a replay of the refused one.
    async fn register_with(&self, requested: u32) -> Result<(), BoxError> {
        let mut requested = requested;
        let mut retried = false;
        loop {
            let outcome = self.attempt(requested).await?;
            let mut state = self.state.lock().await;
            match outcome {
                RegisterOutcome::Registered { expires } => {
                    state.negotiated_expires = Some(expires);
                    state.last_status = Some(200);
                    state.last_success_at = Some(SystemTime::now());
                    state.last_error = None;
                    state.register_count += 1;
                    info!(expires, "registered");
                    return Ok(());
                }
                RegisterOutcome::IntervalTooBrief { min_expires } => {
                    // Learn the floor even when this attempt is not retried:
                    // the next refresh then asks for it outright instead of
                    // spending a round trip on the same rejection.
                    state.min_expires = Some(min_expires);
                    state.last_status = Some(423);
                    match retry_expires(requested, min_expires, retried) {
                        Some(next) => {
                            drop(state);
                            info!(
                                requested,
                                min_expires, "registrar wants a longer registration; retrying"
                            );
                            requested = next;
                            retried = true;
                        }
                        None => {
                            state.last_error =
                                Some(format!("registrar requires Expires >= {min_expires}"));
                            state.failure_count += 1;
                            return Err(format!(
                                "registration failed: interval too brief (registrar minimum {min_expires}s)"
                            )
                            .into());
                        }
                    }
                }
                RegisterOutcome::Unauthorized => {
                    state.last_status = Some(401);
                    state.last_error = Some("authentication failed".into());
                    state.failure_count += 1;
                    return Err("registration rejected: authentication failed".into());
                }
                RegisterOutcome::Failed(status) => {
                    state.last_status = Some(status.code());
                    state.last_error = Some(format!("server returned {status}"));
                    state.failure_count += 1;
                    return Err(format!("registration failed: {status}").into());
                }
                RegisterOutcome::TimedOut => {
                    state.last_error = Some("timed out".into());
                    state.failure_count += 1;
                    return Err("registration timed out".into());
                }
                RegisterOutcome::EngineStopped => return Err("engine stopped".into()),
            }
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
            min_expires: state.min_expires,
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
    use crate::account::{TlsPolicy, Transport};

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
            tls_policy: TlsPolicy::default(),
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

    #[test]
    fn contact_uri_omits_transport_param_for_udp() {
        let local: std::net::SocketAddr = "10.0.0.1:5060".parse().expect("addr");
        let c = contact_uri("1001", local, crate::account::Transport::Udp);
        assert_eq!(c, "sip:1001@10.0.0.1:5060");
    }

    /// RFC 3261 §19.1.1: a Contact URI with no transport parameter means UDP.
    /// Without this the registrar routes inbound INVITEs to a UDP socket that
    /// does not exist on a TCP endpoint.
    #[test]
    fn contact_uri_names_tcp_transport() {
        let local: std::net::SocketAddr = "10.0.0.1:5060".parse().expect("addr");
        let c = contact_uri("1001", local, crate::account::Transport::Tcp);
        assert_eq!(c, "sip:1001@10.0.0.1:5060;transport=tcp");
    }

    /// RFC 3261 §10.2.8: once a registrar has named its minimum, every later
    /// REGISTER asks for at least that much — otherwise each refresh would
    /// earn another `423` and burn a round trip re-learning the same number.
    #[test]
    fn a_learned_floor_raises_the_requested_lifetime() {
        assert_eq!(requested_expires(60, None), 60);
        assert_eq!(requested_expires(60, Some(3600)), 3600);
    }

    /// A floor below what the account already asks for changes nothing.
    #[test]
    fn a_lower_floor_does_not_shorten_the_requested_lifetime() {
        assert_eq!(requested_expires(3600, Some(60)), 3600);
    }

    /// The retry the `423` asks for: ask again at the registrar's minimum.
    #[test]
    fn a_423_retries_at_the_named_minimum() {
        assert_eq!(retry_expires(60, 3600, false), Some(3600));
    }

    /// Only once. A registrar that `423`s the retry too gets to keep its
    /// answer rather than spinning us.
    #[test]
    fn a_second_423_is_not_retried_again() {
        assert_eq!(retry_expires(60, 3600, true), None);
    }

    /// `unregister` sends `Expires: 0`. RFC 3261 §10.3 step 7 only rejects a
    /// *non-zero* interval, so a `423` here is nonsense — and honouring it
    /// would re-create the binding we asked to remove.
    #[test]
    fn a_423_never_bumps_an_unregister() {
        assert_eq!(retry_expires(0, 3600, false), None);
    }

    /// A `Min-Expires` that is not an increase would resend the same request.
    #[test]
    fn a_423_naming_no_increase_is_not_retried() {
        assert_eq!(retry_expires(3600, 3600, false), None);
        assert_eq!(retry_expires(3600, 60, false), None);
    }

    /// The Contact we publish is what the Via transport is read back from, so
    /// a TCP contact must round-trip to a TCP Via.
    #[test]
    fn tcp_contact_round_trips_to_a_tcp_via() {
        use crate::stack::transaction::{transport_of, via_value};
        let local: std::net::SocketAddr = "10.0.0.1:5060".parse().expect("addr");
        let uri: rsip::Uri = contact_uri("1001", local, crate::account::Transport::Tcp)
            .try_into()
            .expect("uri");
        assert!(via_value(transport_of(&uri), local, "b").starts_with("SIP/2.0/TCP "));
    }
}
