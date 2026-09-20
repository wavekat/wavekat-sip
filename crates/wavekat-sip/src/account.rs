//! Runtime SIP account configuration.
//!
//! This is intentionally minimal: just the fields needed to register a
//! UAC against a SIP server. Persistence (TOML files, system keychain)
//! belongs in the application layer, not in this crate.

use serde::{Deserialize, Serialize};

/// Transport protocol for SIP signaling.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    Udp,
    Tcp,
    /// SIP over TLS (RFC 3261 §26.2.1). Defaults to port 5061 and is located
    /// via `_sips._tcp` SRV records.
    Tls,
}

/// How to decide whether to trust a TLS server's certificate.
///
/// There is deliberately no "skip verification" variant. It is the setting
/// people enable to make an error message disappear, after which the connection
/// has ceremony and no security, permanently, with nothing saying so.
/// [`Pinned`](TlsPolicy::Pinned) covers the case it is usually asked for — the
/// self-signed on-premise server — and stays narrow: it trusts one certificate,
/// not every certificate.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TlsPolicy {
    /// Validate against the operating system's trust store. A private CA an
    /// administrator has installed system-wide works with no extra setup.
    #[default]
    SystemRoots,
    /// Accept exactly one certificate, by SHA-256 of its DER encoding.
    Pinned {
        /// The pinned fingerprint. [`UntrustedCertificate::sha256`](crate::UntrustedCertificate::sha256)
        /// reports the value to pin.
        sha256: [u8; 32],
    },
}

/// Runtime SIP account. The password is held in memory while the endpoint
/// is registered; load it from your application's secret store on startup.
#[derive(Debug, Clone, Deserialize)]
pub struct SipAccount {
    /// Display name in From/Contact headers (e.g. `"Office"`).
    pub display_name: String,
    /// SIP user (the part before `@` in the AOR).
    pub username: String,
    /// Plaintext password for digest authentication.
    pub password: String,
    /// SIP domain (the part after `@` in the AOR).
    pub domain: String,

    /// Auth username for digest auth, if different from `username`.
    pub auth_username: Option<String>,
    /// SIP server address, defaults to `domain`.
    pub server: Option<String>,
    /// SIP port, defaults to 5060.
    pub port: Option<u16>,
    /// Transport protocol, defaults to UDP.
    #[serde(default)]
    pub transport: Transport,
}

impl SipAccount {
    /// Auth username: falls back to `username` if not set.
    pub fn auth_username(&self) -> &str {
        self.auth_username.as_deref().unwrap_or(&self.username)
    }

    /// Server address: falls back to `domain` if not set.
    pub fn server(&self) -> &str {
        self.server.as_deref().unwrap_or(&self.domain)
    }

    /// SIP port: defaults to 5061 under TLS, 5060 otherwise.
    ///
    /// RFC 3261 §26.2.1 assigns TLS its own default port; a TLS account that
    /// fell back to 5060 would connect to the cleartext port and fail the
    /// handshake.
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(match self.transport {
            Transport::Tls => 5061,
            Transport::Udp | Transport::Tcp => 5060,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_account() -> SipAccount {
        SipAccount {
            display_name: "Test".to_string(),
            username: "1001".to_string(),
            password: "secret".to_string(),
            domain: "sip.example.com".to_string(),
            auth_username: None,
            server: None,
            port: None,
            transport: Transport::default(),
        }
    }

    #[test]
    fn defaults_auth_username_to_username() {
        let acct = make_account();
        assert_eq!(acct.auth_username(), "1001");
    }

    #[test]
    fn overrides_auth_username() {
        let mut acct = make_account();
        acct.auth_username = Some("admin".to_string());
        assert_eq!(acct.auth_username(), "admin");
    }

    #[test]
    fn defaults_server_to_domain() {
        let acct = make_account();
        assert_eq!(acct.server(), "sip.example.com");
    }

    #[test]
    fn overrides_server() {
        let mut acct = make_account();
        acct.server = Some("10.0.0.1".to_string());
        assert_eq!(acct.server(), "10.0.0.1");
    }

    #[test]
    fn defaults_port_to_5060() {
        let acct = make_account();
        assert_eq!(acct.port(), 5060);
    }

    #[test]
    fn overrides_port() {
        let mut acct = make_account();
        acct.port = Some(5080);
        assert_eq!(acct.port(), 5080);
    }

    #[test]
    fn default_transport_is_udp() {
        assert_eq!(Transport::default(), Transport::Udp);
    }

    #[test]
    fn tls_port_defaults_to_5061() {
        let mut acct = make_account();
        acct.transport = Transport::Tls;
        assert_eq!(acct.port(), 5061);
    }

    #[test]
    fn explicit_port_still_wins_under_tls() {
        let mut acct = make_account();
        acct.transport = Transport::Tls;
        acct.port = Some(5080);
        assert_eq!(acct.port(), 5080);
    }

    #[test]
    fn udp_and_tcp_ports_are_unchanged() {
        let mut acct = make_account();
        acct.transport = Transport::Tcp;
        assert_eq!(acct.port(), 5060);
        acct.transport = Transport::Udp;
        assert_eq!(acct.port(), 5060);
    }

    #[test]
    fn tls_policy_default_is_system_roots() {
        assert_eq!(TlsPolicy::default(), TlsPolicy::SystemRoots);
    }

    #[test]
    fn tls_policy_round_trips_through_serde() {
        // A consumer's stored account config carries `TlsPolicy` with
        // `#[serde(default)]`; if the derive ever stops round-tripping, that
        // config silently stops loading correctly.
        for policy in [
            TlsPolicy::SystemRoots,
            TlsPolicy::Pinned { sha256: [9u8; 32] },
        ] {
            let json = serde_json::to_string(&policy).expect("serialize");
            let back: TlsPolicy = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(policy, back, "round trip through {json}");
        }
    }

    #[test]
    fn tls_policy_serializes_as_snake_case() {
        let json = serde_json::to_string(&TlsPolicy::SystemRoots).expect("serialize");
        assert_eq!(json, "\"system_roots\"");
    }
}
