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

    /// SIP port: defaults to 5060.
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(5060)
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
}
