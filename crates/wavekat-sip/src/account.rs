//! Runtime SIP account configuration.
//!
//! This is intentionally minimal: just the fields needed to register a
//! UAC against a SIP server. Persistence (TOML files, system keychain)
//! belongs in the application layer, not in this crate.

use serde::{Deserialize, Serialize};

/// Transport protocol for SIP signaling.
///
/// Marked `#[non_exhaustive]`: a `match` on this type in consumer code needs a
/// wildcard arm. SIP keeps acquiring transports — this enum has already grown
/// [`Tcp`](Transport::Tcp) and [`Tls`](Transport::Tls), and WebSocket (RFC
/// 7118) is the obvious next one. Without the attribute every such addition is
/// a source break for anyone matching exhaustively; with it they are additive.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Transport {
    #[default]
    Udp,
    Tcp,
    /// SIP over TLS (RFC 3261 §26.2.1). Defaults to port 5061 and is located
    /// via `_sips._tcp` SRV records.
    ///
    /// This variant exists regardless of build configuration, but using it
    /// requires the `tls` cargo feature. Without that feature, establishing
    /// an endpoint with this transport selected returns an `io::Error` with
    /// [`io::ErrorKind::Unsupported`](std::io::ErrorKind::Unsupported)
    /// rather than failing to compile.
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
///
/// This type itself builds and (de)serializes with no cargo feature enabled —
/// a consumer's stored config can carry a `tls_policy` unconditionally — but it
/// only affects a connection once the `tls` feature is enabled and
/// [`Transport::Tls`] is selected. Under any other transport it is accepted
/// and ignored.
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
        ///
        /// Serializes as a 64-character lowercase hex string — the same form
        /// [`UntrustedCertificate::fingerprint_hex`](crate::UntrustedCertificate::fingerprint_hex)
        /// produces, so a fingerprint read off a trust-on-first-use prompt can
        /// be pasted straight into a stored config. A 32-element byte array
        /// (this field's shape before the hex format shipped) still
        /// deserializes, so existing configs are unaffected.
        #[serde(with = "hex_sha256")]
        sha256: [u8; 32],
    },
}

impl TlsPolicy {
    /// Build [`TlsPolicy::Pinned`] from a 64-character hex SHA-256
    /// fingerprint — the same string
    /// [`UntrustedCertificate::fingerprint_hex`](crate::UntrustedCertificate::fingerprint_hex)
    /// produces. Returns an error describing what was wrong (wrong length, or
    /// a non-hex character) rather than truncating or padding.
    ///
    /// This is a convenience constructor, not the serde wire format —
    /// `hex_sha256` (this module) is the one-way door; this function can
    /// change shape freely.
    pub fn pinned_from_hex(hex: &str) -> Result<Self, String> {
        parse_hex_sha256(hex).map(|sha256| Self::Pinned { sha256 })
    }
}

/// Parse a 64-character hex string into a 32-byte digest. Shared by
/// [`TlsPolicy::pinned_from_hex`] and `hex_sha256`'s deserializer, so there is
/// exactly one place that decides what counts as valid hex.
fn parse_hex_sha256(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!(
            "expected a 64-character hex string, got {} characters",
            hex.len()
        ));
    }
    // Checked up front rather than left to `from_str_radix`, which accepts a
    // leading `+`: `"+f"` would otherwise parse as 15.
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("`{hex}` is not valid hex"));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).map_err(|_| format!("`{hex}` is not valid hex"))?;
        out[i] = u8::from_str_radix(s, 16).map_err(|_| format!("`{hex}` is not valid hex"))?;
    }
    Ok(out)
}

/// `TlsPolicy::Pinned`'s `sha256` field as a lowercase hex string on the wire,
/// accepting either that or the legacy 32-element byte array on the way in.
///
/// A fingerprint is display data before it is config data —
/// [`UntrustedCertificate::fingerprint_hex`](crate::UntrustedCertificate::fingerprint_hex)
/// already hands a consumer hex, so serializing as a byte array of integers
/// forced a conversion at the one boundary this type exists to make easy: an
/// operator pasting a fingerprint off a screen into a stored config.
mod hex_sha256 {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub(super) fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        serializer.serialize_str(&hex)
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(Sha256Visitor)
    }

    struct Sha256Visitor;

    impl<'de> Visitor<'de> for Sha256Visitor {
        type Value = [u8; 32];

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "a 64-character lowercase hex string, or a 32-element byte array"
            )
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            super::parse_hex_sha256(v).map_err(E::custom)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut out = [0u8; 32];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(i, &self))?;
            }
            if seq.next_element::<u8>()?.is_some() {
                return Err(de::Error::invalid_length(33, &self));
            }
            Ok(out)
        }
    }
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
    /// How to verify the server's certificate under [`Transport::Tls`].
    /// Ignored for UDP and TCP.
    #[serde(default)]
    pub tls_policy: TlsPolicy,
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
            tls_policy: TlsPolicy::default(),
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
    fn transport_round_trips_through_serde_as_lowercase() {
        // `#[non_exhaustive]` on `Transport` changes what consumers may write
        // in a `match`, not what the derives emit. A stored config carries
        // these strings, so the wire form is pinned here: if the attribute or
        // a future variant ever disturbs `rename_all`, a saved account stops
        // loading with its chosen transport.
        for (transport, wire) in [
            (Transport::Udp, "\"udp\""),
            (Transport::Tcp, "\"tcp\""),
            (Transport::Tls, "\"tls\""),
        ] {
            let json = serde_json::to_string(&transport).expect("serialize");
            assert_eq!(json, wire);
            let back: Transport = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(transport, back, "round trip through {json}");
        }
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

    #[test]
    fn tls_policy_defaults_to_system_roots() {
        assert_eq!(make_account().tls_policy, TlsPolicy::SystemRoots);
    }

    #[test]
    fn tls_policy_pinned_serializes_as_a_hex_string() {
        // The wire form a consumer's stored config actually carries: a
        // fingerprint read off a trust-on-first-use prompt, pasted straight
        // in — not a 32-element array of integers.
        let policy = TlsPolicy::Pinned {
            sha256: [0xabu8; 32],
        };
        let json = serde_json::to_string(&policy).expect("serialize");
        assert_eq!(
            json,
            format!(r#"{{"pinned":{{"sha256":"{}"}}}}"#, "ab".repeat(32))
        );
    }

    #[test]
    fn tls_policy_pinned_accepts_the_legacy_byte_array() {
        // Configs stored before the wire format changed to hex used a
        // 32-element byte array; those must keep deserializing unchanged.
        let mut sha256 = [0u8; 32];
        sha256[0] = 171;
        sha256[1] = 63;
        sha256[31] = 9;
        let array = sha256
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let json = format!(r#"{{"pinned":{{"sha256":[{array}]}}}}"#);
        let policy: TlsPolicy = serde_json::from_str(&json).expect("legacy array deserializes");
        assert_eq!(policy, TlsPolicy::Pinned { sha256 });
    }

    #[test]
    fn tls_policy_pinned_rejects_a_wrong_length_hex_string() {
        let json = r#"{"pinned":{"sha256":"abcd"}}"#;
        let err = serde_json::from_str::<TlsPolicy>(json).expect_err("too short must fail");
        assert!(err.to_string().contains("64"), "{err}");
    }

    #[test]
    fn pinned_from_hex_rejects_a_sign_prefixed_chunk() {
        // `u8::from_str_radix` accepts a leading `+`, so `"+f"` parses as 15.
        // Repeated 32 times it is exactly 64 characters, so the length check
        // passes too — and without a digit guard the result is a pin of
        // `[15; 32]`, silently built from input that is not a fingerprint.
        let bad = "+f".repeat(32);
        assert_eq!(bad.len(), 64);
        let err = TlsPolicy::pinned_from_hex(&bad).expect_err("a `+` is not a hex digit");
        assert!(err.contains("hex"), "{err}");
    }

    #[test]
    fn a_sign_prefixed_pin_in_config_is_rejected() {
        let bad = "+f".repeat(32);
        let json = format!(r#"{{"pinned":{{"sha256":"{bad}"}}}}"#);
        let err = serde_json::from_str::<TlsPolicy>(&json).expect_err("a `+` is not a hex digit");
        assert!(err.to_string().contains("hex"), "{err}");
    }

    #[test]
    fn tls_policy_pinned_rejects_a_non_hex_string() {
        let bad = format!("{}zz", "0".repeat(62)); // 64 chars, trailing non-hex
        let json = format!(r#"{{"pinned":{{"sha256":"{bad}"}}}}"#);
        let err = serde_json::from_str::<TlsPolicy>(&json).expect_err("non-hex must fail");
        assert!(err.to_string().contains("hex"), "{err}");
    }

    #[test]
    fn pinned_from_hex_matches_fingerprint_hex() {
        // The constructor and UntrustedCertificate::fingerprint_hex must
        // agree on format, or an operator pasting one into the other fails.
        let cert = crate::tls_error::UntrustedCertificate {
            sha256: [0x42u8; 32],
            reason: crate::tls_error::CertFailure::UnknownIssuer,
        };
        let policy = TlsPolicy::pinned_from_hex(&cert.fingerprint_hex()).expect("valid hex");
        assert_eq!(
            policy,
            TlsPolicy::Pinned {
                sha256: cert.sha256
            }
        );
    }

    #[test]
    fn pinned_from_hex_rejects_wrong_length() {
        assert!(TlsPolicy::pinned_from_hex("ab").is_err());
    }

    #[test]
    fn pinned_from_hex_rejects_non_hex_characters() {
        assert!(TlsPolicy::pinned_from_hex(&format!("{}zz", "0".repeat(62))).is_err());
    }

    /// A consumer's config predating `tls_policy` — no such key at all — must
    /// still deserialize, with the field defaulting rather than erroring.
    /// (No `toml` dev-dependency in this crate; `serde_json` exercises the
    /// same `#[serde(default)]` path `TlsPolicy` relies on.)
    #[test]
    fn a_config_without_tls_policy_still_deserializes() {
        let json = r#"{
            "display_name": "Test",
            "username": "1001",
            "password": "secret",
            "domain": "sip.example.com",
            "auth_username": null,
            "server": null,
            "port": null,
            "transport": "udp"
        }"#;
        let acct: SipAccount = serde_json::from_str(json).expect("deserializes");
        assert_eq!(acct.tls_policy, TlsPolicy::SystemRoots);
    }
}
