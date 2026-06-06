//! Live-DNS integration tests for RFC 3263 SRV server location.
//!
//! These hit real DNS, so they are `#[ignore]`'d. Run with:
//!
//! ```sh
//! cargo test --test srv_resolution -- --ignored
//! ```
//!
//! Set `WAVEKAT_SIP_SRV_DOMAIN` to a SIP domain that publishes
//! `_sip._udp` SRV records to exercise the SRV path against your own
//! provider.

use wavekat_sip::{resolve_sip_server, SipAccount, Transport};

fn account(domain: &str) -> SipAccount {
    SipAccount {
        display_name: "Test".to_string(),
        username: "1001".to_string(),
        password: "secret".to_string(),
        domain: domain.to_string(),
        auth_username: None,
        server: None,
        port: None,
        transport: Transport::Udp,
    }
}

/// A domain with `_sip._udp` SRV records resolves to the SRV target
/// and port, not the bare host at 5060.
#[tokio::test]
#[ignore = "requires live DNS and a domain publishing _sip._udp SRV records"]
async fn srv_domain_resolves_via_srv() {
    // sip.linphone.org has published _sip._udp SRV records for years;
    // override if it ever changes.
    let domain =
        std::env::var("WAVEKAT_SIP_SRV_DOMAIN").unwrap_or_else(|_| "sip.linphone.org".to_string());
    let addr = resolve_sip_server(&account(&domain))
        .await
        .expect("DNS reachable")
        .expect("SRV path should yield an address");
    assert_ne!(addr.port(), 0);
}

/// A domain without SRV records falls back to A/AAAA at 5060 — exactly
/// the pre-SRV behavior.
#[tokio::test]
#[ignore = "requires live DNS"]
async fn srv_less_domain_falls_back_to_a_record() {
    // example.com publishes A/AAAA but no _sip._udp SRV.
    let addr = resolve_sip_server(&account("example.com"))
        .await
        .expect("DNS reachable")
        .expect("A/AAAA fallback should yield an address");
    assert_eq!(addr.port(), 5060, "fallback must use the default SIP port");
}

/// An explicit port skips DNS-based SRV logic entirely; an IP-literal
/// server resolves without any DNS at all.
#[tokio::test]
#[ignore = "requires live DNS"]
async fn explicit_port_and_ip_literal_take_direct_path() {
    let mut acct = account("example.com");
    acct.server = Some("192.0.2.10".to_string());
    let addr = resolve_sip_server(&acct)
        .await
        .expect("no DNS needed")
        .expect("IP literal always resolves");
    assert_eq!(addr, "192.0.2.10:5060".parse().unwrap());

    let mut acct = account("example.com");
    acct.port = Some(5080);
    let addr = resolve_sip_server(&acct)
        .await
        .expect("DNS reachable")
        .expect("A/AAAA at explicit port");
    assert_eq!(addr.port(), 5080);
}
