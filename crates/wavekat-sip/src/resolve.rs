//! SIP server location per a subset of RFC 3263: DNS SRV lookup with
//! RFC 2782 ordering, falling back to plain A/AAAA.
//!
//! Scope (see `docs/20260606-srv-lookup.md` for the full design):
//!
//! - An explicit `port` on the account, or an IP-literal `server`,
//!   skips SRV entirely and resolves A/AAAA directly (RFC 3263 §4.1) —
//!   identical to the crate's historical behavior.
//! - Otherwise `_sip._udp.<host>` / `_sip._tcp.<host>` is queried and
//!   candidates are ordered by priority, then weighted-random within a
//!   priority class (RFC 2782). The first target that resolves wins,
//!   at the SRV-provided port.
//! - No SRV records (NXDOMAIN/empty, or a failed query) falls back to
//!   A/AAAA on the bare host at the default port — today's behavior.
//! - NAPTR and TLS (`_sips._tcp`) are not implemented.

use std::net::{IpAddr, SocketAddr};

use tracing::debug;

use crate::account::{SipAccount, Transport};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// One DNS SRV record (RFC 2782) describing a SIP server candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRecord {
    /// Lower priority classes are tried first.
    pub priority: u16,
    /// Relative weight for selection within a priority class.
    pub weight: u16,
    /// Port the service listens on at `target`.
    pub port: u16,
    /// Target host name (no trailing dot). `"."` means the service is
    /// decidedly not available at this domain.
    pub target: String,
}

/// Order SRV records per RFC 2782: ascending priority, then
/// weighted-random selection without replacement within each priority
/// class. Zero-weight records are placed first in the selection order,
/// as the RFC prescribes, which gives them a small but non-zero chance.
///
/// Pure and deterministic for a given `seed` (an embedded SplitMix64
/// PRNG drives the weighted choice), so callers should seed it from an
/// entropy source and tests can pin the seed.
pub fn order_candidates(records: &[SrvRecord], seed: u64) -> Vec<SrvRecord> {
    let mut rng = SplitMix64(seed);
    let mut sorted = records.to_vec();
    // Stable sort: equal-priority records keep their relative order,
    // which the per-class shuffle below then randomizes by weight.
    sorted.sort_by_key(|r| r.priority);

    let mut ordered = Vec::with_capacity(sorted.len());
    let mut start = 0;
    while start < sorted.len() {
        let priority = sorted[start].priority;
        let end = sorted[start..]
            .iter()
            .position(|r| r.priority != priority)
            .map(|p| start + p)
            .unwrap_or(sorted.len());

        let mut class: Vec<SrvRecord> = sorted[start..end].to_vec();
        // RFC 2782: order zero-weight records first before the running
        //-sum walk so they can still be selected when the roll is 0.
        class.sort_by_key(|r| r.weight != 0);
        while !class.is_empty() {
            let total: u64 = class.iter().map(|r| u64::from(r.weight)).sum();
            let pick = if total == 0 {
                // All weights zero: uniform choice. (Modulo bias is
                // negligible for the handful of records SRV answers
                // carry.)
                (rng.next_u64() % class.len() as u64) as usize
            } else {
                let roll = rng.next_u64() % (total + 1);
                let mut running = 0u64;
                let mut chosen = 0;
                for (idx, rec) in class.iter().enumerate() {
                    running += u64::from(rec.weight);
                    if running >= roll {
                        chosen = idx;
                        break;
                    }
                }
                chosen
            };
            ordered.push(class.remove(pick));
        }
        start = end;
    }
    ordered
}

/// Minimal deterministic PRNG (SplitMix64) so the weighted choice in
/// [`order_candidates`] is seedable in tests without a `rand` dep.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// Seed for the weighted-random SRV ordering. Mixes the std hasher's
/// per-process random keys with the current time — plenty for load
/// distribution, no cryptographic claim.
fn entropy_seed() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let hashed = RandomState::new().build_hasher().finish();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::from(d.subsec_nanos()))
        .unwrap_or(0);
    hashed ^ nanos
}

/// How to locate the SIP server for an account (pure decision, no DNS).
#[derive(Debug, Clone, PartialEq, Eq)]
enum LocationPlan {
    /// Skip SRV (RFC 3263 §4.1): the account pins an explicit port, or
    /// the server is an IP literal. Resolve `host:port` directly.
    Direct { host: String, port: u16 },
    /// Query SRV `name`; on no records fall back to A/AAAA on
    /// `host:port`.
    Srv {
        name: String,
        host: String,
        port: u16,
    },
}

fn location_plan(account: &SipAccount) -> LocationPlan {
    let host = account.server().to_string();
    if account.port.is_some() || host.parse::<IpAddr>().is_ok() {
        return LocationPlan::Direct {
            host,
            port: account.port(),
        };
    }
    let proto = match account.transport {
        Transport::Udp => "udp",
        Transport::Tcp => "tcp",
    };
    LocationPlan::Srv {
        name: format!("_sip._{proto}.{host}"),
        host,
        port: account.port(),
    }
}

/// DNS operations [`resolve_with`] needs, split out so unit tests can
/// inject a mock and stay off the network.
trait Dns {
    /// SRV records for `name`. NXDOMAIN / empty answers are `Ok(vec![])`;
    /// `Err` is reserved for query failures (SERVFAIL, timeout, …).
    async fn srv(&self, name: &str) -> Result<Vec<SrvRecord>, BoxError>;
    /// First A/AAAA address for `host`, paired with `port`.
    async fn lookup(&self, host: &str, port: u16) -> Result<Option<SocketAddr>, BoxError>;
}

/// Real DNS: SRV via `hickory-resolver` (system config), A/AAAA via
/// `tokio::net::lookup_host` — the exact call the pre-SRV code made,
/// so direct and fallback paths keep identical semantics (including
/// `/etc/hosts`).
struct SystemDns;

impl Dns for SystemDns {
    async fn srv(&self, name: &str) -> Result<Vec<SrvRecord>, BoxError> {
        // Built per call, and only on the SRV path: the direct path
        // never pays for parsing the system resolver config.
        let resolver = hickory_resolver::TokioResolver::builder_tokio()?.build();
        match resolver.srv_lookup(name).await {
            Ok(answer) => Ok(answer
                .iter()
                .map(|srv| SrvRecord {
                    priority: srv.priority(),
                    weight: srv.weight(),
                    port: srv.port(),
                    target: srv.target().to_string().trim_end_matches('.').to_string(),
                })
                .collect()),
            Err(e) if e.is_no_records_found() => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    async fn lookup(&self, host: &str, port: u16) -> Result<Option<SocketAddr>, BoxError> {
        let mut addrs = tokio::net::lookup_host((host, port)).await?;
        Ok(addrs.next())
    }
}

/// Resolve the account's SIP server to a single socket address per the
/// RFC 3263 subset described in the module docs.
///
/// Returns `Ok(None)` when DNS answers but yields no usable address
/// (mirrors the historical `lookup_host` behavior); the caller then
/// leaves destination selection to the SIP stack.
pub async fn resolve_sip_server(account: &SipAccount) -> Result<Option<SocketAddr>, BoxError> {
    resolve_with(&SystemDns, account, entropy_seed()).await
}

async fn resolve_with<D: Dns>(
    dns: &D,
    account: &SipAccount,
    seed: u64,
) -> Result<Option<SocketAddr>, BoxError> {
    match location_plan(account) {
        LocationPlan::Direct { host, port } => {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Ok(Some(SocketAddr::new(ip, port)));
            }
            dns.lookup(&host, port).await
        }
        LocationPlan::Srv { name, host, port } => {
            let records = match dns.srv(&name).await {
                Ok(records) => records,
                Err(e) => {
                    // Robustness over strictness: a broken SRV query
                    // must never make dialing worse than the pre-SRV
                    // behavior, so treat it like an empty answer.
                    debug!("SRV query {name} failed ({e}); falling back to A/AAAA");
                    Vec::new()
                }
            };
            for candidate in order_candidates(&records, seed) {
                if candidate.target == "." || candidate.target.is_empty() {
                    // RFC 2782: "." target = service decidedly not
                    // available at this domain.
                    continue;
                }
                match dns.lookup(&candidate.target, candidate.port).await {
                    Ok(Some(addr)) => {
                        debug!(
                            "SRV {name} -> {}:{} -> {addr}",
                            candidate.target, candidate.port
                        );
                        return Ok(Some(addr));
                    }
                    Ok(None) => continue,
                    Err(e) => {
                        debug!(
                            "SRV target {}:{} failed to resolve ({e}); trying next",
                            candidate.target, candidate.port
                        );
                        continue;
                    }
                }
            }
            if !records.is_empty() {
                // SRV records exist but none of their targets resolve.
                // RFC 3263: do not fall back to A/AAAA in that case.
                return Ok(None);
            }
            debug!("no SRV records for {name}; falling back to A/AAAA on {host}:{port}");
            dns.lookup(&host, port).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    fn rec(priority: u16, weight: u16, port: u16, target: &str) -> SrvRecord {
        SrvRecord {
            priority,
            weight,
            port,
            target: target.to_string(),
        }
    }

    fn account(server: Option<&str>, port: Option<u16>, transport: Transport) -> SipAccount {
        SipAccount {
            display_name: "Test".to_string(),
            username: "1001".to_string(),
            password: "secret".to_string(),
            domain: "sip.example.com".to_string(),
            auth_username: None,
            server: server.map(str::to_string),
            port,
            transport,
        }
    }

    // --- order_candidates: pure RFC 2782 ordering ---

    #[test]
    fn orders_by_ascending_priority_regardless_of_seed() {
        let records = vec![
            rec(20, 0, 5060, "backup.example.com"),
            rec(10, 0, 5060, "primary.example.com"),
            rec(30, 0, 5060, "last.example.com"),
        ];
        for seed in 0..32 {
            let ordered = order_candidates(&records, seed);
            let priorities: Vec<u16> = ordered.iter().map(|r| r.priority).collect();
            assert_eq!(priorities, vec![10, 20, 30], "seed {seed}");
        }
    }

    #[test]
    fn weighted_selection_prefers_heavier_records() {
        let records = vec![
            rec(10, 90, 5060, "heavy.example.com"),
            rec(10, 10, 5060, "light.example.com"),
        ];
        let mut heavy_first = 0;
        let trials = 400;
        for seed in 0..trials {
            let ordered = order_candidates(&records, seed);
            if ordered[0].target == "heavy.example.com" {
                heavy_first += 1;
            }
        }
        // Expected ~90%. Allow generous slack; the seed range is fixed
        // so this is deterministic, not flaky.
        assert!(
            heavy_first > trials * 7 / 10,
            "heavy record picked first only {heavy_first}/{trials} times"
        );
    }

    #[test]
    fn all_zero_weights_return_every_record() {
        let records = vec![
            rec(10, 0, 5060, "a.example.com"),
            rec(10, 0, 5061, "b.example.com"),
            rec(10, 0, 5062, "c.example.com"),
        ];
        let ordered = order_candidates(&records, 7);
        assert_eq!(ordered.len(), 3);
        let mut targets: Vec<&str> = ordered.iter().map(|r| r.target.as_str()).collect();
        targets.sort_unstable();
        assert_eq!(
            targets,
            vec!["a.example.com", "b.example.com", "c.example.com"]
        );
    }

    #[test]
    fn mixed_zero_and_nonzero_weights_keep_all_records() {
        let records = vec![
            rec(10, 0, 5060, "zero.example.com"),
            rec(10, 100, 5060, "hundred.example.com"),
            rec(10, 0, 5060, "zero2.example.com"),
        ];
        for seed in 0..16 {
            let ordered = order_candidates(&records, seed);
            assert_eq!(ordered.len(), 3, "seed {seed}");
        }
        // Zero-weight records can still come first occasionally (roll
        // of 0); just assert the heavy one usually leads.
        let lead = (0..100)
            .filter(|&seed| order_candidates(&records, seed)[0].target == "hundred.example.com")
            .count();
        assert!(lead > 50, "weight-100 led only {lead}/100 times");
    }

    #[test]
    fn single_record_passes_through() {
        let records = vec![rec(5, 20, 5070, "only.example.com")];
        assert_eq!(order_candidates(&records, 0), records);
    }

    #[test]
    fn empty_records_yield_empty() {
        assert!(order_candidates(&[], 42).is_empty());
    }

    #[test]
    fn same_seed_is_deterministic() {
        let records = vec![
            rec(10, 30, 5060, "a.example.com"),
            rec(10, 30, 5060, "b.example.com"),
            rec(10, 30, 5060, "c.example.com"),
        ];
        assert_eq!(
            order_candidates(&records, 1234),
            order_candidates(&records, 1234)
        );
    }

    // --- location_plan: skip-SRV decision rules ---

    #[test]
    fn explicit_port_skips_srv() {
        let acct = account(Some("pbx.example.com"), Some(5080), Transport::Udp);
        assert_eq!(
            location_plan(&acct),
            LocationPlan::Direct {
                host: "pbx.example.com".to_string(),
                port: 5080,
            }
        );
    }

    #[test]
    fn ipv4_literal_skips_srv() {
        let acct = account(Some("192.0.2.10"), None, Transport::Udp);
        assert_eq!(
            location_plan(&acct),
            LocationPlan::Direct {
                host: "192.0.2.10".to_string(),
                port: 5060,
            }
        );
    }

    #[test]
    fn ipv6_literal_skips_srv() {
        let acct = account(Some("2001:db8::1"), None, Transport::Udp);
        assert_eq!(
            location_plan(&acct),
            LocationPlan::Direct {
                host: "2001:db8::1".to_string(),
                port: 5060,
            }
        );
    }

    #[test]
    fn bare_domain_uses_udp_srv_label() {
        let acct = account(None, None, Transport::Udp);
        assert_eq!(
            location_plan(&acct),
            LocationPlan::Srv {
                name: "_sip._udp.sip.example.com".to_string(),
                host: "sip.example.com".to_string(),
                port: 5060,
            }
        );
    }

    #[test]
    fn tcp_transport_uses_tcp_srv_label() {
        let acct = account(Some("pbx.example.com"), None, Transport::Tcp);
        assert_eq!(
            location_plan(&acct),
            LocationPlan::Srv {
                name: "_sip._tcp.pbx.example.com".to_string(),
                host: "pbx.example.com".to_string(),
                port: 5060,
            }
        );
    }

    // --- resolve_with: SRV resolution + fallback via mock DNS ---

    struct MockDns {
        srv: Result<Vec<SrvRecord>, String>,
        hosts: HashMap<(String, u16), SocketAddr>,
        calls: Mutex<Vec<String>>,
    }

    impl MockDns {
        fn new(srv: Result<Vec<SrvRecord>, String>) -> Self {
            Self {
                srv,
                hosts: HashMap::new(),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn with_host(mut self, host: &str, port: u16, addr: &str) -> Self {
            let addr: SocketAddr = addr.parse().unwrap();
            self.hosts.insert((host.to_string(), port), addr);
            self
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl Dns for MockDns {
        async fn srv(&self, name: &str) -> Result<Vec<SrvRecord>, BoxError> {
            self.calls.lock().unwrap().push(format!("srv:{name}"));
            self.srv.clone().map_err(Into::into)
        }

        async fn lookup(&self, host: &str, port: u16) -> Result<Option<SocketAddr>, BoxError> {
            self.calls.lock().unwrap().push(format!("a:{host}:{port}"));
            Ok(self.hosts.get(&(host.to_string(), port)).copied())
        }
    }

    #[tokio::test]
    async fn direct_ip_literal_makes_no_dns_calls() {
        let dns = MockDns::new(Ok(vec![]));
        let acct = account(Some("192.0.2.10"), None, Transport::Udp);
        let addr = resolve_with(&dns, &acct, 0).await.unwrap();
        assert_eq!(addr, Some("192.0.2.10:5060".parse().unwrap()));
        assert!(dns.calls().is_empty(), "IP literal must not touch DNS");
    }

    #[tokio::test]
    async fn direct_hostname_resolves_at_configured_port() {
        let dns = MockDns::new(Ok(vec![rec(10, 0, 9999, "ignored.example.com")])).with_host(
            "pbx.example.com",
            5080,
            "198.51.100.1:5080",
        );
        let acct = account(Some("pbx.example.com"), Some(5080), Transport::Udp);
        let addr = resolve_with(&dns, &acct, 0).await.unwrap();
        assert_eq!(addr, Some("198.51.100.1:5080".parse().unwrap()));
        assert_eq!(
            dns.calls(),
            vec!["a:pbx.example.com:5080"],
            "explicit port must skip SRV entirely"
        );
    }

    #[tokio::test]
    async fn empty_srv_falls_back_to_a_lookup_at_default_port() {
        let dns = MockDns::new(Ok(vec![])).with_host("sip.example.com", 5060, "203.0.113.5:5060");
        let acct = account(None, None, Transport::Udp);
        let addr = resolve_with(&dns, &acct, 0).await.unwrap();
        assert_eq!(addr, Some("203.0.113.5:5060".parse().unwrap()));
        assert_eq!(
            dns.calls(),
            vec!["srv:_sip._udp.sip.example.com", "a:sip.example.com:5060"]
        );
    }

    #[tokio::test]
    async fn srv_query_error_falls_back_to_a_lookup() {
        let dns = MockDns::new(Err("SERVFAIL".to_string())).with_host(
            "sip.example.com",
            5060,
            "203.0.113.5:5060",
        );
        let acct = account(None, None, Transport::Udp);
        let addr = resolve_with(&dns, &acct, 0).await.unwrap();
        assert_eq!(addr, Some("203.0.113.5:5060".parse().unwrap()));
    }

    #[tokio::test]
    async fn srv_records_resolve_target_with_srv_port() {
        let dns = MockDns::new(Ok(vec![rec(10, 0, 5070, "sipserver.example.com")])).with_host(
            "sipserver.example.com",
            5070,
            "198.51.100.9:5070",
        );
        let acct = account(None, None, Transport::Udp);
        let addr = resolve_with(&dns, &acct, 0).await.unwrap();
        assert_eq!(addr, Some("198.51.100.9:5070".parse().unwrap()));
        assert_eq!(
            dns.calls(),
            vec![
                "srv:_sip._udp.sip.example.com",
                "a:sipserver.example.com:5070"
            ],
            "must use the SRV port, not 5060, and not fall back"
        );
    }

    #[tokio::test]
    async fn failed_candidate_falls_through_to_next() {
        let dns = MockDns::new(Ok(vec![
            rec(10, 0, 5070, "dead.example.com"),
            rec(20, 0, 5071, "alive.example.com"),
        ]))
        .with_host("alive.example.com", 5071, "198.51.100.2:5071");
        let acct = account(None, None, Transport::Udp);
        let addr = resolve_with(&dns, &acct, 0).await.unwrap();
        assert_eq!(addr, Some("198.51.100.2:5071".parse().unwrap()));
    }

    #[tokio::test]
    async fn dot_target_is_skipped_without_fallback() {
        // RFC 2782: a lone "." target means the service is decidedly
        // unavailable. SRV records exist, so no A/AAAA fallback either.
        let dns = MockDns::new(Ok(vec![rec(10, 0, 5060, ".")])).with_host(
            "sip.example.com",
            5060,
            "203.0.113.5:5060",
        );
        let acct = account(None, None, Transport::Udp);
        let addr = resolve_with(&dns, &acct, 0).await.unwrap();
        assert_eq!(addr, None);
        assert_eq!(dns.calls(), vec!["srv:_sip._udp.sip.example.com"]);
    }

    #[tokio::test]
    async fn unresolvable_srv_targets_do_not_fall_back() {
        let dns = MockDns::new(Ok(vec![rec(10, 0, 5070, "ghost.example.com")])).with_host(
            "sip.example.com",
            5060,
            "203.0.113.5:5060",
        );
        let acct = account(None, None, Transport::Udp);
        let addr = resolve_with(&dns, &acct, 0).await.unwrap();
        assert_eq!(addr, None, "RFC 3263: SRV present means no A/AAAA fallback");
    }
}
