//! Shared SIP endpoint: UDP/TCP transport bound, dialog layer wired,
//! incoming-transaction stream exposed.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rsipstack::{
    dialog::dialog_layer::DialogLayer,
    transaction::{
        endpoint::{EndpointBuilder, EndpointInnerRef},
        TransactionReceiver,
    },
    transport::{udp::UdpConnection, SipAddr, SipConnection, TransportLayer},
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::account::{SipAccount, Transport};

/// A bound SIP endpoint that owns its transport and dialog layer.
pub struct SipEndpoint {
    /// Endpoint inner ref — used to build requests, vias, etc.
    pub inner: EndpointInnerRef,
    /// Dialog layer for sending INVITEs and tracking dialogs.
    pub dialog_layer: Arc<DialogLayer>,
    /// First bound SIP address (host:port).
    pub sip_addr: SipAddr,
    /// Transport the endpoint was bound for. Mirrors `SipAccount::transport`
    /// at the moment of `SipEndpoint::new`. Cached here so diagnostics can
    /// report it without holding onto the account.
    transport: Transport,
    transport_cancel: CancellationToken,
}

impl SipEndpoint {
    /// Bind transport and start the endpoint's serve loop.
    ///
    /// Returns the endpoint plus the stream of incoming transactions
    /// (you'll typically forward INVITE transactions from this to a
    /// callee handler).
    pub async fn new(
        account: &SipAccount,
        _cancel: CancellationToken,
    ) -> Result<(Self, TransactionReceiver), Box<dyn std::error::Error + Send + Sync>> {
        let local_ip = detect_local_ip(account)?;
        let bind_addr: SocketAddr = SocketAddr::new(local_ip, 0);
        info!("Binding SIP transport to {bind_addr}");

        let transport_cancel = CancellationToken::new();
        let transport_layer = TransportLayer::new(transport_cancel.clone());

        match account.transport {
            Transport::Udp => {
                let udp = UdpConnection::create_connection(
                    bind_addr,
                    None,
                    Some(transport_cancel.clone()),
                )
                .await?;
                transport_layer.add_transport(SipConnection::Udp(udp));
            }
            Transport::Tcp => {
                // TCP uses outbound connections; transport_layer handles
                // it via DNS/registry lookup.
            }
        }

        let user_agent = build_user_agent(
            env!("CARGO_PKG_VERSION"),
            crate::GIT_HASH,
            &os_version(),
            std::env::consts::ARCH,
            &hostname::get()
                .map(|h| h.to_string_lossy().into_owned())
                .unwrap_or_default(),
        );

        info!("User-Agent: {user_agent}");

        let endpoint = EndpointBuilder::new()
            .with_user_agent(&user_agent)
            .with_transport_layer(transport_layer)
            .with_cancel_token(transport_cancel.clone())
            .build();

        let inner = endpoint.inner.clone();
        tokio::spawn({
            let inner = inner.clone();
            async move {
                if let Err(e) = inner.serve().await {
                    warn!("endpoint serve error: {e}");
                }
            }
        });

        let sip_addr = endpoint
            .get_addrs()
            .into_iter()
            .next()
            .ok_or("No SIP address bound")?;

        let dialog_layer = Arc::new(DialogLayer::new(inner.clone()));
        let incoming = endpoint.incoming_transactions()?;

        Ok((
            Self {
                inner,
                dialog_layer,
                sip_addr,
                transport: account.transport,
                transport_cancel,
            },
            incoming,
        ))
    }

    /// Local IP address this endpoint is bound to.
    pub fn local_ip(&self) -> IpAddr {
        self.local_addr()
            .map(|a| a.ip())
            .unwrap_or(IpAddr::from([127, 0, 0, 1]))
    }

    /// Local socket address (IP + port) this endpoint is bound to.
    ///
    /// Returns `None` if the underlying rsipstack address can't be parsed
    /// as a `SocketAddr` (in practice this only happens before transport
    /// is fully up, which shouldn't be observable from a constructed
    /// `SipEndpoint`).
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.sip_addr.addr.to_string().parse::<SocketAddr>().ok()
    }

    /// Transport this endpoint was bound for (UDP/TCP).
    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// Cancel the transport — stops the serve loop and frees the socket.
    pub fn shutdown(&self) {
        self.transport_cancel.cancel();
    }
}

/// Build the User-Agent header string.
fn build_user_agent(version: &str, git_hash: &str, os: &str, arch: &str, host: &str) -> String {
    format!("wavekat-sip/{version} ({git_hash}) ({os}/{arch}) {host}")
}

/// Returns a human-friendly OS name with version, e.g. `"macOS 15.5"`.
///
/// Falls back to `std::env::consts::OS` if the version cannot be determined.
fn os_version() -> String {
    #[cfg(target_os = "macos")]
    {
        if let Ok(out) = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
        {
            let ver = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !ver.is_empty() {
                return format!("macOS {ver}");
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(contents) = std::fs::read_to_string("/etc/os-release") {
            for line in contents.lines() {
                if let Some(name) = line.strip_prefix("PRETTY_NAME=") {
                    return name.trim_matches('"').to_string();
                }
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(out) = std::process::Command::new("cmd")
            .args(["/C", "ver"])
            .output()
        {
            let ver = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !ver.is_empty() {
                return ver;
            }
        }
    }
    std::env::consts::OS.to_string()
}

/// Detect the local IP that routes to the SIP server.
///
/// Opens a temporary UDP socket, connects to the server (no data sent),
/// and reads back the OS-chosen source address.
fn detect_local_ip(
    account: &SipAccount,
) -> Result<IpAddr, Box<dyn std::error::Error + Send + Sync>> {
    let dest = format!("{}:{}", account.server(), account.port());
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(&dest)?;
    let local = sock.local_addr()?;
    Ok(local.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_account(server: Option<&str>, port: Option<u16>) -> SipAccount {
        SipAccount {
            display_name: "Test".to_string(),
            username: "1001".to_string(),
            password: "secret".to_string(),
            domain: "localhost".to_string(),
            auth_username: None,
            server: server.map(|s| s.to_string()),
            port,
            transport: Transport::default(),
        }
    }

    #[test]
    fn build_user_agent_format() {
        let ua = build_user_agent("0.0.1", "abc1234", "macOS 15.5", "aarch64", "myhost.local");
        assert_eq!(
            ua,
            "wavekat-sip/0.0.1 (abc1234) (macOS 15.5/aarch64) myhost.local"
        );
    }

    #[test]
    fn build_user_agent_empty_host() {
        let ua = build_user_agent("1.0.0", "def5678", "Linux", "x86_64", "");
        assert_eq!(ua, "wavekat-sip/1.0.0 (def5678) (Linux/x86_64) ");
    }

    #[test]
    fn os_version_returns_non_empty() {
        let version = os_version();
        assert!(!version.is_empty());
        #[cfg(target_os = "macos")]
        assert!(version.starts_with("macOS"), "got: {version}");
    }

    #[test]
    fn detect_local_ip_returns_non_unspecified() {
        let account = make_account(Some("127.0.0.1"), Some(5060));
        let ip = detect_local_ip(&account).unwrap();
        assert!(!ip.is_unspecified(), "detected IP should not be 0.0.0.0");
        assert_eq!(ip, IpAddr::from([127, 0, 0, 1]));
    }

    #[test]
    fn detect_local_ip_uses_server_field() {
        let account = make_account(Some("127.0.0.1"), None);
        let ip = detect_local_ip(&account).unwrap();
        assert_eq!(ip, IpAddr::from([127, 0, 0, 1]));
    }

    #[test]
    fn detect_local_ip_falls_back_to_domain() {
        let account = make_account(None, None);
        let ip = detect_local_ip(&account).unwrap();
        assert_eq!(ip, IpAddr::from([127, 0, 0, 1]));
    }

    #[tokio::test]
    async fn endpoint_exposes_local_addr_and_transport() {
        let account = make_account(Some("127.0.0.1"), Some(5060));
        let cancel = CancellationToken::new();
        let (endpoint, _incoming) = SipEndpoint::new(&account, cancel.clone()).await.unwrap();

        let local = endpoint.local_addr().expect("local_addr available");
        assert_eq!(local.ip(), IpAddr::from([127, 0, 0, 1]));
        assert_ne!(local.port(), 0, "bound port should be assigned");
        assert_eq!(endpoint.local_ip(), local.ip());
        assert_eq!(endpoint.transport(), Transport::Udp);

        endpoint.shutdown();
    }
}
