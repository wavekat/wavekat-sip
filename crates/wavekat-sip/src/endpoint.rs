//! Shared SIP endpoint: UDP/TCP transport bound, dialog layer wired,
//! incoming-transaction stream exposed.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rsip::StatusCode;
use rsipstack::{
    dialog::{dialog::Dialog, dialog_layer::DialogLayer},
    transaction::{
        endpoint::{EndpointBuilder, EndpointInnerRef, EndpointOption},
        transaction::Transaction,
        TransactionReceiver,
    },
    transport::{udp::UdpConnection, SipAddr, SipConnection, TransportLayer},
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::account::{SipAccount, Transport};

/// Host part appended to the random prefix in generated `Call-ID` headers.
///
/// rsipstack's default is `restsend.com` (its author's product domain), which
/// would otherwise leak into every REGISTER and INVITE we send. We override it
/// to our own product domain; the random prefix already provides global
/// uniqueness per RFC 3261, so the suffix is purely cosmetic/branding.
const CALLID_SUFFIX: &str = "wavekat.com";

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
        cancel: CancellationToken,
    ) -> Result<(Self, TransactionReceiver), Box<dyn std::error::Error + Send + Sync>> {
        Self::new_with_app(account, None, cancel).await
    }

    /// Like [`SipEndpoint::new`], but prepends an application product
    /// token to the `User-Agent` header, ahead of this library's own
    /// token (the convention from RFC 7231 §5.5.3 / RFC 3261 §20.41:
    /// most significant product first).
    ///
    /// Pass the token preformatted, e.g. `"my-app/1.2.3 (abc1234)"`,
    /// yielding a header like:
    ///
    /// ```text
    /// my-app/1.2.3 (abc1234) wavekat-sip/0.0.13 (macOS 15.5/aarch64) myhost.local
    /// ```
    pub async fn new_with_app(
        account: &SipAccount,
        app_product: Option<&str>,
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
            app_product,
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
            .with_option(EndpointOption {
                callid_suffix: Some(CALLID_SUFFIX.to_string()),
                ..EndpointOption::default()
            })
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

    /// Route an inbound in-dialog transaction (BYE, INFO, OPTIONS,
    /// re-INVITE, …) to its matching dialog and drive the dialog's
    /// `handle()` to completion.
    ///
    /// The incoming-transaction stream returned by [`SipEndpoint::new`]
    /// yields *every* inbound transaction the transport receives — the
    /// initial INVITE for a new call, but also subsequent BYE/INFO/etc.
    /// for already-established dialogs. Initial INVITEs go to
    /// [`crate::Callee`]; everything else should be handed to this
    /// helper so the dialog state machine advances (e.g. moving to
    /// `Terminated` on a remote BYE and sending the matching 200 OK).
    ///
    /// On a non-matching transaction this replies with `481 Call/
    /// Transaction Does Not Exist` per RFC 3261; on a matching dialog
    /// of an unsupported kind (subscriptions, publications) it replies
    /// `501 Not Implemented`. The outcome is returned so callers can
    /// emit diagnostics.
    pub async fn dispatch_in_dialog(
        &self,
        mut tx: Transaction,
    ) -> Result<DispatchOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let Some(dialog) = self.dialog_layer.match_dialog(&tx) else {
            // No dialog matched. Best-effort 481; rsipstack's transport
            // layer drops stateless replies that fail to send.
            let _ = tx.reply(StatusCode::CallTransactionDoesNotExist).await;
            return Ok(DispatchOutcome::NoDialog);
        };

        match dialog {
            Dialog::ServerInvite(mut d) => {
                d.handle(&mut tx).await?;
                Ok(DispatchOutcome::Handled)
            }
            Dialog::ClientInvite(mut d) => {
                d.handle(&mut tx).await?;
                Ok(DispatchOutcome::Handled)
            }
            _ => {
                let _ = tx.reply(StatusCode::NotImplemented).await;
                Ok(DispatchOutcome::Unsupported)
            }
        }
    }
}

/// Outcome of [`SipEndpoint::dispatch_in_dialog`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// A dialog matched and ran its handler. Subsequent state
    /// transitions (e.g. `Terminated` on a BYE) will appear on the
    /// dialog's `DialogStateReceiver`.
    Handled,
    /// No dialog matched the transaction's `Call-ID` + tag pair. The
    /// helper replied `481 Call/Transaction Does Not Exist`.
    NoDialog,
    /// A dialog matched, but its kind isn't an INVITE dialog (e.g.
    /// subscriptions). The helper replied `501 Not Implemented`.
    Unsupported,
}

/// Build the User-Agent header string.
///
/// `app_product` is an optional consumer-supplied product token (e.g.
/// `"my-app/1.2.3 (abc1234)"`) placed before the library's own token.
/// The library git hash is omitted when unavailable (registry builds
/// have no `.git`, so `GIT_HASH` is `"unknown"` there).
fn build_user_agent(
    app_product: Option<&str>,
    version: &str,
    git_hash: &str,
    os: &str,
    arch: &str,
    host: &str,
) -> String {
    let app = app_product.map(|a| format!("{a} ")).unwrap_or_default();
    let hash = if git_hash.is_empty() || git_hash == "unknown" {
        String::new()
    } else {
        format!(" ({git_hash})")
    };
    format!("{app}wavekat-sip/{version}{hash} ({os}/{arch}) {host}")
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
///
/// Deliberately uses the OS resolver (`connect` → getaddrinfo), not the
/// SRV-aware [`crate::resolve`] path: this only needs *a* route to pick
/// a source IP, not the actual SIP target. Consequence: a domain with
/// SRV records but no A/AAAA on the bare host still fails here — see
/// `docs/20260606-srv-lookup.md`.
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
        let ua = build_user_agent(
            None,
            "0.0.1",
            "abc1234",
            "macOS 15.5",
            "aarch64",
            "myhost.local",
        );
        assert_eq!(
            ua,
            "wavekat-sip/0.0.1 (abc1234) (macOS 15.5/aarch64) myhost.local"
        );
    }

    #[test]
    fn build_user_agent_empty_host() {
        let ua = build_user_agent(None, "1.0.0", "def5678", "Linux", "x86_64", "");
        assert_eq!(ua, "wavekat-sip/1.0.0 (def5678) (Linux/x86_64) ");
    }

    #[test]
    fn build_user_agent_with_app_product() {
        let ua = build_user_agent(
            Some("my-app/1.2.3 (cafe123)"),
            "0.0.13",
            "abc1234",
            "macOS 15.5",
            "aarch64",
            "myhost.local",
        );
        assert_eq!(
            ua,
            "my-app/1.2.3 (cafe123) wavekat-sip/0.0.13 (abc1234) (macOS 15.5/aarch64) myhost.local"
        );
    }

    #[test]
    fn build_user_agent_omits_unknown_git_hash() {
        // Registry builds have no .git checkout, so GIT_HASH falls back
        // to "unknown" — that's noise on the wire, drop the parens.
        let ua = build_user_agent(
            Some("my-app/1.2.3 (cafe123)"),
            "0.0.13",
            "unknown",
            "macOS 15.5",
            "aarch64",
            "myhost.local",
        );
        assert_eq!(
            ua,
            "my-app/1.2.3 (cafe123) wavekat-sip/0.0.13 (macOS 15.5/aarch64) myhost.local"
        );
        let ua = build_user_agent(None, "0.0.13", "", "Linux", "x86_64", "host");
        assert_eq!(ua, "wavekat-sip/0.0.13 (Linux/x86_64) host");
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

    #[tokio::test]
    async fn endpoint_overrides_callid_suffix() {
        let account = make_account(Some("127.0.0.1"), Some(5060));
        let cancel = CancellationToken::new();
        let (endpoint, _incoming) = SipEndpoint::new(&account, cancel.clone()).await.unwrap();

        let suffix = endpoint
            .inner
            .option
            .callid_suffix
            .as_deref()
            .expect("callid_suffix should be configured");
        assert_eq!(suffix, CALLID_SUFFIX);
        assert_ne!(
            suffix, "restsend.com",
            "should not fall back to rsipstack's default"
        );

        endpoint.shutdown();
    }
}
