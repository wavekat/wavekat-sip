//! RFC 5626 §3.5.1 keepalive for stream transports.
//!
//! A TCP or TLS connection sits idle between REGISTER refreshes, and idle
//! connections are what NAT devices forget, without telling either end. This
//! task keeps the connection busy with a double-CRLF "ping" and notices when
//! it has died:
//!
//! - a ping that can't be written means the connection is gone;
//! - a registrar that has answered pings before (a single-CRLF "pong") and
//!   then misses one is no longer reachable on it.
//!
//! Either way the task cancels the transport's `closed` token. The read task
//! stops on it, the engine sees its transport end, and the consumer gets the
//! same signal as when the peer closes the connection. A registrar that never
//! pongs is never judged by its silence — many don't implement the pong.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::WriteHalf;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use super::stream::{write_message, SipStream};

/// The ping: an empty line twice, which can't be part of a SIP message.
pub(crate) const PING: &[u8] = b"\r\n\r\n";

/// How often to ping, and how long to wait for a pong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StreamKeepalive {
    /// Time between pings. Short enough to keep NAT devices that drop idle
    /// TCP mappings after a minute or two from dropping this one.
    pub(crate) interval: Duration,
    /// How long a registrar that pongs gets to answer a ping (RFC 5626
    /// §4.4.1 uses 10 s).
    pub(crate) pong_timeout: Duration,
}

impl Default for StreamKeepalive {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            pong_timeout: Duration::from_secs(10),
        }
    }
}

/// Whether a ping that saw `before` keepalives arrive before it was sent,
/// and `after` by the end of the pong timeout, went unanswered by a peer
/// that is known to answer.
pub(crate) fn pong_missed(before: u64, after: u64) -> bool {
    before > 0 && after == before
}

/// Ping `peer` every `cfg.interval` until `closed` is cancelled, cancelling
/// it if the connection turns out to be dead.
///
/// `keepalives` counts the bare CRLFs the read task has skipped — pongs, and
/// any pings the registrar sends us, both proof the connection works.
pub(crate) async fn run(
    write: Arc<Mutex<WriteHalf<SipStream>>>,
    peer: SocketAddr,
    keepalives: Arc<AtomicU64>,
    closed: CancellationToken,
    cfg: StreamKeepalive,
) {
    loop {
        tokio::select! {
            _ = closed.cancelled() => return,
            _ = tokio::time::sleep(cfg.interval) => {}
        }
        let before = keepalives.load(Ordering::Acquire);
        if let Err(e) = write_message(&mut *write.lock().await, PING).await {
            warn!(%peer, error = %e, "keepalive ping failed; closing the connection");
            closed.cancel();
            return;
        }
        trace!(%peer, "keepalive ping sent");
        if before == 0 {
            // This registrar has never ponged; its silence says nothing.
            continue;
        }
        tokio::select! {
            _ = closed.cancelled() => return,
            _ = tokio::time::sleep(cfg.pong_timeout) => {}
        }
        if pong_missed(before, keepalives.load(Ordering::Acquire)) {
            warn!(%peer, "no answer to a keepalive ping; closing the connection");
            closed.cancel();
            return;
        }
        debug!(%peer, "keepalive answered");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_that_never_answered_is_not_judged_by_silence() {
        assert!(!pong_missed(0, 0));
    }

    #[test]
    fn a_peer_that_answers_and_then_stops_has_missed_a_pong() {
        assert!(pong_missed(3, 3));
        assert!(!pong_missed(3, 4));
    }

    #[test]
    fn the_default_pings_well_inside_common_nat_timeouts() {
        let k = StreamKeepalive::default();
        assert_eq!(k.interval, Duration::from_secs(30));
        assert_eq!(k.pong_timeout, Duration::from_secs(10));
        assert!(k.pong_timeout < k.interval);
    }

    #[test]
    fn the_ping_is_a_double_crlf() {
        assert_eq!(PING, b"\r\n\r\n");
    }
}
