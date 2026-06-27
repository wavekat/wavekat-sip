//! Transaction engine: the async runner that drives the sans-IO §17 state
//! machines over a real UDP socket.
//!
//! A single task owns the socket, the transaction table, and the timers, and
//! `select!`s over three sources:
//!
//! - **inbound datagrams** — parsed and demuxed by [`TransactionKey`] to an
//!   existing transaction, or used to open a new server transaction;
//! - **fired timers** — looked up and fed back into the owning machine;
//! - **TU commands** — start a client transaction, hand a server transaction
//!   its response, or send a message outside any transaction (the 2xx ACK).
//!
//! Each machine returns [`TxAction`]s, which this runner applies: put bytes on
//! the wire, arm/cancel a timer, or publish an [`Event`] to the TU. Because
//! the machines are sans-IO, all the protocol logic stays unit-tested in their
//! own modules; this file is only plumbing, exercised by the loopback tests at
//! the bottom.
//!
//! Timers use a generation counter rather than cancellable handles: arming a
//! timer bumps the `(transaction, TimerId)` generation and spawns a sleeper
//! tagged with it; a fired timer is ignored unless its generation still
//! matches, so `StopTimer` (and re-arming) is just an increment.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rsip::{Method, Request, Response, SipMessage};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use super::transaction::client_invite::ClientInvite;
use super::transaction::client_non_invite::ClientNonInvite;
use super::transaction::server_invite::ServerInvite;
use super::transaction::server_non_invite::ServerNonInvite;
use super::transaction::{Reliability, TimerId, Timers, Transaction, TransactionKey, TxAction};
use super::transport::UdpTransport;

/// A request from the transaction user (TU) to the engine.
pub(crate) enum Command {
    /// Open a client transaction: send `request` to `peer` and report its
    /// responses, timeout, or termination back as [`Event`]s.
    StartClient { request: Request, peer: SocketAddr },
    /// Hand a server transaction the response the TU wants it to send.
    SendResponse {
        key: TransactionKey,
        response: Response,
    },
    /// Send a message that belongs to no transaction — specifically the ACK
    /// for a 2xx, which is a dialog-layer concern, not a transaction one.
    SendOutOfDialog {
        message: SipMessage,
        peer: SocketAddr,
    },
}

/// Something the engine surfaces up to the TU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Event {
    /// A new inbound request opened a server transaction.
    IncomingRequest {
        key: TransactionKey,
        request: Request,
        peer: SocketAddr,
    },
    /// A response was delivered for one of our client transactions.
    Response {
        key: TransactionKey,
        response: Response,
    },
    /// A request matched no transaction (a 2xx ACK, or a stray in-dialog
    /// request) — handed up for the dialog layer to route.
    UnmatchedRequest { request: Request, peer: SocketAddr },
    /// A transaction timed out without a final response.
    TimedOut { key: TransactionKey },
    /// A transaction terminated; any TU state keyed on it can be dropped.
    Terminated { key: TransactionKey },
}

/// Handle the TU uses to drive a running engine.
pub(crate) struct EngineHandle {
    cmd_tx: mpsc::Sender<Command>,
    local_addr: SocketAddr,
}

impl EngineHandle {
    /// The local address the engine's socket is bound to.
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Queue a client transaction. Returns `false` if the engine has stopped.
    pub(crate) async fn start_client(&self, request: Request, peer: SocketAddr) -> bool {
        self.cmd_tx
            .send(Command::StartClient { request, peer })
            .await
            .is_ok()
    }

    /// Hand a server transaction its response.
    pub(crate) async fn send_response(&self, key: TransactionKey, response: Response) -> bool {
        self.cmd_tx
            .send(Command::SendResponse { key, response })
            .await
            .is_ok()
    }

    /// Send a message outside any transaction (the 2xx ACK).
    pub(crate) async fn send_out_of_dialog(&self, message: SipMessage, peer: SocketAddr) -> bool {
        self.cmd_tx
            .send(Command::SendOutOfDialog { message, peer })
            .await
            .is_ok()
    }
}

/// A fired timer, tagged with the generation that armed it.
struct TimerFire {
    key: TransactionKey,
    id: TimerId,
    generation: u64,
}

/// A live transaction plus the routing state the engine keeps for it.
struct Entry {
    tx: Transaction,
    /// Where this transaction's messages go (client: the target; server: the
    /// source the request arrived from).
    peer: SocketAddr,
    /// Current generation per armed timer; a fired timer with a stale
    /// generation has been cancelled or superseded.
    timers: HashMap<TimerId, u64>,
}

/// The engine task's owned state.
struct Engine {
    transport: Arc<UdpTransport>,
    reliability: Reliability,
    timers: Timers,
    txns: HashMap<TransactionKey, Entry>,
    timer_tx: mpsc::Sender<TimerFire>,
    event_tx: mpsc::Sender<Event>,
}

/// Bind a UDP socket and spawn the engine task.
///
/// Returns a handle for issuing commands and the stream of [`Event`]s the
/// engine produces. The task runs until `cancel` fires or the socket errors.
pub(crate) async fn start(
    local: SocketAddr,
    cancel: CancellationToken,
) -> io::Result<(EngineHandle, mpsc::Receiver<Event>)> {
    start_with_timers(local, Timers::default(), cancel).await
}

/// Like [`start`], but with explicit base timers. Used by tests to shrink the
/// RFC timer table so timeouts and soak periods fire in milliseconds.
pub(crate) async fn start_with_timers(
    local: SocketAddr,
    timers: Timers,
    cancel: CancellationToken,
) -> io::Result<(EngineHandle, mpsc::Receiver<Event>)> {
    let transport = Arc::new(UdpTransport::bind(local).await?);
    let local_addr = transport.local_addr()?;
    let reliability = transport.reliability();

    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let (event_tx, event_rx) = mpsc::channel(64);
    let (timer_tx, timer_rx) = mpsc::channel(256);

    let engine = Engine {
        transport,
        reliability,
        timers,
        txns: HashMap::new(),
        timer_tx,
        event_tx,
    };
    tokio::spawn(engine.run(cmd_rx, timer_rx, cancel));

    Ok((EngineHandle { cmd_tx, local_addr }, event_rx))
}

impl Engine {
    async fn run(
        mut self,
        mut cmd_rx: mpsc::Receiver<Command>,
        mut timer_rx: mpsc::Receiver<TimerFire>,
        cancel: CancellationToken,
    ) {
        let transport = self.transport.clone();
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                recvd = transport.recv() => match recvd {
                    Ok((msg, src)) => self.on_inbound(msg, src).await,
                    Err(e) => { warn!(error = %e, "UDP receive failed; stopping engine"); break; }
                },
                Some(fire) = timer_rx.recv() => self.on_timer_fire(fire).await,
                Some(cmd) = cmd_rx.recv() => self.on_command(cmd).await,
            }
        }
    }

    async fn on_inbound(&mut self, msg: SipMessage, src: SocketAddr) {
        match msg {
            SipMessage::Request(req) => self.on_request(req, src).await,
            SipMessage::Response(resp) => self.on_response(resp).await,
        }
    }

    async fn on_response(&mut self, resp: Response) {
        let Some(key) = TransactionKey::from_response(&resp) else {
            return;
        };
        match self.txns.get_mut(&key) {
            Some(entry) => {
                let actions = entry.tx.on_response(&resp);
                self.apply(&key, actions).await;
            }
            // A response with no matching transaction is a late/duplicate final
            // (e.g. a retransmitted 2xx after the client INVITE tx terminated);
            // the dialog layer owns 2xx retransmits, so there is nothing to do
            // at this layer yet.
            None => debug!("response matched no transaction; dropping"),
        }
    }

    async fn on_request(&mut self, req: Request, src: SocketAddr) {
        let Some(key) = TransactionKey::from_request(&req) else {
            return;
        };

        // Retransmission or ACK for an existing transaction.
        if let Some(entry) = self.txns.get_mut(&key) {
            let actions = entry.tx.on_request(&req);
            self.apply(&key, actions).await;
            return;
        }

        // No transaction yet — open one, or hand up an out-of-transaction ACK.
        let (tx, actions) = match req.method() {
            Method::Ack => {
                // An ACK matching no server INVITE transaction is the ACK for a
                // 2xx: a dialog concern, not a transaction one.
                let _ = self
                    .event_tx
                    .send(Event::UnmatchedRequest {
                        request: req,
                        peer: src,
                    })
                    .await;
                return;
            }
            Method::Invite => {
                let (t, a) = ServerInvite::start(&req, self.timers, self.reliability);
                (Transaction::ServerInvite(t), a)
            }
            _ => {
                let (t, a) = ServerNonInvite::start(&req, self.timers, self.reliability);
                (Transaction::ServerNonInvite(t), a)
            }
        };
        self.txns.insert(
            key.clone(),
            Entry {
                tx,
                peer: src,
                timers: HashMap::new(),
            },
        );
        self.apply(&key, actions).await;
    }

    async fn on_timer_fire(&mut self, fire: TimerFire) {
        // Ignore a timer that has been cancelled, re-armed, or whose
        // transaction is already gone.
        let current = self
            .txns
            .get(&fire.key)
            .and_then(|e| e.timers.get(&fire.id).copied());
        if current != Some(fire.generation) {
            return;
        }
        let actions = self
            .txns
            .get_mut(&fire.key)
            .map(|e| e.tx.on_timer(fire.id))
            .unwrap_or_default();
        self.apply(&fire.key, actions).await;
    }

    async fn on_command(&mut self, cmd: Command) {
        match cmd {
            Command::StartClient { request, peer } => {
                let Some(key) = TransactionKey::from_request(&request) else {
                    return;
                };
                let is_invite = *request.method() == Method::Invite;
                let (tx, actions) = if is_invite {
                    let (t, a) = ClientInvite::start(request, self.timers, self.reliability);
                    (Transaction::ClientInvite(t), a)
                } else {
                    let (t, a) = ClientNonInvite::start(request, self.timers, self.reliability);
                    (Transaction::ClientNonInvite(t), a)
                };
                self.txns.insert(
                    key.clone(),
                    Entry {
                        tx,
                        peer,
                        timers: HashMap::new(),
                    },
                );
                self.apply(&key, actions).await;
            }
            Command::SendResponse { key, response } => {
                let actions = match self.txns.get_mut(&key).map(|e| &mut e.tx) {
                    Some(Transaction::ServerInvite(t)) => t.send_response(response),
                    Some(Transaction::ServerNonInvite(t)) => t.send_response(response),
                    _ => Vec::new(),
                };
                self.apply(&key, actions).await;
            }
            Command::SendOutOfDialog { message, peer } => {
                if let Err(e) = self.transport.send_to(&message, peer).await {
                    warn!(error = %e, "out-of-dialog send failed");
                }
            }
        }
    }

    /// Apply the actions a state machine returned.
    async fn apply(&mut self, key: &TransactionKey, actions: Vec<TxAction>) {
        for action in actions {
            match action {
                TxAction::Send(msg) => {
                    if let Some(peer) = self.txns.get(key).map(|e| e.peer) {
                        if let Err(e) = self.transport.send_to(&msg, peer).await {
                            warn!(error = %e, "transport send failed");
                        }
                    }
                }
                TxAction::StartTimer { id, after } => self.arm_timer(key, id, after),
                TxAction::StopTimer(id) => self.stop_timer(key, id),
                TxAction::DeliverResponse(response) => {
                    let _ = self
                        .event_tx
                        .send(Event::Response {
                            key: key.clone(),
                            response,
                        })
                        .await;
                }
                TxAction::DeliverRequest(request) => {
                    if let Some(peer) = self.txns.get(key).map(|e| e.peer) {
                        let _ = self
                            .event_tx
                            .send(Event::IncomingRequest {
                                key: key.clone(),
                                request,
                                peer,
                            })
                            .await;
                    }
                }
                TxAction::TimedOut => {
                    let _ = self
                        .event_tx
                        .send(Event::TimedOut { key: key.clone() })
                        .await;
                }
                TxAction::Terminated => {
                    self.txns.remove(key);
                    let _ = self
                        .event_tx
                        .send(Event::Terminated { key: key.clone() })
                        .await;
                }
            }
        }
    }

    fn arm_timer(&mut self, key: &TransactionKey, id: TimerId, after: Duration) {
        let Some(entry) = self.txns.get_mut(key) else {
            return;
        };
        let generation = {
            let g = entry.timers.entry(id).or_insert(0);
            *g += 1;
            *g
        };
        let timer_tx = self.timer_tx.clone();
        let key = key.clone();
        tokio::spawn(async move {
            tokio::time::sleep(after).await;
            let _ = timer_tx
                .send(TimerFire {
                    key,
                    id,
                    generation,
                })
                .await;
        });
    }

    fn stop_timer(&mut self, key: &TransactionKey, id: TimerId) {
        if let Some(entry) = self.txns.get_mut(key) {
            // Bump the generation so any outstanding sleeper for this timer is
            // ignored when it fires.
            if let Some(g) = entry.timers.get_mut(&id) {
                *g += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    const BRANCH: &str = "z9hG4bK-engine";

    /// Tiny timers so soak/timeout timers fire in milliseconds:
    /// Timer F/timeout = 64·T1 = ~64ms, Timer K = T4 = 5ms.
    fn fast_timers() -> Timers {
        Timers {
            t1: Duration::from_millis(1),
            t2: Duration::from_millis(4),
            t4: Duration::from_millis(5),
        }
    }

    async fn recv_event(rx: &mut mpsc::Receiver<Event>) -> Event {
        timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("event within timeout")
            .expect("channel open")
    }

    fn options_to(peer: SocketAddr) -> Request {
        let raw = format!(
            "OPTIONS sip:bob@{peer} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:5060;branch={BRANCH}\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>\r\n\
             Call-ID: call-eng\r\n\
             CSeq: 4 OPTIONS\r\n\
             Content-Length: 0\r\n\r\n"
        );
        Request::try_from(raw.as_bytes()).unwrap()
    }

    fn response(code: u16, method: &str) -> Response {
        let raw = format!(
            "SIP/2.0 {code} X\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:5060;branch={BRANCH}\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>;tag=bob\r\n\
             Call-ID: call-eng\r\n\
             CSeq: 4 {method}\r\n\
             Content-Length: 0\r\n\r\n"
        );
        Response::try_from(raw.as_bytes()).unwrap()
    }

    fn invite_to(peer: SocketAddr) -> Request {
        let raw = format!(
            "INVITE sip:bob@{peer} SIP/2.0\r\n\
             Via: SIP/2.0/UDP 127.0.0.1:5060;branch={BRANCH}\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>\r\n\
             Call-ID: call-eng\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Length: 0\r\n\r\n"
        );
        Request::try_from(raw.as_bytes()).unwrap()
    }

    #[tokio::test]
    async fn client_transaction_delivers_response_then_terminates() {
        let cancel = CancellationToken::new();
        let (handle, mut events) = start_with_timers(
            "127.0.0.1:0".parse().unwrap(),
            fast_timers(),
            cancel.clone(),
        )
        .await
        .unwrap();

        // A fake peer that answers the OPTIONS.
        let server = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        assert!(
            handle
                .start_client(options_to(server_addr), server_addr)
                .await
        );

        // The engine sends the OPTIONS; reply 200 to its source.
        let (got, engine_src) = server.recv().await.unwrap();
        assert!(matches!(got, SipMessage::Request(_)));
        server
            .send_to(&response(200, "OPTIONS").into(), engine_src)
            .await
            .unwrap();

        match recv_event(&mut events).await {
            Event::Response { response, .. } => assert_eq!(response.status_code().code(), 200),
            other => panic!("expected Response, got {other:?}"),
        }
        assert!(matches!(
            recv_event(&mut events).await,
            Event::Terminated { .. }
        ));
        cancel.cancel();
    }

    #[tokio::test]
    async fn inbound_invite_opens_server_transaction_and_sends_response() {
        let cancel = CancellationToken::new();
        let (handle, mut events) = start_with_timers(
            "127.0.0.1:0".parse().unwrap(),
            fast_timers(),
            cancel.clone(),
        )
        .await
        .unwrap();
        let engine_addr = handle.local_addr();

        let peer = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        // Peer sends an INVITE into the engine.
        peer.send_to(&invite_to(engine_addr).into(), engine_addr)
            .await
            .unwrap();

        let key = match recv_event(&mut events).await {
            Event::IncomingRequest { key, request, .. } => {
                assert_eq!(*request.method(), Method::Invite);
                key
            }
            other => panic!("expected IncomingRequest, got {other:?}"),
        };

        // TU answers 486; the engine puts it on the wire toward the peer.
        assert!(handle.send_response(key, response(486, "INVITE")).await);
        let (got, _) = peer.recv().await.unwrap();
        match got {
            SipMessage::Response(r) => assert_eq!(r.status_code().code(), 486),
            other => panic!("expected response, got {other:?}"),
        }
        cancel.cancel();
    }

    #[tokio::test]
    async fn no_final_response_times_out() {
        let cancel = CancellationToken::new();
        // Short timers so Timer F fires quickly: 64·T1 with T1 = 1ms ≈ 64ms.
        let (handle, mut events) = start_with_timers(
            "127.0.0.1:0".parse().unwrap(),
            fast_timers(),
            cancel.clone(),
        )
        .await
        .unwrap();

        // Send to a bound-but-silent socket that never answers.
        let sink = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let sink_addr = sink.local_addr().unwrap();

        assert!(handle.start_client(options_to(sink_addr), sink_addr).await);

        // Timer F fires (~64ms) → the transaction reports timeout, then
        // terminates. (Exact timer-table values are checked sans-IO in the
        // transaction unit tests; here we prove the engine wires them through.)
        assert!(matches!(
            recv_event(&mut events).await,
            Event::TimedOut { .. }
        ));
        assert!(matches!(
            recv_event(&mut events).await,
            Event::Terminated { .. }
        ));
        cancel.cancel();
    }
}
