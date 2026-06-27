//! User-agent facade: one engine, many concurrent flows.
//!
//! The composed flows in [`registration`](super::registration) and
//! [`call`](super::call) each assume they own the engine's single event
//! stream. Real use needs a registration, several calls, and keepalives
//! sharing one socket at once, so this module owns the event stream and
//! **routes** each [`Event`] to the flow that owns its transaction.
//!
//! A small router task keeps a `TransactionKey → Sender<Event>` table.
//! Before starting a client transaction a flow *subscribes* its key (and
//! waits for the router to confirm, closing the race against a fast reply);
//! inbound requests with no matching subscription — new INVITEs and the 2xx
//! ACK — go to the `incoming` stream for the callee/dialog layer.
//!
//! This is the layer the public wrappers (`Registrar`, `Caller`, `Callee`)
//! are built on.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;

use rsip::{Header, Method, Request, Response, SipMessage, StatusCode};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_util::sync::CancellationToken;

use super::auth;
use super::call::{build_cancel, build_invite, cseq_of, CallConfig, CallOutcome};
use super::dialog::Dialog;
use super::engine::{self, EngineHandle, Event};
use super::registration::{build_register, granted_expires, RegisterConfig, RegisterOutcome};
use super::transaction::{Timers, TransactionKey};

/// A request the router hands up because it matched no client transaction:
/// a brand-new inbound request (INVITE/BYE/…) or the ACK for a 2xx we sent.
pub(crate) struct Incoming {
    pub key: TransactionKey,
    pub request: Request,
    pub peer: SocketAddr,
}

/// A subscription request from a flow to the router.
struct Subscribe {
    key: TransactionKey,
    tx: mpsc::Sender<Event>,
    ack: oneshot::Sender<()>,
}

/// A bound user agent: a shared engine plus the router that fans events out.
pub(crate) struct Ua {
    engine: EngineHandle,
    subscribe_tx: mpsc::Sender<Subscribe>,
    incoming: Mutex<mpsc::Receiver<Incoming>>,
    /// Product token emitted as `User-Agent` on outbound requests, if set.
    user_agent: Option<String>,
}

impl Ua {
    /// Bind a UDP socket and start the engine + router with default timers.
    pub(crate) async fn bind(local: SocketAddr, cancel: CancellationToken) -> io::Result<Self> {
        Self::bind_full(local, Timers::default(), None, cancel).await
    }

    /// Bind with explicit base timers (tests shrink them).
    pub(crate) async fn bind_with_timers(
        local: SocketAddr,
        timers: Timers,
        cancel: CancellationToken,
    ) -> io::Result<Self> {
        Self::bind_full(local, timers, None, cancel).await
    }

    /// Bind advertising `user_agent` as the `User-Agent` on outbound requests.
    pub(crate) async fn bind_with_app(
        local: SocketAddr,
        user_agent: Option<String>,
        cancel: CancellationToken,
    ) -> io::Result<Self> {
        Self::bind_full(local, Timers::default(), user_agent, cancel).await
    }

    async fn bind_full(
        local: SocketAddr,
        timers: Timers,
        user_agent: Option<String>,
        cancel: CancellationToken,
    ) -> io::Result<Self> {
        let (engine, events) = engine::start_with_timers(local, timers, cancel).await?;
        let (subscribe_tx, subscribe_rx) = mpsc::channel(32);
        let (incoming_tx, incoming_rx) = mpsc::channel(32);
        tokio::spawn(router(events, subscribe_rx, incoming_tx));
        Ok(Self {
            engine,
            subscribe_tx,
            incoming: Mutex::new(incoming_rx),
            user_agent,
        })
    }

    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.engine.local_addr()
    }

    /// Register, answering a single `401`/`407` digest challenge.
    pub(crate) async fn register(
        &self,
        cfg: &RegisterConfig,
        peer: SocketAddr,
        first_cseq: u32,
    ) -> RegisterOutcome {
        let mut request = build_register(cfg, first_cseq, self.local_addr());
        let mut challenged = false;
        loop {
            let Some(mut rx) = self.start_client(&request, peer).await else {
                return RegisterOutcome::EngineStopped;
            };
            match self.await_final(&mut rx).await {
                Some(response) => {
                    let code = response.status_code().code();
                    if (200..300).contains(&code) {
                        return RegisterOutcome::Registered {
                            expires: granted_expires(&response).unwrap_or(cfg.expires),
                        };
                    }
                    if (code == 401 || code == 407) && !challenged {
                        match auth::build_retry(&request, &response, cfg.creds_for_retry()) {
                            Some(retry) => {
                                request = retry;
                                challenged = true;
                                continue;
                            }
                            None => return RegisterOutcome::Unauthorized,
                        }
                    }
                    if code == 401 || code == 407 {
                        return RegisterOutcome::Unauthorized;
                    }
                    return RegisterOutcome::Failed(response.status_code().clone());
                }
                None => return RegisterOutcome::TimedOut,
            }
        }
    }

    /// Place a call: send INVITE, follow provisionals, answer one challenge,
    /// and on a 2xx build the dialog and ACK it.
    pub(crate) async fn call(
        &self,
        cfg: &CallConfig,
        peer: SocketAddr,
        first_cseq: u32,
    ) -> CallOutcome {
        self.call_cancellable(cfg, peer, first_cseq, &CancellationToken::new(), None)
            .await
    }

    /// Like [`Ua::call`], but `cancel` aborts a still-ringing INVITE with a
    /// `CANCEL` (RFC 3261 §9): once a provisional has arrived, firing the token
    /// sends the CANCEL and the call resolves `Rejected(487 Request
    /// Terminated)`. Each provisional status (e.g. `180 Ringing`) is forwarded
    /// to `progress` when present.
    pub(crate) async fn call_cancellable(
        &self,
        cfg: &CallConfig,
        peer: SocketAddr,
        first_cseq: u32,
        cancel: &CancellationToken,
        progress: Option<&mpsc::Sender<StatusCode>>,
    ) -> CallOutcome {
        let mut request = build_invite(cfg, first_cseq, self.local_addr());
        let mut challenged = false;
        loop {
            let Some(mut rx) = self.start_client(&request, peer).await else {
                return CallOutcome::EngineStopped;
            };
            match self
                .await_final_cancellable(&mut rx, peer, &request, cancel, progress)
                .await
            {
                Some(response) => {
                    let code = response.status_code().code();
                    if (200..300).contains(&code) {
                        let Some(dialog) = Dialog::uac(&request, &response, cfg.contact.clone())
                        else {
                            return CallOutcome::Rejected(response.status_code().clone());
                        };
                        let ack = dialog.ack_2xx(cseq_of(&request));
                        self.engine
                            .send_out_of_dialog(SipMessage::Request(ack), peer)
                            .await;
                        return CallOutcome::Answered {
                            dialog: Box::new(dialog),
                            response: Box::new(response),
                        };
                    }
                    if (code == 401 || code == 407) && !challenged {
                        match auth::build_retry(&request, &response, cfg.creds_for_retry()) {
                            Some(retry) => {
                                request = retry;
                                challenged = true;
                                continue;
                            }
                            None => return CallOutcome::Unauthorized,
                        }
                    }
                    if code == 401 || code == 407 {
                        return CallOutcome::Unauthorized;
                    }
                    return CallOutcome::Rejected(response.status_code().clone());
                }
                None => return CallOutcome::TimedOut,
            }
        }
    }

    /// Tear down a confirmed dialog with an in-dialog BYE; `true` on a 2xx.
    pub(crate) async fn hangup(&self, peer: SocketAddr, dialog: &mut Dialog) -> bool {
        let bye = dialog.new_request(Method::Bye);
        let Some(mut rx) = self.start_client(&bye, peer).await else {
            return false;
        };
        match self.await_final(&mut rx).await {
            Some(response) => (200..300).contains(&response.status_code().code()),
            None => false,
        }
    }

    /// Send a request through the engine and (optionally) an in-dialog request
    /// the caller built; returns its final response, or `None` on timeout.
    pub(crate) async fn send_in_dialog(
        &self,
        peer: SocketAddr,
        request: Request,
    ) -> Option<Response> {
        let mut rx = self.start_client(&request, peer).await?;
        self.await_final(&mut rx).await
    }

    /// Send an in-dialog re-INVITE carrying `extra_headers` + `body` (typically
    /// an SDP re-offer) and return its final response, or `None` on timeout.
    ///
    /// A re-INVITE is an INVITE transaction, so on a 2xx the TU **must** send
    /// the ACK (RFC 3261 §13.2.2.4) — done here, out of transaction, reusing the
    /// re-INVITE's CSeq. Non-2xx finals are returned as-is (their ACK is handled
    /// by the transaction itself).
    pub(crate) async fn reinvite(
        &self,
        peer: SocketAddr,
        dialog: &mut Dialog,
        extra_headers: Vec<Header>,
        body: Vec<u8>,
    ) -> Option<Response> {
        let request = dialog.new_request_with(Method::Invite, extra_headers, body);
        let cseq = cseq_of(&request);
        let mut rx = self.start_client(&request, peer).await?;
        let response = self.await_final(&mut rx).await?;
        if (200..300).contains(&response.status_code().code()) {
            let ack = dialog.ack_2xx(cseq);
            self.engine
                .send_out_of_dialog(SipMessage::Request(ack), peer)
                .await;
        }
        Some(response)
    }

    /// Send an in-dialog `INFO` carrying `extra_headers` + `body` and return its
    /// final response, or `None` on timeout. `INFO` is a non-INVITE request, so
    /// no ACK follows its 2xx.
    pub(crate) async fn info(
        &self,
        peer: SocketAddr,
        dialog: &mut Dialog,
        extra_headers: Vec<Header>,
        body: Vec<u8>,
    ) -> Option<Response> {
        let request = dialog.new_request_with(Method::Info, extra_headers, body);
        self.send_in_dialog(peer, request).await
    }

    /// Have a server transaction send `response` for the request keyed by `key`.
    pub(crate) async fn answer(&self, key: TransactionKey, response: Response) -> bool {
        self.engine.send_response(key, response).await
    }

    /// The next inbound request with no matching client transaction.
    pub(crate) async fn next_incoming(&self) -> Option<Incoming> {
        self.incoming.lock().await.recv().await
    }

    /// Subscribe `request`'s key, then start its client transaction. Returns a
    /// receiver of that transaction's events, or `None` if the engine stopped.
    async fn start_client(
        &self,
        request: &Request,
        peer: SocketAddr,
    ) -> Option<mpsc::Receiver<Event>> {
        let key = TransactionKey::from_request(request)?;
        let (tx, rx) = mpsc::channel(16);
        let (ack, ack_rx) = oneshot::channel();
        self.subscribe_tx
            .send(Subscribe { key, tx, ack })
            .await
            .ok()?;
        // Wait until the router has the subscription before we send, so a fast
        // reply can't arrive before we're listening.
        ack_rx.await.ok()?;
        let mut request = request.clone();
        self.apply_user_agent(&mut request);
        if !self.engine.start_client(request, peer).await {
            return None;
        }
        Some(rx)
    }

    /// Add our `User-Agent` to an outbound request if a product token is set and
    /// the request doesn't already carry one. The header rides every client
    /// transaction (INVITE / REGISTER / BYE / re-INVITE / INFO); it does not
    /// affect the transaction key, which is keyed on Via + method.
    fn apply_user_agent(&self, request: &mut Request) {
        let Some(product) = &self.user_agent else {
            return;
        };
        let has_ua = request
            .headers
            .iter()
            .any(|h| matches!(h, Header::UserAgent(_)));
        if !has_ua {
            request
                .headers
                .push(Header::UserAgent(product.clone().into()));
        }
    }

    /// Pump a transaction's events until its final response, or `None` on
    /// timeout / engine stop. Provisionals and Terminated are skipped.
    async fn await_final(&self, rx: &mut mpsc::Receiver<Event>) -> Option<Response> {
        while let Some(event) = rx.recv().await {
            match event {
                Event::Response { response, .. } => {
                    if response.status_code().code() >= 200 {
                        return Some(response);
                    }
                }
                Event::TimedOut { .. } => return None,
                _ => continue,
            }
        }
        None
    }

    /// Like [`Ua::await_final`], but also watches `cancel`: once a provisional
    /// has arrived, firing the token sends a `CANCEL` for `invite` (RFC 3261
    /// §9.1 forbids CANCEL before the first provisional). The INVITE's final
    /// response — a `487` after a successful CANCEL — is still returned.
    async fn await_final_cancellable(
        &self,
        rx: &mut mpsc::Receiver<Event>,
        peer: SocketAddr,
        invite: &Request,
        cancel: &CancellationToken,
        progress: Option<&mpsc::Sender<StatusCode>>,
    ) -> Option<Response> {
        let mut cancel_requested = false;
        let mut cancel_sent = false;
        let mut provisional_seen = false;
        loop {
            tokio::select! {
                event = rx.recv() => match event {
                    Some(Event::Response { response, .. }) => {
                        if response.status_code().code() >= 200 {
                            return Some(response);
                        }
                        if let Some(tx) = progress {
                            let _ = tx.send(response.status_code().clone()).await;
                        }
                        provisional_seen = true;
                        if cancel_requested && !cancel_sent {
                            self.send_cancel(invite, peer).await;
                            cancel_sent = true;
                        }
                    }
                    Some(Event::TimedOut { .. }) => return None,
                    Some(_) => continue,
                    None => return None,
                },
                _ = cancel.cancelled(), if !cancel_requested => {
                    cancel_requested = true;
                    if provisional_seen && !cancel_sent {
                        self.send_cancel(invite, peer).await;
                        cancel_sent = true;
                    }
                }
            }
        }
    }

    /// Fire a `CANCEL` for an in-flight INVITE as its own (non-INVITE)
    /// transaction; we don't wait on its 2xx — the cancelled INVITE's `487` is
    /// what resolves the call.
    async fn send_cancel(&self, invite: &Request, peer: SocketAddr) {
        if let Some(request) = build_cancel(invite) {
            self.engine.start_client(request, peer).await;
        }
    }
}

/// The router task: fan engine events out to subscribers, and hand
/// unmatched inbound requests to the `incoming` stream.
async fn router(
    mut events: mpsc::Receiver<Event>,
    mut subscribe_rx: mpsc::Receiver<Subscribe>,
    incoming_tx: mpsc::Sender<Incoming>,
) {
    let mut subs: HashMap<TransactionKey, mpsc::Sender<Event>> = HashMap::new();
    loop {
        tokio::select! {
            sub = subscribe_rx.recv() => {
                let Some(sub) = sub else { continue };
                subs.insert(sub.key, sub.tx);
                let _ = sub.ack.send(());
            }
            ev = events.recv() => {
                let Some(ev) = ev else { break };
                match ev {
                    Event::IncomingRequest { key, request, peer } => {
                        let _ = incoming_tx.send(Incoming { key, request, peer }).await;
                    }
                    Event::UnmatchedRequest { request, peer } => {
                        if let Some(key) = TransactionKey::from_request(&request) {
                            let _ = incoming_tx.send(Incoming { key, request, peer }).await;
                        }
                    }
                    other => {
                        if let Some(key) = other.key().cloned() {
                            let terminated = matches!(other, Event::Terminated { .. });
                            if let Some(tx) = subs.get(&key) {
                                let _ = tx.send(other).await;
                            }
                            if terminated {
                                subs.remove(&key);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::transport::UdpTransport;
    use rsip::Uri;
    use std::time::Duration;
    use tokio::time::timeout;

    fn fast_timers() -> Timers {
        Timers {
            t1: Duration::from_millis(1),
            t2: Duration::from_millis(4),
            t4: Duration::from_millis(5),
        }
    }

    fn reg_config() -> RegisterConfig {
        RegisterConfig {
            registrar_uri: Uri::try_from("sip:example.com").unwrap(),
            aor: Uri::try_from("sip:alice@example.com").unwrap(),
            contact: Uri::try_from("sip:alice@127.0.0.1:5060").unwrap(),
            from_tag: "alicetag".into(),
            call_id: "reg-call".into(),
            expires: 60,
            username: "alice".into(),
            password: "secret".into(),
        }
    }

    fn call_config() -> CallConfig {
        CallConfig {
            target: Uri::try_from("sip:bob@example.com").unwrap(),
            from: Uri::try_from("sip:alice@example.com").unwrap(),
            contact: Uri::try_from("sip:alice@127.0.0.1:5060").unwrap(),
            from_tag: "alicetag".into(),
            call_id: "call-xyz".into(),
            sdp: b"v=0\r\n".to_vec(),
            extra_headers: Vec::new(),
            username: "alice".into(),
            password: "secret".into(),
        }
    }

    fn echo(req: &Request) -> String {
        use rsip::message::HeadersExt;
        format!(
            "{}\r\n{}\r\n{}\r\n{}\r\n",
            req.via_header().unwrap(),
            req.from_header().unwrap(),
            req.call_id_header().unwrap(),
            req.cseq_header().unwrap(),
        )
    }

    #[tokio::test]
    async fn register_then_call_share_one_engine() {
        let cancel = CancellationToken::new();
        let ua = Ua::bind_with_timers(
            "127.0.0.1:0".parse().unwrap(),
            fast_timers(),
            cancel.clone(),
        )
        .await
        .unwrap();

        // One peer plays registrar then callee.
        let peer = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let server = tokio::spawn(async move {
            // REGISTER → 401 then 200.
            let (m, src) = peer.recv().await.unwrap();
            let SipMessage::Request(r) = m else { panic!() };
            let h = echo(&r);
            let c = format!("SIP/2.0 401 Unauthorized\r\n{h}To: <sip:alice@example.com>;tag=s\r\nWWW-Authenticate: Digest realm=\"example.com\", nonce=\"n\", qop=\"auth\"\r\nContent-Length: 0\r\n\r\n");
            peer.send_to(&SipMessage::try_from(c.as_bytes()).unwrap(), src)
                .await
                .unwrap();
            let (m, src) = peer.recv().await.unwrap();
            let SipMessage::Request(r) = m else { panic!() };
            let h = echo(&r);
            let ok = format!("SIP/2.0 200 OK\r\n{h}To: <sip:alice@example.com>;tag=s\r\nExpires: 60\r\nContent-Length: 0\r\n\r\n");
            peer.send_to(&SipMessage::try_from(ok.as_bytes()).unwrap(), src)
                .await
                .unwrap();

            // INVITE → 200 (Contact + tag), then absorb the ACK.
            let (m, src) = peer.recv().await.unwrap();
            let SipMessage::Request(r) = m else { panic!() };
            assert_eq!(*r.method(), Method::Invite);
            let h = echo(&r);
            let ok = format!("SIP/2.0 200 OK\r\n{h}To: <sip:bob@example.com>;tag=b\r\nContact: <sip:bob@127.0.0.1:5070>\r\nContent-Length: 0\r\n\r\n");
            peer.send_to(&SipMessage::try_from(ok.as_bytes()).unwrap(), src)
                .await
                .unwrap();
            let (m, _) = peer.recv().await.unwrap();
            assert!(matches!(m, SipMessage::Request(a) if *a.method() == Method::Ack));
        });

        let reg = timeout(
            Duration::from_secs(3),
            ua.register(&reg_config(), peer_addr, 1),
        )
        .await
        .unwrap();
        assert_eq!(reg, RegisterOutcome::Registered { expires: 60 });

        let call = timeout(
            Duration::from_secs(3),
            ua.call(&call_config(), peer_addr, 1),
        )
        .await
        .unwrap();
        assert!(matches!(call, CallOutcome::Answered { .. }));

        server.await.unwrap();
        cancel.cancel();
    }

    #[tokio::test]
    async fn inbound_invite_reaches_incoming_and_can_be_answered() {
        let cancel = CancellationToken::new();
        let ua = Ua::bind_with_timers(
            "127.0.0.1:0".parse().unwrap(),
            fast_timers(),
            cancel.clone(),
        )
        .await
        .unwrap();
        let ua_addr = ua.local_addr();

        let caller = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let invite = format!(
            "INVITE sip:alice@{ua_addr} SIP/2.0\r\n\
             Via: SIP/2.0/UDP {caller};branch=z9hG4bK-in\r\n\
             From: <sip:bob@example.com>;tag=bob\r\n\
             To: <sip:alice@example.com>\r\n\
             Contact: <sip:bob@{caller}>\r\n\
             Call-ID: inbound\r\n\
             CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
            caller = caller.local_addr().unwrap()
        );
        caller
            .send_to(&SipMessage::try_from(invite.as_bytes()).unwrap(), ua_addr)
            .await
            .unwrap();

        let incoming = timeout(Duration::from_secs(2), ua.next_incoming())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*incoming.request.method(), Method::Invite);

        // Answer 200 and confirm the caller sees it.
        let ok = format!(
            "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP {c};branch=z9hG4bK-in\r\n\
             From: <sip:bob@example.com>;tag=bob\r\nTo: <sip:alice@example.com>;tag=alice\r\n\
             Call-ID: inbound\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n",
            c = caller.local_addr().unwrap()
        );
        let response = Response::try_from(ok.as_bytes()).unwrap();
        assert!(ua.answer(incoming.key, response).await);

        let (m, _) = timeout(Duration::from_secs(2), caller.recv())
            .await
            .unwrap()
            .unwrap();
        match m {
            SipMessage::Response(r) => assert_eq!(r.status_code().code(), 200),
            _ => panic!("expected the 200"),
        }
        cancel.cancel();
    }

    #[tokio::test]
    async fn user_agent_injected_only_when_configured() {
        let cancel = CancellationToken::new();
        let with_app = Ua::bind_with_app(
            "127.0.0.1:0".parse().unwrap(),
            Some("wavekat-test/9.9".into()),
            cancel.clone(),
        )
        .await
        .unwrap();
        let plain = Ua::bind("127.0.0.1:0".parse().unwrap(), cancel.clone())
            .await
            .unwrap();

        let mut req = build_invite(&call_config(), 1, with_app.local_addr());
        with_app.apply_user_agent(&mut req);
        assert!(
            req.to_string().contains("User-Agent: wavekat-test/9.9"),
            "configured product token must ride the request",
        );
        // Idempotent: a second pass does not duplicate the header.
        with_app.apply_user_agent(&mut req);
        assert_eq!(
            req.to_string().matches("User-Agent:").count(),
            1,
            "User-Agent must not be duplicated",
        );

        let mut plain_req = build_invite(&call_config(), 1, plain.local_addr());
        plain.apply_user_agent(&mut plain_req);
        assert!(
            !plain_req.to_string().contains("User-Agent"),
            "no token configured → no header",
        );
        cancel.cancel();
    }

    #[tokio::test]
    async fn reinvite_acks_the_2xx() {
        let cancel = CancellationToken::new();
        let ua = Ua::bind_with_timers(
            "127.0.0.1:0".parse().unwrap(),
            fast_timers(),
            cancel.clone(),
        )
        .await
        .unwrap();

        let peer = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let server = tokio::spawn(async move {
            // Initial INVITE → 200 → ACK.
            let (m, src) = peer.recv().await.unwrap();
            let SipMessage::Request(r) = m else { panic!() };
            assert_eq!(*r.method(), Method::Invite);
            let h = echo(&r);
            let ok = format!("SIP/2.0 200 OK\r\n{h}To: <sip:bob@example.com>;tag=b\r\nContact: <sip:bob@{peer_addr}>\r\nContent-Length: 0\r\n\r\n");
            peer.send_to(&SipMessage::try_from(ok.as_bytes()).unwrap(), src)
                .await
                .unwrap();
            let (m, _) = peer.recv().await.unwrap();
            assert!(matches!(m, SipMessage::Request(a) if *a.method() == Method::Ack));

            // Re-INVITE → 200, then the engine MUST send the ACK.
            let (m, src) = peer.recv().await.unwrap();
            let SipMessage::Request(r) = m else { panic!() };
            assert_eq!(*r.method(), Method::Invite, "re-INVITE is an INVITE");
            // Its CSeq advanced past the initial INVITE.
            assert!(cseq_of(&r) > 1, "re-INVITE CSeq should advance");
            let h = echo(&r);
            let ok = format!("SIP/2.0 200 OK\r\n{h}To: <sip:bob@example.com>;tag=b\r\nContact: <sip:bob@{peer_addr}>\r\nContent-Length: 0\r\n\r\n");
            peer.send_to(&SipMessage::try_from(ok.as_bytes()).unwrap(), src)
                .await
                .unwrap();
            let (m, _) = peer.recv().await.unwrap();
            assert!(
                matches!(m, SipMessage::Request(a) if *a.method() == Method::Ack),
                "engine must ACK the re-INVITE 2xx",
            );
        });

        let outcome = timeout(
            Duration::from_secs(3),
            ua.call(&call_config(), peer_addr, 1),
        )
        .await
        .unwrap();
        let CallOutcome::Answered { dialog, .. } = outcome else {
            panic!("call should be answered");
        };
        let mut dialog = *dialog;

        let response = timeout(
            Duration::from_secs(3),
            ua.reinvite(peer_addr, &mut dialog, Vec::new(), b"v=0\r\n".to_vec()),
        )
        .await
        .unwrap();
        assert_eq!(response.unwrap().status_code().code(), 200);

        server.await.unwrap();
        cancel.cancel();
    }

    #[tokio::test]
    async fn cancel_after_ringing_terminates_call() {
        let shutdown = CancellationToken::new();
        let ua = Ua::bind_with_timers(
            "127.0.0.1:0".parse().unwrap(),
            fast_timers(),
            shutdown.clone(),
        )
        .await
        .unwrap();

        let peer = UdpTransport::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut invite_echo: Option<String> = None;
            let mut sent_ringing = false;
            loop {
                let (m, src) = peer.recv().await.unwrap();
                let SipMessage::Request(r) = m else { continue };
                match r.method() {
                    // Ring once; tolerate INVITE retransmissions.
                    Method::Invite if !sent_ringing => {
                        let h = echo(&r);
                        invite_echo = Some(h.clone());
                        let ringing = format!("SIP/2.0 180 Ringing\r\n{h}To: <sip:bob@example.com>;tag=b\r\nContent-Length: 0\r\n\r\n");
                        peer.send_to(&SipMessage::try_from(ringing.as_bytes()).unwrap(), src)
                            .await
                            .unwrap();
                        sent_ringing = true;
                    }
                    Method::Invite => {}
                    Method::Cancel => {
                        // 200 to the CANCEL, then 487 to the INVITE, then ACK.
                        let ch = echo(&r);
                        let ok = format!("SIP/2.0 200 OK\r\n{ch}To: <sip:bob@example.com>;tag=b\r\nContent-Length: 0\r\n\r\n");
                        peer.send_to(&SipMessage::try_from(ok.as_bytes()).unwrap(), src)
                            .await
                            .unwrap();
                        let h = invite_echo.clone().unwrap();
                        let term = format!("SIP/2.0 487 Request Terminated\r\n{h}To: <sip:bob@example.com>;tag=b\r\nContent-Length: 0\r\n\r\n");
                        peer.send_to(&SipMessage::try_from(term.as_bytes()).unwrap(), src)
                            .await
                            .unwrap();
                        let (m, _) = peer.recv().await.unwrap();
                        assert!(
                            matches!(m, SipMessage::Request(a) if *a.method() == Method::Ack),
                            "engine ACKs the 487",
                        );
                        return;
                    }
                    _ => {}
                }
            }
        });

        // Request cancellation up front; the engine defers the CANCEL until the
        // 180 arrives (RFC 3261 §9.1). Observe provisionals on `progress`.
        let dial_cancel = CancellationToken::new();
        dial_cancel.cancel();
        let (progress_tx, mut progress_rx) = mpsc::channel(8);
        let outcome = timeout(
            Duration::from_secs(3),
            ua.call_cancellable(
                &call_config(),
                peer_addr,
                1,
                &dial_cancel,
                Some(&progress_tx),
            ),
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome, CallOutcome::Rejected(s) if s.code() == 487),
            "cancel-while-ringing resolves to 487 Request Terminated",
        );
        assert_eq!(
            progress_rx.recv().await.map(|s| s.code()),
            Some(180),
            "the 180 Ringing was observed on the progress channel",
        );

        server.await.unwrap();
        shutdown.cancel();
    }
}
