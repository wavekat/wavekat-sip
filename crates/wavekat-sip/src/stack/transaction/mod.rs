//! RFC 3261 §17 transaction layer, expressed sans-IO.
//!
//! A SIP transaction is a short-lived state machine that sits between the
//! transaction user (TU — our dialog/registration logic) and the transport.
//! Its whole job is timers and retransmissions: hide packet loss on
//! unreliable transports and absorb duplicates, so the TU sees each logical
//! request/response once.
//!
//! ## Sans-IO
//!
//! These machines never touch a socket or the clock. Each one maps an input
//! event — a received [`SipMessage`], a fired [`TimerId`], or (server side) a
//! response the TU wants to send — to an ordered list of [`TxAction`]s the
//! caller must perform: put a message on the wire, arm or cancel a timer,
//! hand a message up to the TU, or report that the transaction finished. A
//! thin transport runner (a later phase) owns the UDP/TCP socket and a timer
//! wheel and simply applies whatever actions come back.
//!
//! This is what makes the timer-heavy core testable: a unit test feeds events
//! and asserts on the action list and the timer durations, with no sleeping
//! and no sockets — exactly the RFC §17 timer tables, checked directly.
//!
//! ## What we implement
//!
//! All four machines, because our UA drives all four:
//!
//! | Machine | RFC | Methods | Module |
//! |---------|-----|---------|--------|
//! | Client INVITE | §17.1.1 | INVITE | [`client_invite`] |
//! | Client non-INVITE | §17.1.2 | REGISTER, BYE, CANCEL, INFO, OPTIONS | [`client_non_invite`] |
//! | Server INVITE | §17.2.1 | inbound INVITE | [`server_invite`] |
//! | Server non-INVITE | §17.2.2 | inbound BYE, INFO, OPTIONS, CANCEL | [`server_non_invite`] |

use std::hash::{BuildHasher, Hash, Hasher};
use std::mem::discriminant;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rsip::headers::ToTypedHeader;
use rsip::message::HeadersExt;
use rsip::{Header, Headers, Method, Request, Response, SipMessage};

pub(crate) mod client_invite;
pub(crate) mod client_non_invite;
pub(crate) mod server_invite;
pub(crate) mod server_non_invite;

/// RFC 3261 magic cookie that prefixes every `branch` parameter we generate,
/// marking the value as RFC 3261-compliant (§8.1.1.7).
pub(crate) const MAGIC_COOKIE: &str = "z9hG4bK";

/// Whether the underlying transport delivers reliably (TCP/TLS) or may drop
/// and reorder (UDP). This single bit selects every transaction timer that
/// differs between the two: retransmit timers run only on unreliable
/// transports, and the post-final "soak" timers (D/I/J/K) collapse to zero on
/// reliable ones because there is nothing to retransmit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reliability {
    /// TCP / TLS — no retransmissions, soak timers fire immediately.
    Reliable,
    /// UDP — retransmit on Timer A/E/G, soak after the final response.
    Unreliable,
}

impl Reliability {
    pub(crate) fn is_reliable(self) -> bool {
        matches!(self, Reliability::Reliable)
    }
}

impl From<crate::account::Transport> for Reliability {
    fn from(transport: crate::account::Transport) -> Self {
        match transport {
            crate::account::Transport::Udp => Reliability::Unreliable,
            crate::account::Transport::Tcp => Reliability::Reliable,
        }
    }
}

/// The RFC 3261 §17 base timer values (T1/T2/T4) from which every transaction
/// timer is derived. Defaults are the RFC's recommended values; tests can
/// shrink them to keep wall-clock assertions fast, and the transport runner
/// can tune T1 to a measured RTT.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Timers {
    /// Round-trip time estimate (default 500 ms). Seeds Timer A/E/G and, at
    /// ×64, the transaction timeout Timer B/F/H.
    pub t1: Duration,
    /// Maximum retransmit interval (default 4 s) for non-INVITE Timer E and
    /// INVITE response Timer G.
    pub t2: Duration,
    /// Maximum time a message lingers in the network (default 5 s). Sets the
    /// Confirmed/Completed soak timers I and K.
    pub t4: Duration,
}

impl Default for Timers {
    fn default() -> Self {
        Self {
            t1: Duration::from_millis(500),
            t2: Duration::from_secs(4),
            t4: Duration::from_secs(5),
        }
    }
}

impl Timers {
    /// Timer B/F/H = 64·T1 — the overall transaction timeout.
    pub(crate) fn timeout(&self) -> Duration {
        self.t1 * 64
    }

    /// Timer D — wait in client-INVITE Completed to absorb retransmitted
    /// final responses. "≥ 32 s" on unreliable transports, zero on reliable.
    pub(crate) fn d(&self, rel: Reliability) -> Duration {
        if rel.is_reliable() {
            Duration::ZERO
        } else {
            Duration::from_secs(32)
        }
    }

    /// Timer I — wait in server-INVITE Confirmed to absorb retransmitted ACKs.
    /// T4 on unreliable, zero on reliable.
    pub(crate) fn i(&self, rel: Reliability) -> Duration {
        if rel.is_reliable() {
            Duration::ZERO
        } else {
            self.t4
        }
    }

    /// Timer J — wait in server-non-INVITE Completed to absorb retransmitted
    /// requests. 64·T1 on unreliable, zero on reliable.
    pub(crate) fn j(&self, rel: Reliability) -> Duration {
        if rel.is_reliable() {
            Duration::ZERO
        } else {
            self.timeout()
        }
    }

    /// Timer K — wait in client-non-INVITE Completed to absorb retransmitted
    /// final responses. T4 on unreliable, zero on reliable.
    pub(crate) fn k(&self, rel: Reliability) -> Duration {
        if rel.is_reliable() {
            Duration::ZERO
        } else {
            self.t4
        }
    }
}

/// Identifies a transaction timer. The variants map one-to-one onto the
/// letters used in RFC 3261 §17, so the FSMs and their tests read like the
/// spec's timer tables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum TimerId {
    /// Client INVITE request retransmit (unreliable only).
    A,
    /// Client INVITE transaction timeout.
    B,
    /// Client INVITE Completed soak.
    D,
    /// Client non-INVITE request retransmit (unreliable only).
    E,
    /// Client non-INVITE transaction timeout.
    F,
    /// Server INVITE final-response retransmit (unreliable only).
    G,
    /// Server INVITE wait-for-ACK timeout.
    H,
    /// Server INVITE Confirmed soak.
    I,
    /// Server non-INVITE Completed soak.
    J,
    /// Client non-INVITE Completed soak.
    K,
}

/// One unit of work a transaction asks its caller to perform. The FSMs return
/// these in order; the caller (a future transport runner, or a unit test)
/// applies them against a real socket and timer wheel, or simply inspects
/// them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TxAction {
    /// Put this message on the wire (initial send, retransmit, or ACK).
    Send(SipMessage),
    /// Arm a timer; if already running, reschedule it to fire `after` from now.
    StartTimer { id: TimerId, after: Duration },
    /// Cancel a running timer.
    StopTimer(TimerId),
    /// Deliver a received response up to the TU (client transactions).
    DeliverResponse(Response),
    /// Deliver a received request up to the TU (server transactions: the
    /// initial request and any CANCEL; ACK retransmits are absorbed here).
    DeliverRequest(Request),
    /// No final response arrived before the timeout timer fired.
    TimedOut,
    /// The transaction reached Terminated; the caller may drop it.
    Terminated,
}

/// Identifies the transaction a message belongs to, for demultiplexing
/// inbound traffic to the right state machine (RFC 3261 §17.1.3 / §17.2.3).
///
/// The match key is the top `Via` branch plus the `sent-by` host, combined
/// with the method. `ACK` is folded onto `INVITE` so a non-2xx ACK reaches
/// its server INVITE transaction; `CANCEL` keeps its own identity so it forms
/// a separate (non-INVITE) transaction from the INVITE it cancels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransactionKey {
    branch: String,
    sent_by: String,
    method: Method,
}

impl Hash for TransactionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.branch.hash(state);
        self.sent_by.hash(state);
        // `rsip::Method` is a field-less enum but does not derive `Hash`; its
        // discriminant is hashable and uniquely identifies the variant.
        discriminant(&self.method).hash(state);
    }
}

impl TransactionKey {
    /// Build the match key from an inbound (or outbound) request. Uses the
    /// request line method, with `ACK` folded onto `INVITE`.
    pub(crate) fn from_request(req: &Request) -> Option<Self> {
        Self::build(req, normalize(*req.method()))
    }

    /// Build the match key from a response. The method comes from the
    /// response's `CSeq` (a response carries the request's `Via` and `CSeq`).
    pub(crate) fn from_response(resp: &Response) -> Option<Self> {
        let method = resp.cseq_header().ok()?.typed().ok()?.method;
        Self::build(resp, normalize(method))
    }

    fn build(msg: &impl HeadersExt, method: Method) -> Option<Self> {
        let via = msg.via_header().ok()?.typed().ok()?;
        let branch = via.branch()?.value().to_string();
        let sent_by = via.sent_by().host_with_port.to_string();
        Some(Self {
            branch,
            sent_by,
            method,
        })
    }

    /// The key of the INVITE transaction a CANCEL targets: same `branch` and
    /// `sent-by`, with the method folded to `INVITE`. A CANCEL shares the top
    /// `Via` branch of the request it cancels (RFC 3261 §9.1), so this maps a
    /// received CANCEL's key onto the server INVITE transaction it must 487.
    pub(crate) fn invite_target(&self) -> TransactionKey {
        TransactionKey {
            branch: self.branch.clone(),
            sent_by: self.sent_by.clone(),
            method: Method::Invite,
        }
    }
}

/// Fold `ACK` onto `INVITE` for transaction matching; every other method
/// keeps its identity. (An ACK for a non-2xx response is absorbed by the
/// server INVITE transaction that sent the final response.)
fn normalize(method: Method) -> Method {
    match method {
        Method::Ack => Method::Invite,
        other => other,
    }
}

/// Process-wide counter feeding [`gen_branch`]; guarantees uniqueness within
/// a process without locking.
static BRANCH_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a globally-unique `Via` branch value carrying the RFC 3261 magic
/// cookie (§8.1.1.7). Uniqueness comes from a monotonic per-process counter
/// mixed with a randomly-seeded hash, so values don't collide within a
/// process or across restarts — without taking a `rand` dependency.
pub(crate) fn gen_branch() -> String {
    let n = BRANCH_COUNTER.fetch_add(1, Ordering::Relaxed);
    let seed = std::collections::hash_map::RandomState::new().hash_one(n);
    format!("{MAGIC_COOKIE}{n:x}{seed:x}")
}

/// Build the `Via` header value for one of our outgoing requests: a UDP
/// sent-by of `sent_by`, the given transaction `branch`, and a bare `;rport`
/// (RFC 3581).
///
/// `rport` is what lets us be reached behind NAT. Without it, a proxy records
/// our private sent-by / `Contact` and routes a later in-dialog request (most
/// importantly the peer's `BYE`) to an address that never arrives — so the call
/// never tears down on a remote hangup. With it, the proxy stamps `received` /
/// `rport` from the packet's real source and routes back there instead. The
/// value is empty in a request (RFC 3581 §3); the server fills it in its
/// response.
pub(crate) fn via_value(sent_by: impl std::fmt::Display, branch: &str) -> String {
    format!("SIP/2.0/UDP {sent_by};rport;branch={branch}")
}

/// Generate a unique dialog tag (`From`/`To` tag). Like [`gen_branch`] but
/// without the transaction magic cookie — a tag is just an opaque token.
pub(crate) fn gen_tag() -> String {
    use std::hash::BuildHasher;
    let n = BRANCH_COUNTER.fetch_add(1, Ordering::Relaxed);
    let seed = std::collections::hash_map::RandomState::new().hash_one(n);
    format!("wk{n:x}{seed:x}")
}

/// Build the ACK for a non-2xx final response, per RFC 3261 §17.1.1.3.
///
/// This ACK is part of the client INVITE *transaction* (unlike the ACK for a
/// 2xx, which the TU/dialog sends as a separate transaction). It reuses the
/// INVITE's top `Via` (same branch), `From`, `Call-ID`, request-URI, and
/// `CSeq` sequence number; takes `To` from the response (so the remote tag is
/// echoed); copies any `Route` set; and carries an empty body.
pub(crate) fn build_non_2xx_ack(invite: &Request, response: &Response) -> Option<Request> {
    let mut headers = Headers::default();
    headers.push(Header::Via(invite.via_header().ok()?.clone()));
    headers.push(Header::From(invite.from_header().ok()?.clone()));
    // To with the remote tag the server placed on its final response.
    headers.push(Header::To(response.to_header().ok()?.clone()));
    headers.push(Header::CallId(invite.call_id_header().ok()?.clone()));

    let seq = invite.cseq_header().ok()?.typed().ok()?.seq;
    let cseq: rsip::headers::CSeq = rsip::typed::CSeq {
        seq,
        method: Method::Ack,
    }
    .into();
    headers.push(Header::CSeq(cseq));

    // Preserve the request's route set on the ACK (§17.1.1.3).
    for header in invite.headers.iter() {
        if let Header::Route(route) = header {
            headers.push(Header::Route(route.clone()));
        }
    }
    headers.push(Header::MaxForwards(rsip::headers::MaxForwards::default()));
    headers.push(Header::ContentLength(
        rsip::headers::ContentLength::default(),
    ));

    Some(Request {
        method: Method::Ack,
        uri: invite.uri.clone(),
        version: invite.version.clone(),
        headers,
        body: Vec::new(),
    })
}

/// A live transaction of any of the four RFC 3261 §17 kinds, so the engine
/// can hold them in one table and dispatch events without knowing the kind.
// The variant names mirror the RFC's four machine names (client/server ×
// INVITE/non-INVITE); the shared "Invite" suffix is intentional and clearer
// than any rename.
#[allow(clippy::enum_variant_names)]
pub(crate) enum Transaction {
    ClientInvite(client_invite::ClientInvite),
    ClientNonInvite(client_non_invite::ClientNonInvite),
    ServerInvite(server_invite::ServerInvite),
    ServerNonInvite(server_non_invite::ServerNonInvite),
}

impl Transaction {
    /// Feed a received response. Only client transactions react; server
    /// transactions never receive responses, so they return no actions.
    pub(crate) fn on_response(&mut self, resp: &Response) -> Vec<TxAction> {
        match self {
            Transaction::ClientInvite(t) => t.on_response(resp),
            Transaction::ClientNonInvite(t) => t.on_response(resp),
            Transaction::ServerInvite(_) | Transaction::ServerNonInvite(_) => Vec::new(),
        }
    }

    /// Feed a received request (a retransmission, or the ACK for a non-2xx).
    /// Only server transactions react.
    pub(crate) fn on_request(&mut self, req: &Request) -> Vec<TxAction> {
        match self {
            Transaction::ServerInvite(t) => t.on_request(req),
            Transaction::ServerNonInvite(t) => t.on_request(req),
            Transaction::ClientInvite(_) | Transaction::ClientNonInvite(_) => Vec::new(),
        }
    }

    /// Feed a fired timer.
    pub(crate) fn on_timer(&mut self, id: TimerId) -> Vec<TxAction> {
        match self {
            Transaction::ClientInvite(t) => t.on_timer(id),
            Transaction::ClientNonInvite(t) => t.on_timer(id),
            Transaction::ServerInvite(t) => t.on_timer(id),
            Transaction::ServerNonInvite(t) => t.on_timer(id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal but well-formed request for tests, with a single Via, From,
    /// To, Call-ID and CSeq. `with_tag` controls whether To carries a tag.
    fn request(method: Method, branch: &str, seq: u32) -> Request {
        let raw = format!(
            "{m} sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch={b}\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>\r\n\
             Call-ID: call-abc\r\n\
             CSeq: {s} {m}\r\n\
             Content-Length: 0\r\n\r\n",
            m = method,
            b = branch,
            s = seq,
        );
        Request::try_from(raw.as_bytes()).expect("valid request")
    }

    fn response(status: u16, branch: &str, seq: u32, method: Method) -> Response {
        let raw = format!(
            "SIP/2.0 {code} Testing\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch={b}\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>;tag=bob\r\n\
             Call-ID: call-abc\r\n\
             CSeq: {s} {m}\r\n\
             Content-Length: 0\r\n\r\n",
            code = status,
            b = branch,
            s = seq,
            m = method,
        );
        Response::try_from(raw.as_bytes()).expect("valid response")
    }

    #[test]
    fn via_value_advertises_rport_and_keeps_branch_parseable() {
        let v = via_value("192.168.1.46:54991", "z9hG4bK-rp");
        // RFC 3581: the request carries a bare `rport` (no value).
        assert!(v.contains(";rport"), "Via must advertise rport: {v}");
        assert!(
            !v.contains("rport="),
            "request rport must be valueless: {v}"
        );
        assert!(v.contains("branch=z9hG4bK-rp"));
        assert!(v.contains("192.168.1.46:54991"));

        // Regression: the bare `rport` param must not break branch extraction —
        // transaction matching keys off the branch, so a request built with this
        // Via must still yield a key with the right branch.
        let raw = format!(
            "BYE sip:bob@example.com SIP/2.0\r\n\
             Via: {v}\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>;tag=bob\r\n\
             Call-ID: call-abc\r\n\
             CSeq: 2 BYE\r\n\
             Content-Length: 0\r\n\r\n"
        );
        let req = Request::try_from(raw.as_bytes()).expect("valid request");
        let key = TransactionKey::from_request(&req).expect("branch parses despite bare rport");
        assert_eq!(key.branch, "z9hG4bK-rp");
    }

    #[test]
    fn gen_branch_carries_magic_cookie_and_is_unique() {
        let a = gen_branch();
        let b = gen_branch();
        assert!(a.starts_with(MAGIC_COOKIE));
        assert!(b.starts_with(MAGIC_COOKIE));
        assert_ne!(a, b);
    }

    #[test]
    fn timeout_is_64_t1() {
        let t = Timers::default();
        assert_eq!(t.timeout(), Duration::from_millis(500) * 64);
    }

    #[test]
    fn soak_timers_collapse_on_reliable_transport() {
        let t = Timers::default();
        assert_eq!(t.d(Reliability::Reliable), Duration::ZERO);
        assert_eq!(t.i(Reliability::Reliable), Duration::ZERO);
        assert_eq!(t.j(Reliability::Reliable), Duration::ZERO);
        assert_eq!(t.k(Reliability::Reliable), Duration::ZERO);

        assert_eq!(t.d(Reliability::Unreliable), Duration::from_secs(32));
        assert_eq!(t.i(Reliability::Unreliable), t.t4);
        assert_eq!(t.j(Reliability::Unreliable), t.timeout());
        assert_eq!(t.k(Reliability::Unreliable), t.t4);
    }

    #[test]
    fn request_and_response_share_a_key() {
        let req = request(Method::Invite, "z9hG4bK-1", 1);
        let resp = response(180, "z9hG4bK-1", 1, Method::Invite);
        assert_eq!(
            TransactionKey::from_request(&req),
            TransactionKey::from_response(&resp)
        );
    }

    #[test]
    fn ack_folds_onto_invite_but_cancel_does_not() {
        let invite = request(Method::Invite, "z9hG4bK-1", 1);
        let ack = request(Method::Ack, "z9hG4bK-1", 1);
        let cancel = request(Method::Cancel, "z9hG4bK-1", 1);

        assert_eq!(
            TransactionKey::from_request(&invite),
            TransactionKey::from_request(&ack),
            "ACK must reach the INVITE server transaction"
        );
        assert_ne!(
            TransactionKey::from_request(&invite),
            TransactionKey::from_request(&cancel),
            "CANCEL forms its own transaction"
        );
    }

    #[test]
    fn cancel_invite_target_matches_the_invite_key() {
        // RFC 3261 §9.1: a CANCEL carries the same top-`Via` branch as the
        // INVITE it cancels. `invite_target` maps a received CANCEL's key onto
        // that INVITE server transaction so the UAS can 487 it (§9.2). If this
        // ever drifts, a cancelled INVITE would never be terminated and the
        // call would ring forever.
        let invite = request(Method::Invite, "z9hG4bK-cxl", 1);
        let cancel = request(Method::Cancel, "z9hG4bK-cxl", 1);

        let invite_key = TransactionKey::from_request(&invite).unwrap();
        let cancel_key = TransactionKey::from_request(&cancel).unwrap();

        // The CANCEL is its own transaction (method kept distinct)...
        assert_ne!(cancel_key, invite_key);
        // ...but its target is exactly the INVITE's key.
        assert_eq!(cancel_key.invite_target(), invite_key);
        // Branch + sent-by carried over verbatim; only the method is folded.
        let target = cancel_key.invite_target();
        assert_eq!(target.branch, cancel_key.branch);
        assert_eq!(target.sent_by, cancel_key.sent_by);
        assert_eq!(target.method, Method::Invite);
    }

    #[test]
    fn different_branches_yield_different_keys() {
        let a = request(Method::Bye, "z9hG4bK-aaa", 2);
        let b = request(Method::Bye, "z9hG4bK-bbb", 2);
        assert_ne!(
            TransactionKey::from_request(&a),
            TransactionKey::from_request(&b)
        );
    }

    #[test]
    fn non_2xx_ack_copies_dialog_identity_and_echoes_remote_tag() {
        let invite = request(Method::Invite, "z9hG4bK-9", 7);
        let resp = response(486, "z9hG4bK-9", 7, Method::Invite);
        let ack = build_non_2xx_ack(&invite, &resp).expect("ack built");

        assert_eq!(*ack.method(), Method::Ack);
        assert_eq!(ack.uri, invite.uri);
        // Same branch as the INVITE: the ACK is part of the same transaction.
        assert_eq!(
            ack.via_header().unwrap().typed().unwrap().branch(),
            invite.via_header().unwrap().typed().unwrap().branch()
        );
        // CSeq number copied, method rewritten to ACK.
        let cseq = ack.cseq_header().unwrap().typed().unwrap();
        assert_eq!(cseq.seq, 7);
        assert_eq!(cseq.method, Method::Ack);
        // To tag taken from the response, not the (tagless) request To.
        let to = ack.to_header().unwrap().typed().unwrap();
        assert_eq!(
            to.tag().map(|t| t.value().to_string()),
            Some("bob".to_string())
        );
    }
}
