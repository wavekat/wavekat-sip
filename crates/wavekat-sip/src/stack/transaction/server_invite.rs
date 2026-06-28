//! Server INVITE transaction — RFC 3261 §17.2.1.
//!
//! Handles an inbound INVITE: relays the TU's responses, retransmits the
//! final on loss, and absorbs the ACK for a non-2xx.
//!
//! ```text
//!     Proceeding -- INVITE retransmit: resend last provisional
//!        |   \       1xx from TU: send
//!    300 |    \ 2xx from TU: send, terminate (TU owns 2xx + ACK)
//!    -699|     \
//!        v
//!     Completed -- INVITE retransmit / Timer G: resend final (G = min(2·G,T2))
//!        |          Timer H: no ACK → inform TU, terminate
//!    ACK |
//!        v
//!     Confirmed -- ACK retransmit: absorb
//!        |          Timer I: terminate
//!        v
//!     Terminated
//! ```
//!
//! A **2xx** is special: the server transaction sends it and terminates at
//! once. Retransmitting the 2xx until the ACK arrives is the TU/dialog's job
//! (RFC 3261 §13.3.1.4), because that ACK is a separate transaction.

use super::{Reliability, TimerId, Timers, TxAction};
use rsip::{Method, Request, Response, SipMessage};

/// State of a server INVITE transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    /// INVITE received; relaying provisional responses from the TU.
    Proceeding,
    /// A non-2xx final was sent; retransmitting it and waiting for the ACK.
    Completed,
    /// The ACK arrived; absorbing its retransmissions (Timer I).
    Confirmed,
    /// Done.
    Terminated,
}

/// A server INVITE transaction state machine.
pub(crate) struct ServerInvite {
    state: State,
    timers: Timers,
    rel: Reliability,
    last_provisional: Option<Response>,
    last_final: Option<Response>,
    /// Current Timer G interval; doubles up to T2.
    timer_g: std::time::Duration,
}

impl ServerInvite {
    /// Construct from the received INVITE. Hands the request up to the TU so
    /// it can produce responses; no timers run until a final is sent.
    pub(crate) fn start(
        invite: &Request,
        timers: Timers,
        rel: Reliability,
    ) -> (Self, Vec<TxAction>) {
        let tx = Self {
            state: State::Proceeding,
            timers,
            rel,
            last_provisional: None,
            last_final: None,
            timer_g: timers.t1,
        };
        (tx, vec![TxAction::DeliverRequest(invite.clone())])
    }

    pub(crate) fn state(&self) -> State {
        self.state
    }

    /// The TU wants to send `resp` for this transaction.
    pub(crate) fn send_response(&mut self, resp: Response) -> Vec<TxAction> {
        if self.state != State::Proceeding {
            return Vec::new();
        }
        let code = resp.status_code().code();
        if code < 200 {
            self.last_provisional = Some(resp.clone());
            vec![TxAction::Send(SipMessage::Response(resp))]
        } else if code < 300 {
            // 2xx: emit and terminate; the TU now owns 2xx retransmission.
            self.state = State::Terminated;
            vec![
                TxAction::Send(SipMessage::Response(resp)),
                TxAction::Terminated,
            ]
        } else {
            self.last_final = Some(resp.clone());
            let mut actions = vec![TxAction::Send(SipMessage::Response(resp))];
            if !self.rel.is_reliable() {
                actions.push(TxAction::StartTimer {
                    id: TimerId::G,
                    after: self.timers.t1,
                });
            }
            actions.push(TxAction::StartTimer {
                id: TimerId::H,
                after: self.timers.timeout(),
            });
            self.state = State::Completed;
            actions
        }
    }

    /// A request was received for this transaction (a retransmitted INVITE,
    /// or the ACK for a non-2xx final).
    pub(crate) fn on_request(&mut self, req: &Request) -> Vec<TxAction> {
        match (*req.method(), self.state) {
            // Retransmitted INVITE: resend whatever we last sent.
            (Method::Invite, State::Proceeding) => self.resend(&self.last_provisional),
            (Method::Invite, State::Completed) => self.resend(&self.last_final),
            // ACK for our non-2xx final: stop retransmitting, soak in Confirmed.
            (Method::Ack, State::Completed) => {
                if self.rel.is_reliable() {
                    self.state = State::Terminated;
                    vec![
                        TxAction::StopTimer(TimerId::G),
                        TxAction::StopTimer(TimerId::H),
                        TxAction::Terminated,
                    ]
                } else {
                    self.state = State::Confirmed;
                    vec![
                        TxAction::StopTimer(TimerId::G),
                        TxAction::StopTimer(TimerId::H),
                        TxAction::StartTimer {
                            id: TimerId::I,
                            after: self.timers.i(self.rel),
                        },
                    ]
                }
            }
            // Retransmitted ACK while soaking: absorb.
            (Method::Ack, State::Confirmed) => Vec::new(),
            _ => Vec::new(),
        }
    }

    /// Feed a fired timer.
    pub(crate) fn on_timer(&mut self, id: TimerId) -> Vec<TxAction> {
        match (self.state, id) {
            (State::Completed, TimerId::G) => {
                self.timer_g = (self.timer_g * 2).min(self.timers.t2);
                let mut actions = self.resend(&self.last_final);
                actions.push(TxAction::StartTimer {
                    id: TimerId::G,
                    after: self.timer_g,
                });
                actions
            }
            (State::Completed, TimerId::H) => {
                // ACK never arrived.
                self.state = State::Terminated;
                vec![TxAction::TimedOut, TxAction::Terminated]
            }
            (State::Confirmed, TimerId::I) => {
                self.state = State::Terminated;
                vec![TxAction::Terminated]
            }
            _ => Vec::new(),
        }
    }

    fn resend(&self, stored: &Option<Response>) -> Vec<TxAction> {
        match stored {
            Some(resp) => vec![TxAction::Send(SipMessage::Response(resp.clone()))],
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invite() -> Request {
        let raw = "INVITE sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-sin\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>\r\n\
             Call-ID: call-sin\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Length: 0\r\n\r\n";
        Request::try_from(raw.as_bytes()).unwrap()
    }

    fn ack() -> Request {
        let raw = "ACK sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-sin\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>;tag=bob\r\n\
             Call-ID: call-sin\r\n\
             CSeq: 1 ACK\r\n\
             Content-Length: 0\r\n\r\n";
        Request::try_from(raw.as_bytes()).unwrap()
    }

    fn response(code: u16) -> Response {
        let raw = format!(
            "SIP/2.0 {code} X\r\n\
             Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-sin\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>;tag=bob\r\n\
             Call-ID: call-sin\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Length: 0\r\n\r\n"
        );
        Response::try_from(raw.as_bytes()).unwrap()
    }

    #[test]
    fn start_delivers_request_to_tu() {
        let (tx, actions) =
            ServerInvite::start(&invite(), Timers::default(), Reliability::Unreliable);
        assert_eq!(tx.state(), State::Proceeding);
        assert!(matches!(actions[0], TxAction::DeliverRequest(_)));
    }

    #[test]
    fn provisional_is_sent_and_remembered() {
        let (mut tx, _) =
            ServerInvite::start(&invite(), Timers::default(), Reliability::Unreliable);
        let out = tx.send_response(response(180));
        assert_eq!(
            out,
            vec![TxAction::Send(SipMessage::Response(response(180)))]
        );
        // A retransmitted INVITE now replays the 180.
        let replay = tx.on_request(&invite());
        assert_eq!(
            replay,
            vec![TxAction::Send(SipMessage::Response(response(180)))]
        );
    }

    #[test]
    fn two_xx_sends_and_terminates() {
        let (mut tx, _) =
            ServerInvite::start(&invite(), Timers::default(), Reliability::Unreliable);
        let out = tx.send_response(response(200));
        assert_eq!(tx.state(), State::Terminated);
        assert!(matches!(out[0], TxAction::Send(_)));
        assert_eq!(out[1], TxAction::Terminated);
    }

    #[test]
    fn non_2xx_final_arms_g_and_h_on_udp() {
        let (mut tx, _) =
            ServerInvite::start(&invite(), Timers::default(), Reliability::Unreliable);
        let out = tx.send_response(response(486));
        assert_eq!(tx.state(), State::Completed);
        assert!(matches!(out[0], TxAction::Send(_)));
        assert!(out
            .iter()
            .any(|a| matches!(a, TxAction::StartTimer { id: TimerId::G, .. })));
        assert!(out
            .iter()
            .any(|a| matches!(a, TxAction::StartTimer { id: TimerId::H, .. })));
    }

    #[test]
    fn non_2xx_final_skips_g_on_reliable() {
        let (mut tx, _) = ServerInvite::start(&invite(), Timers::default(), Reliability::Reliable);
        let out = tx.send_response(response(500));
        assert!(!out
            .iter()
            .any(|a| matches!(a, TxAction::StartTimer { id: TimerId::G, .. })));
        assert!(out
            .iter()
            .any(|a| matches!(a, TxAction::StartTimer { id: TimerId::H, .. })));
    }

    #[test]
    fn timer_g_retransmits_final_and_doubles_capped_at_t2() {
        let timers = Timers::default();
        let (mut tx, _) = ServerInvite::start(&invite(), timers, Reliability::Unreliable);
        tx.send_response(response(486));
        let expected = [timers.t1 * 2, timers.t1 * 4, timers.t2, timers.t2];
        for want in expected {
            let out = tx.on_timer(TimerId::G);
            assert!(matches!(out[0], TxAction::Send(_)));
            match out[1] {
                TxAction::StartTimer {
                    id: TimerId::G,
                    after,
                } => assert_eq!(after, want),
                _ => panic!("expected Timer G reschedule"),
            }
        }
    }

    #[test]
    fn ack_moves_completed_to_confirmed_and_arms_i() {
        let (mut tx, _) =
            ServerInvite::start(&invite(), Timers::default(), Reliability::Unreliable);
        tx.send_response(response(486));
        let out = tx.on_request(&ack());
        assert_eq!(tx.state(), State::Confirmed);
        assert!(out.contains(&TxAction::StopTimer(TimerId::G)));
        assert!(out.contains(&TxAction::StopTimer(TimerId::H)));
        assert!(matches!(
            out.last(),
            Some(TxAction::StartTimer { id: TimerId::I, .. })
        ));
        // Retransmitted ACK is absorbed.
        assert!(tx.on_request(&ack()).is_empty());
    }

    #[test]
    fn ack_terminates_immediately_on_reliable() {
        let (mut tx, _) = ServerInvite::start(&invite(), Timers::default(), Reliability::Reliable);
        tx.send_response(response(486));
        let out = tx.on_request(&ack());
        assert_eq!(tx.state(), State::Terminated);
        assert!(out.contains(&TxAction::Terminated));
    }

    #[test]
    fn timer_h_times_out_waiting_for_ack() {
        let (mut tx, _) =
            ServerInvite::start(&invite(), Timers::default(), Reliability::Unreliable);
        tx.send_response(response(486));
        let out = tx.on_timer(TimerId::H);
        assert_eq!(out, vec![TxAction::TimedOut, TxAction::Terminated]);
    }

    #[test]
    fn timer_i_terminates_from_confirmed() {
        let (mut tx, _) =
            ServerInvite::start(&invite(), Timers::default(), Reliability::Unreliable);
        tx.send_response(response(486));
        tx.on_request(&ack());
        assert_eq!(tx.on_timer(TimerId::I), vec![TxAction::Terminated]);
        assert_eq!(tx.state(), State::Terminated);
    }
}
