//! Client non-INVITE transaction — RFC 3261 §17.1.2.
//!
//! Drives REGISTER, BYE, CANCEL, INFO and OPTIONS. Simpler than the INVITE
//! machine: there is no ACK, and a final response of any class ends the
//! request/response exchange.
//!
//! ```text
//!     Trying ----- Timer E: resend, E = min(2·E, T2)
//!        |   \     Timer F: inform TU (timeout)
//!    1xx |    \ 200-699 → deliver, Completed
//!        v     \
//!    Proceeding - Timer E: resend, E = T2
//!        |        Timer F: inform TU (timeout)
//!        |        200-699 → deliver, Completed
//!        v
//!    Completed -- retransmitted final: absorb
//!        |        Timer K: terminate
//!        v
//!    Terminated
//! ```

use super::{Reliability, TimerId, Timers, TxAction};
use rsip::{Request, Response, SipMessage};

/// State of a client non-INVITE transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    /// Request sent, nothing back yet; retransmitting on Timer E.
    Trying,
    /// A provisional response arrived; still retransmitting (capped at T2).
    Proceeding,
    /// A final response arrived; absorbing its retransmissions (Timer K).
    Completed,
    /// Done.
    Terminated,
}

/// A client non-INVITE transaction state machine.
pub(crate) struct ClientNonInvite {
    state: State,
    timers: Timers,
    rel: Reliability,
    request: Request,
    /// Current Timer E interval; doubles up to T2.
    timer_e: std::time::Duration,
}

impl ClientNonInvite {
    /// Begin the transaction: send the request and arm Timers E (unreliable
    /// only) and F.
    pub(crate) fn start(
        request: Request,
        timers: Timers,
        rel: Reliability,
    ) -> (Self, Vec<TxAction>) {
        let mut actions = vec![TxAction::Send(SipMessage::Request(request.clone()))];
        if !rel.is_reliable() {
            actions.push(TxAction::StartTimer {
                id: TimerId::E,
                after: timers.t1,
            });
        }
        actions.push(TxAction::StartTimer {
            id: TimerId::F,
            after: timers.timeout(),
        });
        let tx = Self {
            state: State::Trying,
            timers,
            rel,
            request,
            timer_e: timers.t1,
        };
        (tx, actions)
    }

    pub(crate) fn state(&self) -> State {
        self.state
    }

    /// Feed a response received for this transaction.
    pub(crate) fn on_response(&mut self, resp: &Response) -> Vec<TxAction> {
        let code = resp.status_code().code();
        match self.state {
            State::Trying | State::Proceeding => {
                if code < 200 {
                    // Provisional: deliver and (from Trying) enter Proceeding.
                    self.state = State::Proceeding;
                    vec![TxAction::DeliverResponse(resp.clone())]
                } else {
                    self.enter_completed(resp)
                }
            }
            // Retransmitted final: absorb silently (no ACK for non-INVITE).
            State::Completed | State::Terminated => Vec::new(),
        }
    }

    /// Feed a fired timer.
    pub(crate) fn on_timer(&mut self, id: TimerId) -> Vec<TxAction> {
        match (self.state, id) {
            (State::Trying, TimerId::E) => {
                // Back off, capped at T2.
                self.timer_e = (self.timer_e * 2).min(self.timers.t2);
                self.retransmit()
            }
            (State::Proceeding, TimerId::E) => {
                // In Proceeding the interval is pinned at T2.
                self.timer_e = self.timers.t2;
                self.retransmit()
            }
            (State::Trying | State::Proceeding, TimerId::F) => {
                self.state = State::Terminated;
                vec![TxAction::TimedOut, TxAction::Terminated]
            }
            (State::Completed, TimerId::K) => {
                self.state = State::Terminated;
                vec![TxAction::Terminated]
            }
            _ => Vec::new(),
        }
    }

    fn retransmit(&self) -> Vec<TxAction> {
        vec![
            TxAction::Send(SipMessage::Request(self.request.clone())),
            TxAction::StartTimer {
                id: TimerId::E,
                after: self.timer_e,
            },
        ]
    }

    fn enter_completed(&mut self, resp: &Response) -> Vec<TxAction> {
        if self.rel.is_reliable() {
            // Timer K is zero: terminate immediately.
            self.state = State::Terminated;
            return vec![
                TxAction::DeliverResponse(resp.clone()),
                TxAction::Terminated,
            ];
        }
        self.state = State::Completed;
        vec![
            TxAction::StopTimer(TimerId::E),
            TxAction::StopTimer(TimerId::F),
            TxAction::DeliverResponse(resp.clone()),
            TxAction::StartTimer {
                id: TimerId::K,
                after: self.timers.k(self.rel),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        let raw = "OPTIONS sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-opt\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>\r\n\
             Call-ID: call-opt\r\n\
             CSeq: 4 OPTIONS\r\n\
             Content-Length: 0\r\n\r\n";
        Request::try_from(raw.as_bytes()).unwrap()
    }

    fn response(code: u16) -> Response {
        let raw = format!(
            "SIP/2.0 {code} X\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-opt\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>;tag=bob\r\n\
             Call-ID: call-opt\r\n\
             CSeq: 4 OPTIONS\r\n\
             Content-Length: 0\r\n\r\n"
        );
        Response::try_from(raw.as_bytes()).unwrap()
    }

    #[test]
    fn start_sends_request_and_arms_e_and_f_on_udp() {
        let (tx, actions) =
            ClientNonInvite::start(request(), Timers::default(), Reliability::Unreliable);
        assert_eq!(tx.state(), State::Trying);
        assert!(matches!(actions[0], TxAction::Send(_)));
        assert!(matches!(
            actions[1],
            TxAction::StartTimer { id: TimerId::E, .. }
        ));
        assert!(matches!(
            actions[2],
            TxAction::StartTimer { id: TimerId::F, .. }
        ));
    }

    #[test]
    fn timer_e_backs_off_capped_at_t2() {
        let timers = Timers::default();
        let (mut tx, _) = ClientNonInvite::start(request(), timers, Reliability::Unreliable);
        // T1=500ms → 1s → 2s → 4s(=T2) → stays 4s.
        let expected = [
            timers.t1 * 2,
            timers.t1 * 4,
            timers.t2, // capped
            timers.t2,
        ];
        for want in expected {
            let out = tx.on_timer(TimerId::E);
            match out[1] {
                TxAction::StartTimer {
                    id: TimerId::E,
                    after,
                } => assert_eq!(after, want),
                _ => panic!("expected Timer E reschedule"),
            }
        }
    }

    #[test]
    fn provisional_enters_proceeding_and_pins_e_to_t2() {
        let timers = Timers::default();
        let (mut tx, _) = ClientNonInvite::start(request(), timers, Reliability::Unreliable);
        let out = tx.on_response(&response(100));
        assert_eq!(tx.state(), State::Proceeding);
        assert!(matches!(out[0], TxAction::DeliverResponse(_)));
        // Timer E in Proceeding fires at exactly T2 regardless of prior backoff.
        match tx.on_timer(TimerId::E)[1] {
            TxAction::StartTimer {
                id: TimerId::E,
                after,
            } => assert_eq!(after, timers.t2),
            _ => panic!("expected Timer E reschedule"),
        }
    }

    #[test]
    fn final_response_completes_and_arms_k_on_udp() {
        let (mut tx, _) =
            ClientNonInvite::start(request(), Timers::default(), Reliability::Unreliable);
        let out = tx.on_response(&response(200));
        assert_eq!(tx.state(), State::Completed);
        assert!(out.contains(&TxAction::StopTimer(TimerId::E)));
        assert!(out.contains(&TxAction::StopTimer(TimerId::F)));
        assert!(out
            .iter()
            .any(|a| matches!(a, TxAction::DeliverResponse(_))));
        assert!(matches!(
            out.last(),
            Some(TxAction::StartTimer { id: TimerId::K, .. })
        ));
    }

    #[test]
    fn final_response_terminates_immediately_on_reliable() {
        let (mut tx, _) =
            ClientNonInvite::start(request(), Timers::default(), Reliability::Reliable);
        let out = tx.on_response(&response(404));
        assert_eq!(tx.state(), State::Terminated);
        assert!(matches!(out[0], TxAction::DeliverResponse(_)));
        assert_eq!(out[1], TxAction::Terminated);
    }

    #[test]
    fn retransmitted_final_is_absorbed() {
        let (mut tx, _) =
            ClientNonInvite::start(request(), Timers::default(), Reliability::Unreliable);
        tx.on_response(&response(200));
        assert!(tx.on_response(&response(200)).is_empty());
    }

    #[test]
    fn timer_f_times_out() {
        let (mut tx, _) =
            ClientNonInvite::start(request(), Timers::default(), Reliability::Unreliable);
        let out = tx.on_timer(TimerId::F);
        assert_eq!(out, vec![TxAction::TimedOut, TxAction::Terminated]);
    }

    #[test]
    fn timer_k_terminates_from_completed() {
        let (mut tx, _) =
            ClientNonInvite::start(request(), Timers::default(), Reliability::Unreliable);
        tx.on_response(&response(200));
        assert_eq!(tx.on_timer(TimerId::K), vec![TxAction::Terminated]);
        assert_eq!(tx.state(), State::Terminated);
    }
}
