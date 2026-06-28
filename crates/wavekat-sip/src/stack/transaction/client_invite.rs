//! Client INVITE transaction — RFC 3261 §17.1.1.
//!
//! ```text
//!                    |INVITE sent
//!     Calling -------+--- Timer A: resend, A = 2·A
//!        |  \        +--- Timer B: inform TU (timeout)
//!    1xx |   \ 2xx → deliver, terminate
//!        v    \ 300-699 → ACK, deliver, Completed
//!    Proceeding ----- 2xx → deliver, terminate
//!        |            300-699 → ACK, deliver, Completed
//!        v
//!    Completed --- retransmitted 300-699: resend ACK
//!        |         Timer D: terminate
//!        v
//!    Terminated
//! ```
//!
//! The ACK for a **non-2xx** final response is built and sent *inside* this
//! transaction (it shares the INVITE's branch). The ACK for a **2xx** is the
//! TU/dialog's job — a separate transaction — so on a 2xx this machine just
//! hands the response up and terminates.

use super::{build_non_2xx_ack, Reliability, TimerId, Timers, TxAction};
use rsip::{Request, Response, SipMessage};

/// State of a client INVITE transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    /// INVITE sent, no response yet; retransmitting on Timer A.
    Calling,
    /// A provisional response arrived; waiting for the final.
    Proceeding,
    /// A non-2xx final arrived; absorbing its retransmissions (Timer D).
    Completed,
    /// Done; the runner may drop the transaction.
    Terminated,
}

/// A client INVITE transaction state machine.
pub(crate) struct ClientInvite {
    state: State,
    timers: Timers,
    rel: Reliability,
    /// The original INVITE — kept to retransmit it and to build the non-2xx ACK.
    invite: Request,
    /// Current Timer A interval; doubles on each retransmission.
    timer_a: std::time::Duration,
}

impl ClientInvite {
    /// Begin the transaction: send the INVITE and arm Timers A (unreliable
    /// only) and B.
    pub(crate) fn start(
        invite: Request,
        timers: Timers,
        rel: Reliability,
    ) -> (Self, Vec<TxAction>) {
        let mut actions = vec![TxAction::Send(SipMessage::Request(invite.clone()))];
        if !rel.is_reliable() {
            actions.push(TxAction::StartTimer {
                id: TimerId::A,
                after: timers.t1,
            });
        }
        actions.push(TxAction::StartTimer {
            id: TimerId::B,
            after: timers.timeout(),
        });
        let tx = Self {
            state: State::Calling,
            timers,
            rel,
            invite,
            timer_a: timers.t1,
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
            State::Calling | State::Proceeding => {
                if code < 200 {
                    self.on_provisional(resp)
                } else if code < 300 {
                    // 2xx: hand up; the TU sends the ACK and owns the dialog.
                    self.state = State::Terminated;
                    vec![
                        TxAction::DeliverResponse(resp.clone()),
                        TxAction::Terminated,
                    ]
                } else {
                    self.on_final_failure(resp)
                }
            }
            // Retransmitted non-2xx final: resend the ACK, do not re-deliver.
            State::Completed if code >= 300 => match build_non_2xx_ack(&self.invite, resp) {
                Some(ack) => vec![TxAction::Send(SipMessage::Request(ack))],
                None => Vec::new(),
            },
            State::Completed | State::Terminated => Vec::new(),
        }
    }

    /// Feed a fired timer.
    pub(crate) fn on_timer(&mut self, id: TimerId) -> Vec<TxAction> {
        match (self.state, id) {
            // Retransmit the INVITE, doubling the interval (unreliable only).
            (State::Calling, TimerId::A) => {
                self.timer_a *= 2;
                vec![
                    TxAction::Send(SipMessage::Request(self.invite.clone())),
                    TxAction::StartTimer {
                        id: TimerId::A,
                        after: self.timer_a,
                    },
                ]
            }
            // No response in time.
            (State::Calling, TimerId::B) => {
                self.state = State::Terminated;
                vec![TxAction::TimedOut, TxAction::Terminated]
            }
            // Done absorbing retransmitted finals.
            (State::Completed, TimerId::D) => {
                self.state = State::Terminated;
                vec![TxAction::Terminated]
            }
            _ => Vec::new(),
        }
    }

    fn on_provisional(&mut self, resp: &Response) -> Vec<TxAction> {
        if self.state == State::Calling {
            // Leave Calling: stop retransmitting (A) and the timeout (B); a
            // call may legitimately stay in Proceeding (ringing) for minutes.
            self.state = State::Proceeding;
            vec![
                TxAction::StopTimer(TimerId::A),
                TxAction::StopTimer(TimerId::B),
                TxAction::DeliverResponse(resp.clone()),
            ]
        } else {
            vec![TxAction::DeliverResponse(resp.clone())]
        }
    }

    fn on_final_failure(&mut self, resp: &Response) -> Vec<TxAction> {
        let Some(ack) = build_non_2xx_ack(&self.invite, resp) else {
            return Vec::new();
        };
        let mut actions = vec![
            TxAction::Send(SipMessage::Request(ack)),
            TxAction::DeliverResponse(resp.clone()),
        ];
        if self.rel.is_reliable() {
            // Timer D is zero on reliable transports: terminate at once.
            self.state = State::Terminated;
            actions.push(TxAction::Terminated);
        } else {
            self.state = State::Completed;
            actions.push(TxAction::StartTimer {
                id: TimerId::D,
                after: self.timers.d(self.rel),
            });
        }
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsip::Method;

    fn invite() -> Request {
        let raw = "INVITE sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-inv\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>\r\n\
             Call-ID: call-abc\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Length: 0\r\n\r\n";
        Request::try_from(raw.as_bytes()).unwrap()
    }

    fn response(code: u16) -> Response {
        let raw = format!(
            "SIP/2.0 {code} X\r\n\
             Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-inv\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>;tag=bob\r\n\
             Call-ID: call-abc\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Length: 0\r\n\r\n"
        );
        Response::try_from(raw.as_bytes()).unwrap()
    }

    #[test]
    fn start_sends_invite_and_arms_a_and_b_on_udp() {
        let (tx, actions) =
            ClientInvite::start(invite(), Timers::default(), Reliability::Unreliable);
        assert_eq!(tx.state(), State::Calling);
        assert!(matches!(actions[0], TxAction::Send(_)));
        assert!(matches!(
            actions[1],
            TxAction::StartTimer { id: TimerId::A, .. }
        ));
        assert!(matches!(
            actions[2],
            TxAction::StartTimer { id: TimerId::B, .. }
        ));
    }

    #[test]
    fn start_skips_timer_a_on_reliable_transport() {
        let (_tx, actions) =
            ClientInvite::start(invite(), Timers::default(), Reliability::Reliable);
        assert!(!actions
            .iter()
            .any(|a| matches!(a, TxAction::StartTimer { id: TimerId::A, .. })));
        assert!(actions
            .iter()
            .any(|a| matches!(a, TxAction::StartTimer { id: TimerId::B, .. })));
    }

    #[test]
    fn timer_a_retransmits_and_doubles() {
        let (mut tx, _) = ClientInvite::start(invite(), Timers::default(), Reliability::Unreliable);
        let a = tx.on_timer(TimerId::A);
        assert!(matches!(a[0], TxAction::Send(_)));
        match a[1] {
            TxAction::StartTimer {
                id: TimerId::A,
                after,
            } => assert_eq!(after, Timers::default().t1 * 2),
            _ => panic!("expected Timer A reschedule"),
        }
        // Second fire doubles again → 4·T1.
        let a2 = tx.on_timer(TimerId::A);
        match a2[1] {
            TxAction::StartTimer {
                id: TimerId::A,
                after,
            } => assert_eq!(after, Timers::default().t1 * 4),
            _ => panic!("expected Timer A reschedule"),
        }
    }

    #[test]
    fn timer_b_times_out_the_transaction() {
        let (mut tx, _) = ClientInvite::start(invite(), Timers::default(), Reliability::Unreliable);
        let out = tx.on_timer(TimerId::B);
        assert_eq!(out, vec![TxAction::TimedOut, TxAction::Terminated]);
        assert_eq!(tx.state(), State::Terminated);
    }

    #[test]
    fn provisional_moves_to_proceeding_and_stops_retransmits() {
        let (mut tx, _) = ClientInvite::start(invite(), Timers::default(), Reliability::Unreliable);
        let out = tx.on_response(&response(180));
        assert_eq!(tx.state(), State::Proceeding);
        assert!(out.contains(&TxAction::StopTimer(TimerId::A)));
        assert!(out.contains(&TxAction::StopTimer(TimerId::B)));
        assert!(matches!(out.last(), Some(TxAction::DeliverResponse(_))));
        // A retransmit timer firing in Proceeding is ignored.
        assert!(tx.on_timer(TimerId::A).is_empty());
    }

    #[test]
    fn success_delivers_and_terminates_without_acking() {
        let (mut tx, _) = ClientInvite::start(invite(), Timers::default(), Reliability::Unreliable);
        let out = tx.on_response(&response(200));
        assert_eq!(tx.state(), State::Terminated);
        assert!(matches!(out[0], TxAction::DeliverResponse(_)));
        assert_eq!(out[1], TxAction::Terminated);
        // No ACK is sent by the transaction for a 2xx.
        assert!(!out.iter().any(|a| matches!(a, TxAction::Send(_))));
    }

    #[test]
    fn non_2xx_final_acks_delivers_and_enters_completed_on_udp() {
        let (mut tx, _) = ClientInvite::start(invite(), Timers::default(), Reliability::Unreliable);
        let out = tx.on_response(&response(486));
        assert_eq!(tx.state(), State::Completed);
        // ACK first, then deliver, then arm Timer D.
        match &out[0] {
            TxAction::Send(SipMessage::Request(r)) => assert_eq!(*r.method(), Method::Ack),
            other => panic!("expected ACK send, got {other:?}"),
        }
        assert!(matches!(out[1], TxAction::DeliverResponse(_)));
        assert!(matches!(
            out[2],
            TxAction::StartTimer { id: TimerId::D, .. }
        ));
    }

    #[test]
    fn retransmitted_non_2xx_resends_ack_only() {
        let (mut tx, _) = ClientInvite::start(invite(), Timers::default(), Reliability::Unreliable);
        tx.on_response(&response(486));
        let out = tx.on_response(&response(486));
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], TxAction::Send(SipMessage::Request(_))));
    }

    #[test]
    fn non_2xx_final_terminates_immediately_on_reliable() {
        let (mut tx, _) = ClientInvite::start(invite(), Timers::default(), Reliability::Reliable);
        let out = tx.on_response(&response(500));
        assert_eq!(tx.state(), State::Terminated);
        assert!(matches!(out[0], TxAction::Send(_)));
        assert!(matches!(out[1], TxAction::DeliverResponse(_)));
        assert_eq!(out[2], TxAction::Terminated);
    }

    #[test]
    fn timer_d_terminates_from_completed() {
        let (mut tx, _) = ClientInvite::start(invite(), Timers::default(), Reliability::Unreliable);
        tx.on_response(&response(404));
        let out = tx.on_timer(TimerId::D);
        assert_eq!(out, vec![TxAction::Terminated]);
        assert_eq!(tx.state(), State::Terminated);
    }
}
