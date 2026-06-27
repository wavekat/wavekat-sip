//! Server non-INVITE transaction — RFC 3261 §17.2.2.
//!
//! Handles an inbound BYE, INFO, OPTIONS or CANCEL: relays the TU's
//! responses and replays the last one on a retransmitted request.
//!
//! ```text
//!     Trying ----- request retransmit: absorb (nothing sent yet)
//!        |   \     1xx from TU → send, Proceeding
//!        |    \ 200-699 from TU → send, Completed
//!        v
//!     Proceeding - request retransmit: resend last provisional
//!        |          1xx from TU: send
//!        |          200-699 from TU → send, Completed
//!        v
//!     Completed -- request retransmit: resend final
//!        |          Timer J: terminate
//!        v
//!     Terminated
//! ```

use super::{Reliability, TimerId, Timers, TxAction};
use rsip::{Request, Response, SipMessage};

/// State of a server non-INVITE transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    /// Request received; the TU has not responded yet.
    Trying,
    /// A provisional response was sent.
    Proceeding,
    /// A final response was sent; absorbing retransmissions (Timer J).
    Completed,
    /// Done.
    Terminated,
}

/// A server non-INVITE transaction state machine.
pub(crate) struct ServerNonInvite {
    state: State,
    timers: Timers,
    rel: Reliability,
    last_response: Option<Response>,
}

impl ServerNonInvite {
    /// Construct from the received request and hand it up to the TU.
    pub(crate) fn start(
        request: &Request,
        timers: Timers,
        rel: Reliability,
    ) -> (Self, Vec<TxAction>) {
        let tx = Self {
            state: State::Trying,
            timers,
            rel,
            last_response: None,
        };
        (tx, vec![TxAction::DeliverRequest(request.clone())])
    }

    pub(crate) fn state(&self) -> State {
        self.state
    }

    /// The TU wants to send `resp` for this transaction.
    pub(crate) fn send_response(&mut self, resp: Response) -> Vec<TxAction> {
        if matches!(self.state, State::Completed | State::Terminated) {
            return Vec::new();
        }
        self.last_response = Some(resp.clone());
        let code = resp.status_code().code();
        if code < 200 {
            self.state = State::Proceeding;
            vec![TxAction::Send(SipMessage::Response(resp))]
        } else {
            let send = TxAction::Send(SipMessage::Response(resp));
            if self.rel.is_reliable() {
                // Timer J is zero: terminate immediately after sending.
                self.state = State::Terminated;
                vec![send, TxAction::Terminated]
            } else {
                self.state = State::Completed;
                vec![
                    send,
                    TxAction::StartTimer {
                        id: TimerId::J,
                        after: self.timers.j(self.rel),
                    },
                ]
            }
        }
    }

    /// A retransmitted request was received for this transaction.
    pub(crate) fn on_request(&mut self, _req: &Request) -> Vec<TxAction> {
        match self.state {
            // Nothing sent yet — there is nothing to replay.
            State::Trying => Vec::new(),
            State::Proceeding | State::Completed => match &self.last_response {
                Some(resp) => vec![TxAction::Send(SipMessage::Response(resp.clone()))],
                None => Vec::new(),
            },
            State::Terminated => Vec::new(),
        }
    }

    /// Feed a fired timer.
    pub(crate) fn on_timer(&mut self, id: TimerId) -> Vec<TxAction> {
        match (self.state, id) {
            (State::Completed, TimerId::J) => {
                self.state = State::Terminated;
                vec![TxAction::Terminated]
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        let raw = "BYE sip:bob@example.com SIP/2.0\r\n\
             Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-bye\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>;tag=bob\r\n\
             Call-ID: call-bye\r\n\
             CSeq: 9 BYE\r\n\
             Content-Length: 0\r\n\r\n";
        Request::try_from(raw.as_bytes()).unwrap()
    }

    fn response(code: u16) -> Response {
        let raw = format!(
            "SIP/2.0 {code} X\r\n\
             Via: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-bye\r\n\
             From: <sip:alice@example.com>;tag=alice\r\n\
             To: <sip:bob@example.com>;tag=bob\r\n\
             Call-ID: call-bye\r\n\
             CSeq: 9 BYE\r\n\
             Content-Length: 0\r\n\r\n"
        );
        Response::try_from(raw.as_bytes()).unwrap()
    }

    #[test]
    fn start_delivers_request() {
        let (tx, actions) =
            ServerNonInvite::start(&request(), Timers::default(), Reliability::Unreliable);
        assert_eq!(tx.state(), State::Trying);
        assert!(matches!(actions[0], TxAction::DeliverRequest(_)));
    }

    #[test]
    fn retransmit_in_trying_is_absorbed() {
        let (mut tx, _) =
            ServerNonInvite::start(&request(), Timers::default(), Reliability::Unreliable);
        assert!(tx.on_request(&request()).is_empty());
    }

    #[test]
    fn provisional_then_replays_on_retransmit() {
        let (mut tx, _) =
            ServerNonInvite::start(&request(), Timers::default(), Reliability::Unreliable);
        let out = tx.send_response(response(100));
        assert_eq!(tx.state(), State::Proceeding);
        assert!(matches!(out[0], TxAction::Send(_)));
        assert_eq!(
            tx.on_request(&request()),
            vec![TxAction::Send(SipMessage::Response(response(100)))]
        );
    }

    #[test]
    fn final_completes_and_arms_j_on_udp() {
        let (mut tx, _) =
            ServerNonInvite::start(&request(), Timers::default(), Reliability::Unreliable);
        let out = tx.send_response(response(200));
        assert_eq!(tx.state(), State::Completed);
        assert!(matches!(out[0], TxAction::Send(_)));
        assert!(matches!(
            out[1],
            TxAction::StartTimer { id: TimerId::J, .. }
        ));
        // Retransmitted request replays the final.
        assert_eq!(
            tx.on_request(&request()),
            vec![TxAction::Send(SipMessage::Response(response(200)))]
        );
    }

    #[test]
    fn final_terminates_immediately_on_reliable() {
        let (mut tx, _) =
            ServerNonInvite::start(&request(), Timers::default(), Reliability::Reliable);
        let out = tx.send_response(response(404));
        assert_eq!(tx.state(), State::Terminated);
        assert!(matches!(out[0], TxAction::Send(_)));
        assert_eq!(out[1], TxAction::Terminated);
    }

    #[test]
    fn timer_j_terminates_from_completed() {
        let (mut tx, _) =
            ServerNonInvite::start(&request(), Timers::default(), Reliability::Unreliable);
        tx.send_response(response(200));
        assert_eq!(tx.on_timer(TimerId::J), vec![TxAction::Terminated]);
        assert_eq!(tx.state(), State::Terminated);
    }
}
