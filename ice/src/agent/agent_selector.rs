use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};
use stun::attributes::*;
use stun::fingerprint::*;
use stun::integrity::*;
use stun::message::*;
use stun::textattrs::*;

use crate::agent::agent_internal::*;
use crate::candidate::*;
use crate::control::*;
use crate::priority::*;
use crate::use_candidate::*;

trait ControllingSelector {
    fn start(&mut self);
    fn contact_candidates(&mut self);
    fn ping_candidate(&mut self, local: &Rc<dyn Candidate>, remote: &Rc<dyn Candidate>);
    fn handle_success_response(
        &mut self,
        m: &Message,
        local: &Rc<dyn Candidate>,
        remote: &Rc<dyn Candidate>,
        remote_addr: SocketAddr,
    );
    fn handle_binding_request(
        &mut self,
        m: &Message,
        local: &Rc<dyn Candidate>,
        remote: &Rc<dyn Candidate>,
    );
}

trait ControlledSelector {
    fn start(&mut self);
    fn contact_candidates(&mut self);
    fn ping_candidate(&mut self, local: &Rc<dyn Candidate>, remote: &Rc<dyn Candidate>);
    fn handle_success_response(
        &mut self,
        m: &Message,
        local: &Rc<dyn Candidate>,
        remote: &Rc<dyn Candidate>,
        remote_addr: SocketAddr,
    );
    fn handle_binding_request(
        &mut self,
        m: &Message,
        local: &Rc<dyn Candidate>,
        remote: &Rc<dyn Candidate>,
    );
}

impl AgentInternal {
    fn is_nominatable(&self, c: &Rc<dyn Candidate>) -> bool {
        let start_time = self.start_time;
        match c.candidate_type() {
            CandidateType::Host => {
                Instant::now()
                    .checked_duration_since(start_time)
                    .unwrap_or_else(|| Duration::from_secs(0))
                    .as_nanos()
                    > self.host_acceptance_min_wait.as_nanos()
            }
            _ => {
                log::error!(
                    "is_nominatable invalid candidate type {}",
                    c.candidate_type()
                );
                false
            }
        }
    }

    fn nominate_pair(&mut self) {
        let result = {
            if let Some(pair) = &self.nominated_pair {
                // The controlling agent MUST include the USE-CANDIDATE attribute in
                // order to nominate a candidate pair (Section 8.1.1).  The controlled
                // agent MUST NOT include the USE-CANDIDATE attribute in a Binding
                // request.

                let (msg, result) = {
                    let ufrag_pwd = &self.ufrag_pwd;
                    let username =
                        ufrag_pwd.remote_ufrag.clone() + ":" + ufrag_pwd.local_ufrag.as_str();
                    let mut msg = Message::new();
                    let result = msg.build(&[
                        Box::new(BINDING_REQUEST),
                        Box::new(TransactionId::new()),
                        Box::new(Username::new(ATTR_USERNAME, username)),
                        Box::<UseCandidateAttr>::default(),
                        Box::new(AttrControlling(self.tie_breaker)),
                        Box::new(PriorityAttr(pair.local.priority())),
                        Box::new(MessageIntegrity::new_short_term_integrity(
                            ufrag_pwd.remote_pwd.clone(),
                        )),
                        Box::new(FINGERPRINT),
                    ]);
                    (msg, result)
                };

                if let Err(err) = result {
                    log::error!("{}", err);
                    None
                } else {
                    log::trace!(
                        "ping STUN (nominate candidate pair from {} to {}",
                        pair.local,
                        pair.remote
                    );
                    let local = pair.local.clone();
                    let remote = pair.remote.clone();
                    Some((msg, local, remote))
                }
            } else {
                None
            }
        };

        if let Some((msg, local, remote)) = result {
            self.send_binding_request(&msg, &local, &remote);
        }
    }

    pub(crate) fn start(&mut self) {
        if self.is_controlling {
            ControllingSelector::start(self);
        } else {
            ControlledSelector::start(self);
        }
    }

    pub(crate) fn contact_candidates(&mut self) {
        if self.is_controlling {
            ControllingSelector::contact_candidates(self);
        } else {
            ControlledSelector::contact_candidates(self);
        }
    }

    pub(crate) fn ping_candidate(&mut self, local: &Rc<dyn Candidate>, remote: &Rc<dyn Candidate>) {
        if self.is_controlling {
            ControllingSelector::ping_candidate(self, local, remote);
        } else {
            ControlledSelector::ping_candidate(self, local, remote);
        }
    }

    pub(crate) fn handle_success_response(
        &mut self,
        m: &Message,
        local: &Rc<dyn Candidate>,
        remote: &Rc<dyn Candidate>,
        remote_addr: SocketAddr,
    ) {
        if self.is_controlling {
            ControllingSelector::handle_success_response(self, m, local, remote, remote_addr);
        } else {
            ControlledSelector::handle_success_response(self, m, local, remote, remote_addr);
        }
    }

    pub(crate) fn handle_binding_request(
        &mut self,
        m: &Message,
        local: &Rc<dyn Candidate>,
        remote: &Rc<dyn Candidate>,
    ) {
        if self.is_controlling {
            ControllingSelector::handle_binding_request(self, m, local, remote);
        } else {
            ControlledSelector::handle_binding_request(self, m, local, remote);
        }
    }
}

impl ControllingSelector for AgentInternal {
    fn start(&mut self) {
        self.nominated_pair = None;
        self.start_time = Instant::now();
    }

    fn contact_candidates(&mut self) {
        // A lite selector should not contact candidates
        if self.lite {
            // This only happens if both peers are lite. See RFC 8445 S6.1.1 and S6.2
            log::trace!("now falling back to full agent");
        }

        let nominated_pair_is_some = self.nominated_pair.is_some();

        if self.agent_conn.get_selected_pair().is_some() {
            if self.validate_selected_pair() {
                log::trace!("[{}]: checking keepalive", self.get_name());
                self.check_keepalive();
            }
        } else if nominated_pair_is_some {
            self.nominate_pair();
        } else {
            let has_nominated_pair =
                if let Some(p) = self.agent_conn.get_best_valid_candidate_pair() {
                    self.is_nominatable(&p.local) && self.is_nominatable(&p.remote)
                } else {
                    false
                };

            if has_nominated_pair {
                if let Some(p) = self.agent_conn.get_best_valid_candidate_pair() {
                    log::trace!(
                        "Nominatable pair found, nominating ({}, {})",
                        p.local.to_string(),
                        p.remote.to_string()
                    );
                    p.nominated = true;
                    self.nominated_pair = Some(p);
                }

                self.nominate_pair();
            } else {
                self.ping_all_candidates();
            }
        }
    }

    fn ping_candidate(&mut self, local: &Rc<dyn Candidate>, remote: &Rc<dyn Candidate>) {
        let (msg, result) = {
            let ufrag_pwd = &self.ufrag_pwd;
            let username = ufrag_pwd.remote_ufrag.clone() + ":" + ufrag_pwd.local_ufrag.as_str();
            let mut msg = Message::new();
            let result = msg.build(&[
                Box::new(BINDING_REQUEST),
                Box::new(TransactionId::new()),
                Box::new(Username::new(ATTR_USERNAME, username)),
                Box::new(AttrControlling(self.tie_breaker)),
                Box::new(PriorityAttr(local.priority())),
                Box::new(MessageIntegrity::new_short_term_integrity(
                    ufrag_pwd.remote_pwd.clone(),
                )),
                Box::new(FINGERPRINT),
            ]);
            (msg, result)
        };

        if let Err(err) = result {
            log::error!("{}", err);
        } else {
            self.send_binding_request(&msg, local, remote);
        }
    }

    fn handle_success_response(
        &mut self,
        m: &Message,
        local: &Rc<dyn Candidate>,
        remote: &Rc<dyn Candidate>,
        remote_addr: SocketAddr,
    ) {
        if let Some(pending_request) = self.handle_inbound_binding_success(m.transaction_id) {
            let transaction_addr = pending_request.destination;

            // Assert that NAT is not symmetric
            // https://tools.ietf.org/html/rfc8445#section-7.2.5.2.1
            if transaction_addr != remote_addr {
                log::debug!("discard message: transaction source and destination does not match expected({}), actual({})", transaction_addr, remote);
                return;
            }

            log::trace!(
                "inbound STUN (SuccessResponse) from {} to {}",
                remote,
                local
            );
            let selected_pair_is_none = self.agent_conn.get_selected_pair().is_none();

            if let Some(p) = self.find_pair(local, remote) {
                p.state = CandidatePairState::Succeeded;
                log::trace!(
                    "Found valid candidate pair: {}, p.state: {}, isUseCandidate: {}, {}",
                    p,
                    p.state,
                    pending_request.is_use_candidate,
                    selected_pair_is_none
                );
                if pending_request.is_use_candidate && selected_pair_is_none {
                    self.set_selected_pair(Some(Rc::clone(&p)));
                }
            } else {
                // This shouldn't happen
                log::error!("Success response from invalid candidate pair");
            }
        } else {
            log::warn!(
                "discard message from ({}), unknown TransactionID 0x{:?}",
                remote,
                m.transaction_id
            );
        }
    }

    fn handle_binding_request(
        &mut self,
        m: &Message,
        local: &Rc<dyn Candidate>,
        remote: &Rc<dyn Candidate>,
    ) {
        self.send_binding_success(m, local, remote);
        log::trace!("controllingSelector: sendBindingSuccess");

        if let Some(p) = self.find_pair(local, remote) {
            let nominated_pair_is_none = self.nominated_pair.is_none();

            log::trace!(
                "controllingSelector: after findPair {}, p.state: {}, {}",
                p,
                p.state,
                nominated_pair_is_none,
                //self.agent_conn.get_selected_pair().await.is_none() //, {}
            );
            if p.state == CandidatePairState::Succeeded
                && nominated_pair_is_none
                && self.agent_conn.get_selected_pair().is_none()
            {
                if let Some(best_pair) = self.agent_conn.get_best_available_candidate_pair() {
                    log::trace!(
                        "controllingSelector: getBestAvailableCandidatePair {}",
                        best_pair
                    );
                    if best_pair == p
                        && self.is_nominatable(&p.local)
                        && self.is_nominatable(&p.remote)
                    {
                        log::trace!("The candidate ({}, {}) is the best candidate available, marking it as nominated",
                            p.local, p.remote);
                        self.nominated_pair = Some(p);
                        self.nominate_pair();
                    }
                } else {
                    log::trace!("No best pair available");
                }
            }
        } else {
            log::trace!("controllingSelector: addPair");
            self.add_pair(local.clone(), remote.clone());
        }
    }
}

impl ControlledSelector for AgentInternal {
    fn start(&mut self) {}

    fn contact_candidates(&mut self) {
        // A lite selector should not contact candidates
        if self.lite {
            self.validate_selected_pair();
        } else if self.agent_conn.get_selected_pair().is_some() {
            if self.validate_selected_pair() {
                log::trace!("[{}]: checking keepalive", self.get_name());
                self.check_keepalive();
            }
        } else {
            self.ping_all_candidates();
        }
    }

    fn ping_candidate(&mut self, local: &Rc<dyn Candidate>, remote: &Rc<dyn Candidate>) {
        let (msg, result) = {
            let ufrag_pwd = &self.ufrag_pwd;
            let username = ufrag_pwd.remote_ufrag.clone() + ":" + ufrag_pwd.local_ufrag.as_str();
            let mut msg = Message::new();
            let result = msg.build(&[
                Box::new(BINDING_REQUEST),
                Box::new(TransactionId::new()),
                Box::new(Username::new(ATTR_USERNAME, username)),
                Box::new(AttrControlled(self.tie_breaker)),
                Box::new(PriorityAttr(local.priority())),
                Box::new(MessageIntegrity::new_short_term_integrity(
                    ufrag_pwd.remote_pwd.clone(),
                )),
                Box::new(FINGERPRINT),
            ]);
            (msg, result)
        };

        if let Err(err) = result {
            log::error!("{}", err);
        } else {
            self.send_binding_request(&msg, local, remote);
        }
    }

    fn handle_success_response(
        &mut self,
        m: &Message,
        local: &Rc<dyn Candidate>,
        remote: &Rc<dyn Candidate>,
        remote_addr: SocketAddr,
    ) {
        // https://tools.ietf.org/html/rfc8445#section-7.3.1.5
        // If the controlled agent does not accept the request from the
        // controlling agent, the controlled agent MUST reject the nomination
        // request with an appropriate error code response (e.g., 400)
        // [RFC5389].

        if let Some(pending_request) = self.handle_inbound_binding_success(m.transaction_id) {
            let transaction_addr = pending_request.destination;

            // Assert that NAT is not symmetric
            // https://tools.ietf.org/html/rfc8445#section-7.2.5.2.1
            if transaction_addr != remote_addr {
                log::debug!("discard message: transaction source and destination does not match expected({}), actual({})", transaction_addr, remote);
                return;
            }

            log::trace!(
                "inbound STUN (SuccessResponse) from {} to {}",
                remote,
                local
            );

            if let Some(p) = self.find_pair(local, remote) {
                p.state = CandidatePairState::Succeeded;
                log::trace!("Found valid candidate pair: {}", p);
            } else {
                // This shouldn't happen
                log::error!("Success response from invalid candidate pair");
            }
        } else {
            log::warn!(
                "discard message from ({}), unknown TransactionID 0x{:?}",
                remote,
                m.transaction_id
            );
        }
    }

    fn handle_binding_request(
        &mut self,
        m: &Message,
        local: &Rc<dyn Candidate>,
        remote: &Rc<dyn Candidate>,
    ) {
        if self.find_pair(local, remote).is_none() {
            self.add_pair(local.clone(), remote.clone());
        }

        if let Some(p) = self.find_pair(local, remote) {
            let use_candidate = m.contains(ATTR_USE_CANDIDATE);
            if use_candidate {
                // https://tools.ietf.org/html/rfc8445#section-7.3.1.5

                if p.state == CandidatePairState::Succeeded {
                    // If the state of this pair is Succeeded, it means that the check
                    // previously sent by this pair produced a successful response and
                    // generated a valid pair (Section 7.2.5.3.2).  The agent sets the
                    // nominated flag value of the valid pair to true.
                    if self.agent_conn.get_selected_pair().is_none() {
                        self.set_selected_pair(Some(Rc::clone(&p)));
                    }
                    self.send_binding_success(m, local, remote);
                } else {
                    // If the received Binding request triggered a new check to be
                    // enqueued in the triggered-check queue (Section 7.3.1.4), once the
                    // check is sent and if it generates a successful response, and
                    // generates a valid pair, the agent sets the nominated flag of the
                    // pair to true.  If the request fails (Section 7.2.5.2), the agent
                    // MUST remove the candidate pair from the valid list, set the
                    // candidate pair state to Failed, and set the checklist state to
                    // Failed.
                    self.ping_candidate(local, remote);
                }
            } else {
                self.send_binding_success(m, local, remote);
                self.ping_candidate(local, remote);
            }
        }
    }
}