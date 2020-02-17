// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// http://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::id::Id;
use crate::message_state::MessageState;
use crate::messages::GossipType;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use std::{cmp, mem};

/// Gossip protocol handler.
pub struct Gossip {
    messages: BTreeMap<Vec<u8>, MessageState>,
    network_size: f64,
    // When in state B, if our counter for a message is incremented to this value, the state
    // transitions to C.  Specified in the paper as `O(ln ln n)`.
    counter_max: u8,
    // The maximum number of rounds to remain in state C for a given message.  Specified in the
    // paper as `O(ln ln n)`.
    max_c_rounds: u8,
    // The maximum total number of rounds for a message to remain in states B or C.  This is a
    // failsafe to allow the definite termination of a message being propagated.  Specified in the
    // paper as `O(ln n)`.
    max_rounds: u8,
    // All peers with which we communicated during this round.
    peers_in_this_round: BTreeSet<Id>,
}

impl Gossip {
    pub fn new() -> Self {
        Gossip {
            messages: BTreeMap::new(),
            network_size: 1.0,
            counter_max: 0,
            max_c_rounds: 0,
            max_rounds: 0,
            peers_in_this_round: BTreeSet::new(),
        }
    }

    pub fn add_peer(&mut self) {
        self.network_size += 1.0;
        self.counter_max = cmp::max(1, self.network_size.ln().ln().ceil() as u8);
        self.max_c_rounds = cmp::max(1, self.network_size.ln().ln().ceil() as u8);
        self.max_rounds = cmp::max(1, self.network_size.ln().ceil() as u8);
    }

    pub fn messages(&self) -> Vec<Vec<u8>> {
        self.messages.keys().cloned().collect()
    }

    /// Start gossiping a new message from this node.
    pub fn new_message(&mut self, msg: Vec<u8>) {
        if self.messages.insert(msg, MessageState::new()).is_some() {
            error!("New messages should be unique.");
        }
    }

    /// Trigger the end of this round.  Returns a list of Push RPCs to be sent to a single random
    /// peer during this new round.
    pub fn next_round(&mut self) -> Vec<GossipType> {
        let mut push_list = vec![];
        let messages = mem::replace(&mut self.messages, BTreeMap::new());
        self.messages = messages
            .into_iter()
            .map(|(message, state)| {
                let new_state = state.next_round(
                    self.counter_max,
                    self.max_c_rounds,
                    self.max_rounds,
                    &self.peers_in_this_round,
                );
                // Filter out any for which `our_counter()` is `None`.
                if let Some(counter) = new_state.our_counter() {
                    push_list.push(GossipType::Push {
                        msg: message.clone(),
                        counter,
                    });
                }
                (message, new_state)
            })
            .collect();
        self.peers_in_this_round.clear();
        // Sends an empty Push in case of nothing to push. It acts as a fetch request to peer.
        if push_list.is_empty() {
            push_list.push(GossipType::Push {
                msg: Vec::new(),
                counter: 0,
            });
        }
        push_list
    }

    /// We've received `rpc` from `peer_id`.  If this is a Push RPC and we've not already heard from
    /// `peer_id` in this round, this returns the list of Pull RPCs which should be sent back to
    /// `peer_id`.
    pub fn receive(&mut self, peer_id: Id, rpc: GossipType) -> Vec<GossipType> {
        let (is_push, message, counter) = match rpc {
            GossipType::Push { msg, counter } => (true, msg, counter),
            GossipType::Pull { msg, counter } => (false, msg, counter),
        };

        // Collect any responses required.
        let is_new_this_round = self.peers_in_this_round.insert(peer_id);
        let responses = if is_new_this_round && is_push {
            let mut responses: Vec<GossipType> = self
                .messages
                .iter()
                .filter_map(|(message, state)| {
                    // Filter out any for which `our_counter()` is `None`.
                    state.our_counter().map(|counter| GossipType::Pull {
                        msg: message.clone(),
                        counter,
                    })
                })
                .collect();
            // Empty Pull notifies the peer that all messages in this node was in State A.
            if responses.is_empty() {
                responses.push(GossipType::Pull {
                    msg: Vec::new(),
                    counter: 0,
                });
            }
            responses
        } else {
            vec![]
        };

        // Empty Push & Pull shall not be inserted into cache.
        if !(message.is_empty() && counter == 0) {
            // Add or update the entry for this message.
            match self.messages.entry(message) {
                Entry::Occupied(mut entry) => entry.get_mut().receive(peer_id, counter),
                Entry::Vacant(entry) => {
                    let _ = entry.insert(MessageState::new_from_peer(counter, self.counter_max));
                }
            }
        }

        responses
    }

    #[cfg(test)]
    /// Clear the cache.
    pub fn clear(&mut self) {
        self.messages.clear();
        self.peers_in_this_round.clear();
    }
}

impl Debug for Gossip {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "Gossip {{ messages: {{ ")?;
        for (message, state) in &self.messages {
            write!(
                formatter,
                "{:02x}{:02x}{:02x}{:02x}: {:?}, ",
                message[0], message[1], message[2], message[3], state
            )?;
        }
        write!(formatter, "}}, network_size: {}, ", self.network_size)?;
        write!(formatter, "counter_max: {}, ", self.counter_max)?;
        write!(formatter, "max_c_rounds: {}, ", self.max_c_rounds)?;
        write!(formatter, "max_rounds: {}, ", self.max_rounds)?;
        write!(
            formatter,
            "peers_in_this_round: {:?} }}",
            self.peers_in_this_round
        )
    }
}
