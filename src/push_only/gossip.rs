// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

#![allow(dead_code)]

use id::Id;
use messages::GossipRpc;
use std::{cmp, u64};
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};

/// Gossip protocol handler.
pub struct Gossip {
    messages: BTreeSet<Vec<u8>>,
    statistics: Statistics,
}

impl Gossip {
    pub fn new() -> Self {
        Gossip {
            messages: BTreeSet::new(),
            statistics: Statistics::default(),
        }
    }

    pub fn messages(&self) -> BTreeSet<Vec<u8>> {
        self.messages.clone()
    }

    /// Start gossiping a new message from this node.
    pub fn new_message(&mut self, msg: Vec<u8>) {
        if !self.messages.insert(msg) {
            error!("New messages should be unique.");
        }
    }

    /// Trigger the end of this round.  Returns a list of Push RPCs to be sent to a single random
    /// peer during this new round.
    pub fn next_round(&mut self) -> Vec<GossipRpc> {
        self.statistics.rounds += 1;
        let push_list: Vec<GossipRpc> = self.messages
            .iter()
            .map(|msg| {
                GossipRpc::Push {
                    msg: msg.clone(),
                    counter: 0,
                }
            })
            .collect();
        self.statistics.full_message_sent += push_list.len() as u64;

        push_list
    }

    /// We've received `rpc` from `peer_id`.
    pub fn receive(&mut self, _peer_id: Id, rpc: GossipRpc) {
        let message = match rpc {
            GossipRpc::Push { msg, .. } => msg,
            _ => panic!("received improper GossipRpc"),
        };
        let _ = self.messages.insert(message);
    }

    #[cfg(test)]
    /// Clear the cache.
    pub fn clear(&mut self) {
        self.statistics = Statistics::default();
        self.messages.clear();
    }

    /// Returns the statistics.
    pub fn statistics(&self) -> Statistics {
        self.statistics
    }
}

impl Debug for Gossip {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Gossip {{ messages: {{ ")?;
        for message in &self.messages {
            write!(
                formatter,
                "{:02x}{:02x}{:02x}{:02x}, ",
                message[0],
                message[1],
                message[2],
                message[3]
            )?;
        }
        write!(formatter, "}} ")
    }
}


/// Statistics on each gossiper.
#[derive(Clone, Copy, Default)]
pub struct Statistics {
    /// Total rounds experienced (each push_tick is considered as one round).
    pub rounds: u64,
    /// Total full message sent from this gossiper.
    pub full_message_sent: u64,
}

impl Statistics {
    /// Create a default with u64::MAX
    pub fn new_max() -> Self {
        Statistics {
            rounds: u64::MAX,
            full_message_sent: u64::MAX,
        }
    }

    /// Add the value of other into self
    pub fn add(&mut self, other: &Statistics) {
        self.rounds += other.rounds;
        self.full_message_sent += other.full_message_sent;
    }

    /// Update self with the min of self and other
    pub fn min(&mut self, other: &Statistics) {
        self.rounds = cmp::min(self.rounds, other.rounds);
        self.full_message_sent = cmp::min(self.full_message_sent, other.full_message_sent);
    }

    /// Update self with the max of self and other
    pub fn max(&mut self, other: &Statistics) {
        self.rounds = cmp::max(self.rounds, other.rounds);
        self.full_message_sent = cmp::max(self.full_message_sent, other.full_message_sent);
    }
}

impl Debug for Statistics {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "rounds: {},  full messages sent: {}",
            self.rounds,
            self.full_message_sent,
        )
    }
}
