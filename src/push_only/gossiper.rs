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

use super::gossip::{Gossip, Statistics};
use ed25519_dalek::{Keypair, PublicKey};
use error::Error;
use id::Id;
use maidsafe_utilities::serialisation;
use messages::{GossipRpc, Message};
use rand::{self, Rng};
use serde::ser::Serialize;
use sha3::Sha3_512;
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};

/// An entity on the network which will gossip messages.
pub struct Gossiper {
    keys: Keypair,
    connected_peers: Vec<Id>,
    gossip: Gossip,
}

impl Gossiper {
    /// The ID of this `Gossiper`, i.e. its public key.
    pub fn id(&self) -> Id {
        self.keys.public.into()
    }

    /// Add the ID of another connected node on the network.
    pub fn add_peer(&mut self, peer_id: Id) -> Result<(), Error> {
        self.connected_peers.push(peer_id);
        self.connected_peers.dedup();
        Ok(())
    }

    /// Send a new message starting at this `Gossiper`.
    pub fn send_new<T: Serialize>(&mut self, message: &T) -> Result<(), Error> {
        if self.connected_peers.is_empty() {
            return Err(Error::NoPeers);
        }
        self.gossip.new_message(serialisation::serialise(message)?);
        Ok(())
    }

    /// Start a new round.  Returns a vector of Push RPCs messages to be sent to the given peer.
    pub fn next_round(&mut self) -> Result<(Id, Vec<Vec<u8>>), Error> {
        let peer_id = match rand::thread_rng().choose(&self.connected_peers) {
            Some(id) => *id,
            None => return Err(Error::NoPeers),
        };
        let push_list = self.gossip.next_round();
        let messages = self.prepare_to_send(push_list);
        debug!("{:?} Sending Push messages to {:?}", self, peer_id);
        Ok((peer_id, messages))
    }

    /// Handles an incoming message from peer.
    pub fn handle_received_message(&mut self, peer_id: &Id, serialised_msg: &[u8]) {
        debug!("{:?} handling message from {:?}", self, peer_id);
        let pub_key = if let Ok(pub_key) = PublicKey::from_bytes(&peer_id.0) {
            pub_key
        } else {
            return;
        };
        let rpc = if let Ok(rpc) = Message::deserialise(serialised_msg, &pub_key) {
            rpc
        } else {
            error!("Failed to deserialise message");
            return;
        };
        self.gossip.receive(*peer_id, rpc);
    }

    /// Returns the list of messages this gossiper has become informed about so far.
    pub fn messages(&self) -> BTreeSet<Vec<u8>> {
        self.gossip.messages()
    }

    /// Returns the statistics of this gossiper.
    pub fn statistics(&self) -> Statistics {
        self.gossip.statistics()
    }

    #[cfg(test)]
    /// Clear the statistics and gossip's cache.
    pub fn clear(&mut self) {
        self.gossip.clear();
    }

    fn prepare_to_send(&mut self, rpcs: Vec<GossipRpc>) -> Vec<Vec<u8>> {
        let mut messages = vec![];
        for rpc in rpcs {
            if let Ok(serialised_msg) = Message::serialise(&rpc, &self.keys) {
                messages.push(serialised_msg);
            } else {
                error!("Failed to serialise {:?}", rpc);
            }
        }
        messages
    }
}

impl Default for Gossiper {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        let keys = Keypair::generate::<Sha3_512>(&mut rng);
        Gossiper {
            keys,
            connected_peers: vec![],
            gossip: Gossip::new(),
        }
    }
}

impl Debug for Gossiper {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?}", self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::{self, Itertools};
    use maidsafe_utilities::SeededRng;
    use rand::{self, Rng};
    use std::collections::BTreeMap;

    fn create_network(
        rng: &mut SeededRng,
        node_count: u32,
        owned_connection: u32,
    ) -> Vec<Gossiper> {
        let mut gossipers = itertools::repeat_call(Gossiper::default)
            .take(node_count as usize)
            .collect_vec();
        // Connect all the gossipers.
        for i in 0..(gossipers.len() - 1) {
            let lhs_id = gossipers[i].id();
            let mut connected = BTreeSet::new();
            while connected.len() as u32 != owned_connection {
                let j = rng.gen_range(0, gossipers.len());
                if j == i {
                    continue;
                } else if !connected.insert(j) {
                    continue;
                }
                let rhs_id = gossipers[j].id();
                let _ = gossipers[j].add_peer(lhs_id);
                let _ = gossipers[i].add_peer(rhs_id);
            }
        }
        gossipers
    }

    fn send_messages(
        rng: &mut SeededRng,
        gossipers: &mut Vec<Gossiper>,
        num_of_msgs: u32,
    ) -> Statistics {
        let mut rumors: Vec<String> = Vec::new();
        for _ in 0..num_of_msgs {
            let raw: Vec<u8> = rng.gen_iter().take(20).collect();
            rumors.push(String::from_utf8_lossy(&raw).to_string());
        }

        // Inform the initial message.
        {
            assert!(num_of_msgs >= 1);
            let gossiper = unwrap!(rand::thread_rng().choose_mut(gossipers));
            let rumor = unwrap!(rumors.pop());
            let _ = gossiper.send_new(&rumor);
        }

        // Polling
        while gossipers.iter().any(|gossiper| {
            gossiper.messages().len() as u32 != num_of_msgs
        })
        {
            let mut messages = BTreeMap::new();
            // Call `next_round()` on each node to gather a list of all Push RPCs.
            for gossiper in gossipers.iter_mut() {
                if !rumors.is_empty() && rng.gen() {
                    let rumor = unwrap!(rumors.pop());
                    let _ = gossiper.send_new(&rumor);
                }
                let (dst_id, push_msgs) = unwrap!(gossiper.next_round());
                let _ = messages.insert((gossiper.id(), dst_id), push_msgs);
            }

            // Send all Push RPCs and the corresponding Pull RPCs.
            for ((src_id, dst_id), push_msgs) in messages {
                let mut dst = unwrap!(gossipers.iter_mut().find(|node| node.id() == dst_id));
                for push_msg in push_msgs.iter() {
                    let _ = dst.handle_received_message(&src_id, &push_msg);
                }
            }
        }

        let mut statistics = Statistics::default();
        // Collect the statistics and clear the nodes for the next iteration.
        for gossiper in gossipers.iter_mut() {
            let stat = gossiper.statistics();
            statistics.add(&stat);
            statistics.rounds = stat.rounds;
            gossiper.clear();
        }

        statistics
    }

    fn one_message_test(num_of_nodes: u32, owned_connection: u32) {
        let mut rng = SeededRng::thread_rng();
        let mut gossipers = create_network(&mut rng, num_of_nodes, owned_connection);
        println!(
            "Network of {} nodes, with owned_connection is {}:",
            num_of_nodes,
            owned_connection
        );
        let iterations = 1000;
        let mut metrics = Vec::new();
        for _ in 0..iterations {
            metrics.push(send_messages(&mut rng, &mut gossipers, 1));
        }

        let mut stats_avg = Statistics::default();
        let mut stats_max = Statistics::default();
        let mut stats_min = Statistics::new_max();

        for stats in metrics {
            stats_avg.add(&stats);
            stats_max.max(&stats);
            stats_min.min(&stats);
        }
        stats_avg.rounds /= iterations;
        stats_avg.full_message_sent /= iterations;

        print!("    AVERAGE ---- ");
        print_metric(&stats_avg);
        print!("    MIN -------- ");
        print_metric(&stats_min);
        print!("    MAX -------- ");
        print_metric(&stats_max);
    }

    fn print_metric(stats: &Statistics) {
        println!(
            "all nodes received the message after rounds: {}, full_msgs_sent: {}",
            stats.rounds,
            stats.full_message_sent
        );
    }

    #[test]
    fn one_message() {
        for i in 2..15 {
            one_message_test(20, i);
        }
    }

}
