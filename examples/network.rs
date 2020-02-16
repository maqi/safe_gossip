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

//! Run a local network of gossiper nodes.

#![forbid(
    exceeding_bitshifts,
    mutable_transmutes,
    no_mangle_const_items,
    unknown_crate_types
)]
#![deny(
    bad_style,
    improper_ctypes,
    missing_docs,
    non_shorthand_field_patterns,
    overflowing_literals,
    stable_features,
    unconditional_recursion,
    unknown_lints,
    unsafe_code,
    unused_allocation,
    unused_attributes,
    unused_comparisons,
    unused_features,
    unused_parens,
    while_true,
    unused
)]
#![warn(
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]
#![allow(
    box_pointers,
    missing_copy_implementations,
    missing_debug_implementations,
    variant_size_differences,
    non_camel_case_types
)]

use futures::try_ready;
use rand;
#[macro_use]
extern crate tokio_io;
#[macro_use]
extern crate unwrap;
use bincode::{deserialize, serialize};
use bytes::{BufMut, BytesMut};
use futures::sync::mpsc;
use futures::{Async, Future, Poll, Stream};
use futures_cpupool::{CpuFuture, CpuPool};
use itertools::Itertools;
use rand::distributions::Alphanumeric;
use rand::Rng;
use safe_gossip::{Error, Gossiper, Id};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{self, Debug, Formatter};
use std::io::Write;
use std::iter::Iterator;
use std::mem;
use std::rc::Rc;
use std::thread;
use tokio::executor::current_thread;
use tokio::net::{TcpListener, TcpStream};
use tokio_io::AsyncRead;

/// TCP stream wrapper presenting a message-based read / write interface.
#[derive(Debug)]
struct MessageStream {
    tcp_stream: TcpStream,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
    incoming_message_length: Option<usize>,
}

impl MessageStream {
    fn new(tcp_stream: TcpStream) -> Self {
        MessageStream {
            tcp_stream,
            read_buffer: BytesMut::new(),
            write_buffer: BytesMut::new(),
            incoming_message_length: None,
        }
    }

    /// Buffer `message` to an internal buffer.  Calls to `poll_flush` will attempt to flush this
    /// buffer to the TCP stream.  The size of `message` as a `u32` is added to the buffer first so
    /// that the correct size can be read by the receiver before it tries to retrieve the actual
    /// message.
    fn buffer(&mut self, message: &[u8]) {
        let serialised_length = unwrap!(serialize(&(message.len() as u32)));
        if self.write_buffer.remaining_mut() < serialised_length.len() + message.len() {
            self.write_buffer.extend_from_slice(&serialised_length);
            self.write_buffer.extend_from_slice(message);
        } else {
            self.write_buffer.put(&serialised_length);
            self.write_buffer.put(message);
        }
    }

    /// Flush the write buffer to the TCP stream.
    fn poll_flush(&mut self) -> Poll<(), Error> {
        while !self.write_buffer.is_empty() {
            // `try_nb` is kind of like `try_ready`, but for operations that return `io::Result`
            // instead of `Async`.  In the case of `io::Result`, an error of `WouldBlock` is
            // equivalent to `Async::NotReady`.
            let num_bytes = try_nb!(self.tcp_stream.write(&self.write_buffer));
            assert!(num_bytes > 0);
            // Discard the first `num_bytes` bytes of the buffer.
            let _ = self.write_buffer.split_to(num_bytes);
        }

        Ok(Async::Ready(()))
    }

    /// Read data from the TCP stream.  This only returns `Ready` when the socket has closed.
    fn fill_read_buffer(&mut self) -> Poll<(), Error> {
        loop {
            self.read_buffer.reserve(1024);
            let num_bytes = try_ready!(self.tcp_stream.read_buf(&mut self.read_buffer));
            if num_bytes == 0 {
                return Ok(Async::Ready(()));
            }
        }
    }
}

impl Stream for MessageStream {
    type Item = BytesMut;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // First, read any new data that might have been received off the TCP stream
        let socket_closed = self.fill_read_buffer()?.is_ready();

        // If we're not part way through reading an incoming message, read the next incoming
        // message's length.
        if self.incoming_message_length.is_none() && self.read_buffer.len() >= 4 {
            let length_buffer = self.read_buffer.split_to(4);
            let length = unwrap!(deserialize::<u32>(&length_buffer)) as usize;
            self.incoming_message_length = Some(length);
        }

        // If we have the next message's length available, read it.
        if let Some(length) = self.incoming_message_length {
            if self.read_buffer.len() >= length {
                self.incoming_message_length = None;
                return Ok(Async::Ready(Some(self.read_buffer.split_to(length))));
            }
        }

        if socket_closed {
            Ok(Async::Ready(None))
        } else {
            Ok(Async::NotReady)
        }
    }
}

/// This is effectively a container for all the state required to manage a node while the network
/// is running.  `Node` implements `Future` and hence each node is run continuously on a single
/// thread from the threadpool.  When the future returns, the `Node` has completed processing all
/// messages.
struct Node {
    gossiper: Gossiper,
    /// This receives new messages from the `Network` object; equivalent to e.g. a new client event.
    channel_receiver: mpsc::UnboundedReceiver<String>,
    /// This can be used to send the received client messages and `Gossiper`'s stats to the
    /// `Network` object.
    stats_sender: mpsc::UnboundedSender<(Id, Vec<String>)>,
    /// Map of peer ID to the wrapped TCP stream connecting us to them.
    peers: HashMap<Id, MessageStream>,
    /// Indicates whether is in a push&pull round
    is_in_round: bool,
    /// If a message is received via `channel_sender` matches this, the node should terminate.
    termination_message: String,
}

impl Node {
    fn new(
        channel_receiver: mpsc::UnboundedReceiver<String>,
        stats_sender: mpsc::UnboundedSender<(Id, Vec<String>)>,
        termination_message: String,
    ) -> Self {
        Node {
            gossiper: Gossiper::default(),
            channel_receiver,
            stats_sender,
            peers: HashMap::new(),
            is_in_round: false,
            termination_message,
        }
    }

    fn add_peer(&mut self, id: Id, tcp_stream: TcpStream) {
        assert!(self
            .peers
            .insert(id, MessageStream::new(tcp_stream))
            .is_none());
        unwrap!(self.gossiper.add_peer(id));
    }

    fn id(&self) -> Id {
        self.gossiper.id()
    }

    /// Receive all new messages from the `Network` object.  If we receive the termination message,
    /// immediately return `false`, otherwise return `true`.
    fn receive_from_channel(&mut self) -> bool {
        while let Async::Ready(Some(message)) = unwrap!(self.channel_receiver.poll()) {
            if message == self.termination_message {
                return false;
            }
            unwrap!(self.gossiper.send_new(&message));
        }
        true
    }

    /// Triggers a new push round
    fn tick(&mut self) {
        if !self.is_in_round {
            self.is_in_round = true;

            let (peer_id, msgs_to_send) = unwrap!(self.gossiper.next_round());
            if let Some(message_stream) = self.peers.get_mut(&peer_id) {
                // Buffer the messages to be sent.
                for msg in msgs_to_send {
                    message_stream.buffer(&msg);
                }
            }
        }
    }

    /// Iterate the peers reading any new messages from their TCP streams.  Removes any peers that
    /// have disconnected.
    fn receive_from_peers(&mut self) {
        let mut disconnected_peers = vec![];
        let mut has_response = false;
        for (peer_id, ref mut message_stream) in &mut self.peers {
            loop {
                match message_stream.poll() {
                    Ok(Async::Ready(Some(message))) => {
                        let msgs_to_send = self.gossiper.handle_received_message(peer_id, &message);
                        // Buffer the messages to be sent back.
                        for msg in msgs_to_send {
                            has_response = true;
                            message_stream.buffer(&msg);
                        }
                    }
                    Ok(Async::Ready(None)) => {
                        // EOF was reached; the remote peer has disconnected.
                        disconnected_peers.push(*peer_id);
                        break;
                    }
                    Ok(Async::NotReady) => break,
                    Err(error) => {
                        println!("Error reading messages from {:?}: {:?}", peer_id, error);
                        disconnected_peers.push(*peer_id);
                        break;
                    }
                }
            }
        }
        for disconnected_peer in disconnected_peers {
            let _ = unwrap!(self.peers.remove(&disconnected_peer));
        }
        self.is_in_round = has_response;
    }

    /// Iterate the peers flushing the write buffers to the TCP streams.  Removes any peers that
    /// have disconnected.
    fn send_to_peers(&mut self) {
        let mut disconnected_peers = vec![];
        for (peer_id, ref mut message_stream) in &mut self.peers {
            if let Err(error) = message_stream.poll_flush() {
                println!("Error writing messages to {:?}: {:?}", peer_id, error);
                disconnected_peers.push(*peer_id);
            }
        }
        for disconnected_peer in disconnected_peers {
            let _ = unwrap!(self.peers.remove(&disconnected_peer));
        }
    }
}

impl Future for Node {
    type Item = ();
    type Error = Error;

    fn poll(&mut self) -> Poll<(), Error> {
        if !self.receive_from_channel() {
            return Ok(Async::Ready(()));
        }
        self.receive_from_peers();
        self.tick();
        self.send_to_peers();
        let messages: Vec<String> = self
            .gossiper
            .messages()
            .into_iter()
            .map(|serialised| unwrap!(deserialize::<String>(&serialised)))
            .collect_vec();
        let id = self.id();

        if messages.len() > 0 {
            unwrap!(self.stats_sender.unbounded_send((id, messages)));
        }

        // If we have no peers left, there is nothing more for this node to do.
        if self.peers.is_empty() {
            return Ok(Async::Ready(()));
        }
        Ok(Async::NotReady)
    }
}

impl Debug for Node {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?} - {:?}", thread::current().id(), self.id())
    }
}

struct Network {
    pool: CpuPool,
    // An mpsc channel sender for each node for giving new client messages to that node.
    message_senders: Vec<mpsc::UnboundedSender<String>>,
    // An mpsc channel receiver for getting the client messages and stats from the nodes.
    stats_receiver: mpsc::UnboundedReceiver<(Id, Vec<String>)>,
    // The last set of client messages received via `stats_receiver` for each node.
    received_messages: HashMap<Id, Vec<String>>,
    // The futures for all nodes.  When these return ready, that node has finished running.
    node_futures: Vec<CpuFuture<(), Error>>,
    // All messages sent in the order they were passed in.  Tuple contains the message and the index
    // of the node used to send.
    client_messages: Vec<(String, usize)>,
    // Message which when sent to a node via its `message_sender` indicates to the node that it
    // should terminate.
    termination_message: String,
    // Stats
    stats: Stats,
}

impl Network {
    fn new(node_count: usize) -> Self {
        let (stats_sender, stats_receiver) = mpsc::unbounded();
        let mut network = Network {
            // pool: CpuPool::new(1),
            pool: CpuPool::new_num_cpus(),
            message_senders: vec![],
            stats_receiver,
            received_messages: HashMap::new(),
            node_futures: vec![],
            client_messages: vec![],
            termination_message: rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(20)
                .collect(),
            stats: Stats::new(),
        };

        let mut nodes = vec![];
        for _ in 0..node_count {
            let (message_sender, message_receiver) = mpsc::unbounded();
            let node = Node::new(
                message_receiver,
                stats_sender.clone(),
                network.termination_message.clone(),
            );
            network.message_senders.push(message_sender);
            nodes.push(node);
        }
        nodes.sort_by(|lhs, rhs| lhs.id().cmp(&rhs.id()));
        //println!("Nodes: {:?}", nodes.iter().map(Node::id).collect_vec());

        let mut rng = rand::thread_rng();
        let mut port = rng.gen_range(0, 65535);
        let address = format!("127.0.0.1:{}", port);
        
        // Connect all the nodes.
        let listening_address = unwrap!(address.parse());
        for i in 0..(node_count - 1) {
            let mut bind_result = TcpListener::bind(&listening_address);
            while bind_result.is_err() {
                port = rng.gen_range(0, 65535);
                let address = format!("127.0.0.1:{}", port);
                let listening_address = unwrap!(address.parse());
                bind_result = TcpListener::bind(&listening_address);
            }
            //println!("Port: {}", port);
            let listener = unwrap!(bind_result);
            let lhs_id = nodes[i].id();
            let listener_address = unwrap!(listener.local_addr());
            let incoming = Rc::new(RefCell::new(listener.incoming().wait()));
            for j in (i + 1)..node_count {
                let rhs_id = nodes[j].id();
                let rhs_stream =
                    current_thread::run(|_| TcpStream::connect(&listener_address)).wait();
                nodes[j].add_peer(lhs_id, unwrap!(rhs_stream));
                let incoming = incoming.clone();
                let lhs_stream = unwrap!(current_thread::run(|_| incoming.borrow_mut()).next());
                nodes[i].add_peer(rhs_id, unwrap!(lhs_stream));
            }
        }

        // Start the nodes running by executing their `poll()` functions on the threadpool.
        for node in nodes {
            network.node_futures.push(network.pool.spawn(node));
        }

        network
    }

    /// Send the given `message`.  If `node_index` is `Some` and is less than the number of `Node`s
    /// in the `Network`, then the `Node` at that index will be chosen as the initial informed one.
    fn send(&mut self, message: &str, node_index: Option<usize>) -> Result<(), Error> {
        let count = match node_index {
            Some(index) if index < self.message_senders.len() => index,
            _ => rand::thread_rng().gen_range(0, self.message_senders.len()),
        };
        self.client_messages.push((message.to_string(), count));
        unwrap!(self.message_senders[count].unbounded_send(message.to_string(),));
        Ok(())
    }

    fn reached_consensus(&mut self) -> bool {
        if self.received_messages.len() == 0 {
            return false;
        }
        let mut did_not_receive_all = 0;

        for received in self.received_messages.values() {
            for (msg, _) in self.client_messages.clone().into_iter() {
                if !received.iter().any(|x| *x == msg) {
                    did_not_receive_all += 1;
                    break;
                }
            }
        }

        let consensused = did_not_receive_all < self.received_messages.len() / 3;
        if consensused {
            println!("Poll count {:?}", self.stats.poll_count);
            println!("Sent count {:?}", self.stats.sent_count);
        }
        consensused
    }
}

impl Future for Network {
    type Item = Stats;
    type Error = String;

    fn poll(&mut self) -> Poll<Stats, String> {
        self.stats.poll_count += 1;

        while let Async::Ready(Some((node_id, messages))) = unwrap!(self.stats_receiver.poll()) {
            //println!("Received from {:?} -- {:?}", node_id, messages);
            let _ = self.received_messages.insert(node_id, messages.clone());
            self.stats.sent_count += messages.len() as u64;
        }

        if !self.received_messages.is_empty() && self.reached_consensus() {
            return Ok(Async::Ready(self.stats.clone()));
        }

        Ok(Async::NotReady)
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        for message_sender in &mut self.message_senders {
            unwrap!(message_sender.unbounded_send(self.termination_message.clone(),));
        }
        let node_futures = mem::replace(&mut self.node_futures, vec![]);
        for node_future in node_futures {
            unwrap!(node_future.wait());
        }
    }
}

fn main() {
    let num_of_nodes = 16;
    let num_of_extra_msgs = 0;
    println!("Number of extra msgs to input {:?}", num_of_extra_msgs);

    let mut polls = vec![];
    let mut sent = vec![];

    for i in 0..100 {
        println!("Sim iter {:?}", i);
        let stats = run(num_of_nodes, num_of_extra_msgs);
        polls.push(stats.clone().poll_count);
        sent.push(stats.clone().sent_count);
    }

    println!("Average poll count {:?}", average(&polls[..]));
    println!("Median poll count {:?}", median(&mut polls[..]));

    println!("Average sent count {:?}", average(&sent[..]));
    println!("Median sent count {:?}", median(&mut sent[..]));
}

fn run(num_of_nodes: u64, num_of_extra_msgs: u64) -> Stats {
    let mut network = Network::new(num_of_nodes as usize);
    unwrap!(network.send("Hello", None));
    unwrap!(network.send("there", Some(999)));
    unwrap!(network.send("world", Some(0)));
    unwrap!(network.send("!", Some(0)));

    // A real network continues to send messages..

    let mut rng = rand::thread_rng();

    let mut messages: Vec<String> = Vec::new();
    for _ in 0..num_of_extra_msgs {
        let msg = rng.sample_iter(&Alphanumeric).take(10).collect::<String>();
        messages.push(msg);
    }

    for msg in messages {
        unwrap!(network.send(&msg[..], Some(0)));
    }

    unwrap!(network.pool.clone().spawn(network).wait())
}

fn average(numbers: &[u64]) -> f32 {
    numbers.iter().sum::<u64>() as f32 / numbers.len() as f32
}

fn median(numbers: &mut [u64]) -> u64 {
    numbers.sort();
    let mid = numbers.len() / 2;
    numbers[mid]
}

/// Statistics on each network sim.
#[derive(Clone, Default)]
pub struct Stats {
    /// Number of polls done
    pub poll_count: u64,
    /// Number of total messages sent
    pub sent_count: u64,
}

impl Stats {
    /// Create a default
    pub fn new() -> Self {
        Stats {
            poll_count: 0,
            sent_count: 0,
        }
    }
}

impl Debug for Stats {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "poll_count: {},  sent_count: {}, ",
            self.poll_count, self.sent_count,
        )
    }
}
