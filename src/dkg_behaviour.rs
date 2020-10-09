use libp2p::kad::record::store::MemoryStore;
use libp2p::kad::{
    AddProviderOk,
    Kademlia,
    KademliaEvent,
    PeerRecord,
    PutRecordOk,
    QueryResult,
    Quorum,
    Record,
    record::Key,
};
use libp2p::gossipsub::protocol::MessageId;
use libp2p::gossipsub::{Gossipsub, GossipsubEvent, GossipsubMessage, MessageAuthenticity, Topic};
use libp2p::{
    gossipsub,
    NetworkBehaviour,
    PeerId,
    identity,
    swarm::NetworkBehaviourEventProcess
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

#[derive(NetworkBehaviour)]
pub struct Dkg {
    pub kademlia: Kademlia<MemoryStore>,
    pub gossipsub: Gossipsub,
}

impl Dkg {
    pub fn new (local_key: identity::Keypair, peer_id: &PeerId ) -> Self {
        let store = MemoryStore::new(peer_id.clone());
        let kademlia = Kademlia::new(peer_id.clone(), store);


        // To content-address message, we can take the hash of message and use it as an ID.
        let message_id_fn = |message: &GossipsubMessage| {
            let mut s = DefaultHasher::new();
            message.data.hash(&mut s);
            MessageId::from(s.finish().to_string())
        };
        // set custom gossipsub
        let gossipsub_config = gossipsub::GossipsubConfigBuilder::new()
            .heartbeat_interval(Duration::from_secs(10))
            .message_id_fn(message_id_fn) // content-address messages. No two messages of the
        //same content will be propagated.
            .build();
        // build a gossipsub network behaviour
        let mut gossipsub =
            gossipsub::Gossipsub::new(MessageAuthenticity::Signed(local_key), gossipsub_config);
        let topic = Topic::new("ferveo-net".into());
        gossipsub.subscribe(topic.clone());
        Dkg { kademlia, gossipsub }
    }

    pub fn handle_input_line(&mut self, line: String) {
        let mut args = line.split(" ");
        match args.next() {
            Some("GET") => {
                let key = {
                    match args.next() {
                        Some(key) => Key::new(&key),
                        None => {
                            eprintln!("Expected key");
                            return;
                        }
                    }
                };
                self.kademlia.get_record(&key, Quorum::One);
            }
            Some("GET_PROVIDERS") => {
                let key = {
                    match args.next() {
                        Some(key) => Key::new(&key),
                        None => {
                            eprintln!("Expected key");
                            return
                        }
                    }
                };
                self.kademlia.get_providers(key);
            }
            Some("PUT") => {
                let key = {
                    match args.next() {
                        Some(key) => Key::new(&key),
                        None => {
                            eprintln!("Expected key");
                            return;
                        }
                    }
                };
                let value = {
                    match args.next() {
                        Some(value) => value.as_bytes().to_vec(),
                        None => {
                            eprintln!("Expected value");
                            return;
                        }
                    }
                };
                let record = Record {
                    key,
                    value,
                    publisher: None,
                    expires: None,
                };
                self.kademlia.put_record(record, Quorum::One).expect("Failed to store record locally.");
            },
            Some("PUT_PROVIDER") => {
                let key = {
                    match args.next() {
                        Some(key) => Key::new(&key),
                        None => {
                            eprintln!("Expected key");
                            return;
                        }
                    }
                };

                self.kademlia.start_providing(key).expect("Failed to start providing key");
            }
            _ => {
                let topic = Topic::new("ferveo-net".into());
                self.gossipsub.publish(&topic, line.as_bytes());
            }
        }
    }
}

impl NetworkBehaviourEventProcess<KademliaEvent> for Dkg {
    // Called when `kademlia` produces an event.
    fn inject_event(&mut self, message: KademliaEvent) {
        match message {
            KademliaEvent::QueryResult { result, .. } => match result {
                QueryResult::GetProviders(Ok(ok)) => {
                    for peer in ok.providers {
                        println!(
                            "Peer {:?} provides key {:?}",
                            peer,
                            std::str::from_utf8(ok.key.as_ref()).unwrap()
                        );
                    }
                }

                QueryResult::GetProviders(Err(err)) => {
                    eprintln!("Failed to get providers: {:?}", err);
                }
                QueryResult::GetRecord(Ok(ok)) => {
                    for PeerRecord { record: Record { key, value, .. }, ..} in ok.records {
                        println!(
                            "Got record {:?} {:?}",
                            std::str::from_utf8(key.as_ref()).unwrap(),
                            std::str::from_utf8(&value).unwrap(),
                        );
                    }
                }
                QueryResult::GetRecord(Err(err)) => {
                    eprintln!("Failed to get record: {:?}", err);
                }
                QueryResult::PutRecord(Ok(PutRecordOk { key })) => {
                    println!(
                        "Successfully put record {:?}",
                        std::str::from_utf8(key.as_ref()).unwrap()
                    );
                }
                QueryResult::PutRecord(Err(err)) => {
                    eprintln!("Failed to put record: {:?}", err);
                }
                QueryResult::StartProviding(Ok(AddProviderOk { key })) => {
                    println!("Successfully put provider record {:?}",
                             std::str::from_utf8(key.as_ref()).unwrap()
                    );
                }
                QueryResult::StartProviding(Err(err)) => {
                    eprintln!("Failed to put provider record: {:?}", err);
                }
                _ => {}
            }
            _ => {}
        }
    }
}

impl NetworkBehaviourEventProcess<GossipsubEvent> for Dkg {
    // Called when `gossipsub` produces an event.
    fn inject_event(&mut self, message: GossipsubEvent) {
        match message {
            GossipsubEvent::Message(peer_id, id, message) => {
                println!(
                    "GossipsubEvent::Message:Got message: {} with id: {} from peer: {:?}",
                    String::from_utf8_lossy(&message.data),
                    id,
                    peer_id
                );
            }
            GossipsubEvent::Subscribed{peer_id, topic: _} => {
                println!(
                    "GossipsubEvent::Subscribed: peer {:?} ",
                    peer_id
                );
            }
            GossipsubEvent::Unsubscribed{peer_id, topic: _ } => {
                println!(
                    "GossipsubEvent::Unsubscribed: peer {:?} ",
                    peer_id
                );
            }
        }
    }
}
