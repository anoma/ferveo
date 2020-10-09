use async_std::{io, task};
use env_logger::{Builder, Env};
use futures::prelude::*;
use std::{
    error::Error,
    task::{Context, Poll},
};
use clap::{Arg, App};
use libp2p::{
    PeerId,
    Swarm,
    identity
};

mod config;
mod dkg_behaviour;

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("Ferveo P2P stack")
        .version("0.1")
        .author("metastatedev")
        .about("p2p stack of a BFT network for a DKG protocol")
        .arg(Arg::new("config")
             .short('c')
             .long("config")
             .value_name("FILE")
             .about("Sets a custom config file")
             .takes_value(true)
        )
        .get_matches();

    Builder::from_env(Env::default().default_filter_or("info")).init();

    // Gets a value for config if supplied by user, or defaults to "default.conf"
    let config_file = matches.value_of("config").unwrap_or("default.conf");
    println!("Value for config: {}", config_file);
    let config = config::read_config(config_file.to_string());
    println!("main->config: {}", config);

    // Create a random PeerId
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {:?}", local_peer_id);

    // Set up an encrypted TCP Transport
    let transport = libp2p::build_development_transport(local_key.clone())?;

    // Create a Swarm to manage peers and events
    let mut swarm = {
        let behaviour = dkg_behaviour::Dkg::new(local_key, &local_peer_id) ;
        Swarm::new(transport, behaviour, local_peer_id)
    };

    // Listen configurated interface
    libp2p::Swarm::listen_on(&mut swarm, config.local_addr.parse().unwrap()).unwrap();

    // Reach out to another node if specified in config file
    for addr in config.addr_pool {
        let dialing = addr.clone();
        match addr.parse() {
            Ok(addr) => match libp2p::Swarm::dial_addr(&mut swarm, addr) {
                Ok(_) => println!("Dialed {:?}", dialing),
                Err(e) => println!("Dial {:?} failed: {:?}", dialing, e),
            },
            Err(err) => println!("Failed to parse address to dial: {:?}", err),
        }
    }

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines();

    // Kick it off.
    let mut listening = false;
    task::block_on(future::poll_fn(move |cx: &mut Context<'_>| {
        loop {
            match stdin.try_poll_next_unpin(cx)? {
                Poll::Ready(Some(line)) => swarm.handle_input_line(line),
                Poll::Ready(None) => panic!("Stdin closed"),
                Poll::Pending => break
            }
        }
        loop {
            match swarm.poll_next_unpin(cx) {
                Poll::Ready(Some(event)) => println!("{:?}", event),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => {
                    if !listening {
                        if let Some(a) = Swarm::listeners(&swarm).next() {
                            println!("Listening on {:?}", a);
                            listening = true;
                        }
                    }
                    break
                }
            }
        }
        Poll::Pending
    }))
}
