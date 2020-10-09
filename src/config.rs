use serde::{Deserialize, Serialize};
// use serde_json::Result;
use std::fs::File;
// use std::io::Read;
use std::fmt;

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub local_addr:String,
    pub addr_pool:Vec<String>
}

pub fn read_config(file:String) -> Config {
    let file = File::open(file).expect("file should open read only");
    // Parse the string of data into a Person object. This is exactly the
    // same function as the one that produced serde_json::Value above, but
    // now we are asking it for a Person as output.
    let conf: Config =serde_json::from_reader(file)
        .expect("fileshould be proper JSON");

    // Do things just like with any other Rust data structure.
    println!("read_config: {}", conf);
    conf
}


impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{{local_addr: {}, addr_pool: {}}}", self.local_addr,
               "[".to_string() + &self.addr_pool.join(",") + &"]")
    }
}
