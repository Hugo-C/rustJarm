use std::net::{TcpStream};
use std::io::{Read, Write, Error};
use std::str::from_utf8;
use jarm::{build_packet, read_packet, PacketSpecification, TlsVersion, CipherList, CipherOrder, TlsVersionSupport, Jarm};

fn main() {
    let host = "jsonplaceholder.typicode.com".to_string();
    let port = "443".to_string();
    let jarm_hash = Jarm::new(host, port).hash();
    println!("JARM hash: {:?}", jarm_hash);
    assert_eq!(jarm_hash, "27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c".to_string());
    println!("Terminated.");
}