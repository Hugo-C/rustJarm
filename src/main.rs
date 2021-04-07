use std::net::{TcpStream};
use std::io::{Read, Write, Error};
use std::str::from_utf8;
use jarm::{build_packet, read_packet, PacketSpecification, TlsVersion, CipherList, CipherOrder, TlsVersionSupport, ExtensionOrder};

fn main() {
    match TcpStream::connect("jsonplaceholder.typicode.com:443") {
        Ok(mut stream) => {
            println!("Successfully connected to server in port 443");

            let spec = PacketSpecification {
                host: "jsonplaceholder.typicode.com".to_string(),
                port: "443".to_string(),
                tls_version: TlsVersion::TLS1_2,
                cipher_list: CipherList::ALL,
                cipher_order: CipherOrder::FORWARD,
                use_grease: false,
                use_rare_apln: false,
                tls_version_support: TlsVersionSupport::TLS1_2,
                extension_order: ExtensionOrder::REVERSE,
            };
            let msg = build_packet(&spec); // b"\x16ello!";

            stream.write(msg).unwrap();

            println!("Sent Hello, awaiting reply...");

            let mut data = [0 as u8; 1484]; // using fixed size byte buffer
            let mut handle = stream.take(1484);

            handle.read(&mut data);
            // let text = from_utf8(&data).unwrap();
            println!("Server reply: {:?}", data);
            let jarm = read_packet(Vec::from(data));
            println!("Jarm: {:?}", jarm.raw);

            // match data {
            //     Ok(d) => {
            //         let text = from_utf8(&data).unwrap();
            //         println!("Unexpected reply: {}", text);
            //     },
            //     Err(e) => {
            //         println!("Failed to receive data: {}", e);
            //     }
            // }
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    println!("Terminated.");
}