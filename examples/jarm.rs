use std::time::Duration;
use rust_jarm::Jarm;

fn main() {
    let host = "jsonplaceholder.typicode.com".to_string();
    let port = "443".to_string();
    let mut jarm_scan = Jarm::new(host, port);
    jarm_scan.timeout = Duration::from_secs(2);
    let jarm_hash = match jarm_scan.hash() {
        Ok(hash) => hash,
        Err(e) => {
            println!("Error: {e:?}");
            return;
        }
    };

    println!("JARM hash: {jarm_hash}");
    assert_eq!(jarm_hash, "27d3ed3ed0003ed1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c".to_string());
    println!("Done");
}