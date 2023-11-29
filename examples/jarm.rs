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

    println!("JARM hash: {}", jarm_hash);
    assert_eq!(jarm_hash, "29d29d00029d29d00042d43d00041d5de67cc9954cc85372523050f20b5007".to_string());
    println!("Done");
}