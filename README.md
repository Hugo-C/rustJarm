# rust_jarm
[![Rust](https://github.com/Hugo-C/rustJarm/actions/workflows/rust.yml/badge.svg)](https://github.com/Hugo-C/rustJarm/actions/workflows/rust.yml) ![Crates.io](https://img.shields.io/crates/v/rust_jarm) ![Crates.io](https://img.shields.io/crates/d/rust_jarm)  
rust_jarm is a library to compute JARM fingerprint. It is more or less a direct translation of [the original jarm implementation](https://github.com/salesforce/jarm) from Python to Rust.

## Installation
put in Cargo.toml:
```
[dependencies]
rust_jarm = "0.2.0"
```

## Usage

````rust
    let host = "some.website.com".to_string();
    let port = "443".to_string();
    let jarm_hash = Jarm::new(host, port).hash().expect("failed to connect");
    println!("JARM hash: {}", jarm_hash);
````

check [main.rs](src/main.rs) for the full example

## Contribute

All contributions and/or feedbacks are welcome to improve the code and the package
