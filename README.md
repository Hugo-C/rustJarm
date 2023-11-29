# rust_jarm
[![Rust](https://github.com/Hugo-C/rustJarm/actions/workflows/rust.yml/badge.svg)](https://github.com/Hugo-C/rustJarm/actions/workflows/rust.yml)
[![dependency status](https://deps.rs/crate/rust_jarm/latest/status.svg)](https://deps.rs/crate/rust_jarm/)
[![Codecov](https://img.shields.io/codecov/c/github/Hugo-C/rustJarm)](https://app.codecov.io/gh/Hugo-C/rustJarm)
[![Crates.io](https://img.shields.io/crates/v/rust_jarm)](https://crates.io/crates/rust_jarm)
[![Crates.io](https://img.shields.io/crates/d/rust_jarm)](https://crates.io/crates/rust_jarm)  
rust_jarm is a library to compute JARM fingerprint. It is more or less a direct translation of [the original jarm implementation](https://github.com/salesforce/jarm) from Python to Rust.

## Installation
put in Cargo.toml:
```
[dependencies]
rust_jarm = "0.3.4"
```

## Usage

````rust
    let host = "some.website.com".to_string();
    let port = "443".to_string();
    let jarm_hash = Jarm::new(host, port).hash().expect("failed to connect");
    println!("JARM hash: {}", jarm_hash);
````

check [jarm.rs](examples/jarm.rs) for the full example, run it with `cargo run --example jarm`

## Contribute

All contributions and/or feedbacks are welcome to improve the code and the package
