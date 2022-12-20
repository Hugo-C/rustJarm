pub mod error;

use rand::{thread_rng, Rng};
use rand::seq::SliceRandom;
use std::str::FromStr;
use sha2::{Sha256, Digest};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::io::{Write, Read};
use std::time::Duration;
use crate::error::{DetailedError, JarmError};

const ALPN_EXTENSION: &[u8; 2] = b"\x00\x10";
const SOCKET_BUFFER: u64 = 1484;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);


pub struct JarmPart {
    pub raw: String
}

impl JarmPart {
    pub fn new(raw: &str) -> JarmPart {
        JarmPart {
            raw: raw.to_string(),
        }
    }
}

pub struct Jarm {
    pub parts: Vec<JarmPart>,
    pub queue: Vec<PacketSpecification>,
    pub rng: Box<dyn JarmRng + 'static>,
    pub timeout: Duration,
}

impl Default for Jarm {
    fn default() -> Self {
        Jarm::new("localhost".to_string(), "80".to_string())
    }
}

impl Jarm {
    pub fn new(host: String, port: String) -> Jarm {
        Jarm {
            parts: Vec::new(),
            queue: vec![
                //<editor-fold defaultstate="collapsed" desc="Packets and formats to send">
                PacketSpecification {
                    host: host.clone(),
                    port: port.clone(),
                    tls_version: TlsVersion::TLS1_2,
                    cipher_list: CipherList::ALL,
                    cipher_order: CipherOrder::FORWARD,
                    use_grease: false,
                    use_rare_apln: false,
                    tls_version_support: TlsVersionSupport::TLS1_2,
                    extension_order: CipherOrder::REVERSE,
                },
                PacketSpecification {
                    host: host.clone(),
                    port: port.clone(),
                    tls_version: TlsVersion::TLS1_2,
                    cipher_list: CipherList::ALL,
                    cipher_order: CipherOrder::REVERSE,
                    use_grease: false,
                    use_rare_apln: false,
                    tls_version_support: TlsVersionSupport::TLS1_2,
                    extension_order: CipherOrder::FORWARD,
                },
                PacketSpecification {
                    host: host.clone(),
                    port: port.clone(),
                    tls_version: TlsVersion::TLS1_2,
                    cipher_list: CipherList::ALL,
                    cipher_order: CipherOrder::TOP_HALF,
                    use_grease: false,
                    use_rare_apln: false,
                    tls_version_support: TlsVersionSupport::NO_SUPPORT,
                    extension_order: CipherOrder::FORWARD,
                },
                PacketSpecification {
                    host: host.clone(),
                    port: port.clone(),
                    tls_version: TlsVersion::TLS1_2,
                    cipher_list: CipherList::ALL,
                    cipher_order: CipherOrder::BOTTOM_HALF,
                    use_grease: false,
                    use_rare_apln: true,
                    tls_version_support: TlsVersionSupport::NO_SUPPORT,
                    extension_order: CipherOrder::FORWARD,
                },
                PacketSpecification {
                    host: host.clone(),
                    port: port.clone(),
                    tls_version: TlsVersion::TLS1_2,
                    cipher_list: CipherList::ALL,
                    cipher_order: CipherOrder::MIDDLE_OUT,
                    use_grease: true,
                    use_rare_apln: true,
                    tls_version_support: TlsVersionSupport::NO_SUPPORT,
                    extension_order: CipherOrder::REVERSE,
                },
                PacketSpecification {
                    host: host.clone(),
                    port: port.clone(),
                    tls_version: TlsVersion::TLS1_1,
                    cipher_list: CipherList::ALL,
                    cipher_order: CipherOrder::FORWARD,
                    use_grease: false,
                    use_rare_apln: false,
                    tls_version_support: TlsVersionSupport::NO_SUPPORT,
                    extension_order: CipherOrder::FORWARD,
                },
                PacketSpecification {
                    host: host.clone(),
                    port: port.clone(),
                    tls_version: TlsVersion::TLS1_3,
                    cipher_list: CipherList::ALL,
                    cipher_order: CipherOrder::FORWARD,
                    use_grease: false,
                    use_rare_apln: false,
                    tls_version_support: TlsVersionSupport::TLS1_3,
                    extension_order: CipherOrder::REVERSE,
                },
                PacketSpecification {
                    host: host.clone(),
                    port: port.clone(),
                    tls_version: TlsVersion::TLS1_3,
                    cipher_list: CipherList::ALL,
                    cipher_order: CipherOrder::REVERSE,
                    use_grease: false,
                    use_rare_apln: false,
                    tls_version_support: TlsVersionSupport::TLS1_3,
                    extension_order: CipherOrder::FORWARD,
                },
                PacketSpecification {
                    host: host.clone(),
                    port: port.clone(),
                    tls_version: TlsVersion::TLS1_3,
                    cipher_list: CipherList::NO1_3,
                    cipher_order: CipherOrder::FORWARD,
                    use_grease: false,
                    use_rare_apln: false,
                    tls_version_support: TlsVersionSupport::TLS1_3,
                    extension_order: CipherOrder::FORWARD,
                },
                PacketSpecification {
                    host,
                    port,
                    tls_version: TlsVersion::TLS1_3,
                    cipher_list: CipherList::ALL,
                    cipher_order: CipherOrder::MIDDLE_OUT,
                    use_grease: true,
                    use_rare_apln: false,
                    tls_version_support: TlsVersionSupport::TLS1_3,
                    extension_order: CipherOrder::REVERSE,
                },
                //</editor-fold>
            ],
            rng: Box::new(PseudoRng {}),
            timeout: DEFAULT_TIMEOUT
        }
    }

    pub fn retrieve_parts(&mut self) -> Result<Vec<JarmPart>, JarmError> {
        let mut parts = Vec::new();
        for spec in &self.queue {
            let payload = build_packet(spec, self.rng.as_ref());

            // Send packet
            let url = format!("{}:{}", spec.host, spec.port);
            let address = resolve(url)?;  // Resolve the ip if needed
            let mut data = [0_u8; SOCKET_BUFFER as usize];
            match TcpStream::connect_timeout(&address, self.timeout) {
                Ok(mut stream) => {
                    stream.write_all(&payload).unwrap();
                    let mut handle = stream.take(SOCKET_BUFFER);
                    let _read_result = handle.read(&mut data)?;
                },
                Err(e) => return Err(JarmError::Connection(DetailedError::from(Box::from(e))))
            }
            let jarm_part = read_packet(Vec::from(data));
            parts.push(jarm_part);
        }
        Ok(parts)
    }

    pub fn hash(&mut self) -> Result<String, JarmError> {
        if self.parts.is_empty(){
            self.parts = self.retrieve_parts()?
        }
        if self.parts.iter().all(|p| p.raw == "|||") {
            return Ok("0".repeat(62));
        }

        let mut fuzzy_hash = String::new();
        let mut alpns_and_ext = String::new();

        for part in &self.parts {
            let components: Vec<&str> = part.raw.split('|').collect();
            // Custom jarm hash includes a fuzzy hash of the ciphers and versions
            fuzzy_hash.push_str(&cipher_bytes(components[0]));
            fuzzy_hash.push(version_byte(components[1]));
            alpns_and_ext.push_str(components[2]);
            alpns_and_ext.push_str(components[3]);
        }

        // Custom jarm hash has the sha256 of alpns and extensions added to the end
        let mut hasher = Sha256::new();
        hasher.update(alpns_and_ext.into_bytes());
        let sha256 = hex::encode(hasher.finalize());
        fuzzy_hash.push_str(sha256.get(0..32).unwrap());
        Ok(fuzzy_hash)
    }
}

#[derive(PartialEq, Eq)]
pub enum TlsVersion {
    TLS1_1,
    TLS1_2,
    TLS1_3,
}

#[derive(PartialEq, Eq)]
pub enum CipherList {
    ALL,
    NO1_3,
}

#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq)]
pub enum CipherOrder {
    FORWARD,
    REVERSE,
    TOP_HALF,
    BOTTOM_HALF,
    MIDDLE_OUT,
}

#[allow(non_camel_case_types)]
#[derive(PartialEq, Eq)]
pub enum TlsVersionSupport {
    TLS1_2,
    TLS1_3,
    NO_SUPPORT,
}

pub struct PacketSpecification {
    pub host: String,
    pub port: String,
    pub tls_version: TlsVersion,
    pub cipher_list: CipherList,
    pub cipher_order: CipherOrder,
    pub use_grease: bool,
    pub use_rare_apln: bool,
    pub tls_version_support: TlsVersionSupport,
    pub extension_order: CipherOrder,
}


pub fn build_packet(jarm_details: &PacketSpecification, rng: &dyn JarmRng) -> Vec<u8> {
    let mut client_hello = Vec::new();
    let mut payload= b"\x16".to_vec();

    match jarm_details.tls_version {
        TlsVersion::TLS1_1 => {
            payload.extend(b"\x03\x02");
            client_hello.extend(b"\x03\x02");
        }
        TlsVersion::TLS1_2 => {
            payload.extend(b"\x03\x03");
            client_hello.extend(b"\x03\x03");
        }
        TlsVersion::TLS1_3 => {
            payload.extend(b"\x03\x01");
            client_hello.extend(b"\x03\x03");
        }
    }

    client_hello.extend(rng.random_bytes());
    let session_id = rng.random_bytes();
    let session_id_length = pack_as_unsigned_char(session_id.len());
    client_hello.push(session_id_length);
    client_hello.extend(session_id);

    let cipher_choice = get_ciphers(jarm_details, rng);
    let client_suites_length = pack_as_unsigned_short(cipher_choice.len());
    client_hello.extend(client_suites_length);
    client_hello.extend(cipher_choice);
    client_hello.push(b'\x01');  // cipher methods
    client_hello.push(b'\x00');  // compression_methods
    client_hello.extend(get_extensions(jarm_details, rng));

    // Finish packet assembly
    let mut inner_length = b"\x00".to_vec();
    inner_length.extend(pack_as_unsigned_short(client_hello.len()));
    let mut handshake_protocol = b"\x01".to_vec();
    handshake_protocol.extend(inner_length);
    handshake_protocol.extend(client_hello);
    let outer_length = pack_as_unsigned_short(handshake_protocol.len());
    payload.extend(outer_length);
    payload.extend(handshake_protocol);
    payload
}

pub fn pack_as_unsigned_char(n: usize) -> u8 {
    if n >= 256 {
        panic!("Can't pack_as_unsigned_char {:?} as it is over 255", n)
    }
    n as u8
}

pub fn pack_as_unsigned_short(n: usize) -> Vec<u8> {
    vec![(n >> 8) as u8, n as u8]
}

pub fn get_ciphers(jarm_details: &PacketSpecification, rng: &dyn JarmRng) -> Vec<u8> {
    // TODO implement all
    let mut selected_ciphers = Vec::new();

    let mut list = match jarm_details.cipher_list {
        CipherList::ALL => {
            vec![b"\x00\x16".to_vec(), b"\x00\x33".to_vec(), b"\x00\x67".to_vec(), b"\xc0\x9e".to_vec(), b"\xc0\xa2".to_vec(), b"\x00\x9e".to_vec(), b"\x00\x39".to_vec(), b"\x00\x6b".to_vec(),
                b"\xc0\x9f".to_vec(), b"\xc0\xa3".to_vec(), b"\x00\x9f".to_vec(), b"\x00\x45".to_vec(), b"\x00\xbe".to_vec(), b"\x00\x88".to_vec(), b"\x00\xc4".to_vec(), b"\x00\x9a".to_vec(),
                b"\xc0\x08".to_vec(), b"\xc0\x09".to_vec(), b"\xc0\x23".to_vec(), b"\xc0\xac".to_vec(), b"\xc0\xae".to_vec(), b"\xc0\x2b".to_vec(), b"\xc0\x0a".to_vec(), b"\xc0\x24".to_vec(),
                b"\xc0\xad".to_vec(), b"\xc0\xaf".to_vec(), b"\xc0\x2c".to_vec(), b"\xc0\x72".to_vec(), b"\xc0\x73".to_vec(), b"\xcc\xa9".to_vec(), b"\x13\x02".to_vec(), b"\x13\x01".to_vec(),
                b"\xcc\x14".to_vec(), b"\xc0\x07".to_vec(), b"\xc0\x12".to_vec(), b"\xc0\x13".to_vec(), b"\xc0\x27".to_vec(), b"\xc0\x2f".to_vec(), b"\xc0\x14".to_vec(), b"\xc0\x28".to_vec(),
                b"\xc0\x30".to_vec(), b"\xc0\x60".to_vec(), b"\xc0\x61".to_vec(), b"\xc0\x76".to_vec(), b"\xc0\x77".to_vec(), b"\xcc\xa8".to_vec(), b"\x13\x05".to_vec(), b"\x13\x04".to_vec(),
                b"\x13\x03".to_vec(), b"\xcc\x13".to_vec(), b"\xc0\x11".to_vec(), b"\x00\x0a".to_vec(), b"\x00\x2f".to_vec(), b"\x00\x3c".to_vec(), b"\xc0\x9c".to_vec(), b"\xc0\xa0".to_vec(),
                b"\x00\x9c".to_vec(), b"\x00\x35".to_vec(), b"\x00\x3d".to_vec(), b"\xc0\x9d".to_vec(), b"\xc0\xa1".to_vec(), b"\x00\x9d".to_vec(), b"\x00\x41".to_vec(), b"\x00\xba".to_vec(),
                b"\x00\x84".to_vec(), b"\x00\xc0".to_vec(), b"\x00\x07".to_vec(), b"\x00\x04".to_vec(), b"\x00\x05".to_vec(),
            ]
        }
        CipherList::NO1_3 => {
            vec![b"\x00\x16".to_vec(), b"\x00\x33".to_vec(), b"\x00\x67".to_vec(), b"\xc0\x9e".to_vec(), b"\xc0\xa2".to_vec(), b"\x00\x9e".to_vec(), b"\x00\x39".to_vec(), b"\x00\x6b".to_vec(),
                b"\xc0\x9f".to_vec(), b"\xc0\xa3".to_vec(), b"\x00\x9f".to_vec(), b"\x00\x45".to_vec(), b"\x00\xbe".to_vec(), b"\x00\x88".to_vec(), b"\x00\xc4".to_vec(), b"\x00\x9a".to_vec(),
                b"\xc0\x08".to_vec(), b"\xc0\x09".to_vec(), b"\xc0\x23".to_vec(), b"\xc0\xac".to_vec(), b"\xc0\xae".to_vec(), b"\xc0\x2b".to_vec(), b"\xc0\x0a".to_vec(), b"\xc0\x24".to_vec(),
                b"\xc0\xad".to_vec(), b"\xc0\xaf".to_vec(), b"\xc0\x2c".to_vec(), b"\xc0\x72".to_vec(), b"\xc0\x73".to_vec(), b"\xcc\xa9".to_vec(), b"\xcc\x14".to_vec(), b"\xc0\x07".to_vec(),
                b"\xc0\x12".to_vec(), b"\xc0\x13".to_vec(), b"\xc0\x27".to_vec(), b"\xc0\x2f".to_vec(), b"\xc0\x14".to_vec(), b"\xc0\x28".to_vec(), b"\xc0\x30".to_vec(), b"\xc0\x60".to_vec(),
                b"\xc0\x61".to_vec(), b"\xc0\x76".to_vec(), b"\xc0\x77".to_vec(), b"\xcc\xa8".to_vec(), b"\xcc\x13".to_vec(), b"\xc0\x11".to_vec(), b"\x00\x0a".to_vec(), b"\x00\x2f".to_vec(),
                b"\x00\x3c".to_vec(), b"\xc0\x9c".to_vec(), b"\xc0\xa0".to_vec(), b"\x00\x9c".to_vec(), b"\x00\x35".to_vec(), b"\x00\x3d".to_vec(), b"\xc0\x9d".to_vec(), b"\xc0\xa1".to_vec(),
                b"\x00\x9d".to_vec(), b"\x00\x41".to_vec(), b"\x00\xba".to_vec(), b"\x00\x84".to_vec(), b"\x00\xc0".to_vec(), b"\x00\x07".to_vec(), b"\x00\x04".to_vec(), b"\x00\x05".to_vec(),
            ]
        }
    };

    cipher_mung(&mut list, &jarm_details.cipher_order);
    if jarm_details.use_grease {
        list.insert(0, rng.random_grease());
    }

    for x in list {
        selected_ciphers.extend(x);
    }
    selected_ciphers
}

pub fn get_extensions(jarm_details: &PacketSpecification, rng: &dyn JarmRng) -> Vec<u8> {
    let mut extension_bytes = Vec::new();
    let mut all_extensions = Vec::new();

    if jarm_details.use_grease {
        all_extensions.extend(rng.random_grease());
        all_extensions.extend(b"\x00\x00");
    }
    all_extensions.extend(extension_server_name(jarm_details));

    // Other extensions
    let extended_master_secret = b"\x00\x17\x00\x00";
    all_extensions.extend(extended_master_secret);
    let max_fragment_length = b"\x00\x01\x00\x01\x01";
    all_extensions.extend(max_fragment_length);
    let renegotiation_info = b"\xff\x01\x00\x01\x00";
    all_extensions.extend(renegotiation_info);
    let supported_groups = b"\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19";
    all_extensions.extend(supported_groups);
    let ec_point_formats = b"\x00\x0b\x00\x02\x01\x00";
    all_extensions.extend(ec_point_formats);
    let session_ticket = b"\x00\x23\x00\x00";
    all_extensions.extend(session_ticket);

    // Application Layer Protocol Negotiation extension
    all_extensions.extend(aplns(jarm_details));
    let signature_algorithms = b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01";
    all_extensions.extend(signature_algorithms);

    // Key share extension
    all_extensions.extend(key_share(jarm_details.use_grease, rng));
    let psk_key_exchange_modes = b"\x00\x2d\x00\x02\x01\x01";
    all_extensions.extend(psk_key_exchange_modes);

    if jarm_details.tls_version == TlsVersion::TLS1_3
        || jarm_details.tls_version_support == TlsVersionSupport::TLS1_2 {
        all_extensions.extend(supported_versions(jarm_details, rng));
    }

    extension_bytes.extend(pack_as_unsigned_short(all_extensions.len()));
    extension_bytes.extend(all_extensions);
    extension_bytes
}

pub fn extension_server_name(jarm_details: &PacketSpecification) -> Vec<u8> {
    let mut ext_sni = b"\x00\x00".to_vec();
    let host_length = jarm_details.host.len();
    let ext_sni_length = host_length + 5;
    ext_sni.extend(pack_as_unsigned_short(ext_sni_length));

    let ext_sni_length2 = host_length + 3;
    ext_sni.extend(pack_as_unsigned_short(ext_sni_length2));
    ext_sni.push(b'\x00');

    let ext_sni_length3 = host_length;
    ext_sni.extend(pack_as_unsigned_short(ext_sni_length3));

    ext_sni.extend(jarm_details.host.bytes());
    ext_sni
}

// Client hello apln extension
pub fn aplns(jarm_details: &PacketSpecification) -> Vec<u8> {
    let mut ext = b"\x00\x10".to_vec();
    let mut alpns: Vec<Vec<u8>> = if jarm_details.use_rare_apln {
        vec![
            b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39".to_vec(),
            b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30".to_vec(),
            b"\x06\x73\x70\x64\x79\x2f\x31".to_vec(),
            b"\x06\x73\x70\x64\x79\x2f\x32".to_vec(),
            b"\x06\x73\x70\x64\x79\x2f\x33".to_vec(),
            b"\x03\x68\x32\x63".to_vec(),
            b"\x02\x68\x71".to_vec(),
        ]
    } else {
        vec![
            b"\x08\x68\x74\x74\x70\x2f\x30\x2e\x39".to_vec(),
            b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x30".to_vec(),
            b"\x08\x68\x74\x74\x70\x2f\x31\x2e\x31".to_vec(),
            b"\x06\x73\x70\x64\x79\x2f\x31".to_vec(),
            b"\x06\x73\x70\x64\x79\x2f\x32".to_vec(),
            b"\x06\x73\x70\x64\x79\x2f\x33\x02\x68\x32".to_vec(),
            b"\x03\x68\x32\x63".to_vec(),
            b"\x02\x68\x71".to_vec()
        ]
    };

    cipher_mung(&mut alpns, &jarm_details.extension_order);

    // flatten the alpns
    let mut all_alpns = Vec::new();
    for alpn in alpns {
        all_alpns.extend(alpn);
    }

    let second_length  = all_alpns.len();
    let first_length = second_length + 2;
    ext.extend(pack_as_unsigned_short(first_length));
    ext.extend(pack_as_unsigned_short(second_length));
    ext.extend(all_alpns);
    ext
}

pub fn cipher_mung(ciphers: &mut Vec<Vec<u8>>, cipher_order: &CipherOrder) {
    match cipher_order {
        CipherOrder::FORWARD => {}  // nothing to do
        CipherOrder::REVERSE => { ciphers.reverse() }
        CipherOrder::TOP_HALF => {
            // Top half gets the middle cipher if needed
            let middle_one = if ciphers.len() % 2 == 1 {
                Some(ciphers[ciphers.len() / 2].clone())
            } else {
                None
            };
            cipher_mung(ciphers, &CipherOrder::REVERSE);
            cipher_mung(ciphers, &CipherOrder::BOTTOM_HALF);

            if let Some(x) = middle_one {
                ciphers.insert(0, x);
            }
        }
        CipherOrder::BOTTOM_HALF => {
            let mut range_to_drain = 0..ciphers.len() / 2;
            if ciphers.len() % 2 == 1 {
                // Also remove the middle one if the length is odd
                range_to_drain.end += 1;
            }
            ciphers.drain(range_to_drain);

        }
        CipherOrder::MIDDLE_OUT => {
            let middle = ciphers.len() / 2;
            let mut output = Vec::new();
            if ciphers.len() % 2 == 1 {
                // output.append(ciphers[middle])
                output.push(ciphers[middle].clone());

                for i in 1..middle+1 {
                    output.push(ciphers[middle + i].clone());
                    output.push(ciphers[middle - i].clone());
                }
            } else {
                for i in 1..middle+1 {
                    output.push(ciphers[middle - 1 + i].clone());
                    output.push(ciphers[middle - i].clone());
                }
            }
            *ciphers = output;
        }
    }
}

pub fn key_share(grease: bool, rng: &dyn JarmRng) -> Vec<u8> {
    let mut ext = b"\x00\x33".to_vec();

    let mut share_ext = if grease {
        let mut grease_start = rng.random_grease();
        grease_start.extend(b"\x00\x01\x00");
        grease_start
    } else {
        Vec::new()
    };
    share_ext.extend(b"\x00\x1d");  // group
    share_ext.extend(b"\x00\x20");  // key_exchange_length
    share_ext.extend(rng.random_bytes());  // key_exchange_length

    let second_length  = share_ext.len();
    let first_length = second_length + 2;
    ext.extend(pack_as_unsigned_short(first_length));
    ext.extend(pack_as_unsigned_short(second_length));
    ext.extend(share_ext);
    ext
}

pub fn supported_versions(jarm_details: &PacketSpecification, rng: &dyn JarmRng) -> Vec<u8> {
    let mut tls = if jarm_details.tls_version_support == TlsVersionSupport::TLS1_2 {
        vec![b"\x03\x01".to_vec(), b"\x03\x02".to_vec(), b"\x03\x03".to_vec()]
    } else {  // TLS 1.3 is supported
        vec![b"\x03\x01".to_vec(), b"\x03\x02".to_vec(), b"\x03\x03".to_vec(), b"\x03\x04".to_vec()]
    };
    cipher_mung(&mut tls, &jarm_details.extension_order);

    // Assemble the extension
    let mut ext = b"\x00\x2b".to_vec();
    let mut versions = if jarm_details.use_grease {
        rng.random_grease()
    } else {
        Vec::new()
    };

    for version in tls {
        versions.extend(version);
    }

    let second_length  = versions.len();
    let first_length = second_length + 1;
    ext.extend(pack_as_unsigned_short(first_length));
    ext.push(pack_as_unsigned_char(second_length));
    ext.extend(versions);
    ext
}

pub fn read_packet(data: Vec<u8>) -> JarmPart {
    if (data[0] != 22) || (data[5] != 2){
        return JarmPart::new("|||");  // Default jarm
    }

    let mut jarm = String::new();
    let counter = data[43];

    // Find server's selected cipher
    let start: usize = (counter + 44) as usize;
    let end: usize = (counter + 45) as usize;
    let selected_cipher = &data[start..=end];

    // Find server's selected version
    let version_start: usize = 9;
    let version_end: usize = 10;
    let version = &data[version_start..=version_end];

    // Format
    jarm += &*hex::encode(selected_cipher);
    jarm += "|";
    jarm += &*hex::encode(version);
    jarm += "|";

    // Extract extensions
    let extensions = extract_extension_info(data, counter);
    jarm += &*extensions;
    JarmPart { raw: jarm}
}

// Convert bytes array to u32
pub fn as_u32_be(array: &[u8]) -> u32 {
    if array.len() != 2 {
        eprintln!("array = {:?}", array);
        unimplemented!()  // not needed for now
    }
    ((array[0] as u32) << 8) + (array[1] as u32)
}

pub fn extract_extension_info(data: Vec<u8>, counter: u8) -> String {
    // Error handling
    //TODO

    // Collect types and value
    let mut count = 49 + counter as u32;
    let length_start: usize = (counter + 47) as usize;
    let length_end: usize = (counter + 48) as usize;

    let length_slice: &[u8] = &data[length_start..=length_end];
    let length = as_u32_be(length_slice);
    let maximum = length + (count - 1);

    let mut types: Vec<&[u8]> = Vec::new();
    let mut values: Vec<Option<&[u8]>> = Vec::new();

    while count < maximum {
        let slice_start = count as usize;
        types.push(&data[slice_start..slice_start+2]);

        let ext_length_start = (count + 2) as usize;
        let ext_length_end = ext_length_start + 2;
        let ext_length_slice: &[u8] = &data[ext_length_start..ext_length_end];
        let ext_length = as_u32_be(ext_length_slice);

        if ext_length == 0 {
            values.push(None);  // TODO FIXME
            count += 4;
        } else {
            let value = &data[slice_start + 4..slice_start + 4 + ext_length as usize];
            values.push(Some(value));
            count += ext_length + 4
        }
    }

    // Read application_layer_protocol_negotiation
    let alpn = find_extension(&types, values);

    let formatted_types = add_formatting_hyphen(&types);
    format!("{}|{}", alpn, formatted_types)
}

pub fn add_formatting_hyphen(types: &[&[u8]]) -> String {
    let types_hex_encoded: Vec<String> = types.iter().map(hex::encode).collect();
    types_hex_encoded.join("-")
}


pub fn find_extension(types: &[&[u8]], values: Vec<Option<&[u8]>>) -> String {
    let mut i = 0;
    while i < types.len() {
        if types.get(i).unwrap() == ALPN_EXTENSION {
            let x = values.get(i).unwrap();
            match x {
                None => {}
                Some(y) => {
                    match std::str::from_utf8(&y[3..]) {
                        Ok(s) => return s.to_string(),
                        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                    };
                }
            }
        }
        i += 1
    }
    "".to_string()
}

pub fn cipher_bytes(cipher: &str) -> String {
    if cipher.is_empty() {
        return "00".to_string()
    }

    let list = vec![
        b"\x00\x04", b"\x00\x05", b"\x00\x07", b"\x00\x0a", b"\x00\x16", b"\x00\x2f", b"\x00\x33", b"\x00\x35",
        b"\x00\x39", b"\x00\x3c", b"\x00\x3d", b"\x00\x41", b"\x00\x45", b"\x00\x67", b"\x00\x6b", b"\x00\x84",
        b"\x00\x88", b"\x00\x9a", b"\x00\x9c", b"\x00\x9d", b"\x00\x9e", b"\x00\x9f", b"\x00\xba", b"\x00\xbe",
        b"\x00\xc0", b"\x00\xc4", b"\xc0\x07", b"\xc0\x08", b"\xc0\x09", b"\xc0\x0a", b"\xc0\x11", b"\xc0\x12",
        b"\xc0\x13", b"\xc0\x14", b"\xc0\x23", b"\xc0\x24", b"\xc0\x27", b"\xc0\x28", b"\xc0\x2b", b"\xc0\x2c",
        b"\xc0\x2f", b"\xc0\x30", b"\xc0\x60", b"\xc0\x61", b"\xc0\x72", b"\xc0\x73", b"\xc0\x76", b"\xc0\x77",
        b"\xc0\x9c", b"\xc0\x9d", b"\xc0\x9e", b"\xc0\x9f", b"\xc0\xa0", b"\xc0\xa1", b"\xc0\xa2", b"\xc0\xa3",
        b"\xc0\xac", b"\xc0\xad", b"\xc0\xae", b"\xc0\xaf", b"\xcc\x13", b"\xcc\x14", b"\xcc\xa8", b"\xcc\xa9",
        b"\x13\x01", b"\x13\x02", b"\x13\x03", b"\x13\x04", b"\x13\x05"
    ];
    let count = match list.iter().position(|&bytes| hex::encode(bytes) == cipher) {
        None => { panic!("cipher not expected {:?}", cipher)}
        Some(index) => { index + 1 }
    };

    let hex_value = hex::encode(count.to_be_bytes());
    hex_value.get(hex_value.len() - 2..hex_value.len()).unwrap().to_string()
}

pub fn version_byte(version: &str) -> char {
    if version.is_empty() {
        return '0';
    }
    let option = "abcdef".to_string();
    let version_index: usize = 3;
    let count: usize = match version.get(version_index..version_index+1) {
        None => { panic!("version not expected {:?}", version)}
        Some(str_count) => { usize::from_str(str_count).unwrap() }
    };
    option.chars().nth(count).unwrap()
}


/// Resolve the given url to an ip
/// the first ip found is returned, else an error is raised.
fn resolve(url: String) -> Result<SocketAddr, JarmError> {
    let mut ips = match url.to_socket_addrs() {
        Ok(address) => address,
        Err(e) => {
            let error = DetailedError::from(Box::from(e));
            return Err(JarmError::DnsResolve(error))
        },
    };
    if let Some(address) = ips.next() {
        Ok(address)
    } else {
        Err(JarmError::DnsResolve(DetailedError::default()))
    }
}


pub trait JarmRng {
    fn random_bytes(&self) -> Vec<u8>;

    fn random_grease(&self) -> Vec<u8>;
}

pub struct PseudoRng {}

pub struct TestRng {}

impl JarmRng for TestRng {  // Mocked Rng used in tests
    fn random_bytes(&self) -> Vec<u8> {
        vec![42; 32]
    }

    fn random_grease(&self) -> Vec<u8> {
        b"\x0a\x0a".to_vec()
    }
}

impl JarmRng for PseudoRng {  // Real Rng used outside of tests
    fn random_bytes(&self) -> Vec<u8> {
        let mut rng = thread_rng();
        rng.gen::<[u8; 32]>().to_vec()
    }

    fn random_grease(&self) -> Vec<u8> {
        let grease_list = vec![
            b"\x0a\x0a".to_vec(),
            b"\x1a\x1a".to_vec(),
            b"\x2a\x2a".to_vec(),
            b"\x3a\x3a".to_vec(),
            b"\x4a\x4a".to_vec(),
            b"\x5a\x5a".to_vec(),
            b"\x6a\x6a".to_vec(),
            b"\x7a\x7a".to_vec(),
            b"\x8a\x8a".to_vec(),
            b"\x9a\x9a".to_vec(),
            b"\xaa\xaa".to_vec(),
            b"\xba\xba".to_vec(),
            b"\xca\xca".to_vec(),
            b"\xda\xda".to_vec(),
            b"\xea\xea".to_vec(),
            b"\xfa\xfa".to_vec(),
        ];
        grease_list.choose(&mut rand::thread_rng()).unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use rstest::*;
    use crate::resolve;
    use crate::error::JarmError;

    #[rstest]
    #[case("invalid_url")]
    #[case("google.com")]  // missing port
    fn test_dns_resolve_error(#[case] invalid_url: String) {
        let expected_error = "invalid socket address";
        let error = resolve(invalid_url).err().unwrap();
        if let JarmError::DnsResolve(err) = error {
            let underlying_error = err.underlying_error.unwrap();
            assert_eq!(underlying_error.to_string(), expected_error);
        } else { panic!("unexpected type") }
    }
}