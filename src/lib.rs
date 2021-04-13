use rand::{thread_rng, Rng};
use rand::seq::SliceRandom;

const ALPN_EXTENSION: &[u8; 2] = b"\x00\x10";

pub struct Jarm {
    pub raw: String
}

impl Jarm {
    fn new(raw: &str) -> Jarm {
        Jarm{
            raw: raw.to_string(),
        }
    }
}

#[derive(PartialEq)]
pub enum TlsVersion {
    TLS1_1,
    TLS1_2,
    TLS1_3,
}

#[derive(PartialEq)]
pub enum CipherList {
    ALL,
    NO1_3,
}

#[derive(PartialEq)]
pub enum CipherOrder {
    FORWARD,
    REVERSE,
    TOP_HALF,
    BOTTOM_HALF,
    MIDDLE_OUT,
}

#[derive(PartialEq)]
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


pub fn build_packet(jarm_details: &PacketSpecification) -> Vec<u8> {
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

    client_hello.extend(random_bytes());
    let session_id = random_bytes();  // TODO mock for unittest
    let session_id_length = pack_as_unsigned_char(session_id.len());
    client_hello.push(session_id_length);
    client_hello.extend(session_id);

    let cipher_choice = get_ciphers(jarm_details);
    let client_suites_length = pack_as_unsigned_short(cipher_choice.len());
    client_hello.extend(client_suites_length);
    client_hello.extend(cipher_choice);
    client_hello.push(b'\x01');  // cipher methods
    client_hello.push(b'\x00');  // compression_methods
    client_hello.extend(get_extensions(jarm_details));

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

// mocked version TODO find a way to use it only for tests
pub fn random_bytes() -> Vec<u8> {
    vec![42; 32]
}

// mocked version TODO find a way to use it only for tests
pub fn random_grease() -> Vec<u8> {
    b"\x0a\x0a".to_vec()
}

// #[cfg(not(test))]
// pub fn grease() -> Vec<u8> {
//     let grease_list = vec![
//         b"\x0a\x0a".to_vec(),
//         b"\x1a\x1a".to_vec(),
//         b"\x2a\x2a".to_vec(),
//         b"\x3a\x3a".to_vec(),
//         b"\x4a\x4a".to_vec(),
//         b"\x5a\x5a".to_vec(),
//         b"\x6a\x6a".to_vec(),
//         b"\x7a\x7a".to_vec(),
//         b"\x8a\x8a".to_vec(),
//         b"\x9a\x9a".to_vec(),
//         b"\xaa\xaa".to_vec(),
//         b"\xba\xba".to_vec(),
//         b"\xca\xca".to_vec(),
//         b"\xda\xda".to_vec(),
//         b"\xea\xea".to_vec(),
//         b"\xfa\xfa".to_vec(),
//     ];
//     grease_list.choose(&mut rand::thread_rng()).unwrap().clone()
// }

// #[cfg(not(test))]
// pub fn random_bytes() -> Vec<u8> {
//     let mut rng = thread_rng();
//     rng.gen::<[u8; 32]>().to_vec()
// }

pub fn pack_as_unsigned_char(n: usize) -> u8 {
    if n >= 256 {
        panic!("Can't pack_as_unsigned_char {:?} as it is over 255", n)
    }
    n as u8
}

pub fn pack_as_unsigned_short(n: usize) -> Vec<u8> {
    vec![(n >> 8) as u8, n as u8]
}

pub fn get_ciphers(jarm_details: &PacketSpecification) -> Vec<u8> {
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
        list.insert(0, random_grease());
    }

    for x in list {
        selected_ciphers.extend(x);
    }
    selected_ciphers
}

pub fn get_extensions(jarm_details: &PacketSpecification) -> Vec<u8> {
    let mut extension_bytes = Vec::new();
    let mut all_extensions = Vec::new();

    if jarm_details.use_grease {
        all_extensions.extend(random_grease());
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
    all_extensions.extend(key_share(jarm_details.use_grease));
    let psk_key_exchange_modes = b"\x00\x2d\x00\x02\x01\x01";
    all_extensions.extend(psk_key_exchange_modes);

    if jarm_details.tls_version == TlsVersion::TLS1_3
        || jarm_details.tls_version_support == TlsVersionSupport::TLS1_2 {
        all_extensions.extend(supported_versions(jarm_details));
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
    eprintln!("ext = {:?}", ext);
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

pub fn key_share(grease: bool) -> Vec<u8> {
    let mut ext = b"\x00\x33".to_vec();

    let mut share_ext = if grease {
        let mut grease_start = random_grease();
        grease_start.extend(b"\x00\x01\x00");
        grease_start
    } else {
        Vec::new()
    };
    share_ext.extend(b"\x00\x1d");  // group
    share_ext.extend(b"\x00\x20");  // key_exchange_length
    share_ext.extend(random_bytes());  // key_exchange_length

    let second_length  = share_ext.len();
    let first_length = second_length + 2;
    ext.extend(pack_as_unsigned_short(first_length));
    ext.extend(pack_as_unsigned_short(second_length));
    ext.extend(share_ext);
    ext
}

pub fn supported_versions(jarm_details: &PacketSpecification) -> Vec<u8> {
    let mut tls = if jarm_details.tls_version_support == TlsVersionSupport::TLS1_2 {
        vec![b"\x03\x01".to_vec(), b"\x03\x02".to_vec(), b"\x03\x03".to_vec()]
    } else {  // TLS 1.3 is supported
        vec![b"\x03\x01".to_vec(), b"\x03\x02".to_vec(), b"\x03\x03".to_vec(), b"\x03\x04".to_vec()]
    };
    cipher_mung(&mut tls, &jarm_details.extension_order);

    // Assemble the extension
    let mut ext = b"\x00\x2b".to_vec();
    let mut versions = if jarm_details.use_grease {
        random_grease()
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

pub fn read_packet(data: Vec<u8>) -> Jarm {
    if (data[0] != 22) || (data[5] != 2){
        return Jarm::new("|||");  // Default jarm
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
    Jarm { raw: jarm}
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
    let length_start: usize = 47;
    let length_end: usize = 48;
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
            values.push(Some(&value));
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
