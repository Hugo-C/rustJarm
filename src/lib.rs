const ALPN_EXTENSION: &[u8; 2] = b"\x00\x10";

pub enum TlsVersion {
    TLS1_1,
    TLS1_2,
    TLS1_3,
}

pub enum CipherList {
    ALL,
    NO1_3,
}

pub enum CipherOrder {
    FORWARD,
    REVERSE,
    TOP_HALF,
    BOTTOM_HALF,
    MIDDLE_OUT,
}

pub enum TlsVersionSupport {
    TLS1_2,
    TLS1_3,
    NO_SUPPORT,
}

pub enum ExtensionOrder {
    FORWARD,
    REVERSE,
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
    pub extension_order: ExtensionOrder,
}


pub fn build_packet(spec: &PacketSpecification) -> &'static [u8; 442] {  // TODO
    return b"\x16\x03\x03\x01\xb5\x01\x00\x01\xb1\x03\x03\xf4\xd2y\xb3I9\t\xf6\xbfz\x86{\xba+\x145Z3#\xd2\xe8\xee_\xb2\x9b5eT\xbeE\xb1\x81 &!\x1am\xa9\xe8t\t\xda\x01\r\xde \xf6\xe8\x10\xe0\x07E'\xcf@\xbaD\xad\xabD\xb4\xc5P\xee\x9a\x00\x8a\x00\x16\x003\x00g\xc0\x9e\xc0\xa2\x00\x9e\x009\x00k\xc0\x9f\xc0\xa3\x00\x9f\x00E\x00\xbe\x00\x88\x00\xc4\x00\x9a\xc0\x08\xc0\t\xc0#\xc0\xac\xc0\xae\xc0+\xc0\n\xc0$\xc0\xad\xc0\xaf\xc0,\xc0r\xc0s\xcc\xa9\x13\x02\x13\x01\xcc\x14\xc0\x07\xc0\x12\xc0\x13\xc0'\xc0/\xc0\x14\xc0(\xc00\xc0`\xc0a\xc0v\xc0w\xcc\xa8\x13\x05\x13\x04\x13\x03\xcc\x13\xc0\x11\x00\n\x00/\x00<\xc0\x9c\xc0\xa0\x00\x9c\x005\x00=\xc0\x9d\xc0\xa1\x00\x9d\x00A\x00\xba\x00\x84\x00\xc0\x00\x07\x00\x04\x00\x05\x01\x00\x00\xde\x00\x00\x00!\x00\x1f\x00\x00\x1cjsonplaceholder.typicode.com\x00\x17\x00\x00\x00\x01\x00\x01\x01\xff\x01\x00\x01\x00\x00\n\x00\n\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00#\x00\x00\x00\x10\x00<\x00:\x02hq\x03h2c\x06spdy/3\x02h2\x06spdy/2\x06spdy/1\x08http/1.1\x08http/1.0\x08http/0.9\x00\r\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 Z]6\x15\xb6?\xd8\xd4\xd1]\xee\xc1\x81\x99\xfe\x01\xf3\t\xdf\x83\xae\xd7\x8b\xb4\xf5\t\x11\x17\x08\xda\x82\x01\x00-\x00\x02\x01\x01\x00+\x00\x07\x06\x03\x03\x03\x02\x03\x01";
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
    ((array[0] as u32) << 8) + ((array[1] as u32) << 0)
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

pub fn add_formatting_hyphen(types: &Vec<&[u8]>) -> String {
    let types_hex_encoded: Vec<String> = types.iter().map(
        |t| hex::encode(t)
    ).collect();
    types_hex_encoded.join("-")
}


pub fn find_extension(types: &Vec<&[u8]>, values: Vec<Option<&[u8]>>) -> String {
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
    return "".to_string();
}


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