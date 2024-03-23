#[cfg(test)]
mod tests {
    use rstest::rstest;
    use rust_jarm::{PacketSpecification, TlsVersion, CipherList, CipherOrder, TlsVersionSupport, Jarm, JarmPart, cipher_bytes, version_byte, TestRng, JarmRng, PseudoRng};

    fn test_rng() -> TestRng {
        TestRng {}
    }

    #[test]
    fn test_jarm_hash() {
        let expected_hash = "27d27d27d27d27d27d27d27d27d27debd865e63a4441da99411bab3aadfedf".to_string();

        let mut jarm = Jarm::default();
        jarm.parts = vec![
            JarmPart::new("c02b|0303|h2|0000-0017-ff01-000b-0023-0010"),
            JarmPart::new("c02b|0303|h2|0000-0017-ff01-000b-0023-0010"),
            JarmPart::new("c02b|0303|h2|0000-0017-ff01-000b-0023-0010"),
            JarmPart::new("c02b|0303|h2|0000-0017-ff01-000b-0023-0010"),
            JarmPart::new("c02b|0303|h2|0000-0017-ff01-000b-0023-0010"),
            JarmPart::new("c02b|0303|h2|0000-0017-ff01-000b-0023-0010"),
            JarmPart::new("c02b|0303|h2|0000-0017-ff01-000b-0023-0010"),
            JarmPart::new("c02b|0303|h2|0000-0017-ff01-000b-0023-0010"),
            JarmPart::new("c02b|0303|h2|0000-0017-ff01-000b-0023-0010"),
            JarmPart::new("c02b|0303|h2|0000-0017-ff01-000b-0023-0010"),
        ];
        jarm.rng = Box::new(TestRng {});  // use the mock rng

        assert_eq!(jarm.hash().unwrap(), expected_hash);
    }

    #[rstest]
    #[case("0004", "01")]
    #[case("c027", "25")]
    #[case("c02b", "27")]
    #[case("1305", "45")]
    fn test_cipher_bytes(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(cipher_bytes(input), expected);
    }

    #[test]
    fn test_cipher_bytes_empty_string() {
        assert_eq!(cipher_bytes(""), "00");
    }

    #[rstest]
    #[case("0000")]
    #[case("0034")]
    fn test_cipher_bytes_is_unexpected(#[case] input: &str) {
        let result = cipher_bytes(input);
        assert_eq!(result, "46");
    }

    #[test]
    fn test_version_byte() {
        assert_eq!(version_byte(""), '0');
        assert_eq!(version_byte("0301"), 'b');
        assert_eq!(version_byte("0303"), 'd');
        assert_eq!(version_byte("0304"), 'e');
    }

    #[test]
    fn test_jarm_hash_null() {
        let expected_hash = String::from_utf8(vec![b'0'; 62]).unwrap();

        let mut jarm = Jarm::default();
        jarm.parts = vec![
            JarmPart::new("|||"),
            JarmPart::new("|||"),
            JarmPart::new("|||"),
            JarmPart::new("|||"),
            JarmPart::new("|||"),
            JarmPart::new("|||"),
            JarmPart::new("|||"),
            JarmPart::new("|||"),
            JarmPart::new("|||"),
            JarmPart::new("|||"),
        ];

        assert_eq!(jarm.hash().unwrap(), expected_hash);
    }

    #[test]
    fn test_build_tls_1_2() {
        // let expected_packet = b"\x16\x03\x03\x01\xb5\x01\x00\x01\xb1\x03\x03\xf4\xd2y\xb3I9\t\xf6\xbfz\x86{\xba+\x145Z3#\xd2\xe8\xee_\xb2\x9b5eT\xbeE\xb1\x81 &!\x1am\xa9\xe8t\t\xda\x01\r\xde \xf6\xe8\x10\xe0\x07E'\xcf@\xbaD\xad\xabD\xb4\xc5P\xee\x9a\x00\x8a\x00\x16\x003\x00g\xc0\x9e\xc0\xa2\x00\x9e\x009\x00k\xc0\x9f\xc0\xa3\x00\x9f\x00E\x00\xbe\x00\x88\x00\xc4\x00\x9a\xc0\x08\xc0\t\xc0#\xc0\xac\xc0\xae\xc0+\xc0\n\xc0$\xc0\xad\xc0\xaf\xc0,\xc0r\xc0s\xcc\xa9\x13\x02\x13\x01\xcc\x14\xc0\x07\xc0\x12\xc0\x13\xc0'\xc0/\xc0\x14\xc0(\xc00\xc0`\xc0a\xc0v\xc0w\xcc\xa8\x13\x05\x13\x04\x13\x03\xcc\x13\xc0\x11\x00\n\x00/\x00<\xc0\x9c\xc0\xa0\x00\x9c\x005\x00=\xc0\x9d\xc0\xa1\x00\x9d\x00A\x00\xba\x00\x84\x00\xc0\x00\x07\x00\x04\x00\x05\x01\x00\x00\xde\x00\x00\x00!\x00\x1f\x00\x00\x1cjsonplaceholder.typicode.com\x00\x17\x00\x00\x00\x01\x00\x01\x01\xff\x01\x00\x01\x00\x00\n\x00\n\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00#\x00\x00\x00\x10\x00<\x00:\x02hq\x03h2c\x06spdy/3\x02h2\x06spdy/2\x06spdy/1\x08http/1.1\x08http/1.0\x08http/0.9\x00\r\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 Z]6\x15\xb6?\xd8\xd4\xd1]\xee\xc1\x81\x99\xfe\x01\xf3\t\xdf\x83\xae\xd7\x8b\xb4\xf5\t\x11\x17\x08\xda\x82\x01\x00-\x00\x02\x01\x01\x00+\x00\x07\x06\x03\x03\x03\x02\x03\x01";
        let expected_packet = b"\x16\x03\x03\x01\xb5\x01\x00\x01\xb1\x03\x03******************************** ********************************\x00\x8a\x00\x16\x003\x00g\xc0\x9e\xc0\xa2\x00\x9e\x009\x00k\xc0\x9f\xc0\xa3\x00\x9f\x00E\x00\xbe\x00\x88\x00\xc4\x00\x9a\xc0\x08\xc0\t\xc0#\xc0\xac\xc0\xae\xc0+\xc0\n\xc0$\xc0\xad\xc0\xaf\xc0,\xc0r\xc0s\xcc\xa9\x13\x02\x13\x01\xcc\x14\xc0\x07\xc0\x12\xc0\x13\xc0'\xc0/\xc0\x14\xc0(\xc00\xc0`\xc0a\xc0v\xc0w\xcc\xa8\x13\x05\x13\x04\x13\x03\xcc\x13\xc0\x11\x00\n\x00/\x00<\xc0\x9c\xc0\xa0\x00\x9c\x005\x00=\xc0\x9d\xc0\xa1\x00\x9d\x00A\x00\xba\x00\x84\x00\xc0\x00\x07\x00\x04\x00\x05\x01\x00\x00\xde\x00\x00\x00!\x00\x1f\x00\x00\x1cjsonplaceholder.typicode.com\x00\x17\x00\x00\x00\x01\x00\x01\x01\xff\x01\x00\x01\x00\x00\n\x00\n\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00#\x00\x00\x00\x10\x00<\x00:\x02hq\x03h2c\x06spdy/3\x02h2\x06spdy/2\x06spdy/1\x08http/1.1\x08http/1.0\x08http/0.9\x00\r\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 ********************************\x00-\x00\x02\x01\x01\x00+\x00\x07\x06\x03\x03\x03\x02\x03\x01".to_vec();

        let tls_1_2_spec = PacketSpecification {
            host: "jsonplaceholder.typicode.com".to_string(),
            port: "443".to_string(),
            tls_version: TlsVersion::TLS1_2,
            cipher_list: CipherList::ALL,
            cipher_order: CipherOrder::FORWARD,
            use_grease: false,
            use_rare_apln: false,
            tls_version_support: TlsVersionSupport::TLS1_2,
            extension_order: CipherOrder::REVERSE,
        };

        let packet = rust_jarm::build_packet(&tls_1_2_spec, &test_rng());
        assert_eq!(packet, expected_packet);
    }

    #[test]
    fn test_build_tls_1_2_reverse() {
        let expected_packet = b"\x16\x03\x03\x01\xb5\x01\x00\x01\xb1\x03\x03******************************** ********************************\x00\x8a\x00\x05\x00\x04\x00\x07\x00\xc0\x00\x84\x00\xba\x00A\x00\x9d\xc0\xa1\xc0\x9d\x00=\x005\x00\x9c\xc0\xa0\xc0\x9c\x00<\x00/\x00\n\xc0\x11\xcc\x13\x13\x03\x13\x04\x13\x05\xcc\xa8\xc0w\xc0v\xc0a\xc0`\xc00\xc0(\xc0\x14\xc0/\xc0'\xc0\x13\xc0\x12\xc0\x07\xcc\x14\x13\x01\x13\x02\xcc\xa9\xc0s\xc0r\xc0,\xc0\xaf\xc0\xad\xc0$\xc0\n\xc0+\xc0\xae\xc0\xac\xc0#\xc0\t\xc0\x08\x00\x9a\x00\xc4\x00\x88\x00\xbe\x00E\x00\x9f\xc0\xa3\xc0\x9f\x00k\x009\x00\x9e\xc0\xa2\xc0\x9e\x00g\x003\x00\x16\x01\x00\x00\xde\x00\x00\x00!\x00\x1f\x00\x00\x1cjsonplaceholder.typicode.com\x00\x17\x00\x00\x00\x01\x00\x01\x01\xff\x01\x00\x01\x00\x00\n\x00\n\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00#\x00\x00\x00\x10\x00<\x00:\x08http/0.9\x08http/1.0\x08http/1.1\x06spdy/1\x06spdy/2\x06spdy/3\x02h2\x03h2c\x02hq\x00\r\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 ********************************\x00-\x00\x02\x01\x01\x00+\x00\x07\x06\x03\x01\x03\x02\x03\x03".to_vec();

        let tls_1_2_spec = PacketSpecification {
            host: "jsonplaceholder.typicode.com".to_string(),
            port: "443".to_string(),
            tls_version: TlsVersion::TLS1_2,
            cipher_list: CipherList::ALL,
            cipher_order: CipherOrder::REVERSE,
            use_grease: false,
            use_rare_apln: false,
            tls_version_support: TlsVersionSupport::TLS1_2,
            extension_order: CipherOrder::FORWARD,
        };

        let packet = rust_jarm::build_packet(&tls_1_2_spec, &test_rng());
        assert_eq!(packet, expected_packet);
    }

    #[test]
    fn test_build_tls_1_2_top_half() {
        let expected_packet = b"\x16\x03\x03\x01f\x01\x00\x01b\x03\x03******************************** ********************************\x00F\xc0\x12\xc0\x07\xcc\x14\x13\x01\x13\x02\xcc\xa9\xc0s\xc0r\xc0,\xc0\xaf\xc0\xad\xc0$\xc0\n\xc0+\xc0\xae\xc0\xac\xc0#\xc0\t\xc0\x08\x00\x9a\x00\xc4\x00\x88\x00\xbe\x00E\x00\x9f\xc0\xa3\xc0\x9f\x00k\x009\x00\x9e\xc0\xa2\xc0\x9e\x00g\x003\x00\x16\x01\x00\x00\xd3\x00\x00\x00!\x00\x1f\x00\x00\x1cjsonplaceholder.typicode.com\x00\x17\x00\x00\x00\x01\x00\x01\x01\xff\x01\x00\x01\x00\x00\n\x00\n\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00#\x00\x00\x00\x10\x00<\x00:\x08http/0.9\x08http/1.0\x08http/1.1\x06spdy/1\x06spdy/2\x06spdy/3\x02h2\x03h2c\x02hq\x00\r\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 ********************************\x00-\x00\x02\x01\x01".to_vec();

        let tls_1_2_spec = PacketSpecification {
            host: "jsonplaceholder.typicode.com".to_string(),
            port: "443".to_string(),
            tls_version: TlsVersion::TLS1_2,
            cipher_list: CipherList::ALL,
            cipher_order: CipherOrder::TOP_HALF,
            use_grease: false,
            use_rare_apln: false,
            tls_version_support: TlsVersionSupport::NO_SUPPORT,
            extension_order: CipherOrder::FORWARD,
        };

        let packet = rust_jarm::build_packet(&tls_1_2_spec, &test_rng());
        assert_eq!(packet, expected_packet);
    }

    #[test]
    fn test_build_tls_1_2_bottom_half() {
        let expected_packet = b"\x16\x03\x03\x01X\x01\x00\x01T\x03\x03******************************** ********************************\x00D\xc0\x13\xc0'\xc0/\xc0\x14\xc0(\xc00\xc0`\xc0a\xc0v\xc0w\xcc\xa8\x13\x05\x13\x04\x13\x03\xcc\x13\xc0\x11\x00\n\x00/\x00<\xc0\x9c\xc0\xa0\x00\x9c\x005\x00=\xc0\x9d\xc0\xa1\x00\x9d\x00A\x00\xba\x00\x84\x00\xc0\x00\x07\x00\x04\x00\x05\x01\x00\x00\xc7\x00\x00\x00!\x00\x1f\x00\x00\x1cjsonplaceholder.typicode.com\x00\x17\x00\x00\x00\x01\x00\x01\x01\xff\x01\x00\x01\x00\x00\n\x00\n\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00#\x00\x00\x00\x10\x000\x00.\x08http/0.9\x08http/1.0\x06spdy/1\x06spdy/2\x06spdy/3\x03h2c\x02hq\x00\r\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 ********************************\x00-\x00\x02\x01\x01".to_vec();

        let tls_1_2_spec = PacketSpecification {
            host: "jsonplaceholder.typicode.com".to_string(),
            port: "443".to_string(),
            tls_version: TlsVersion::TLS1_2,
            cipher_list: CipherList::ALL,
            cipher_order: CipherOrder::BOTTOM_HALF,
            use_grease: false,
            use_rare_apln: true,
            tls_version_support: TlsVersionSupport::NO_SUPPORT,
            extension_order: CipherOrder::FORWARD,
        };

        let packet = rust_jarm::build_packet(&tls_1_2_spec, &test_rng());
        assert_eq!(packet, expected_packet);
    }

    #[test]
    fn test_build_tls_1_2_middle_out() {
        let expected_packet = b"\x16\x03\x03\x01\xa9\x01\x00\x01\xa5\x03\x03******************************** ********************************\x00\x8c\n\n\xc0\x12\xc0\x13\xc0\x07\xc0'\xcc\x14\xc0/\x13\x01\xc0\x14\x13\x02\xc0(\xcc\xa9\xc00\xc0s\xc0`\xc0r\xc0a\xc0,\xc0v\xc0\xaf\xc0w\xc0\xad\xcc\xa8\xc0$\x13\x05\xc0\n\x13\x04\xc0+\x13\x03\xc0\xae\xcc\x13\xc0\xac\xc0\x11\xc0#\x00\n\xc0\t\x00/\xc0\x08\x00<\x00\x9a\xc0\x9c\x00\xc4\xc0\xa0\x00\x88\x00\x9c\x00\xbe\x005\x00E\x00=\x00\x9f\xc0\x9d\xc0\xa3\xc0\xa1\xc0\x9f\x00\x9d\x00k\x00A\x009\x00\xba\x00\x9e\x00\x84\xc0\xa2\x00\xc0\xc0\x9e\x00\x07\x00g\x00\x04\x003\x00\x05\x00\x16\x01\x00\x00\xd0\n\n\x00\x00\x00\x00\x00!\x00\x1f\x00\x00\x1cjsonplaceholder.typicode.com\x00\x17\x00\x00\x00\x01\x00\x01\x01\xff\x01\x00\x01\x00\x00\n\x00\n\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00#\x00\x00\x00\x10\x000\x00.\x02hq\x03h2c\x06spdy/3\x06spdy/2\x06spdy/1\x08http/1.0\x08http/0.9\x00\r\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x003\x00+\x00)\n\n\x00\x01\x00\x00\x1d\x00 ********************************\x00-\x00\x02\x01\x01".to_vec();

        let tls_1_2_spec = PacketSpecification {
            host: "jsonplaceholder.typicode.com".to_string(),
            port: "443".to_string(),
            tls_version: TlsVersion::TLS1_2,
            cipher_list: CipherList::ALL,
            cipher_order: CipherOrder::MIDDLE_OUT,
            use_grease: true,
            use_rare_apln: true,
            tls_version_support: TlsVersionSupport::NO_SUPPORT,
            extension_order: CipherOrder::REVERSE,
        };

        let packet = rust_jarm::build_packet(&tls_1_2_spec, &test_rng());
        assert_eq!(packet, expected_packet);
    }

    #[test]
    fn test_build_tls_1_1() {
        let expected_packet = b"\x16\x03\x02\x01\xaa\x01\x00\x01\xa6\x03\x02******************************** ********************************\x00\x8a\x00\x16\x003\x00g\xc0\x9e\xc0\xa2\x00\x9e\x009\x00k\xc0\x9f\xc0\xa3\x00\x9f\x00E\x00\xbe\x00\x88\x00\xc4\x00\x9a\xc0\x08\xc0\t\xc0#\xc0\xac\xc0\xae\xc0+\xc0\n\xc0$\xc0\xad\xc0\xaf\xc0,\xc0r\xc0s\xcc\xa9\x13\x02\x13\x01\xcc\x14\xc0\x07\xc0\x12\xc0\x13\xc0'\xc0/\xc0\x14\xc0(\xc00\xc0`\xc0a\xc0v\xc0w\xcc\xa8\x13\x05\x13\x04\x13\x03\xcc\x13\xc0\x11\x00\n\x00/\x00<\xc0\x9c\xc0\xa0\x00\x9c\x005\x00=\xc0\x9d\xc0\xa1\x00\x9d\x00A\x00\xba\x00\x84\x00\xc0\x00\x07\x00\x04\x00\x05\x01\x00\x00\xd3\x00\x00\x00!\x00\x1f\x00\x00\x1cjsonplaceholder.typicode.com\x00\x17\x00\x00\x00\x01\x00\x01\x01\xff\x01\x00\x01\x00\x00\n\x00\n\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00#\x00\x00\x00\x10\x00<\x00:\x08http/0.9\x08http/1.0\x08http/1.1\x06spdy/1\x06spdy/2\x06spdy/3\x02h2\x03h2c\x02hq\x00\r\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 ********************************\x00-\x00\x02\x01\x01".to_vec();

        let tls_1_1_spec = PacketSpecification {
            host: "jsonplaceholder.typicode.com".to_string(),
            port: "443".to_string(),
            tls_version: TlsVersion::TLS1_1,
            cipher_list: CipherList::ALL,
            cipher_order: CipherOrder::FORWARD,
            use_grease: false,
            use_rare_apln: false,
            tls_version_support: TlsVersionSupport::NO_SUPPORT,
            extension_order: CipherOrder::FORWARD,
        };

        let packet = rust_jarm::build_packet(&tls_1_1_spec, &test_rng());
        assert_eq!(packet, expected_packet);
    }

    #[test]
    fn test_build_tls_1_3_forward() {
        let expected_packet = b"\x16\x03\x01\x01\xb7\x01\x00\x01\xb3\x03\x03******************************** ********************************\x00\x8a\x00\x16\x003\x00g\xc0\x9e\xc0\xa2\x00\x9e\x009\x00k\xc0\x9f\xc0\xa3\x00\x9f\x00E\x00\xbe\x00\x88\x00\xc4\x00\x9a\xc0\x08\xc0\t\xc0#\xc0\xac\xc0\xae\xc0+\xc0\n\xc0$\xc0\xad\xc0\xaf\xc0,\xc0r\xc0s\xcc\xa9\x13\x02\x13\x01\xcc\x14\xc0\x07\xc0\x12\xc0\x13\xc0'\xc0/\xc0\x14\xc0(\xc00\xc0`\xc0a\xc0v\xc0w\xcc\xa8\x13\x05\x13\x04\x13\x03\xcc\x13\xc0\x11\x00\n\x00/\x00<\xc0\x9c\xc0\xa0\x00\x9c\x005\x00=\xc0\x9d\xc0\xa1\x00\x9d\x00A\x00\xba\x00\x84\x00\xc0\x00\x07\x00\x04\x00\x05\x01\x00\x00\xe0\x00\x00\x00!\x00\x1f\x00\x00\x1cjsonplaceholder.typicode.com\x00\x17\x00\x00\x00\x01\x00\x01\x01\xff\x01\x00\x01\x00\x00\n\x00\n\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00#\x00\x00\x00\x10\x00<\x00:\x02hq\x03h2c\x06spdy/3\x02h2\x06spdy/2\x06spdy/1\x08http/1.1\x08http/1.0\x08http/0.9\x00\r\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 ********************************\x00-\x00\x02\x01\x01\x00+\x00\t\x08\x03\x04\x03\x03\x03\x02\x03\x01".to_vec();

        let tls_1_3_spec = PacketSpecification {
            host: "jsonplaceholder.typicode.com".to_string(),
            port: "443".to_string(),
            tls_version: TlsVersion::TLS1_3,
            cipher_list: CipherList::ALL,
            cipher_order: CipherOrder::FORWARD,
            use_grease: false,
            use_rare_apln: false,
            tls_version_support: TlsVersionSupport::TLS1_3,
            extension_order: CipherOrder::REVERSE,
        };

        let packet = rust_jarm::build_packet(&tls_1_3_spec, &test_rng());
        assert_eq!(packet, expected_packet);
    }

    #[test]
    fn test_build_tls_1_3_reverse() {
        let expected_packet = b"\x16\x03\x01\x01\xb7\x01\x00\x01\xb3\x03\x03******************************** ********************************\x00\x8a\x00\x05\x00\x04\x00\x07\x00\xc0\x00\x84\x00\xba\x00A\x00\x9d\xc0\xa1\xc0\x9d\x00=\x005\x00\x9c\xc0\xa0\xc0\x9c\x00<\x00/\x00\n\xc0\x11\xcc\x13\x13\x03\x13\x04\x13\x05\xcc\xa8\xc0w\xc0v\xc0a\xc0`\xc00\xc0(\xc0\x14\xc0/\xc0'\xc0\x13\xc0\x12\xc0\x07\xcc\x14\x13\x01\x13\x02\xcc\xa9\xc0s\xc0r\xc0,\xc0\xaf\xc0\xad\xc0$\xc0\n\xc0+\xc0\xae\xc0\xac\xc0#\xc0\t\xc0\x08\x00\x9a\x00\xc4\x00\x88\x00\xbe\x00E\x00\x9f\xc0\xa3\xc0\x9f\x00k\x009\x00\x9e\xc0\xa2\xc0\x9e\x00g\x003\x00\x16\x01\x00\x00\xe0\x00\x00\x00!\x00\x1f\x00\x00\x1cjsonplaceholder.typicode.com\x00\x17\x00\x00\x00\x01\x00\x01\x01\xff\x01\x00\x01\x00\x00\n\x00\n\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00#\x00\x00\x00\x10\x00<\x00:\x08http/0.9\x08http/1.0\x08http/1.1\x06spdy/1\x06spdy/2\x06spdy/3\x02h2\x03h2c\x02hq\x00\r\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 ********************************\x00-\x00\x02\x01\x01\x00+\x00\t\x08\x03\x01\x03\x02\x03\x03\x03\x04".to_vec();

        let tls_1_3_spec = PacketSpecification {
            host: "jsonplaceholder.typicode.com".to_string(),
            port: "443".to_string(),
            tls_version: TlsVersion::TLS1_3,
            cipher_list: CipherList::ALL,
            cipher_order: CipherOrder::REVERSE,
            use_grease: false,
            use_rare_apln: false,
            tls_version_support: TlsVersionSupport::TLS1_3,
            extension_order: CipherOrder::FORWARD,
        };

        let packet = rust_jarm::build_packet(&tls_1_3_spec, &test_rng());
        assert_eq!(packet, expected_packet);
    }

    #[test]
    fn test_build_tls_1_3_invalid() {
        let expected_packet = b"\x16\x03\x01\x01\xad\x01\x00\x01\xa9\x03\x03******************************** ********************************\x00\x80\x00\x16\x003\x00g\xc0\x9e\xc0\xa2\x00\x9e\x009\x00k\xc0\x9f\xc0\xa3\x00\x9f\x00E\x00\xbe\x00\x88\x00\xc4\x00\x9a\xc0\x08\xc0\t\xc0#\xc0\xac\xc0\xae\xc0+\xc0\n\xc0$\xc0\xad\xc0\xaf\xc0,\xc0r\xc0s\xcc\xa9\xcc\x14\xc0\x07\xc0\x12\xc0\x13\xc0'\xc0/\xc0\x14\xc0(\xc00\xc0`\xc0a\xc0v\xc0w\xcc\xa8\xcc\x13\xc0\x11\x00\n\x00/\x00<\xc0\x9c\xc0\xa0\x00\x9c\x005\x00=\xc0\x9d\xc0\xa1\x00\x9d\x00A\x00\xba\x00\x84\x00\xc0\x00\x07\x00\x04\x00\x05\x01\x00\x00\xe0\x00\x00\x00!\x00\x1f\x00\x00\x1cjsonplaceholder.typicode.com\x00\x17\x00\x00\x00\x01\x00\x01\x01\xff\x01\x00\x01\x00\x00\n\x00\n\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00#\x00\x00\x00\x10\x00<\x00:\x08http/0.9\x08http/1.0\x08http/1.1\x06spdy/1\x06spdy/2\x06spdy/3\x02h2\x03h2c\x02hq\x00\r\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 ********************************\x00-\x00\x02\x01\x01\x00+\x00\t\x08\x03\x01\x03\x02\x03\x03\x03\x04".to_vec();

        let tls_1_3_spec = PacketSpecification {
            host: "jsonplaceholder.typicode.com".to_string(),
            port: "443".to_string(),
            tls_version: TlsVersion::TLS1_3,
            cipher_list: CipherList::NO1_3,
            cipher_order: CipherOrder::FORWARD,
            use_grease: false,
            use_rare_apln: false,
            tls_version_support: TlsVersionSupport::TLS1_3,
            extension_order: CipherOrder::FORWARD,
        };

        let packet = rust_jarm::build_packet(&tls_1_3_spec, &test_rng());
        assert_eq!(packet, expected_packet);
    }

    #[test]
    fn test_build_tls_1_3_middle_out() {
        let expected_packet = b"\x16\x03\x01\x01\xc4\x01\x00\x01\xc0\x03\x03******************************** ********************************\x00\x8c\n\n\xc0\x12\xc0\x13\xc0\x07\xc0'\xcc\x14\xc0/\x13\x01\xc0\x14\x13\x02\xc0(\xcc\xa9\xc00\xc0s\xc0`\xc0r\xc0a\xc0,\xc0v\xc0\xaf\xc0w\xc0\xad\xcc\xa8\xc0$\x13\x05\xc0\n\x13\x04\xc0+\x13\x03\xc0\xae\xcc\x13\xc0\xac\xc0\x11\xc0#\x00\n\xc0\t\x00/\xc0\x08\x00<\x00\x9a\xc0\x9c\x00\xc4\xc0\xa0\x00\x88\x00\x9c\x00\xbe\x005\x00E\x00=\x00\x9f\xc0\x9d\xc0\xa3\xc0\xa1\xc0\x9f\x00\x9d\x00k\x00A\x009\x00\xba\x00\x9e\x00\x84\xc0\xa2\x00\xc0\xc0\x9e\x00\x07\x00g\x00\x04\x003\x00\x05\x00\x16\x01\x00\x00\xeb\n\n\x00\x00\x00\x00\x00!\x00\x1f\x00\x00\x1cjsonplaceholder.typicode.com\x00\x17\x00\x00\x00\x01\x00\x01\x01\xff\x01\x00\x01\x00\x00\n\x00\n\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00#\x00\x00\x00\x10\x00<\x00:\x02hq\x03h2c\x06spdy/3\x02h2\x06spdy/2\x06spdy/1\x08http/1.1\x08http/1.0\x08http/0.9\x00\r\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x003\x00+\x00)\n\n\x00\x01\x00\x00\x1d\x00 ********************************\x00-\x00\x02\x01\x01\x00+\x00\x0b\n\n\n\x03\x04\x03\x03\x03\x02\x03\x01".to_vec();

        let tls_1_3_spec = PacketSpecification {
            host: "jsonplaceholder.typicode.com".to_string(),
            port: "443".to_string(),
            tls_version: TlsVersion::TLS1_3,
            cipher_list: CipherList::ALL,
            cipher_order: CipherOrder::MIDDLE_OUT,
            use_grease: true,
            use_rare_apln: false,
            tls_version_support: TlsVersionSupport::TLS1_3,
            extension_order: CipherOrder::REVERSE,
        };

        let packet = rust_jarm::build_packet(&tls_1_3_spec, &test_rng());
        assert_eq!(packet, expected_packet);
    }

    #[test]
    fn test_get_ciphers_tls_1_2() {
        let expected_ciphers = b"\x00\x16\x003\x00g\xc0\x9e\xc0\xa2\x00\x9e\x009\x00k\xc0\x9f\xc0\xa3\x00\x9f\x00E\x00\xbe\x00\x88\x00\xc4\x00\x9a\xc0\x08\xc0\t\xc0#\xc0\xac\xc0\xae\xc0+\xc0\n\xc0$\xc0\xad\xc0\xaf\xc0,\xc0r\xc0s\xcc\xa9\x13\x02\x13\x01\xcc\x14\xc0\x07\xc0\x12\xc0\x13\xc0'\xc0/\xc0\x14\xc0(\xc00\xc0`\xc0a\xc0v\xc0w\xcc\xa8\x13\x05\x13\x04\x13\x03\xcc\x13\xc0\x11\x00\n\x00/\x00<\xc0\x9c\xc0\xa0\x00\x9c\x005\x00=\xc0\x9d\xc0\xa1\x00\x9d\x00A\x00\xba\x00\x84\x00\xc0\x00\x07\x00\x04\x00\x05".to_vec();

        let tls_1_2_spec = PacketSpecification {
            host: "jsonplaceholder.typicode.com".to_string(),
            port: "443".to_string(),
            tls_version: TlsVersion::TLS1_2,
            cipher_list: CipherList::ALL,
            cipher_order: CipherOrder::FORWARD,
            use_grease: false,
            use_rare_apln: false,
            tls_version_support: TlsVersionSupport::TLS1_2,
            extension_order: CipherOrder::REVERSE,
        };

        let packet = rust_jarm::get_ciphers(&tls_1_2_spec, &test_rng());
        assert_eq!(packet, expected_ciphers);
    }

    #[test]
    fn test_get_ciphers_tls_1_2_middle_out_and_grease() {
        let expected_ciphers = b"\n\n\xc0\x12\xc0\x13\xc0\x07\xc0'\xcc\x14\xc0/\x13\x01\xc0\x14\x13\x02\xc0(\xcc\xa9\xc00\xc0s\xc0`\xc0r\xc0a\xc0,\xc0v\xc0\xaf\xc0w\xc0\xad\xcc\xa8\xc0$\x13\x05\xc0\n\x13\x04\xc0+\x13\x03\xc0\xae\xcc\x13\xc0\xac\xc0\x11\xc0#\x00\n\xc0\t\x00/\xc0\x08\x00<\x00\x9a\xc0\x9c\x00\xc4\xc0\xa0\x00\x88\x00\x9c\x00\xbe\x005\x00E\x00=\x00\x9f\xc0\x9d\xc0\xa3\xc0\xa1\xc0\x9f\x00\x9d\x00k\x00A\x009\x00\xba\x00\x9e\x00\x84\xc0\xa2\x00\xc0\xc0\x9e\x00\x07\x00g\x00\x04\x003\x00\x05\x00\x16".to_vec();

        let tls_1_2_spec = PacketSpecification {
            host: "jsonplaceholder.typicode.com".to_string(),
            port: "443".to_string(),
            tls_version: TlsVersion::TLS1_2,
            cipher_list: CipherList::ALL,
            cipher_order: CipherOrder::MIDDLE_OUT,
            use_grease: true,
            use_rare_apln: true,
            tls_version_support: TlsVersionSupport::NO_SUPPORT,
            extension_order: CipherOrder::REVERSE,
        };

        let packet = rust_jarm::get_ciphers(&tls_1_2_spec, &test_rng());
        assert_eq!(packet, expected_ciphers);
    }

    #[test]
    fn test_get_extensions() {
        let expected_extensions = b"\x00\xde\x00\x00\x00!\x00\x1f\x00\x00\x1cjsonplaceholder.typicode.com\x00\x17\x00\x00\x00\x01\x00\x01\x01\xff\x01\x00\x01\x00\x00\n\x00\n\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19\x00\x0b\x00\x02\x01\x00\x00#\x00\x00\x00\x10\x00<\x00:\x02hq\x03h2c\x06spdy/3\x02h2\x06spdy/2\x06spdy/1\x08http/1.1\x08http/1.0\x08http/0.9\x00\r\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01\x003\x00&\x00$\x00\x1d\x00 ********************************\x00-\x00\x02\x01\x01\x00+\x00\x07\x06\x03\x03\x03\x02\x03\x01".to_vec();

        let tls_1_2_spec = PacketSpecification {
            host: "jsonplaceholder.typicode.com".to_string(),
            port: "443".to_string(),
            tls_version: TlsVersion::TLS1_2,
            cipher_list: CipherList::ALL,
            cipher_order: CipherOrder::FORWARD,
            use_grease: false,
            use_rare_apln: false,
            tls_version_support: TlsVersionSupport::TLS1_2,
            extension_order: CipherOrder::REVERSE,
        };

        let packet = rust_jarm::get_extensions(&tls_1_2_spec, &test_rng());
        assert_eq!(packet, expected_extensions);
    }

    #[test]
    fn test_extension_server_name() {
        let expected_extension_server_name = b"\x00\x00\x00!\x00\x1f\x00\x00\x1cjsonplaceholder.typicode.com".to_vec();

        let tls_1_2_spec = PacketSpecification {
            host: "jsonplaceholder.typicode.com".to_string(),
            port: "443".to_string(),
            tls_version: TlsVersion::TLS1_2,
            cipher_list: CipherList::ALL,
            cipher_order: CipherOrder::FORWARD,
            use_grease: false,
            use_rare_apln: false,
            tls_version_support: TlsVersionSupport::TLS1_2,
            extension_order: CipherOrder::REVERSE,
        };

        let packet = rust_jarm::extension_server_name(&tls_1_2_spec);
        assert_eq!(packet, expected_extension_server_name);
    }

    #[test]
    fn test_alpns() {
        let expected_alpns = b"\x00\x10\x00<\x00:\x02hq\x03h2c\x06spdy/3\x02h2\x06spdy/2\x06spdy/1\x08http/1.1\x08http/1.0\x08http/0.9".to_vec();

        let tls_1_2_spec = PacketSpecification {
            host: "jsonplaceholder.typicode.com".to_string(),
            port: "443".to_string(),
            tls_version: TlsVersion::TLS1_2,
            cipher_list: CipherList::ALL,
            cipher_order: CipherOrder::FORWARD,
            use_grease: false,
            use_rare_apln: false,
            tls_version_support: TlsVersionSupport::TLS1_2,
            extension_order: CipherOrder::REVERSE,
        };

        let packet = rust_jarm::aplns(&tls_1_2_spec);
        assert_eq!(packet, expected_alpns);
    }

    #[test]
    fn test_cipher_mung_forward() {
        let mut input_ciphers = vec![
            b"\x08http/0.9".to_vec(),
            b"\x08http/1.0".to_vec(),
            b"\x08http/1.1".to_vec(),
            b"\x06spdy/1".to_vec(),
            b"\x06spdy/2".to_vec(),
            b"\x06spdy/3\x02h2".to_vec(),
            b"\x03h2c".to_vec(),
            b"\x02hq".to_vec(),
        ];
        let original = input_ciphers.clone();

        rust_jarm::cipher_mung(&mut input_ciphers, &CipherOrder::FORWARD);
        assert_eq!(input_ciphers, original);  // Nothing changed for Forward order
    }

    #[test]
    fn test_cipher_mung_reverse() {
        let mut input_ciphers = vec![
            b"\x08http/0.9".to_vec(),
            b"\x08http/1.0".to_vec(),
            b"\x08http/1.1".to_vec(),
            b"\x06spdy/1".to_vec(),
            b"\x06spdy/2".to_vec(),
            b"\x06spdy/3\x02h2".to_vec(),
            b"\x03h2c".to_vec(),
            b"\x02hq".to_vec(),
        ];
        let expected_ciphers_output = vec![
            b"\x02hq".to_vec(),
            b"\x03h2c".to_vec(),
            b"\x06spdy/3\x02h2".to_vec(),
            b"\x06spdy/2".to_vec(),
            b"\x06spdy/1".to_vec(),
            b"\x08http/1.1".to_vec(),
            b"\x08http/1.0".to_vec(),
            b"\x08http/0.9".to_vec(),
        ];

        rust_jarm::cipher_mung(&mut input_ciphers, &CipherOrder::REVERSE);
        assert_eq!(input_ciphers, expected_ciphers_output);
    }

    #[test]
    fn test_cipher_mung_top_half() {
        let mut input_ciphers = vec![
            b"\x02hq".to_vec(),
            b"\x03h2c".to_vec(),
            b"\x06spdy/3\x02h2".to_vec(),
            b"\x06spdy/2".to_vec(),
            b"\x06spdy/1".to_vec(),
            b"\x08http/1.1".to_vec(),
            b"\x08http/1.0".to_vec(),
            b"\x08http/0.9".to_vec(),
        ];

        let expected_ciphers_output = vec![
            b"\x06spdy/2".to_vec(),
            b"\x06spdy/3\x02h2".to_vec(),
            b"\x03h2c".to_vec(),
            b"\x02hq".to_vec(),
        ];

        rust_jarm::cipher_mung(&mut input_ciphers, &CipherOrder::TOP_HALF);
        assert_eq!(input_ciphers, expected_ciphers_output);
    }

    #[test]
    fn test_cipher_mung_top_half_odd() {
        let mut input_ciphers = vec![
            b"\x02hq".to_vec(),
            b"\x03h2c".to_vec(),
            b"\x06spdy/3\x02h2".to_vec(),
            b"\x06spdy/2".to_vec(),
            b"\x06spdy/1".to_vec(),
            b"\x08http/1.1".to_vec(),
            b"\x08http/1.0".to_vec(),
        ];

        let expected_ciphers_output = vec![
            b"\x06spdy/2".to_vec(),
            b"\x06spdy/3\x02h2".to_vec(),
            b"\x03h2c".to_vec(),
            b"\x02hq".to_vec(),
        ];

        rust_jarm::cipher_mung(&mut input_ciphers, &CipherOrder::TOP_HALF);
        assert_eq!(input_ciphers, expected_ciphers_output);
    }

    #[test]
    fn test_cipher_mung_bottom_half() {
        let mut input_ciphers = vec![
            b"\x02hq".to_vec(),
            b"\x03h2c".to_vec(),
            b"\x06spdy/3\x02h2".to_vec(),
            b"\x06spdy/2".to_vec(),
            b"\x06spdy/1".to_vec(),
            b"\x08http/1.1".to_vec(),
            b"\x08http/1.0".to_vec(),
            b"\x08http/0.9".to_vec(),
        ];

        let expected_ciphers_output = vec![
            b"\x06spdy/1".to_vec(),
            b"\x08http/1.1".to_vec(),
            b"\x08http/1.0".to_vec(),
            b"\x08http/0.9".to_vec(),
        ];

        rust_jarm::cipher_mung(&mut input_ciphers, &CipherOrder::BOTTOM_HALF);
        assert_eq!(input_ciphers, expected_ciphers_output);
    }

    #[test]
    fn test_cipher_mung_bottom_half_odd() {
        let mut input_ciphers = vec![
            b"\x02hq".to_vec(),
            b"\x03h2c".to_vec(),
            b"\x06spdy/3\x02h2".to_vec(),
            b"\x06spdy/2".to_vec(),
            b"\x06spdy/1".to_vec(),
            b"\x08http/1.1".to_vec(),
            b"\x08http/1.0".to_vec(),
        ];

        let expected_ciphers_output = vec![
            b"\x06spdy/1".to_vec(),
            b"\x08http/1.1".to_vec(),
            b"\x08http/1.0".to_vec(),
        ];

        rust_jarm::cipher_mung(&mut input_ciphers, &CipherOrder::BOTTOM_HALF);
        assert_eq!(input_ciphers, expected_ciphers_output);
    }

    #[test]
    fn test_cipher_mung_middle_out() {
        let mut input_ciphers = vec![
            b"\x02hq".to_vec(),
            b"\x03h2c".to_vec(),
            b"\x06spdy/3\x02h2".to_vec(),
            b"\x06spdy/2".to_vec(),
            b"\x06spdy/1".to_vec(),
            b"\x08http/1.1".to_vec(),
            b"\x08http/1.0".to_vec(),
            b"\x08http/0.9".to_vec(),
        ];

        let expected_ciphers_output = vec![
            b"\x06spdy/1".to_vec(),
            b"\x06spdy/2".to_vec(),
            b"\x08http/1.1".to_vec(),
            b"\x06spdy/3\x02h2".to_vec(),
            b"\x08http/1.0".to_vec(),
            b"\x03h2c".to_vec(),
            b"\x08http/0.9".to_vec(),
            b"\x02hq".to_vec(),
        ];

        rust_jarm::cipher_mung(&mut input_ciphers, &CipherOrder::MIDDLE_OUT);
        assert_eq!(input_ciphers, expected_ciphers_output);
    }

    #[test]
    fn test_cipher_mung_middle_out_odd() {
        let mut input_ciphers = vec![
            b"\x02hq".to_vec(),
            b"\x03h2c".to_vec(),
            b"\x06spdy/3\x02h2".to_vec(),
            b"\x06spdy/2".to_vec(),
            b"\x06spdy/1".to_vec(),
            b"\x08http/1.1".to_vec(),
            b"\x08http/1.0".to_vec(),
        ];

        let expected_ciphers_output = vec![
            b"\x06spdy/2".to_vec(),
            b"\x06spdy/1".to_vec(),
            b"\x06spdy/3\x02h2".to_vec(),
            b"\x08http/1.1".to_vec(),
            b"\x03h2c".to_vec(),
            b"\x08http/1.0".to_vec(),
            b"\x02hq".to_vec(),
        ];

        rust_jarm::cipher_mung(&mut input_ciphers, &CipherOrder::MIDDLE_OUT);
        assert_eq!(input_ciphers, expected_ciphers_output);
    }

    #[test]
    fn test_key_share() {
        let expected_key_share = b"\x003\x00&\x00$\x00\x1d\x00 ********************************".to_vec();
        assert_eq!(rust_jarm::key_share(false, &test_rng()), expected_key_share);
    }

    #[test]
    fn test_supported_versions() {
        let expected_supported_versions = b"\x00+\x00\x07\x06\x03\x03\x03\x02\x03\x01".to_vec();

        let tls_1_2_spec = PacketSpecification {
            host: "jsonplaceholder.typicode.com".to_string(),
            port: "443".to_string(),
            tls_version: TlsVersion::TLS1_2,
            cipher_list: CipherList::ALL,
            cipher_order: CipherOrder::FORWARD,
            use_grease: false,
            use_rare_apln: false,
            tls_version_support: TlsVersionSupport::TLS1_2,
            extension_order: CipherOrder::REVERSE,
        };

        assert_eq!(rust_jarm::supported_versions(&tls_1_2_spec, &test_rng()), expected_supported_versions);
    }

    #[test]
    fn test_read_packet_tls_1_2() {
        let input_hex = "160303004c0200004803035ffb8b2d1d50e207efcff257647b8cb319bd10a920b6968d444f574e4752440100c02b0000200000000000170000ff01000100000b000201000023000000100005000302683216030308a50b0008a100089e0004c7308204c330820469a003020102021003f93e0cd51ed9e174d552a522425dba300a06082a8648ce3d040302304a310b300906035504061302555331193017060355040a1310436c6f7564666c6172652c20496e632e3120301e06035504031317436c6f7564666c61726520496e63204543432043412d33301e170d3230303732393030303030305a170d3231303732393132303030305a306d310b3009060355040613025553310b3009060355040813024341311630140603550407130d53616e204672616e636973636f31193017060355040a1310436c6f7564666c6172652c20496e632e311e301c06035504031315736e692e636c6f7564666c61726573736c2e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004d73c51db4658abcb9d7ab52ff121496eb4c7e8e985d8742b20cef649c6e4ad1a692c44a12964c289bc2bd4aa22d767a0e7f95802de915a05e0ede1b4b9ce9636a382030c30820308301f0603551d23041830168014a5ce37eaebb0750e946788b445fad9241087961f301d0603551d0e0416041455da5417da45572aac6f8b2988693e361b204b75303e0603551d1104373035820e2a2e74797069636f64652e636f6d8215736e692e636c6f7564666c61726573736c2e636f6d820c74797069636f64652e636f6d300e0603551d0f0101ff040403020780301d0603551d250416301406082b0601050507030106082b06010505070302307b0603551d1f047430723037a035a0338631687474703a2f2f63726c332e64696769636572742e636f6d2f436c6f7564666c617265496e6345434343412d332e63726c3037a035a0338631687474703a2f2f63726c342e64696769636572742e636f6d2f436c6f7564666c617265496e6345434343412d332e63726c304c0603551d2004453043303706096086480186fd6c0101302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c010202307606082b06010505070101046a3068302406082b060105050730018618687474703a2f2f6f6373702e64696769636572742e636f6d304006082b060105050730028634687474703a2f2f636163657274732e64696769636572742e636f6d2f436c6f7564666c617265496e6345434343412d332e637274300c0603551d130101ff0402300030820104060a2b06010401d6790204020481f50481f200f0007600f65c942fd1773022145418083094568ee34d131933bfdf0c2f200bcc4ef164e3000001739b984538000004030047304502200221d2639b0c1f5ee1e66e4ddaf2c54e42833539f859f9c24407bec51f8ed759022100a36a3758696d4f734a432d2a20434c3b231747a4a71510dc468bdd3b5ca731d90076005cdc4392fee6ab4544b15e9ad456e61037fbd5fa47dca17394b25ee6f6c70eca000001739b9845670000040300473045022100eb62006e7d9149f9b6df5b2f00b588e890a0842c8bda890c41db7b7ebba9bfe20220209f2fac15cc45bcc4cad77a560a1d3bfd1fccb72ade6d423fe8f464633826fa300a06082a8648ce3d0403020348003045022100833607c623fcd6d6f159c3e06ab582031b4918c734ffeb9362ebe034de33f78202200fd50b4eaafb4ade2ae16f39d94c2da629d7a05a3bc1d0e9b943ed03b0840dda0003d1308203cd308202b5a00302010202100a3787645e5fb48c224efd1bed140c3c300d06092a864886f70d01010b0500305a310b300906035504061302494531123010060355040a130942616c74696d6f726531133011060355040b130a43796265725472757374312230200603550403131942616c74696d6f7265204379626572547275737420526f6f74301e170d3230303132373132343830385a170d3234313233";
        let input_packet = hex::decode(input_hex).unwrap();
        let expected_result = "c02b|0303|h2|0000-0017-ff01-000b-0023-0010";

        let jarm = rust_jarm::read_packet(input_packet);

        assert_eq!(jarm.raw, expected_result);
    }

    #[test]
    fn test_pack_as_unsigned_char() {
        assert_eq!(rust_jarm::pack_as_unsigned_char(1), b'\x01');
        assert_eq!(rust_jarm::pack_as_unsigned_char(32), b' ');
        assert_eq!(rust_jarm::pack_as_unsigned_char(45), b'-');
        assert_eq!(rust_jarm::pack_as_unsigned_char(102), b'f');
    }

    #[test]
    fn test_pack_as_unsigned_short() {
        eprintln!("\x00\x01 = {:?}", b"\x00\x01".to_vec());
        eprintln!("\x00 = {:?}", b"\x00");
        assert_eq!(rust_jarm::pack_as_unsigned_short(1), b"\x00\x01".to_vec());
        assert_eq!(rust_jarm::pack_as_unsigned_short(32), b"\x00 ".to_vec());
        assert_eq!(rust_jarm::pack_as_unsigned_short(45), b"\x00-".to_vec());
        assert_eq!(rust_jarm::pack_as_unsigned_short(102), b"\x00f".to_vec());
        assert_eq!(rust_jarm::pack_as_unsigned_short(1020), b"\x03\xfc".to_vec());
    }

    #[test]
    fn test_as_u32_be() {
        assert_eq!(rust_jarm::as_u32_be(&[0, 1]), 1);
        assert_eq!(rust_jarm::as_u32_be(&[1, 0]), 256);
        assert_eq!(rust_jarm::as_u32_be(&[4, 7]), 1031);
    }

    #[test]
    fn test_mocked_random_bytes() {
        let expected_mock_value: Vec<u8> = b"********************************".to_vec();
        let rng = TestRng {};
        assert_eq!(rng.random_bytes(), expected_mock_value);
    }

    #[test]
    #[cfg_attr(not(feature = "flaky_tests"), ignore = "Use pseudo rng")]
    fn test_not_mocked_random_bytes() {
        let expected_mock_value: Vec<u8> = b"********************************".to_vec();
        let rng = PseudoRng {};
        assert_ne!(rng.random_bytes(), expected_mock_value);
    }

    #[test]
    fn test_mocked_random_grease() {
        let expected_mock_value: Vec<u8> = b"\x0a\x0a".to_vec();
        let rng = TestRng {};
        assert_eq!(rng.random_grease(), expected_mock_value);
    }

    #[test]
    #[cfg_attr(not(feature = "flaky_tests"), ignore = "Use pseudo rng")]
    fn test_not_mocked_random_grease() {
        let expected_mock_value: Vec<u8> = b"\x0a\x0a".to_vec();
        let rng = PseudoRng {};
        assert_ne!(rng.random_grease(), expected_mock_value);
    }

    #[test]
    fn test_find_extension() {  // TODO add more example
        let types: Vec<&[u8]> = vec![b"\x00\x00", b"\x00\x17", b"\xff\x01", b"\x00\x0b", b"\x00#", b"\x00\x10"];
        let values: Vec<Option<&[u8]>> = vec![None, None, Some(b"\x00"), Some(b"\x01\x00"), None, Some(b"\x00\x03\x02h2")];
        let expected_result = "h2".to_string();

        let result = rust_jarm::find_extension(&types, values);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn test_add_formatting_hyphen() {
        let types: Vec<&[u8]> = vec![b"\x00\x00", b"\x00\x17", b"\xff\x01", b"\x00\x0b", b"\x00#", b"\x00\x10"];
        let expected_result = "0000-0017-ff01-000b-0023-0010".to_string();

        let result = rust_jarm::add_formatting_hyphen(&types);

        assert_eq!(result, expected_result);
    }

    fn server_packet_fixture() -> String {
        String::from("160303004c0200004803035fff763e66828f14f1107414d298002a2a6cef45158d699a444f574e4752440100c02b0000200000000000170000ff01000100000b000201000023000000100005000302683216030308a50b0008a100089e0004c7308204c330820469a003020102021003f93e0cd51ed9e174d552a522425dba300a06082a8648ce3d040302304a310b300906035504061302555331193017060355040a1310436c6f7564666c6172652c20496e632e3120301e06035504031317436c6f7564666c61726520496e63204543432043412d33301e170d3230303732393030303030305a170d3231303732393132303030305a306d310b3009060355040613025553310b3009060355040813024341311630140603550407130d53616e204672616e636973636f31193017060355040a1310436c6f7564666c6172652c20496e632e311e301c06035504031315736e692e636c6f7564666c61726573736c2e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004d73c51db4658abcb9d7ab52ff121496eb4c7e8e985d8742b20cef649c6e4ad1a692c44a12964c289bc2bd4aa22d767a0e7f95802de915a05e0ede1b4b9ce9636a382030c30820308301f0603551d23041830168014a5ce37eaebb0750e946788b445fad9241087961f301d0603551d0e0416041455da5417da45572aac6f8b2988693e361b204b75303e0603551d1104373035820e2a2e74797069636f64652e636f6d8215736e692e636c6f7564666c61726573736c2e636f6d820c74797069636f64652e636f6d300e0603551d0f0101ff040403020780301d0603551d250416301406082b0601050507030106082b06010505070302307b0603551d1f047430723037a035a0338631687474703a2f2f63726c332e64696769636572742e636f6d2f436c6f7564666c617265496e6345434343412d332e63726c3037a035a0338631687474703a2f2f63726c342e64696769636572742e636f6d2f436c6f7564666c617265496e6345434343412d332e63726c304c0603551d2004453043303706096086480186fd6c0101302a302806082b06010505070201161c68747470733a2f2f7777772e64696769636572742e636f6d2f4350533008060667810c010202307606082b06010505070101046a3068302406082b060105050730018618687474703a2f2f6f6373702e64696769636572742e636f6d304006082b060105050730028634687474703a2f2f636163657274732e64696769636572742e636f6d2f436c6f7564666c617265496e6345434343412d332e637274300c0603551d130101ff0402300030820104060a2b06010401d6790204020481f50481f200f0007600f65c942fd1773022145418083094568ee34d131933bfdf0c2f200bcc4ef164e3000001739b984538000004030047304502200221d2639b0c1f5ee1e66e4ddaf2c54e42833539f859f9c24407bec51f8ed759022100a36a3758696d4f734a432d2a20434c3b231747a4a71510dc468bdd3b5ca731d90076005cdc4392fee6ab4544b15e9ad456e61037fbd5fa47dca17394b25ee6f6c70eca000001739b9845670000040300473045022100eb62006e7d9149f9b6df5b2f00b588e890a0842c8bda890c41db7b7ebba9bfe20220209f2fac15cc45bcc4cad77a560a1d3bfd1fccb72ade6d423fe8f464633826fa300a06082a8648ce3d0403020348003045022100833607c623fcd6d6f159c3e06ab582031b4918c734ffeb9362ebe034de33f78202200fd50b4eaafb4ade2ae16f39d94c2da629d7a05a3bc1d0e9b943ed03b0840dda0003d1308203cd308202b5a00302010202100a3787645e5fb48c224efd1bed140c3c300d06092a864886f70d01010b0500305a310b300906035504061302494531123010060355040a130942616c74696d6f726531133011060355040b130a43796265725472757374312230200603550403131942616c74696d6f72652043796265725472")
    }

    #[test]
    fn test_extract_extension_info() {
        let expected_result = "h2|0000-0017-ff01-000b-0023-0010";
        let input_hex = server_packet_fixture();
        let input_packet = hex::decode(input_hex).unwrap();
        let counter: usize = 0;

        let extension = rust_jarm::extract_extension_info(input_packet, counter);

        assert_eq!(extension, expected_result);
    }

    #[test]
    fn test_extract_extension_info_non_zero_counter() {
        let expected_result = "|0033-002b";
        let input_hex = "160303007a0200007603031d9f05dd4890d4d2d6f1e52ac85ebbe9ef513ae1dec929184898e79fbb85f6c1202a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a130200002e00330024001d0020f55d8616ecdb3aede2b32ec195e1ce736063addc26b3a3a2066d9b1395faef33002b0002030414030300010117030309520c60b16e828fcbb0f4e7b7eff58472a0813912b1d5c92dc7d38d31ae5a226f9616ad8ddcc46716aaac7af43e29811d6c91aa3c45b5ce681297ce7d8856e78833f52ef6980da27f9cd763880e12472b56b181c67d7d68b270494f3bd4aa63951d2a3be43e5f49974d6a3e1466f7be7142c77ef768890444a9a08e7dd582b8ddfe04548e3da334e7480a818ca920360e318904fee523096381ef5b90500c7eb9e60d71d2d3291ca96d7dd966c117d1068685e878ff105330c810615fb257481e12ce616dbdd442124881c3b60f237252c5d1c863457517e4f837fd07db84bd28414ba9b67adcc4386310e861d5506b3cd2bfda4b0ece9451afe369e44ae4c3632c1f2a5098098677bb17d8af11350c99bda022d35f95bec0f0e2a19776b321a65942147d1b2cc95f468b9995bd08e0a1f36b912715fdad4c19b278545000c143171c7ff0929ee79f3ee6617014d5619bcf326d5017029bd559de91aedc32d879f1a9ae7642af4dc704fea1b94bea5b3c83265ac17aba12dde5bec9333a3bc6ff8ff3f232a7470c03cf0c465e0d22634f8fdc5e4d074fa583eb8cb928c1fbce39ba1e3851bb942cb3e56fe9c01ea908e196f9ab657bb3d3890192b7c6a4b5dfd12cd360adf1411ecec667bb3a6aa436449e14dc5ca44eb51723c93e3c009e840bf806d8f86a096d52409cc0b65ef5e0833ba7a88881fe5cff74158f5907744b36d83a183b20ae7cc9a2a2175e9cd8fc41d7e98823f295868b47c1fc7d80efd8ea7ca2c75d0a5d460e5f2cc77540a325a2e15be0496154c4a020737f222e64fdca274097d3c4fd6166ee20c6e7dcc3ca22e45153d075b5e4a82c5525a622a53d22145ac0115f704f6c46db34849bb75c5ed081c4881a596f2482dbaccdb122308fa85801c0c7afcfdceae7bd96c93ac6b4d341cefa3d21b032bb542473a85b091f43baaf195182d1ebc632c9fd2a232ae6183f689b324c550a58ad2c184803504802f71224015f9ec0697f87732e67b4fb3f8ff6a1a19a256bef9364bf81b5b53a71ee43f53be7920ea5820d43277a8140f853a0b5122ccbc4c321af0ebc688294869cbc29a35a87f197288b01a003b88d3e327c77f586c4c3746f6c6763fe0395885b4650a0b8b84d4feb3cb3c481d6d530756d1de4a517393d1669957da443bbc5fb2369595fef8272b17c69ad3e7e66a05f01cf2e194127f88164fb8bf0672c624df9a8462138854c13b7e63d089b9607b1aa86336b17cdb82a68448a51af56911664e87f2e9d04d16132744a5211fc6063ae46b84ba10ab2cd5333406cdaf9bd9c4bd3514fd45305e1bbb24c2df4467ebf5acb2c1fae1ee9e4db8ab464dd0222f7076d7d2e6939bf0c60b2a6cd9c4b5dc0cad0cc5084292b8f3848eda34366e9dad15d8e30b3a64ca67d7f6e26a304331e5a445fc55f76469090728df465471be9320c5d254e32b22a622709ff2427ad852d802a48333165e3615b78b81169b23e4efea11fe353270110db0ee7343af6c4c4ac390e8702e4f175cb25aebb63327482b40b6a60f5d7bb50baa34273a0256097a362bd384e209dcd86732aa7f10cc015d41fe29f3c321f95af23837dfedab6f7a29b686de6f5d7d3ef6e1c72fd6aa83eb6c44f099a8ee68f9d75c8855d9d1b0277d9a427ff6282bf996bb7d2c12d0c4785b8c2c2fc51438d1599e88cdd4c48eddab8ae8cedbb59e41de0536fd68fc454fecea1b289af5b9a1f8874f6b28ac96430765fb455d0f3a40c7fbcc9cde9a019b3b3c1fb30d8c9431dd1a56463bfb816b85ee6ba046d930e2b1d99b9c020b59e65276d6000f7c91784f391233508167407278a548904fd0777f2e2fd581fbda2701e6435eb60bcf6bad0f64c1ab14cf82e03ee1ae6fe752e558b37e263fd0c61";
        let input_packet = hex::decode(input_hex).unwrap();
        let counter: usize = 32;

        let extension = rust_jarm::extract_extension_info(input_packet, counter);

        assert_eq!(extension, expected_result);
    }

    #[test]
    fn test_extract_extension_info_incorrect_server_hello_length() {
        let expected_result = "|";
        let input_hex = "160303004a02000046030363b1b9e1dc4c5d4d8a9998d4d939ebf07c1d2499991ee35b8fd8871e642e824e202e6cceb91ca5f1f8f18749fb00394deb136e0f08fea88b8902547ba7e8dbe5bac02f0016030300070b00000300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let input_packet = hex::decode(input_hex).unwrap();
        let counter: usize = 32;

        let extension = rust_jarm::extract_extension_info(input_packet, counter);

        assert_eq!(extension, expected_result);
    }

    #[test]
    fn test_extract_extension_info_length_start_is_11() {
        let expected_result = "|";
        let input_hex = server_packet_fixture();
        let mut input_packet = hex::decode(input_hex).unwrap();


        let counter: usize = 32;
        let length_start_index = counter + 47;
        input_packet[length_start_index] = 11;  // Force the value to 11

        let extension = rust_jarm::extract_extension_info(input_packet, counter);

        assert_eq!(extension, expected_result);
    }

    #[test]
    fn test_extract_extension_info_incoming_error_1() {
        let expected_result = "|";
        let input_hex = server_packet_fixture();
        let mut input_packet = hex::decode(input_hex).unwrap();

        let counter: usize = 32;
        // Force error value
        let incoming_error_1 = b"\x0e\xac\x0b".to_vec();
        input_packet[(counter+50)..(counter+53)].copy_from_slice(&incoming_error_1[..]);

        let extension = rust_jarm::extract_extension_info(input_packet, counter);

        assert_eq!(extension, expected_result);
    }

    #[test]
    fn test_extract_extension_info_incoming_error_2() {
        let expected_result = "|";
        let input_hex = server_packet_fixture();
        let mut input_packet = hex::decode(input_hex).unwrap();

        let counter: usize = 32;
        // Force error value
        let incoming_error_2 = b"\x0f\xf0\x0b".to_vec();
        input_packet[(counter +82)..(counter +85)].copy_from_slice(&incoming_error_2[..]);

        let extension = rust_jarm::extract_extension_info(input_packet, counter);

        assert_eq!(extension, expected_result);
    }
}