use lktls::crypto::aead::AeadAlgorithm;
use lktls::crypto::hkdf::HkdfAlgorithm;
use lktls::crypto::prf::PrfAlgorithm;
use lktls::crypto::tls12_cipher::{Tls12CipherSuite, Tls12KeyExchange};
use lktls::handshake::tls12::create_tls12_record_cipher;
use lktls::record::{reader::RecordReader, writer::RecordWriter};

// Freeze the existing public parameters independently of the new descriptors.
const TLS12: &[(u16, usize, usize, usize, bool, bool)] = &[
    (0xc02b, 16, 0, 4, false, false),
    (0xc02f, 16, 0, 4, false, false),
    (0xc02c, 32, 0, 4, true, false),
    (0xc030, 32, 0, 4, true, false),
    (0xcca9, 32, 0, 12, false, false),
    (0xcca8, 32, 0, 12, false, false),
    (0xc009, 16, 20, 16, false, false),
    (0xc00a, 32, 20, 16, false, false),
    (0xc023, 16, 32, 16, false, false),
    (0xc024, 32, 48, 16, true, false),
    (0xc013, 16, 20, 16, false, false),
    (0xc014, 32, 20, 16, false, false),
    (0xc027, 16, 32, 16, false, false),
    (0xc028, 32, 48, 16, true, false),
    (0x0035, 32, 20, 16, false, true),
    (0x002f, 16, 20, 16, false, true),
    (0x003d, 32, 32, 16, false, true),
    (0x003c, 16, 32, 16, false, true),
    (0x009c, 16, 0, 4, false, true),
    (0x009d, 32, 0, 4, true, true),
    (0x000a, 24, 20, 8, false, true),
    (0xc008, 24, 20, 8, false, false),
    (0xc012, 24, 20, 8, false, false),
];

#[test]
fn existing_tls12_suite_parameters_and_record_interoperation() {
    for &(code, key_len, mac_len, iv_len, sha384, rsa) in TLS12 {
        let suite = Tls12CipherSuite::from_code_point(code).unwrap();
        assert_eq!(suite.code_point(), code);
        assert_eq!(suite.enc_key_len(), key_len);
        assert_eq!(suite.mac_key_len(), mac_len);
        assert_eq!(suite.fixed_iv_len(), iv_len);
        assert_eq!(suite.is_cbc(), mac_len != 0);
        assert_eq!(suite.is_aead(), mac_len == 0);
        assert_eq!(suite.key_exchange() == Tls12KeyExchange::Rsa, rsa);
        assert_eq!(suite.prf_algorithm() == PrfAlgorithm::Sha384, sha384);
        assert_eq!(suite.hash_algorithm() == HkdfAlgorithm::Sha384, sha384);

        let key: Vec<u8> = (1..=key_len as u8).collect();
        let iv = vec![0x52; iv_len];
        let mac = vec![0x73; mac_len];
        let mut writer = RecordWriter::new();
        writer.set_tls12_keys(create_tls12_record_cipher(&suite, &key, &iv, &mac).unwrap());
        let mut reader = RecordReader::new();
        reader.set_tls12_keys(create_tls12_record_cipher(&suite, &key, &iv, &mac).unwrap());
        for payload in [b"first record".as_slice(), b"second record"] {
            reader.feed(&writer.write_record(23, payload).unwrap());
            let record = reader.next_record().unwrap().unwrap();
            assert_eq!(record.content_type, 23);
            assert_eq!(record.payload, payload, "suite {code:04x}");
        }
    }
}

#[test]
fn suite_factory_rejects_key_material_from_a_different_suite() {
    for &(code, key_len, mac_len, iv_len, _, _) in TLS12 {
        let suite = Tls12CipherSuite::from_code_point(code).unwrap();
        let wrong_key = vec![0x31; if key_len == 16 { 32 } else { 16 }];
        assert!(
            create_tls12_record_cipher(&suite, &wrong_key, &vec![0; iv_len], &vec![0; mac_len])
                .is_err(),
            "suite {code:04x} accepted another suite's key length"
        );
        assert!(
            create_tls12_record_cipher(&suite, &vec![0; key_len], &[], &vec![0; mac_len]).is_err()
        );
        assert!(create_tls12_record_cipher(
            &suite,
            &vec![0; key_len],
            &vec![0; iv_len],
            &vec![0; mac_len + 1]
        )
        .is_err());
    }
}

#[test]
fn tls13_algorithm_resolution_does_not_accept_tls12_or_grease() {
    for (code, algorithm) in [
        (0x1301, AeadAlgorithm::Aes128Gcm),
        (0x1302, AeadAlgorithm::Aes256Gcm),
        (0x1303, AeadAlgorithm::Chacha20Poly1305),
    ] {
        assert_eq!(AeadAlgorithm::from_cipher_suite(code), Some(algorithm));
        assert!(Tls12CipherSuite::from_code_point(code).is_none());
    }
    for code in [0xc02b, 0x0a0a, 0x00ff, 0xffff] {
        assert!(AeadAlgorithm::from_cipher_suite(code).is_none());
    }
}
