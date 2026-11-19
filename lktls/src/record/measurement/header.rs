//! Gates the existing header cache; this is not a new parsing implementation.

use super::{observe, CopySite, Suite, AEAD_SUITES};
use crate::crypto::aead::{Aead, AeadAlgorithm};
use crate::crypto::tls12_cipher::Tls12CipherSuite;
use crate::error::{AlertDescription, TlsError};
use crate::record::reader::RecordReader;
use crate::record::ReadKeys;

fn install_reader(reader: &mut RecordReader, suite: Suite, iv_byte: u8) {
    match suite {
        Suite::Tls13(algorithm) => reader.install_keys(
            ReadKeys::tls13(algorithm, &vec![0x42; algorithm.key_len()], &[iv_byte; 12]).unwrap(),
        ),
        Suite::Tls12(code) => {
            let suite = Tls12CipherSuite::from_code_point(code).unwrap();
            reader.install_keys(ReadKeys::tls12(
                suite
                    .descriptor()
                    .record_cipher(
                        &vec![0x42; suite.enc_key_len()],
                        &vec![iv_byte; suite.fixed_iv_len()],
                        &[],
                    )
                    .unwrap(),
            ));
        }
    }
}

#[test]
fn cached_record_header_parses_once_under_single_byte_fragmentation() {
    for suite in AEAD_SUITES {
        for size in [1, 1024, 16384] {
            let (mut writer, mut reader) = suite.pair();
            let plaintext = vec![7; size];
            let wire = writer.write_record(23, &plaintext).unwrap();
            let mut output = Vec::new();
            for (position, byte) in wire.iter().enumerate() {
                assert_eq!(reader.feed_bounded(&[*byte], wire.len()), 1);
                let kind = reader.next_record_into(&mut output).unwrap();
                assert_eq!(kind, (position + 1 == wire.len()).then_some(23));
                assert_eq!(
                    reader.measurement_header_parses(),
                    usize::from(position >= 4)
                );
            }
            assert_eq!(output, plaintext);
            assert_eq!(reader.next_record_into(&mut output).unwrap(), None);
            assert_eq!(reader.measurement_header_parses(), 1);
            reader.feed(&writer.write_record(23, b"next").unwrap());
            assert_eq!(reader.next_record_into(&mut output).unwrap(), Some(23));
            assert_eq!(output, b"next");
            assert_eq!(reader.measurement_header_parses(), 2);
        }
    }
}

#[test]
fn cached_record_header_survives_cursor_compaction() {
    for suite in AEAD_SUITES {
        let (mut writer, mut reader) = suite.pair();
        let first = writer.write_record(23, &[1; 100]).unwrap();
        let second = writer.write_record(23, &[2; 100]).unwrap();
        reader.feed(&first);
        reader.feed(&second[..7]);
        let mut output = Vec::new();
        assert_eq!(reader.next_record_into(&mut output).unwrap(), Some(23));
        assert_eq!(output, [1; 100]);
        assert_eq!(reader.next_record_into(&mut output).unwrap(), None);
        assert_eq!(reader.measurement_header_parses(), 2);
        let (_, copies) = observe(|| {
            assert_eq!(
                reader.feed_bounded(&second[7..], second.len()),
                second.len() - 7
            );
        });
        assert_eq!(copies.bytes[CopySite::InputCompact as usize], 7);
        assert_eq!(reader.next_record_into(&mut output).unwrap(), Some(23));
        assert_eq!(output, [2; 100]);
        assert_eq!(reader.measurement_header_parses(), 2);
    }
}

#[test]
fn cached_record_header_uses_current_keys_after_installation() {
    for suite in AEAD_SUITES {
        let (mut writer, _) = suite.pair();
        let wire = writer
            .write_record(23, b"after CCS or ServerHello")
            .unwrap();
        let mut reader = RecordReader::new();
        let mut output = Vec::new();
        reader.feed(&wire[..7]);
        assert_eq!(reader.next_record_into(&mut output).unwrap(), None);
        install_reader(&mut reader, suite, 0x24);
        reader.feed(&wire[7..]);
        assert_eq!(reader.next_record_into(&mut output).unwrap(), Some(23));
        assert_eq!(output, b"after CCS or ServerHello");
        assert_eq!(reader.measurement_header_parses(), 1);
    }

    let suite = Suite::Tls13(AeadAlgorithm::Aes128Gcm);
    let (mut writer, mut reader) = suite.pair();
    reader.feed(&writer.write_record(23, b"old epoch").unwrap());
    assert_eq!(reader.next_record().unwrap().unwrap().payload, b"old epoch");
    writer.set_keys(Aead::new(AeadAlgorithm::Aes128Gcm, &[0x42; 16], &[0x55; 12]).unwrap());
    let wire = writer.write_record(23, b"new epoch sequence zero").unwrap();
    reader.feed(&wire[..7]);
    assert!(reader.next_record().unwrap().is_none());
    install_reader(&mut reader, suite, 0x55);
    reader.feed(&wire[7..]);
    assert_eq!(
        reader.next_record().unwrap().unwrap().payload,
        b"new epoch sequence zero"
    );
    assert_eq!(reader.measurement_header_parses(), 2);
}

#[test]
fn cached_record_header_rechecks_epoch_limits_and_cannot_revive_after_failure() {
    // A TLS 1.2-sized ciphertext cannot retain its validation result after
    // switching to the smaller TLS 1.3 ciphertext limit. Only wire metadata is cached.
    let (_, mut reader) = Suite::Tls12(0xc02b).pair();
    reader.feed(&[23, 3, 3, 0x42, 0x68]); // 17000 bytes, incomplete TLS 1.2 ciphertext
    assert!(reader.next_record().unwrap().is_none());
    install_reader(&mut reader, Suite::Tls13(AeadAlgorithm::Aes128Gcm), 0x55);
    assert!(
        matches!(reader.next_record(), Err(TlsError::LocalAlert { alert, .. })
        if alert.description == AlertDescription::RecordOverflow)
    );
    assert_eq!(reader.measurement_header_parses(), 1);
    assert_eq!(reader.buffered_len(), 0);
    assert!(reader.is_poisoned());

    for suite in AEAD_SUITES {
        let (mut writer, mut reader) = suite.pair();
        let mut wire = writer.write_record(23, b"bad tag").unwrap();
        *wire.last_mut().unwrap() ^= 1;
        reader.feed(&wire[..7]);
        assert!(reader.next_record().unwrap().is_none());
        reader.feed(&wire[7..]);
        let mut output = vec![9];
        assert!(reader.next_record_into(&mut output).is_err());
        assert!(output.is_empty());
        assert!(reader.is_poisoned());
        assert_eq!(reader.buffered_len(), 0);
        install_reader(&mut reader, suite, 0x24);
        assert_eq!(reader.feed_bounded(&wire, wire.len()), 0);
        assert!(reader.next_record_into(&mut output).is_err());
        assert_eq!(reader.measurement_header_parses(), 1);
    }
}
