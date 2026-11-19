use lktls::crypto::aead::AeadAlgorithm;
use lktls::crypto::tls12_cipher::{Tls12Chacha20Cipher, Tls12GcmCipher, Tls12RecordCipher};
use lktls::record::buffer::RecordBuffer;
use lktls::record::reader::RecordReader;
use lktls::record::writer::{RecordWriter, WriteStop};
use lktls::record::{ReadKeys, WriteKeys, MAX_RECORD_PAYLOAD};

fn pair(kind: u8) -> (RecordWriter, RecordReader, usize) {
    let mut writer = RecordWriter::new();
    let mut reader = RecordReader::new();
    let expansion = match kind {
        0..=2 => {
            let alg = [
                AeadAlgorithm::Aes128Gcm,
                AeadAlgorithm::Aes256Gcm,
                AeadAlgorithm::Chacha20Poly1305,
            ][kind as usize];
            writer.install_keys(WriteKeys::tls13(alg, &vec![7; alg.key_len()], &[9; 12]).unwrap());
            reader.install_keys(ReadKeys::tls13(alg, &vec![7; alg.key_len()], &[9; 12]).unwrap());
            22
        }
        3 | 4 => {
            let create = || {
                Tls12RecordCipher::Gcm(
                    Tls12GcmCipher::new(
                        &vec![7; if kind == 3 { 16 } else { 32 }],
                        &[9; 4],
                        kind == 4,
                    )
                    .unwrap(),
                )
            };
            writer.install_keys(WriteKeys::tls12(create()));
            reader.install_keys(ReadKeys::tls12(create()));
            29
        }
        _ => {
            let create = || {
                Tls12RecordCipher::Chacha20(Tls12Chacha20Cipher::new(&[7; 32], &[9; 12]).unwrap())
            };
            writer.install_keys(WriteKeys::tls12(create()));
            reader.install_keys(ReadKeys::tls12(create()));
            21
        }
    };
    (writer, reader, expansion)
}

#[test]
fn no_capacity_does_not_consume_nonce_and_partial_output_resumes_exactly_once() {
    for kind in 0..6 {
        let (mut writer, mut reader, overhead) = pair(kind);
        let (mut control, _, _) = pair(kind);
        let payload = vec![0x42; MAX_RECORD_PAYLOAD + 17];
        let expected = control.write_record(23, &payload).unwrap();
        let mut output = Vec::with_capacity(expected.len());
        let stop = writer.write_into(23, &payload, &mut output, 0);
        assert_eq!(stop.accepted_plaintext, 0);
        assert!(matches!(stop.stop, WriteStop::NeedOutputCapacity));
        let stop = writer.write_into(23, &payload, &mut output, MAX_RECORD_PAYLOAD + overhead);
        assert_eq!(stop.accepted_plaintext, MAX_RECORD_PAYLOAD);
        assert_eq!(stop.committed_ciphertext, output.len());
        assert!(matches!(stop.stop, WriteStop::NeedOutputCapacity));
        let stop = writer.write_into(
            23,
            &payload[MAX_RECORD_PAYLOAD..],
            &mut output,
            expected.len(),
        );
        assert_eq!(stop.accepted_plaintext, 17);
        assert!(matches!(stop.stop, WriteStop::Complete));
        assert_eq!(output, expected);
        let mut decoded = Vec::with_capacity(MAX_RECORD_PAYLOAD + overhead);
        let mut incoming = output.as_slice();
        let mut plaintext = Vec::new();
        while !incoming.is_empty() || reader.buffered_len() != 0 {
            let accepted = reader.feed_bounded(incoming, MAX_RECORD_PAYLOAD + overhead);
            incoming = &incoming[accepted..];
            if let Some(ct) = reader.next_record_into(&mut decoded).unwrap() {
                assert_eq!(ct, 23);
                plaintext.extend_from_slice(&decoded);
            }
        }
        assert_eq!(plaintext, payload);
    }
}

#[test]
fn read_failure_invalidates_plaintext_and_cannot_resume_after_key_installation() {
    for kind in 0..6 {
        let (mut writer, mut reader, _) = pair(kind);
        let mut ciphertext = writer.write_record(23, b"authenticated").unwrap();
        *ciphertext.last_mut().unwrap() ^= 1;
        reader.feed(&ciphertext);
        let mut output = b"previous data".to_vec();
        assert!(reader.next_record_into(&mut output).is_err());
        assert!(output.is_empty());
        assert!(reader.is_poisoned());
        reader.install_keys(ReadKeys::tls13(AeadAlgorithm::Aes128Gcm, &[1; 16], &[2; 12]).unwrap());
        assert_eq!(reader.feed_bounded(&ciphertext, 65536), 0);
        assert!(reader.next_record_into(&mut output).is_err());
    }
}

#[test]
fn cursor_budget_counts_only_unconsumed_bytes() {
    let mut buffer = RecordBuffer::new(8);
    assert_eq!(buffer.append(b"abcdef"), 6);
    buffer.consume(3);
    assert_eq!(buffer.append(b"ghijklm"), 5);
    assert_eq!(buffer.as_slice(), b"defghijk");
    assert_eq!(buffer.remaining_capacity(), 0);
    buffer.consume(8);
    assert!(buffer.is_empty());
    assert_eq!(buffer.append(b"12345678"), 8);
    buffer.consume(2);
    buffer.truncate_pending(3);
    assert_eq!(buffer.as_slice(), b"345");
    assert_eq!(buffer.remaining_capacity(), 5);
}

#[test]
fn cached_partial_header_and_empty_records_reuse_output() {
    let (mut writer, mut reader, _) = pair(0);
    let ciphertext = writer.write_record(23, b"").unwrap();
    let mut output = Vec::with_capacity(100);
    let pointer = output.as_ptr();
    for (offset, byte) in ciphertext.iter().enumerate() {
        assert_eq!(reader.feed_bounded(&[*byte], ciphertext.len()), 1);
        let result = reader.next_record_into(&mut output).unwrap();
        assert_eq!(result, (offset + 1 == ciphertext.len()).then_some(23));
    }
    assert!(output.is_empty());
    assert_eq!(output.as_ptr(), pointer);
}
