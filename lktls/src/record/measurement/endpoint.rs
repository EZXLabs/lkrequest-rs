//! The measured interval enters public endpoints. Fixture copies used to
//! collect transport bytes and compare plaintext are outside that interval.

use super::{observe, Copies, CopySite, Suite, AEAD_SUITES};
use crate::connection::{ClientConnection, ReadProgress, TcpConnection};
use crate::crypto::aead::AeadAlgorithm;
use crate::handshake::driver::HandshakeResult;
use crate::profile::types::TlsClientHelloStyle;
use crate::record::MAX_RECORD_PAYLOAD;

enum Endpoint {
    Tcp(Box<TcpConnection>),
    Client(Box<ClientConnection>),
}

impl Endpoint {
    fn new(suite: Suite, continuous: bool) -> Self {
        let (writer, mut reader) = suite.pair();
        let (version, code) = match suite {
            Suite::Tls13(algorithm) => {
                reader.finish_tls13_handshake();
                (
                    0x0304,
                    match algorithm {
                        AeadAlgorithm::Aes128Gcm => 0x1301,
                        AeadAlgorithm::Aes256Gcm => 0x1302,
                        AeadAlgorithm::Chacha20Poly1305 => 0x1303,
                    },
                )
            }
            Suite::Tls12(code) => (0x0303, code),
        };
        let result = HandshakeResult {
            reader,
            writer,
            negotiated_alpn: None,
            negotiated_cipher_suite: Some(code),
            negotiated_version: Some(version),
            peer_certificates: Vec::new(),
            post_handshake: None,
            session_ticket_ctx: None,
        };
        if continuous {
            Self::Client(Box::new(ClientConnection::from_handshake(
                result,
                TlsClientHelloStyle::Generic,
            )))
        } else {
            Self::Tcp(Box::new(TcpConnection::from_handshake(
                result,
                TlsClientHelloStyle::Generic,
            )))
        }
    }

    fn write(&mut self, plaintext: &[u8]) -> usize {
        match self {
            Self::Tcp(connection) => connection.write_application(plaintext),
            Self::Client(connection) => connection.write_application(plaintext),
        }
        .unwrap()
    }

    fn output(&self) -> &[u8] {
        match self {
            Self::Tcp(connection) => connection.output(),
            Self::Client(connection) => connection.output(),
        }
    }

    fn consume_output(&mut self, count: usize) {
        match self {
            Self::Tcp(connection) => connection.consume_output(count),
            Self::Client(connection) => connection.consume_output(count),
        }
    }

    fn feed(&mut self, ciphertext: &[u8]) -> usize {
        match self {
            Self::Tcp(connection) => connection.feed_bounded(ciphertext),
            Self::Client(connection) => connection.feed_bounded(ciphertext),
        }
    }

    fn process_read(&mut self) -> ReadProgress {
        match self {
            Self::Tcp(connection) => connection.process_read(),
            Self::Client(connection) => connection.process_read(),
        }
        .unwrap()
    }

    fn plaintext(&self) -> &[u8] {
        match self {
            Self::Tcp(connection) => connection.plaintext(),
            Self::Client(connection) => connection.plaintext(),
        }
    }

    fn consume_plaintext(&mut self, count: usize) {
        match self {
            Self::Tcp(connection) => connection.consume_plaintext(count),
            Self::Client(connection) => connection.consume_plaintext(count),
        }
    }

    fn start_close(&mut self) {
        match self {
            Self::Tcp(connection) => connection.start_close(),
            Self::Client(connection) => connection.start_close(),
        }
    }
}

fn assert_plaintext_budget(copies: Copies, accepted: usize) {
    assert_eq!(
        copies.bytes[CopySite::PlaintextSeal as usize],
        accepted as u64
    );
    assert_eq!(
        copies.calls[CopySite::PlaintextSeal as usize],
        accepted.div_ceil(MAX_RECORD_PAYLOAD) as u64
    );
    assert_eq!(
        copies.bytes[CopySite::OutputAppend as usize],
        0,
        "an endpoint must seal into its final queue, without appending a staged record"
    );
}

fn verify_wire(suite: Suite, ciphertext: &[u8], expected: &[u8]) {
    let (_, mut peer) = suite.pair();
    peer.feed(ciphertext);
    let mut plaintext = Vec::new();
    while let Some(record) = peer.next_record().unwrap() {
        assert_eq!(record.content_type, 23);
        plaintext.extend_from_slice(&record.payload);
    }
    assert_eq!(peer.buffered_len(), 0);
    assert_eq!(plaintext, expected);
}

fn emit(
    suite: Suite,
    continuous: bool,
    size: usize,
    scenario: &str,
    accepted: usize,
    copies: Copies,
) {
    println!(
        "{}",
        serde_json::json!({
            "kind": "endpoint_copy_budget",
            "endpoint": if continuous { "ClientConnection" } else { "TcpConnection" },
            "suite": format!("{suite:?}"), "payload_bytes": size, "scenario": scenario,
            "accepted_plaintext_bytes": accepted, "copies": copies.json(), "elapsed_ns": null,
            "boundary": "public connection methods; fixture transport and comparison copies excluded",
        "source_derived_tls12_overhead_copy_bytes": suite.source_derived_crypto_copies(false) as u64
            * copies.calls[CopySite::PlaintextSeal as usize],
        "source_derived_scope": "explicit nonce/tag Vec appends; excluded from observed sites; not a backend measurement",
        })
    );
}

#[test]
fn endpoint_copy_budget_single_and_multi_record_writes() {
    for continuous in [false, true] {
        for suite in AEAD_SUITES {
            for size in [1, 1024, 16384] {
                for multi in [false, true] {
                    let mut endpoint = Endpoint::new(suite, continuous);
                    let plaintext =
                        vec![0x31; size + if multi { 2 * MAX_RECORD_PAYLOAD } else { 0 }];
                    let (accepted, copies) = observe(|| endpoint.write(&plaintext));
                    assert_eq!(accepted, plaintext.len());
                    assert_plaintext_budget(copies, accepted);
                    assert_eq!(copies.bytes[CopySite::OutputCompact as usize], 0);
                    verify_wire(suite, endpoint.output(), &plaintext);
                    emit(
                        suite,
                        continuous,
                        size,
                        if multi {
                            "multi_record_write"
                        } else {
                            "single_record_write"
                        },
                        accepted,
                        copies,
                    );
                }
            }
        }
    }
}

fn consume_transport(endpoint: &mut Endpoint, wire: &mut Vec<u8>, count: usize) {
    wire.extend_from_slice(&endpoint.output()[..count]);
    let (_, copies) = observe(|| endpoint.consume_output(count));
    assert_eq!(
        copies.bytes, [0; 8],
        "short transport writes only advance a cursor"
    );
}

#[test]
fn endpoint_output_compaction_is_amortized_for_bytewise_consumption() {
    for continuous in [false, true] {
        for suite in AEAD_SUITES {
            for retry_size in [1, MAX_RECORD_PAYLOAD] {
                let mut endpoint = Endpoint::new(suite, continuous);
                let initial = vec![0x31; 512 * 1024];
                let mut expected_len = endpoint.write(&initial);
                let retry = vec![0x31; retry_size];
                loop {
                    let accepted = endpoint.write(&retry);
                    expected_len += accepted;
                    if accepted == 0 {
                        break;
                    }
                }
                let mut wire = Vec::new();
                let mut copies = Copies::default();
                for _ in 0..2048 {
                    consume_transport(&mut endpoint, &mut wire, 1);
                    let (accepted, observed) = observe(|| endpoint.write(&retry));
                    assert_plaintext_budget(observed, accepted);
                    expected_len += accepted;
                    copies.add(observed);
                }
                assert!(
                    copies.bytes[CopySite::OutputCompact as usize] <= wire.len() as u64,
                    "retry_size={retry_size}: moved {} ciphertext bytes after draining only {}",
                    copies.bytes[CopySite::OutputCompact as usize],
                    wire.len()
                );
                let bytewise_compaction_bytes = copies.bytes[CopySite::OutputCompact as usize];
                assert_eq!(bytewise_compaction_bytes, 0);
                assert_eq!(copies.bytes[CopySite::PlaintextSeal as usize], 0);
                // After enough transport progress, compaction may recover tail
                // space, but every moved byte must be paid for by a drained byte.
                for _ in 0..4 {
                    let count = endpoint.output().len().div_ceil(2);
                    consume_transport(&mut endpoint, &mut wire, count);
                    let (accepted, observed) = observe(|| endpoint.write(&retry));
                    assert!(accepted > 0);
                    assert_plaintext_budget(observed, accepted);
                    expected_len += accepted;
                    copies.add(observed);
                    assert!(copies.bytes[CopySite::OutputCompact as usize] <= wire.len() as u64);
                }
                println!(
                    "{}",
                    serde_json::json!({
                        "kind": "endpoint_amortized_output",
                        "endpoint": if continuous { "ClientConnection" } else { "TcpConnection" },
                        "suite": format!("{suite:?}"), "retry_plaintext_bytes": retry_size,
                        "bytewise_drained_bytes": 2048, "bytewise_compaction_bytes": bytewise_compaction_bytes,
                        "total_drained_before_final_flush": wire.len(),
                        "total_application_compaction_bytes": copies.bytes[CopySite::OutputCompact as usize],
                        "crypto_backend_copy_bytes": null, "allocator_relocation_copy_bytes": null,
                        "elapsed_ns": null,
                    })
                );
                let remaining = endpoint.output().len();
                consume_transport(&mut endpoint, &mut wire, remaining);
                verify_wire(suite, &wire, &vec![0x31; expected_len]);
            }
        }
    }
}

#[test]
fn endpoint_control_output_reclaims_reserved_capacity_after_short_consumption() {
    for continuous in [false, true] {
        for suite in AEAD_SUITES {
            let mut endpoint = Endpoint::new(suite, continuous);
            let initial = vec![0x31; 512 * 1024];
            let mut expected_len = endpoint.write(&initial);
            loop {
                let accepted = endpoint.write(&[0x31]);
                expected_len += accepted;
                if accepted == 0 {
                    break;
                }
            }
            let mut wire = Vec::new();
            consume_transport(&mut endpoint, &mut wire, 1);
            let pending = endpoint.output().to_vec();
            let (_, control) = observe(|| endpoint.start_close());
            assert_eq!(
                control.bytes[CopySite::OutputCompact as usize],
                pending.len() as u64
            );
            assert_eq!(control.bytes[CopySite::PlaintextSeal as usize], 2);
            assert!(endpoint.output().starts_with(&pending));
            assert!(endpoint.output().len() <= 256 * 1024);
            let remaining = endpoint.output().len();
            consume_transport(&mut endpoint, &mut wire, remaining);
            let (_, mut peer) = suite.pair();
            peer.feed(&wire);
            let mut application_bytes = 0;
            let mut closed = false;
            while let Some(record) = peer.next_record().unwrap() {
                assert!(!closed, "no records may follow this close_notify");
                if record.content_type == 23 {
                    assert!(record.payload.iter().all(|byte| *byte == 0x31));
                    application_bytes += record.payload.len();
                } else {
                    assert_eq!(record.content_type, 21);
                    assert_eq!(record.payload, [1, 0]);
                    closed = true;
                }
            }
            assert_eq!(application_bytes, expected_len);
            assert!(closed);
        }
    }
}

#[test]
fn endpoint_copy_budget_capacity_retries_and_partial_output_consumption() {
    for continuous in [false, true] {
        for suite in AEAD_SUITES {
            for size in [1, 1024, 16384] {
                let mut endpoint = Endpoint::new(suite, continuous);
                let plaintext = vec![0x31; 512 * 1024 + size];
                let (mut accepted, mut total) = observe(|| endpoint.write(&plaintext));
                assert!(accepted > 0 && accepted < plaintext.len());
                assert_plaintext_budget(total, accepted);
                assert!(endpoint.output().len() <= 256 * 1024);
                let committed = endpoint.output().to_vec();
                let first_record_len =
                    5 + usize::from(u16::from_be_bytes([committed[3], committed[4]]));
                for _ in 0..3 {
                    let (count, copies) = observe(|| endpoint.write(&plaintext[accepted..]));
                    assert_eq!(count, 0);
                    assert_eq!(copies.bytes, [0; 8]);
                    assert_eq!(endpoint.output(), committed);
                }
                let mut wire = Vec::new();
                consume_transport(&mut endpoint, &mut wire, 1);
                let (count, copies) = observe(|| endpoint.write(&plaintext[accepted..]));
                assert_eq!(count, 0);
                assert_plaintext_budget(copies, 0);
                assert_eq!(copies.bytes[CopySite::OutputCompact as usize], 0);
                total.add(copies);
                consume_transport(&mut endpoint, &mut wire, first_record_len + 2);
                let pending = endpoint.output().to_vec();
                let (count, copies) = observe(|| endpoint.write(&plaintext[accepted..]));
                assert_eq!(
                    count, 0,
                    "a small consumed prefix cannot pay for compaction"
                );
                assert_plaintext_budget(copies, count);
                assert!(endpoint.output().starts_with(&pending));
                total.add(copies);
                accepted += count;
                while accepted < plaintext.len() {
                    let count = endpoint.output().len().div_ceil(2);
                    consume_transport(&mut endpoint, &mut wire, count);
                    let (count, copies) = observe(|| endpoint.write(&plaintext[accepted..]));
                    assert!(count > 0);
                    assert_plaintext_budget(copies, count);
                    total.add(copies);
                    accepted += count;
                    assert!(endpoint.output().len() <= 256 * 1024);
                }
                while !endpoint.output().is_empty() {
                    let count = endpoint.output().len().min(1511);
                    consume_transport(&mut endpoint, &mut wire, count);
                }
                assert_plaintext_budget(total, plaintext.len());
                verify_wire(suite, &wire, &plaintext);
                emit(
                    suite,
                    continuous,
                    size,
                    "capacity_retry_partial_consume",
                    accepted,
                    total,
                );
            }
        }
    }
}

#[test]
fn endpoint_copy_budget_receive_and_partial_plaintext_consumption() {
    for continuous in [false, true] {
        for suite in AEAD_SUITES {
            for size in [1, 1024, 16384] {
                let mut endpoint = Endpoint::new(suite, continuous);
                let (mut peer, _) = suite.pair();
                let plaintext = vec![0x31; size];
                let records: Vec<_> = (0..3)
                    .map(|_| peer.write_record(23, &plaintext).unwrap())
                    .collect();
                let wire = records.concat();
                let (accepted, mut copies) = observe(|| endpoint.feed(&wire));
                assert_eq!(accepted, wire.len());
                assert_eq!(
                    copies.bytes[CopySite::InputFeed as usize],
                    wire.len() as u64
                );
                for record in &records {
                    let (progress, opened) = observe(|| endpoint.process_read());
                    assert_eq!(progress, ReadProgress::Plaintext);
                    assert_eq!(
                        opened.bytes[CopySite::CiphertextOpen as usize],
                        (record.len() - 5) as u64
                    );
                    assert_eq!(opened.calls[CopySite::CiphertextOpen as usize], 1);
                    copies.add(opened);
                    assert_eq!(endpoint.plaintext(), plaintext);
                    let pointer = endpoint.plaintext().as_ptr();
                    let consumed = size / 2;
                    let (progress, retained) = observe(|| {
                        endpoint.consume_plaintext(consumed);
                        endpoint.process_read()
                    });
                    assert_eq!(progress, ReadProgress::Plaintext);
                    assert_eq!(retained.bytes, [0; 8]);
                    assert_eq!(
                        endpoint.plaintext().as_ptr(),
                        pointer.wrapping_add(consumed)
                    );
                    assert_eq!(endpoint.plaintext(), &plaintext[consumed..]);
                    let (_, consumed) = observe(|| endpoint.consume_plaintext(size - consumed));
                    assert_eq!(consumed.bytes, [0; 8]);
                }
                let (progress, empty) = observe(|| endpoint.process_read());
                assert_eq!(progress, ReadProgress::NeedInput);
                assert_eq!(empty.bytes, [0; 8]);
                assert_eq!(copies.bytes[CopySite::PlaintextSeal as usize], 0);
                assert_eq!(
                    copies.bytes[CopySite::CiphertextOpen as usize],
                    (wire.len() - 15) as u64
                );
                emit(
                    suite,
                    continuous,
                    size,
                    "receive_partial_plaintext_consume",
                    0,
                    copies,
                );
            }
        }
    }
}
