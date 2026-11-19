use lktls::connection::TcpConnection;
use lktls::crypto::aead::AeadAlgorithm;
use lktls::crypto::hkdf::HkdfAlgorithm;
use lktls::error::{AlertDescription, TlsError};
use lktls::handshake::driver::{HandshakeResult, SessionTicketContext};
use lktls::profile::types::TlsClientHelloStyle;
use lktls::record::{reader::RecordReader, writer::RecordWriter};

fn ticket(extensions: &[u8]) -> Vec<u8> {
    let mut body = vec![0, 0, 0x0e, 0x10, 0, 0, 0, 0, 0, 0, 1, 7];
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(extensions);
    let mut message = vec![4];
    message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    message.extend_from_slice(&body);
    message
}

fn parse(message: &[u8]) -> Result<lktls::session_store::SessionTicketData, String> {
    lktls::session_store::parse_tls13_new_session_ticket(
        message,
        &[0x22; 32],
        HkdfAlgorithm::Sha256,
        AeadAlgorithm::Aes128Gcm,
        0x1301,
        None,
    )
}

#[test]
fn ticket_parser_rejects_inconsistent_lengths_and_known_extension_duplicates() {
    let mut missing_extensions = ticket(&[]);
    missing_extensions.truncate(missing_extensions.len() - 2);
    missing_extensions[3] -= 2;
    let mut trailing = ticket(&[]);
    trailing.push(0);
    trailing[3] += 1;
    let mut header_mismatch = ticket(&[]);
    header_mismatch[3] += 1;
    let mut empty_ticket = ticket(&[]);
    empty_ticket.remove(15);
    empty_ticket[14] = 0;
    empty_ticket[3] -= 1;
    let duplicate_early = ticket(&[0, 42, 0, 4, 0, 0, 0, 1, 0, 42, 0, 4, 0, 0, 0, 2]);
    let short_early = ticket(&[0, 42, 0, 2, 0, 1]);
    for (name, invalid) in [
        ("missing extension vector", missing_extensions),
        ("trailing bytes", trailing),
        ("header mismatch", header_mismatch),
        ("empty ticket", empty_ticket),
        ("duplicate early_data", duplicate_early),
        ("short early_data", short_early),
    ] {
        assert!(parse(&invalid).is_err(), "accepted {name}");
    }
    let unknown = ticket(&[0xfa, 0xfa, 0, 0, 0xfa, 0xfa, 0, 1, 9]);
    assert_eq!(parse(&unknown).unwrap().ticket, [7]);
}

#[test]
fn tcp_validates_tickets_even_without_a_session_store() {
    let mut connection = TcpConnection::from_handshake(
        HandshakeResult {
            reader: RecordReader::new(),
            writer: RecordWriter::new(),
            negotiated_alpn: None,
            negotiated_cipher_suite: Some(0x1301),
            negotiated_version: Some(0x0304),
            peer_certificates: Vec::new(),
            post_handshake: None,
            session_ticket_ctx: None,
        },
        TlsClientHelloStyle::ChromiumBoringssl,
    );
    let malformed = ticket(&[0, 42, 0, 2, 0, 1]);
    connection.feed(&RecordWriter::new().write_record(22, &malformed).unwrap());
    assert!(
        matches!(connection.process_read(), Err(TlsError::LocalAlert { alert, .. }) if alert.description == AlertDescription::DecodeError)
    );
    assert!(connection.output().ends_with(&[2, 50]));
}

#[test]
fn ticket_lifetime_policy_discards_unusable_sessions_without_failing_tls() {
    use lktls::session_store::{AlpsSessionState, InMemorySessionStore, SessionStore};
    use std::sync::Arc;

    for lifetime in [0u32, 604_800, 604_801] {
        let store = Arc::new(InMemorySessionStore::new());
        let context = SessionTicketContext {
            resumption_master_secret: vec![0x22; 32],
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            cipher_suite: 0x1301,
            alpn: None,
            alps: AlpsSessionState::NotNegotiated,
            peer_transport_parameters: None,
            store: store.clone(),
            host_key: "localhost:443".into(),
        };
        let mut connection = lktls::connection::QuicPostHandshake::new(Some(context));
        let mut message = ticket(&[]);
        message[4..8].copy_from_slice(&lifetime.to_be_bytes());
        assert!(connection.read(&message).is_ok());
        assert_eq!(store.take("localhost:443").is_some(), lifetime == 604_800);
    }
}

#[test]
fn quic_control_cannot_resume_after_a_fatal_ticket() {
    let mut control = lktls::connection::QuicPostHandshake::new(None);
    assert!(control.read(&ticket(&[0, 42, 0, 4, 0, 0, 0, 1])).is_err());
    assert!(matches!(
        control.read(&ticket(&[])),
        Err(lktls::connection::QuicControlError::Failed)
    ));
}

#[test]
fn tls12_legacy_ticket_parser_uses_exact_message_and_ticket_lengths() {
    let parse = |bytes: &[u8]| {
        lktls::session_store::parse_tls12_new_session_ticket(
            bytes,
            &[7; 48],
            None,
            None,
            Some(true),
        )
    };
    let valid = vec![4, 0, 0, 7, 0, 0, 0, 60, 0, 1, 0x42];
    assert_eq!(parse(&valid).unwrap().ticket, [0x42]);
    assert_eq!(
        parse(&valid[4..]).unwrap().used_extended_master_secret,
        Some(true)
    );
    let mut bad_header = valid.clone();
    bad_header[3] += 1;
    let mut trailing = valid;
    trailing.push(0);
    trailing[3] += 1;
    assert!(parse(&bad_header).is_err());
    assert!(parse(&trailing).is_err());
}
