use lktls::handshake::tls12::{Tls12Handshake, Tls12HandshakeAction};
use lktls::verify::policy::VerificationPolicy;

fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut encoded = vec![kind];
    encoded.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    encoded.extend_from_slice(body);
    encoded
}

fn hello(client: bool, suite: u16, extensions: &[(u16, &[u8])]) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0x42; 32]);
    body.push(0);
    if client {
        body.extend_from_slice(&[0, 2]);
    }
    body.extend_from_slice(&suite.to_be_bytes());
    if client {
        body.push(1);
    }
    body.push(0);
    let mut encoded = Vec::new();
    for (code, payload) in extensions {
        encoded.extend_from_slice(&code.to_be_bytes());
        encoded.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        encoded.extend_from_slice(payload);
    }
    body.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
    body.extend_from_slice(&encoded);
    message(if client { 1 } else { 2 }, &body)
}

fn negotiate(suite: u16, code: u16, payload: &[u8]) -> lktls::error::Result<Tls12HandshakeAction> {
    let mut hs = Tls12Handshake::new([0x42; 32], "localhost", VerificationPolicy::Insecure);
    hs.feed_client_hello(&hello(true, suite, &[(code, &[])]));
    hs.process_handshake_record(&hello(false, suite, &[(code, payload)]))
}

#[test]
fn tls12_empty_server_extensions_are_validated_even_with_raw_offers() {
    for code in [0, 5, 22, 23, 35] {
        assert!(negotiate(0xc013, code, &[]).is_ok(), "code={code}");
        assert!(negotiate(0xc013, code, &[0]).is_err(), "code={code}");
    }
}

#[test]
fn tls12_known_extensions_cannot_appear_in_the_wrong_context() {
    for code in [
        10, 13, 21, 27, 34, 41, 42, 43, 44, 45, 51, 57, 0x4469, 0x44cd, 0x0a0a,
    ] {
        assert!(negotiate(0xc013, code, &[]).is_err(), "code={code}");
    }
}

#[test]
fn tls12_renegotiation_point_formats_and_sct_have_exact_vectors() {
    assert!(negotiate(0xc013, 0xff01, &[0]).is_ok());
    for payload in [&[][..], &[1, 0], &[0, 0]] {
        assert!(negotiate(0xc013, 0xff01, payload).is_err());
    }
    assert!(negotiate(0xc013, 11, &[1, 0]).is_ok());
    for payload in [&[][..], &[0], &[1, 1], &[1, 0, 0]] {
        assert!(negotiate(0xc013, 11, payload).is_err());
    }
    assert!(negotiate(0xc013, 18, &[0, 3, 0, 1, 0]).is_ok());
    for payload in [&[][..], &[0, 0], &[0, 2, 0, 0], &[0, 4, 0, 1, 0]] {
        assert!(negotiate(0xc013, 18, payload).is_err());
    }
}

#[test]
fn encrypt_then_mac_is_for_cbc_suites_only() {
    for suite in [0xc02f, 0xcca8, 0x009c] {
        assert!(negotiate(suite, 22, &[]).is_err(), "suite={suite:04x}");
    }
}

#[test]
fn ecdhe_ecdsa_cbc_suites_have_executable_descriptors() {
    for suite in [0xc009, 0xc00a, 0xc023, 0xc024] {
        assert!(negotiate(suite, 23, &[]).is_ok(), "suite={suite:04x}");
    }
}

fn server_flight(suite: u16, status: bool) -> Tls12Handshake {
    let mut hs = Tls12Handshake::new([0x42; 32], "localhost", VerificationPolicy::Insecure);
    let extensions: &[(u16, &[u8])] = if status { &[(5, &[])] } else { &[] };
    hs.process_handshake_record(&hello(false, suite, extensions))
        .unwrap();
    hs.process_handshake_record(&message(11, &[0, 0, 4, 0, 0, 1, 0]))
        .unwrap();
    hs
}

fn key_exchange() -> Vec<u8> {
    let key = lktls::crypto::kx::generate_key_pair(lktls::crypto::kx::KxGroup::X25519).unwrap();
    let mut body = vec![3, 0, 29, key.public_key.len() as u8];
    body.extend_from_slice(&key.public_key);
    body.extend_from_slice(&[4, 3, 0, 1, 0]);
    body
}

#[test]
fn certificate_vector_cannot_hide_trailing_or_empty_entries() {
    for body in [
        &[0, 0, 3, 0, 0, 1, 0][..],
        &[0, 0, 4, 0, 0, 1, 0, 0],
        &[0, 0, 5, 0, 0, 1, 0, 0],
        &[0, 0, 3, 0, 0, 0],
    ] {
        let mut hs = Tls12Handshake::new([0x42; 32], "localhost", VerificationPolicy::Insecure);
        hs.process_handshake_record(&hello(false, 0xc02b, &[]))
            .unwrap();
        assert!(
            hs.process_handshake_record(&message(11, body)).is_err(),
            "body={body:?}"
        );
    }
}

#[test]
fn key_exchange_and_hello_done_bodies_are_exact() {
    let mut hs = server_flight(0xc02b, false);
    let mut ske = key_exchange();
    ske.push(0);
    assert!(hs.process_handshake_record(&message(12, &ske)).is_err());
    let mut hs = server_flight(0xc02b, false);
    hs.process_handshake_record(&message(12, &key_exchange()))
        .unwrap();
    assert!(hs.process_handshake_record(&message(14, &[0])).is_err());
}

#[test]
fn certificate_request_is_structural_and_may_appear_only_once() {
    for body in [
        &[][..],
        &[0, 0, 2, 4, 3, 0, 0],
        &[1, 1, 0, 1, 4, 0, 0],
        &[1, 1, 0, 2, 4, 3, 0, 1, 0],
    ] {
        let mut hs = server_flight(0xc02b, false);
        hs.process_handshake_record(&message(12, &key_exchange()))
            .unwrap();
        assert!(
            hs.process_handshake_record(&message(13, body)).is_err(),
            "body={body:?}"
        );
    }
    let mut hs = server_flight(0xc02b, false);
    hs.process_handshake_record(&message(12, &key_exchange()))
        .unwrap();
    let request = message(13, &[1, 1, 0, 2, 4, 3, 0, 0]);
    hs.process_handshake_record(&request).unwrap();
    assert!(hs.process_handshake_record(&request).is_err());
}

#[test]
fn certificate_status_is_negotiated_structural_and_single_use() {
    let status = message(22, &[1, 0, 0, 1, 0]);
    let mut unsolicited = server_flight(0xc02b, false);
    assert!(unsolicited.process_handshake_record(&status).is_err());
    for body in [
        &[][..],
        &[2, 0, 0, 1, 0],
        &[1, 0, 0, 0],
        &[1, 0, 0, 1, 0, 0],
    ] {
        let mut hs = server_flight(0xc02b, true);
        assert!(hs.process_handshake_record(&message(22, body)).is_err());
    }
    for suite in [0xc02b, 0x002f] {
        let mut hs = server_flight(suite, true);
        hs.process_handshake_record(&status).unwrap();
        assert!(hs.process_handshake_record(&status).is_err());
    }
}

#[test]
fn negotiated_certificate_status_may_be_omitted() {
    let mut hs = server_flight(0xc02b, true);
    hs.process_handshake_record(&message(12, &key_exchange()))
        .unwrap();
    assert!(matches!(
        hs.process_handshake_record(&message(14, &[])).unwrap(),
        Tls12HandshakeAction::SendClientFlight(_)
    ));
    let mut rsa = server_flight(0x002f, true);
    assert!(matches!(
        rsa.process_handshake_record(&message(13, &[1, 1, 0, 2, 4, 1, 0, 0]))
            .unwrap(),
        Tls12HandshakeAction::ContinueReading
    ));
}

#[test]
fn insecure_tls12_accepts_legacy_ecdsa_schemes_but_rejects_wrong_authentication() {
    for scheme in [0x0203u16, 0x0603] {
        let mut hs = server_flight(0xc02b, false);
        let mut body = key_exchange();
        let offset = body.len() - 5;
        body[offset..offset + 2].copy_from_slice(&scheme.to_be_bytes());
        hs.process_handshake_record(&message(12, &body)).unwrap();
    }
    let mut hs = server_flight(0xc02f, false);
    assert!(hs
        .process_handshake_record(&message(12, &key_exchange()))
        .is_err());
}

fn resumed_finished() -> (Tls12Handshake, Vec<u8>) {
    let mut hs = Tls12Handshake::new([0x42; 32], "localhost", VerificationPolicy::Insecure);
    hs.set_session_ticket_resumption(vec![0x73; 48], Some(false));
    let client = hello(true, 0xc02b, &[]);
    let server = hello(false, 0xc02b, &[]);
    hs.feed_client_hello(&client);
    hs.process_handshake_record(&server).unwrap();
    hs.accept_abbreviated_ccs().unwrap();
    let transcript = [client, server].concat();
    let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &transcript);
    let verify = lktls::crypto::prf::compute_verify_data(
        lktls::crypto::prf::PrfAlgorithm::Sha256,
        &[0x73; 48],
        "server finished",
        hash.as_ref(),
    )
    .unwrap();
    (hs, verify)
}

#[test]
fn finished_message_header_and_flow_are_part_of_the_contract() {
    let (mut hs, verify) = resumed_finished();
    let mut malformed = message(20, &verify);
    malformed[3] = 11;
    assert!(hs.process_abbreviated_server_finished(&malformed).is_err());
    let (mut hs, verify) = resumed_finished();
    assert!(hs.process_server_finished(&verify).is_err());
    let (mut hs, verify) = resumed_finished();
    assert!(hs
        .process_abbreviated_server_finished(&message(20, &verify))
        .is_ok());
}

#[test]
fn failed_handshake_cannot_continue_with_replacement_messages() {
    let mut hs = server_flight(0xc02b, false);
    let valid = key_exchange();
    let mut malformed = valid.clone();
    malformed.push(0);
    assert!(hs
        .process_handshake_record(&message(12, &malformed))
        .is_err());
    assert!(hs.process_handshake_record(&message(12, &valid)).is_err());
}

fn resumption_with_ticket_ack(acknowledged: bool) -> Tls12Handshake {
    let mut hs = Tls12Handshake::new([0x42; 32], "localhost", VerificationPolicy::Insecure);
    hs.set_session_ticket_resumption(vec![0x73; 48], Some(false));
    hs.feed_client_hello(&hello(true, 0xc02b, &[(35, &[])]));
    let extensions: &[(u16, &[u8])] = if acknowledged { &[(35, &[])] } else { &[] };
    hs.process_handshake_record(&hello(false, 0xc02b, extensions))
        .unwrap();
    hs
}

#[test]
fn tls12_ticket_is_negotiated_and_has_an_exact_vector() {
    let valid = [0, 0, 0, 60, 0, 1, 0x42];
    let mut hs = resumption_with_ticket_ack(false);
    assert!(hs.process_handshake_record(&message(4, &valid)).is_err());
    for body in [&valid[..6], &[0, 0, 0, 60, 0, 1, 0x42, 0]] {
        let mut hs = resumption_with_ticket_ack(true);
        assert!(hs.process_handshake_record(&message(4, body)).is_err());
    }
}

#[test]
fn tls12_renewed_ticket_commits_the_abbreviated_flight() {
    for next in [
        message(4, &[0, 0, 0, 60, 0, 1, 0x42]),
        message(11, &[0, 0, 4, 0, 0, 1, 0]),
    ] {
        let mut hs = resumption_with_ticket_ack(true);
        hs.process_handshake_record(&message(4, &[0, 0, 0, 60, 0, 1, 0x42]))
            .unwrap();
        assert!(hs.process_handshake_record(&next).is_err());
    }
}

#[test]
fn tls12_promised_ticket_must_precede_ccs() {
    let mut hs = resumption_with_ticket_ack(true);
    assert!(hs.accept_abbreviated_ccs().is_err());
    let mut hs = resumption_with_ticket_ack(true);
    // Empty tickets are a valid refusal to issue a session, per RFC 5077.
    hs.process_handshake_record(&message(4, &[0, 0, 0, 0, 0, 0]))
        .unwrap();
    assert!(hs.accept_abbreviated_ccs().is_ok());
}

fn full_flight_with_ticket() -> Tls12Handshake {
    let mut hs = Tls12Handshake::new([0x42; 32], "localhost", VerificationPolicy::Insecure);
    hs.feed_client_hello(&hello(
        true,
        0xc02b,
        &[(35, &[]), (13, &[0, 2, 4, 3]), (10, &[0, 2, 0, 29])],
    ));
    hs.process_handshake_record(&hello(false, 0xc02b, &[(35, &[])]))
        .unwrap();
    hs.process_handshake_record(&message(11, &[0, 0, 4, 0, 0, 1, 0]))
        .unwrap();
    hs.process_handshake_record(&message(12, &key_exchange()))
        .unwrap();
    hs.process_handshake_record(&message(14, &[])).unwrap();
    hs
}

#[test]
fn tls12_full_flight_validates_tickets_before_ccs() {
    for body in [&[][..], &[0, 0, 0, 60, 0, 1], &[0, 0, 0, 60, 0, 1, 0x42, 0]] {
        assert!(full_flight_with_ticket()
            .process_handshake_record(&message(4, body))
            .is_err());
    }
    let mut hs = full_flight_with_ticket();
    let ticket = message(4, &[0, 0, 0, 60, 0, 1, 0x42]);
    hs.process_handshake_record(&ticket).unwrap();
    assert!(hs.process_handshake_record(&ticket).is_err());
    let mut hs = full_flight_with_ticket();
    hs.notify_server_ccs_received();
    assert!(hs.process_handshake_record(&ticket).is_err());
}
