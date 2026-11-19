//! External-consumer fixture using only APIs present before the TLS refactor.
//! Run this exact file at 70db5785 and at the candidate with separate targets.
//! This checks source compatibility and basic facade behavior, not semver for
//! every exported item or authentication provenance of arbitrary legacy tickets.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use lktls::crypto::{aead::AeadAlgorithm, hkdf::HkdfAlgorithm};
use lktls::handshake::driver::{
    HandshakeConfig, HandshakeDriver, HandshakeOutput, HandshakeResult, PostHandshakeState,
    QuicHandshakeConfig, QuicHandshakeDriver, QuicHandshakeOutput, QuicHandshakeResult,
    QuicTrafficSecrets, SessionTicketContext,
};
use lktls::handshake::tls12::{Tls12Handshake, Tls12State};
use lktls::handshake::tls13::{Tls13Handshake, Tls13State};
use lktls::profile::{presets, types::TlsProfile};
use lktls::record::{reader::RecordReader, writer::RecordWriter};
use lktls::session_store::{AlpsSessionState, SessionStore, SessionTicketData, TicketTlsVersion};
use lktls::verify::policy::VerificationPolicy;

#[derive(Debug, Default)]
struct ExternalStore(Mutex<Option<(String, SessionTicketData)>>);

impl SessionStore for ExternalStore {
    fn store(&self, host: &str, ticket: SessionTicketData) {
        *self.0.lock().unwrap() = Some((host.into(), ticket));
    }

    fn take(&self, host: &str) -> Option<SessionTicketData> {
        let mut stored = self.0.lock().unwrap();
        if stored.as_ref().is_some_and(|(key, _)| key == host) {
            stored.take().map(|(_, ticket)| ticket)
        } else {
            None
        }
    }
}

fn config(profile: TlsProfile) -> HandshakeConfig {
    HandshakeConfig {
        profile,
        hostname: "localhost".into(),
        port: 443,
        verification_policy: VerificationPolicy::Strict,
        alps_payload: None,
        session_store: Some(Arc::new(ExternalStore::default())),
        ech_config_list: None,
        custom_ca_anchors: None,
        keylog_callback: None,
        client_hello_callback: None,
        trust_anchor_observer: None,
    }
}

#[test]
fn external_config_literals_and_driver_entry_points_remain_compatible() {
    let config = config(presets::chrome_144());
    let mut tcp = HandshakeDriver::new(config.clone());
    let hello = tcp.start().unwrap();
    assert_eq!(hello.first(), Some(&22));
    tcp.feed(&[]);
    match tcp.progress().unwrap() {
        HandshakeOutput::NeedData => {}
        HandshakeOutput::SendData(_) | HandshakeOutput::Done { .. } => {
            panic!("a peer flight is required")
        }
    }

    let mut quic = QuicHandshakeDriver::new(QuicHandshakeConfig {
        tls: config,
        transport_parameters: vec![],
    });
    let hello = quic.start().unwrap();
    assert_eq!(hello.first(), Some(&1));
    quic.feed(&[]);
    match quic.progress().unwrap() {
        QuicHandshakeOutput::NeedData => {}
        QuicHandshakeOutput::SendData(_)
        | QuicHandshakeOutput::HandshakeSecretsReady { .. }
        | QuicHandshakeOutput::Done { .. } => panic!("a peer flight is required"),
    }
}

#[test]
fn external_ticket_literal_and_two_method_store_remain_compatible() {
    let store = ExternalStore::default();
    let ticket = SessionTicketData {
        ticket: vec![1, 2, 3],
        resumption_psk: vec![0x42; 32],
        tls_version: TicketTlsVersion::Tls13,
        cipher_suite: 0x1301,
        lifetime_secs: 60,
        age_add: 0,
        received_at: Instant::now(),
        alpn: None,
        alps: AlpsSessionState::NotNegotiated,
        hkdf_algorithm: HkdfAlgorithm::Sha256,
        aead_algorithm: AeadAlgorithm::Aes128Gcm,
        master_secret: vec![],
        max_early_data_size: 0,
        peer_transport_parameters: None,
        used_extended_master_secret: None,
    };
    assert!(!ticket.is_expired());
    store.store("localhost:443", ticket);
    assert!(store.take("other:443").is_none());
    assert_eq!(store.take("localhost:443").unwrap().ticket, [1, 2, 3]);
    assert!(store.take("localhost:443").is_none());
}

#[test]
fn external_result_literals_and_post_handshake_methods_remain_compatible() {
    let mut post = PostHandshakeState {
        server_app_secret: vec![1; 32],
        client_app_secret: vec![2; 32],
        hkdf_algorithm: HkdfAlgorithm::Sha256,
        aead_algorithm: AeadAlgorithm::Aes128Gcm,
        exporter_master_secret: vec![3; 32],
    };
    let mut reader = RecordReader::new();
    reader.set_keys(post.process_key_update().unwrap());
    let (message, key) = post.build_key_update_response().unwrap();
    assert_eq!(message, [24, 0, 0, 1, 0]);
    let mut writer = RecordWriter::new();
    writer.set_keys(key);
    let result = HandshakeResult {
        reader,
        writer,
        negotiated_alpn: Some("h2".into()),
        negotiated_cipher_suite: Some(0x1301),
        negotiated_version: Some(0x0304),
        peer_certificates: vec![],
        post_handshake: Some(post),
        session_ticket_ctx: Some(SessionTicketContext {
            resumption_master_secret: vec![4; 32],
            hkdf_algorithm: HkdfAlgorithm::Sha256,
            aead_algorithm: AeadAlgorithm::Aes128Gcm,
            cipher_suite: 0x1301,
            alpn: None,
            alps: AlpsSessionState::NotNegotiated,
            peer_transport_parameters: None,
            store: Arc::new(ExternalStore::default()),
            host_key: "localhost:443".into(),
        }),
    };
    let secrets = QuicTrafficSecrets {
        client_secret: vec![5; 32],
        server_secret: vec![6; 32],
        hkdf_algorithm: HkdfAlgorithm::Sha256,
        aead_algorithm: AeadAlgorithm::Aes128Gcm,
    };
    let quic = QuicHandshakeResult {
        negotiated_alpn: Some("h3".into()),
        negotiated_cipher_suite: Some(0x1301),
        handshake_secrets: secrets.clone(),
        app_secrets: secrets,
        post_handshake: result.post_handshake,
        session_ticket_ctx: result.session_ticket_ctx,
        peer_transport_params: None,
        early_data_accepted: false,
        session_resumed: false,
    };
    assert_eq!(quic.negotiated_alpn.as_deref(), Some("h3"));
}

#[test]
fn low_level_version_facades_remain_available() {
    let mut tls12 = Tls12Handshake::new([7; 32], "localhost", VerificationPolicy::Strict);
    tls12.set_custom_ca_anchors(Arc::default());
    assert_eq!(tls12.state(), Tls12State::WaitServerHello);
    assert!(tls12.master_secret().is_none());
    assert!(tls12.server_certificates().is_empty());

    let mut tls13 = Tls13Handshake::new(presets::chrome_144(), "localhost");
    tls13.set_verification_policy(VerificationPolicy::Strict);
    assert_eq!(tls13.state(), Tls13State::Start);
    assert_eq!(tls13.build_client_hello().unwrap().first(), Some(&1));
    assert_eq!(tls13.state(), Tls13State::WaitServerHello);
}
