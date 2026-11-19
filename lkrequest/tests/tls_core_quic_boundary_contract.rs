//! A key transition cannot reinterpret Initial CRYPTO bytes as Handshake input.

use std::sync::Arc;

use lktls::handshake::driver::{HandshakeConfig, QuicHandshakeDriver, QuicHandshakeOutput};
use lktls::profile::presets;
use lktls::verify::policy::VerificationPolicy;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

fn setup() -> (QuicHandshakeDriver, rustls::quic::ServerConnection) {
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let anchor =
        lktls::verify::certchain::parse_trust_anchor_from_der(identity.cert.der()).unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![identity.cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            identity.signing_key.serialize_der(),
        )),
    )
    .unwrap();
    config.alpn_protocols = vec![b"h3".to_vec()];
    let peer = rustls::quic::ServerConnection::new(
        Arc::new(config),
        rustls::quic::Version::V1,
        Vec::new(),
    )
    .unwrap();
    let client = QuicHandshakeDriver::new(
        HandshakeConfig {
            profile: presets::chrome_155_quic(),
            hostname: "localhost".into(),
            port: 443,
            verification_policy: VerificationPolicy::Strict,
            alps_payload: None,
            session_store: None,
            ech_config_list: None,
            custom_ca_anchors: Some(Arc::new(vec![anchor])),
            keylog_callback: None,
            client_hello_callback: None,
            trust_anchor_observer: None,
        }
        .into_quic(Vec::new()),
    );
    (client, peer)
}

fn server_flights() -> (QuicHandshakeDriver, Vec<u8>, Vec<u8>) {
    let (mut client, mut peer) = setup();
    peer.read_hs(&client.start().unwrap()).unwrap();
    let mut initial = Vec::new();
    assert!(
        peer.write_hs(&mut initial).is_some(),
        "ServerHello must expose the Handshake key transition"
    );
    assert_eq!(initial[0], 2);
    let mut handshake = Vec::new();
    let _ = peer.write_hs(&mut handshake);
    assert_eq!(handshake[0], 8);
    (client, initial, handshake)
}

#[test]
fn quic_connection_requires_key_delivery_before_next_level_input() {
    use lktls::connection::{QuicClientConnection, QuicLevel};
    for consume_keys in [false, true] {
        let (driver, mut peer) = setup();
        let mut client = QuicClientConnection::new(driver).unwrap();
        let mut hello = Vec::new();
        assert!(client.write_handshake(&mut hello).is_none());
        peer.read_hs(&hello).unwrap();
        let mut initial = Vec::new();
        assert!(peer.write_hs(&mut initial).is_some());
        let mut handshake = Vec::new();
        let _ = peer.write_hs(&mut handshake);
        assert!(client.read(&initial).unwrap().is_none());
        if !consume_keys {
            assert!(client.read(&handshake).is_err());
            assert!(client.read(&[]).is_err());
            let mut output = Vec::new();
            assert!(client.write_handshake(&mut output).is_none());
            assert!(
                output.is_empty(),
                "failed connection must discard keys and output"
            );
            continue;
        }
        let mut output = Vec::new();
        assert_eq!(
            client.write_handshake(&mut output).unwrap().0,
            QuicLevel::Handshake
        );
        assert!(output.is_empty());
        assert!(client.read(&handshake).unwrap().is_some());
        assert_eq!(
            client.write_handshake(&mut output).unwrap().0,
            QuicLevel::OneRtt
        );
        assert_eq!(output[0], 20, "Finished precedes OneRtt keys");
        peer.read_hs(&output).unwrap();
        assert!(!peer.is_handshaking());
        output.clear();
        assert!(client.write_handshake(&mut output).is_none());
        assert!(output.is_empty());
    }
}

#[test]
fn quic_initial_server_hello_rejects_complete_or_partial_handshake_epoch_tail() {
    for tail_length in [1, 3, 5, usize::MAX] {
        let (mut client, mut initial, handshake) = server_flights();
        let ee_length = lktls::handshake::framing::message_length(&handshake, 0xff_ffff)
            .unwrap()
            .unwrap();
        initial.extend_from_slice(&handshake[..tail_length.min(ee_length)]);
        client.feed(&initial);
        assert!(
            client.progress().is_err(),
            "Initial CRYPTO accepted a next-epoch suffix of {} bytes",
            tail_length.min(ee_length)
        );
    }
}

#[test]
fn quic_server_hello_fragmentation_with_a_clean_key_boundary_is_valid() {
    let (mut client, initial, handshake) = server_flights();
    client.feed(&initial[..3]);
    assert!(matches!(
        client.progress().unwrap(),
        QuicHandshakeOutput::NeedData
    ));
    client.feed(&initial[3..]);
    assert!(matches!(
        client.progress().unwrap(),
        QuicHandshakeOutput::HandshakeSecretsReady { .. }
    ));
    client.feed(&handshake);
    assert!(matches!(
        client.progress().unwrap(),
        QuicHandshakeOutput::Done { .. }
    ));
}
