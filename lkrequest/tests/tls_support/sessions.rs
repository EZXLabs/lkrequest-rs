//! Authenticated issuance context for synthetic protocol regression tickets.

use std::io::Cursor;
use std::sync::Arc;

use lktls::handshake::driver::{
    HandshakeConfig, HandshakeDriver, HandshakeOutput, QuicHandshakeDriver, QuicHandshakeOutput,
    SessionTicketContext,
};
use lktls::session_store::{InMemorySessionStore, SessionTicketData};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, TrustAnchor};

pub fn seeded_session(
    hostname: &str,
    port: u16,
    mut anchors: Vec<TrustAnchor<'static>>,
    ticket: SessionTicketData,
    quic: bool,
) -> (Arc<InMemorySessionStore>, Arc<Vec<TrustAnchor<'static>>>) {
    let identity = rcgen::generate_simple_self_signed(vec![hostname.into()]).unwrap();
    anchors
        .push(lktls::verify::certchain::parse_trust_anchor_from_der(identity.cert.der()).unwrap());
    let anchors = Arc::new(anchors);
    let mut server = rustls::ServerConfig::builder_with_provider(
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
    if quic {
        server.alpn_protocols = vec![b"h3".to_vec()];
    }
    let store = Arc::new(InMemorySessionStore::new());
    let config = HandshakeConfig {
        profile: if quic {
            lktls::profile::presets::chrome_155_quic()
        } else {
            lktls::profile::presets::chrome_155()
        },
        hostname: hostname.into(),
        port,
        verification_policy: lktls::verify::policy::VerificationPolicy::Strict,
        alps_payload: None,
        session_store: Some(store.clone()),
        ech_config_list: None,
        custom_ca_anchors: Some(anchors.clone()),
        keylog_callback: None,
        client_hello_callback: None,
        trust_anchor_observer: None,
    };
    let context = if quic {
        quic_context(config, server)
    } else {
        tcp_context(config, server)
    };
    context.store.store(&context.host_key, ticket);
    (store, anchors)
}

fn tcp_context(config: HandshakeConfig, server: rustls::ServerConfig) -> SessionTicketContext {
    let mut client = HandshakeDriver::new(config);
    let mut server = rustls::ServerConnection::new(Arc::new(server)).unwrap();
    let mut to_server = client.start().unwrap();
    for _ in 0..16 {
        if !to_server.is_empty() {
            server.read_tls(&mut Cursor::new(&to_server)).unwrap();
            server.process_new_packets().unwrap();
            to_server.clear();
        }
        let mut to_client = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut to_client).unwrap();
        }
        client.feed(&to_client);
        loop {
            match client.progress().unwrap() {
                HandshakeOutput::SendData(data) => to_server.extend_from_slice(&data),
                HandshakeOutput::NeedData => break,
                HandshakeOutput::Done { to_send, result } => {
                    server.read_tls(&mut Cursor::new(to_send)).unwrap();
                    server.process_new_packets().unwrap();
                    assert!(!server.is_handshaking());
                    return result.session_ticket_ctx.unwrap();
                }
            }
        }
    }
    panic!("TLS fixture handshake did not complete");
}

fn quic_context(config: HandshakeConfig, server: rustls::ServerConfig) -> SessionTicketContext {
    let mut client = QuicHandshakeDriver::new(config.into_quic(Vec::new()));
    let mut server = rustls::quic::ServerConnection::new(
        Arc::new(server),
        rustls::quic::Version::V1,
        Vec::new(),
    )
    .unwrap();
    let mut to_server = client.start().unwrap();
    for _ in 0..16 {
        if !to_server.is_empty() {
            server.read_hs(&to_server).unwrap();
            to_server.clear();
        }
        let mut to_client = Vec::new();
        let _ = server.write_hs(&mut to_client);
        client.feed(&to_client);
        loop {
            match client.progress().unwrap() {
                QuicHandshakeOutput::SendData(data) => to_server.extend_from_slice(&data),
                QuicHandshakeOutput::HandshakeSecretsReady { to_send, .. } => {
                    to_server.extend_from_slice(&to_send)
                }
                QuicHandshakeOutput::NeedData => break,
                QuicHandshakeOutput::Done { to_send, result } => {
                    server.read_hs(&to_send).unwrap();
                    assert!(!server.is_handshaking());
                    return result.session_ticket_ctx.unwrap();
                }
            }
        }
    }
    panic!("QUIC fixture handshake did not complete");
}
