//! Sans-I/O lifecycle contracts against an independent in-memory rustls peer.

use std::io::{Cursor, Read};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use lktls::config::{CompileOptions, CompiledClientConfig, ConnectionInputs, Transport};
use lktls::connection::{ClientConnection, HandshakeProgress, ReadProgress};
use lktls::profile::{presets, types::TlsVersion};
use lktls::session_store::{
    ClientSession, ClientSessionStore, InMemorySessionStore, SessionStore, SessionTicketData,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

#[path = "tls_core_endpoint_contract/config_measure.rs"]
mod config_measure;
#[path = "tls_core_endpoint_contract/measure.rs"]
mod measure;

#[derive(Debug, Default)]
struct ObservedStore {
    inner: InMemorySessionStore,
    takes: AtomicUsize,
}
impl SessionStore for ObservedStore {
    fn store(&self, host: &str, ticket: SessionTicketData) {
        self.inner.store(host, ticket);
    }
    fn take(&self, _: &str) -> Option<SessionTicketData> {
        panic!("endpoint must not fall back to an unauthenticated cache lookup");
    }
    fn client_sessions(&self) -> Option<&dyn ClientSessionStore> {
        Some(self)
    }
}
impl ClientSessionStore for ObservedStore {
    fn store_session(&self, host: &str, session: ClientSession) {
        self.inner.store_session(host, session);
    }
    fn take_session(&self, host: &str) -> Option<ClientSession> {
        self.takes.fetch_add(1, Ordering::Relaxed);
        self.inner.take_session(host)
    }
}

struct Peer {
    server: Arc<rustls::ServerConfig>,
    client: Arc<CompiledClientConfig>,
}
impl Peer {
    fn new(tls12: bool) -> Self {
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let anchor =
            lktls::verify::certchain::parse_trust_anchor_from_der(identity.cert.der()).unwrap();
        let mut server = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[if tls12 {
            &rustls::version::TLS12
        } else {
            &rustls::version::TLS13
        }])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![identity.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                identity.signing_key.serialize_der(),
            )),
        )
        .unwrap();
        server.ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
        let mut profile = presets::chrome_144();
        profile.tls_min_version = if tls12 {
            TlsVersion::Tls12
        } else {
            TlsVersion::Tls13
        };
        profile.tls_max_version = profile.tls_min_version;
        let options = CompileOptions {
            custom_ca_anchors: Some(Arc::new(vec![anchor])),
            ..CompileOptions::compatibility()
        };
        let client =
            CompiledClientConfig::compile(Arc::new(profile), Transport::Tcp, options).unwrap();
        Self {
            server: Arc::new(server),
            client,
        }
    }

    fn connect(&self, store: Arc<ObservedStore>, hellos: Arc<AtomicUsize>) -> ClientConnection {
        let mut inputs = ConnectionInputs::new("localhost", 443);
        inputs.session_store = Some(store);
        inputs.client_hello_callback = Some(Arc::new(move |_| {
            hellos.fetch_add(1, Ordering::Relaxed);
        }));
        ClientConnection::from_compiled(self.client.clone(), inputs).unwrap()
    }
}

#[test]
fn pending_initial_output_is_stable_and_consumes_attempt_services_once() {
    let peer = Peer::new(false);
    let store = Arc::new(ObservedStore::default());
    let hellos = Arc::new(AtomicUsize::new(0));
    let mut client = peer.connect(store.clone(), hellos.clone());
    let hello = client.output().to_vec();
    assert!(!hello.is_empty());
    assert!(client.write_application(b"too early").is_err());
    for consumed in [0, 1, 17] {
        client.consume_output(consumed);
        let remaining = client.output().to_vec();
        for _ in 0..8 {
            assert_eq!(
                client.progress_handshake().unwrap(),
                HandshakeProgress::NeedOutput
            );
            assert_eq!(client.output(), remaining);
        }
    }
    assert_eq!(client.output(), &hello[18..]);
    client.consume_output(client.output().len());
    for _ in 0..8 {
        assert_eq!(
            client.progress_handshake().unwrap(),
            HandshakeProgress::NeedInput
        );
    }
    assert_eq!(hellos.load(Ordering::Relaxed), 1);
    assert_eq!(store.takes.load(Ordering::Relaxed), 1);
}

#[test]
fn bounded_input_reports_only_the_prefix_owned_by_the_endpoint() {
    let peer = Peer::new(false);
    let mut client = peer.connect(Arc::default(), Arc::default());
    let capacity = client.input_capacity();
    assert!(capacity > 0 && capacity < 1024 * 1024);
    let input = vec![0; capacity + 123];
    assert_eq!(client.feed_bounded(&input[..3]), 3);
    assert_eq!(client.input_capacity(), capacity - 3);
    assert_eq!(client.feed_bounded(&input[3..]), capacity - 3);
    assert_eq!(client.input_capacity(), 0);
    assert_eq!(client.feed_bounded(&input), 0);
    client.fail();
    assert_eq!(client.feed_bounded(&input), 0);
    assert!(client.write_application(b"closed").is_err());
}

#[test]
fn fatal_handshake_error_cannot_be_resumed_or_accept_application_data() {
    let peer = Peer::new(false);
    let mut client = peer.connect(Arc::default(), Arc::default());
    client.consume_output(client.output().len());
    assert_eq!(client.feed_bounded(&[21, 3, 3, 0, 2, 2, 40]), 7);
    assert!(client.progress_handshake().is_err());
    let terminal_output = client.output().to_vec();
    assert!(client.is_closed());
    for _ in 0..3 {
        assert!(client.progress_handshake().is_err());
        assert!(client.process_read().is_err());
        assert!(client.write_application(b"must not encode").is_err());
        assert_eq!(client.feed_bounded(&[22, 3, 3, 0, 0]), 0);
        assert_eq!(client.input_capacity(), 0);
        assert!(client.plaintext().is_empty());
        assert_eq!(client.output(), terminal_output);
    }
}

fn send_output(client: &mut ClientConnection, server: &mut rustls::ServerConnection) {
    while !client.output().is_empty() {
        let snapshot = client.output().to_vec();
        let count = snapshot.len().min(17);
        assert_eq!(
            server
                .read_tls(&mut Cursor::new(&snapshot[..count]))
                .unwrap(),
            count
        );
        server.process_new_packets().unwrap();
        client.consume_output(count);
        assert_eq!(client.output(), &snapshot[count..]);
    }
}

fn server_output(server: &mut rustls::ServerConnection) -> Vec<u8> {
    let mut output = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut output).unwrap();
    }
    output
}

fn authenticate(client: &mut ClientConnection, server: &mut rustls::ServerConnection) {
    for _ in 0..32 {
        match client.progress_handshake().unwrap() {
            HandshakeProgress::NeedOutput if client.negotiated_version().is_none() => {
                send_output(client, server)
            }
            HandshakeProgress::NeedOutput | HandshakeProgress::Complete => return,
            HandshakeProgress::NeedInput => {
                let input = server_output(server);
                assert!(!input.is_empty(), "independent peer must make progress");
                assert_eq!(client.feed_bounded(&input), input.len());
            }
        }
    }
    panic!("endpoint did not authenticate within bounded flights");
}

#[test]
fn queued_finished_precedes_application_data_and_ticket_reuse_is_single_consumption() {
    for tls12 in [false, true] {
        let peer = Peer::new(tls12);
        let store = Arc::new(ObservedStore::default());
        let hellos = Arc::new(AtomicUsize::new(0));
        for resumed in [false, true] {
            let mut client = peer.connect(store.clone(), hellos.clone());
            let initial = client.output().to_vec();
            for _ in 0..8 {
                assert_eq!(
                    client.progress_handshake().unwrap(),
                    HandshakeProgress::NeedOutput
                );
                assert_eq!(client.output(), initial);
            }
            let mut server = rustls::ServerConnection::new(peer.server.clone()).unwrap();
            authenticate(&mut client, &mut server);
            let pending_finished = client.output().to_vec();
            if !tls12 || resumed {
                assert!(!pending_finished.is_empty());
            }
            let payload = b"application bytes after authenticated Finished";
            assert_eq!(client.write_application(payload).unwrap(), payload.len());
            assert!(client.output().starts_with(&pending_finished));
            send_output(&mut client, &mut server);
            assert!(!server.is_handshaking());
            assert_eq!(
                server.handshake_kind(),
                Some(if resumed {
                    rustls::HandshakeKind::Resumed
                } else {
                    rustls::HandshakeKind::Full
                })
            );
            let mut received = vec![0; payload.len()];
            server.reader().read_exact(&mut received).unwrap();
            assert_eq!(received, payload);
            assert_eq!(
                client.progress_handshake().unwrap(),
                HandshakeProgress::Complete
            );
            // Receive post-handshake TLS 1.3 tickets through the same owner.
            let tickets = server_output(&mut server);
            assert_eq!(client.feed_bounded(&tickets), tickets.len());
            assert_eq!(client.process_read().unwrap(), ReadProgress::NeedInput);
            assert_eq!(hellos.load(Ordering::Relaxed), if resumed { 2 } else { 1 });
            assert_eq!(
                store.takes.load(Ordering::Relaxed),
                if resumed { 2 } else { 1 }
            );
        }
    }
}
