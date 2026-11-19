use std::io::Cursor;
use std::sync::Arc;

use lktls::handshake::driver::{
    HandshakeConfig, HandshakeDriver, HandshakeOutput, HandshakeResult,
};
use lktls::profile::{presets, types::TlsVersion};
use lktls::session_store::{
    ClientSession, ClientSessionStore, InMemorySessionStore, SessionStore, SessionTicketData,
};
use lktls::verify::policy::VerificationPolicy;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, TrustAnchor};

struct Peer {
    config: Arc<rustls::ServerConfig>,
    anchors: Arc<Vec<TrustAnchor<'static>>>,
    tls12: bool,
    fragment_tickets: bool,
    server_hello_fragment_size: Option<usize>,
}

impl Peer {
    fn new(tls12: bool) -> Self {
        Self::with_provider(tls12, rustls::crypto::ring::default_provider())
    }

    fn with_provider(tls12: bool, provider: rustls::crypto::CryptoProvider) -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let anchor =
            lktls::verify::certchain::parse_trust_anchor_from_der(cert.cert.der()).unwrap();
        let mut config = rustls::ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[if tls12 {
                &rustls::version::TLS12
            } else {
                &rustls::version::TLS13
            }])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
            )
            .unwrap();
        config.ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
        Self {
            config: Arc::new(config),
            anchors: Arc::new(vec![anchor]),
            tls12,
            fragment_tickets: false,
            server_hello_fragment_size: None,
        }
    }

    fn client(&self, store: Arc<dyn SessionStore>) -> HandshakeConfig {
        let mut profile = presets::chrome_144();
        if self.tls12 {
            profile.tls_max_version = TlsVersion::Tls12;
        }
        HandshakeConfig {
            profile,
            hostname: "localhost".into(),
            port: 443,
            verification_policy: VerificationPolicy::Strict,
            alps_payload: None,
            session_store: Some(store),
            ech_config_list: None,
            custom_ca_anchors: Some(self.anchors.clone()),
            keylog_callback: None,
            client_hello_callback: None,
            trust_anchor_observer: None,
        }
    }

    fn handshake(
        &self,
        config: HandshakeConfig,
        corrupt_finished: bool,
    ) -> Result<rustls::HandshakeKind, lktls::error::TlsError> {
        self.handshake_with_rewrite(config, corrupt_finished, |_| {})
    }

    fn handshake_with_rewrite(
        &self,
        config: HandshakeConfig,
        corrupt_finished: bool,
        mut rewrite: impl FnMut(&mut Vec<u8>),
    ) -> Result<rustls::HandshakeKind, lktls::error::TlsError> {
        let mut server = rustls::ServerConnection::new(self.config.clone()).unwrap();
        let mut client = HandshakeDriver::new(config);
        let mut to_server = client.start()?;
        let mut completed: Option<Box<HandshakeResult>> = None;
        for _ in 0..32 {
            if !to_server.is_empty() {
                server.read_tls(&mut Cursor::new(&to_server)).unwrap();
                server.process_new_packets().unwrap();
                to_server.clear();
            }
            let mut to_client = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut to_client).unwrap();
            }
            if let Some(mut result) = completed {
                result.reader.feed(&to_client);
                while let Some(record) = result.reader.next_record()? {
                    if record.content_type == 22 {
                        let mut messages = record.payload.as_slice();
                        while !messages.is_empty() {
                            assert!(messages.len() >= 4);
                            let length = ((messages[1] as usize) << 16)
                                | ((messages[2] as usize) << 8)
                                | messages[3] as usize;
                            let (message, rest) = messages.split_at(4 + length);
                            assert_eq!(message[0], 4);
                            result
                                .session_ticket_ctx
                                .as_ref()
                                .unwrap()
                                .process_new_session_ticket(message);
                            messages = rest;
                        }
                    }
                }
                assert!(!server.is_handshaking());
                return Ok(server.handshake_kind().unwrap());
            }
            if self.tls12 {
                to_client =
                    rewrite_tls12_records(&to_client, self.fragment_tickets, corrupt_finished);
            }
            if let Some(size) = self.server_hello_fragment_size {
                to_client = fragment_server_hello_records(&to_client, size);
            }
            rewrite(&mut to_client);
            client.feed(&to_client);
            loop {
                match client.progress()? {
                    HandshakeOutput::SendData(data) => to_server.extend_from_slice(&data),
                    HandshakeOutput::NeedData => break,
                    HandshakeOutput::Done { to_send, result } => {
                        to_server.extend_from_slice(&to_send);
                        completed = Some(result);
                        break;
                    }
                }
            }
        }
        panic!("in-memory handshake did not complete");
    }
}

fn rewrite_tls12_records(
    mut records: &[u8],
    fragment_tickets: bool,
    corrupt_finished: bool,
) -> Vec<u8> {
    let mut output = Vec::new();
    let mut protected = false;
    while !records.is_empty() {
        assert!(records.len() >= 5);
        let end = 5 + u16::from_be_bytes([records[3], records[4]]) as usize;
        let (record, rest) = records.split_at(end);
        if fragment_tickets && !protected && record[0] == 22 && record.get(5) == Some(&4) {
            for fragment in record[5..].chunks(3) {
                output.extend_from_slice(&record[..3]);
                output.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
                output.extend_from_slice(fragment);
            }
        } else {
            output.extend_from_slice(record);
            if protected && record[0] == 22 && corrupt_finished {
                *output.last_mut().unwrap() ^= 1;
            }
        }
        protected |= record[0] == 20;
        records = rest;
    }
    output
}

fn fragment_server_hello_records(mut records: &[u8], fragment_size: usize) -> Vec<u8> {
    let mut output = Vec::new();
    let mut protected = false;
    while !records.is_empty() {
        let end = 5 + u16::from_be_bytes([records[3], records[4]]) as usize;
        let (record, rest) = records.split_at(end);
        if !protected && record[0] == 22 && record.get(5) == Some(&2) {
            for fragment in record[5..].chunks(fragment_size) {
                output.extend_from_slice(&record[..3]);
                output.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
                output.extend_from_slice(fragment);
            }
        } else {
            output.extend_from_slice(record);
        }
        protected |= record[0] == 20;
        records = rest;
    }
    output
}

#[test]
fn tls12_fragmented_initial_server_hello_preserves_full_and_resumed_handshakes() {
    for size in [1, 2, 4, 17] {
        let mut peer = Peer::new(true);
        peer.server_hello_fragment_size = Some(size);
        let config = peer.client(Arc::new(InMemorySessionStore::new()));
        assert_eq!(
            peer.handshake(config.clone(), false).unwrap(),
            rustls::HandshakeKind::Full
        );
        assert_eq!(
            peer.handshake(config, false).unwrap(),
            rustls::HandshakeKind::Resumed
        );
    }
}

#[test]
fn tls13_fragmented_initial_server_hello_preserves_full_and_resumed_handshakes() {
    for size in [1, 2, 4, 17] {
        let mut peer = Peer::new(false);
        peer.server_hello_fragment_size = Some(size);
        let config = peer.client(Arc::new(InMemorySessionStore::new()));
        assert_eq!(
            peer.handshake(config.clone(), false).unwrap(),
            rustls::HandshakeKind::Full
        );
        assert_eq!(
            peer.handshake(config, false).unwrap(),
            rustls::HandshakeKind::Resumed
        );
    }
}

#[test]
fn tls13_fragmented_hrr_and_second_server_hello_complete_authentication() {
    for size in [1, 3, 17] {
        let mut provider = rustls::crypto::ring::default_provider();
        provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP384R1];
        let mut peer = Peer::with_provider(false, provider);
        peer.server_hello_fragment_size = Some(size);
        let config = peer.client(Arc::new(InMemorySessionStore::new()));
        assert_eq!(
            peer.handshake(config, false).unwrap(),
            rustls::HandshakeKind::FullWithHelloRetryRequest
        );
    }
}

#[test]
fn server_flight_boundary_cannot_discard_a_trailing_message() {
    for tls12 in [false, true] {
        for trailer in [&[4, 0][..], &[4, 0, 0, 8, 0][..], &[4, 0, 0, 0][..]] {
            let peer = Peer::new(tls12);
            let config = peer.client(Arc::new(InMemorySessionStore::new()));
            let error = peer
                .handshake_with_rewrite(config, false, |records| {
                    // TLS 1.2: append after ServerHelloDone. TLS 1.3: append after ServerHello.
                    let mut pos = 0;
                    let mut boundary = None;
                    while pos < records.len() {
                        let length =
                            u16::from_be_bytes([records[pos + 3], records[pos + 4]]) as usize;
                        if records[pos] != 22 {
                            break;
                        }
                        boundary = Some((pos, length));
                        pos += 5 + length;
                        if !tls12 {
                            break;
                        }
                    }
                    let Some((start, length)) = boundary else {
                        return;
                    };
                    let end = start + 5 + length;
                    records.splice(end..end, trailer.iter().copied());
                    records[start + 3..start + 5]
                        .copy_from_slice(&((length + trailer.len()) as u16).to_be_bytes());
                })
                .unwrap_err();
            assert!(
                matches!(error, lktls::error::TlsError::LocalAlert { alert, .. }
                if alert.description == lktls::error::AlertDescription::UnexpectedMessage),
                "{error:?}"
            );
        }
    }
}

#[test]
fn unchanged_verification_context_resumes_both_tls_versions() {
    for tls12 in [false, true] {
        let peer = Peer::new(tls12);
        let config = peer.client(Arc::new(InMemorySessionStore::new()));
        assert_eq!(
            peer.handshake(config.clone(), false).unwrap(),
            rustls::HandshakeKind::Full
        );
        assert_eq!(
            peer.handshake(config.clone(), false).unwrap(),
            rustls::HandshakeKind::Resumed
        );
        assert_eq!(
            peer.handshake(config, false).unwrap(),
            rustls::HandshakeKind::Resumed
        );
    }
}

#[test]
fn configured_cache_ttl_controls_full_and_resumed_handshakes() {
    use std::time::Duration;

    for tls12 in [false, true] {
        let peer = Peer::new(tls12);
        for ttl in [Duration::ZERO, Duration::from_secs(7200)] {
            let config = peer.client(Arc::new(InMemorySessionStore::new().with_ttl(ttl)));
            assert_eq!(
                peer.handshake(config.clone(), false).unwrap(),
                rustls::HandshakeKind::Full
            );
            for _ in 0..2 {
                assert_eq!(
                    peer.handshake(config.clone(), false).unwrap(),
                    if ttl.is_zero() {
                        rustls::HandshakeKind::Full
                    } else {
                        rustls::HandshakeKind::Resumed
                    }
                );
            }
        }
        let store = Arc::new(InMemorySessionStore::new().with_ttl(Duration::from_secs(1)));
        let config = peer.client(store.clone());
        assert_eq!(
            peer.handshake(config.clone(), false).unwrap(),
            rustls::HandshakeKind::Full
        );
        std::thread::sleep(Duration::from_millis(1100));
        assert_eq!(
            peer.handshake(config, false).unwrap(),
            rustls::HandshakeKind::Full
        );
    }
}

#[test]
fn safari_tls12_session_ids_resume_repeatedly_without_tickets() {
    let peer = Peer::new(true);
    let mut config = peer.client(Arc::new(InMemorySessionStore::new()));
    config.profile = presets::safari_26();
    config.profile.tls_max_version = TlsVersion::Tls12;
    assert!(!config
        .profile
        .extensions
        .iter()
        .any(|extension| extension.extension_type == 35));
    for attempt in 0..4 {
        assert_eq!(
            peer.handshake(config.clone(), false).unwrap(),
            if attempt == 0 {
                rustls::HandshakeKind::Full
            } else {
                rustls::HandshakeKind::Resumed
            },
            "attempt {attempt}"
        );
    }
}

#[test]
fn insecure_session_cannot_bypass_strict_authentication() {
    for tls12 in [false, true] {
        let peer = Peer::new(tls12);
        let mut config = peer.client(Arc::new(InMemorySessionStore::new()));
        config.custom_ca_anchors = None;
        config.verification_policy = VerificationPolicy::Insecure;
        assert_eq!(
            peer.handshake(config.clone(), false).unwrap(),
            rustls::HandshakeKind::Full
        );
        config.verification_policy = VerificationPolicy::Strict;
        assert!(
            peer.handshake(config, false).is_err(),
            "TLS 1.{} reused an insecure session under Strict",
            if tls12 { 2 } else { 3 }
        );
    }
}

#[test]
fn removing_a_trust_anchor_forces_fresh_authentication() {
    for tls12 in [false, true] {
        let peer = Peer::new(tls12);
        let mut config = peer.client(Arc::new(InMemorySessionStore::new()));
        assert_eq!(
            peer.handshake(config.clone(), false).unwrap(),
            rustls::HandshakeKind::Full
        );
        config.custom_ca_anchors = None;
        assert!(
            peer.handshake(config, false).is_err(),
            "TLS 1.{} resumed after removing its trust anchor",
            if tls12 { 2 } else { 3 }
        );
    }
}

#[test]
fn tls12_failed_finished_does_not_publish_a_session() {
    let peer = Peer::new(true);
    let store = Arc::new(InMemorySessionStore::new());
    assert!(peer.handshake(peer.client(store.clone()), true).is_err());
    assert!(
        store.take("localhost:443").is_none(),
        "ticket was published before Finished authentication"
    );
}

#[test]
fn tls12_failed_resumed_finished_does_not_publish_a_renewed_ticket() {
    let peer = Peer::new(true);
    let store = Arc::new(InMemorySessionStore::new());
    let config = peer.client(store.clone());
    assert_eq!(
        peer.handshake(config.clone(), false).unwrap(),
        rustls::HandshakeKind::Full
    );
    assert!(peer.handshake(config.clone(), true).is_err());
    assert!(store.take("localhost:443").is_none());
    assert_eq!(
        peer.handshake(config, false).unwrap(),
        rustls::HandshakeKind::Full
    );
}

#[test]
fn tls12_received_fatal_alert_discards_the_offered_session() {
    let peer = Peer::new(true);
    let store = Arc::new(InMemorySessionStore::new());
    let config = peer.client(store.clone());
    peer.handshake(config.clone(), false).unwrap();
    let mut driver = HandshakeDriver::new(config);
    driver.start().unwrap();
    driver.feed(&[21, 3, 3, 0, 2, 2, 40]);
    assert!(
        matches!(driver.progress(), Err(lktls::error::TlsError::Alert(alert)) if alert.is_fatal())
    );
    assert!(store.take("localhost:443").is_none());
}

#[test]
fn tls12_ticket_renewal_uses_fresh_plaintext_session_ids() {
    let peer = Peer::new(true);
    let mut config = peer.client(Arc::new(InMemorySessionStore::new()));
    let hellos = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = hellos.clone();
    config.client_hello_callback = Some(Arc::new(move |hello| {
        let sid_length = hello[38] as usize;
        let session_id = hello[39..39 + sid_length].to_vec();
        let mut extensions = &hello[39 + sid_length..];
        let suites_length = u16::from_be_bytes([extensions[0], extensions[1]]) as usize;
        extensions = &extensions[2 + suites_length..];
        extensions = &extensions[1 + extensions[0] as usize..];
        let length = u16::from_be_bytes([extensions[0], extensions[1]]) as usize;
        extensions = &extensions[2..2 + length];
        let mut ticket = Vec::new();
        while !extensions.is_empty() {
            let kind = u16::from_be_bytes([extensions[0], extensions[1]]);
            let length = u16::from_be_bytes([extensions[2], extensions[3]]) as usize;
            if kind == 35 {
                ticket = extensions[4..4 + length].to_vec();
            }
            extensions = &extensions[4 + length..];
        }
        observed.lock().unwrap().push((session_id, ticket));
    }));
    for attempt in 0..5 {
        assert_eq!(
            peer.handshake(config.clone(), false).unwrap(),
            if attempt == 0 {
                rustls::HandshakeKind::Full
            } else {
                rustls::HandshakeKind::Resumed
            }
        );
    }
    let hellos = hellos.lock().unwrap();
    let resumed = &hellos[1..];
    assert!(resumed
        .iter()
        .all(|(sid, ticket)| sid.len() == 32 && !ticket.is_empty()));
    for pair in resumed.windows(2) {
        assert_ne!(pair[0].1, pair[1].1, "control: tickets must rotate");
    }
    assert_eq!(
        resumed
            .iter()
            .map(|(sid, _)| sid)
            .collect::<std::collections::HashSet<_>>()
            .len(),
        4
    );
}

#[test]
fn tls12_fragmented_tickets_are_authenticated_before_publication() {
    let mut peer = Peer::new(true);
    peer.fragment_tickets = true;
    let config = peer.client(Arc::new(InMemorySessionStore::new()));
    assert_eq!(
        peer.handshake(config.clone(), false).unwrap(),
        rustls::HandshakeKind::Full
    );
    assert_eq!(
        peer.handshake(config.clone(), false).unwrap(),
        rustls::HandshakeKind::Resumed
    );
    assert_eq!(
        peer.handshake(config, false).unwrap(),
        rustls::HandshakeKind::Resumed
    );
}

#[derive(Debug, Default)]
struct MisdirectedStore(std::sync::Mutex<Vec<ClientSession>>);

impl SessionStore for MisdirectedStore {
    fn store(&self, _: &str, _: SessionTicketData) {
        panic!("engine must use opaque session storage");
    }
    fn take(&self, _: &str) -> Option<SessionTicketData> {
        panic!("engine must not take twice through the legacy API");
    }
    fn client_sessions(&self) -> Option<&dyn ClientSessionStore> {
        Some(self)
    }
}

impl ClientSessionStore for MisdirectedStore {
    fn store_session(&self, _: &str, session: ClientSession) {
        self.0.lock().unwrap().push(session);
    }
    fn take_session(&self, _: &str) -> Option<ClientSession> {
        self.0.lock().unwrap().pop()
    }
}

#[test]
fn a_custom_store_cannot_redirect_a_session_to_another_peer_or_port() {
    for tls12 in [false, true] {
        for change_port in [false, true] {
            let peer = Peer::new(tls12);
            let mut config = peer.client(Arc::new(MisdirectedStore::default()));
            assert_eq!(
                peer.handshake(config.clone(), false).unwrap(),
                rustls::HandshakeKind::Full
            );
            if change_port {
                config.port = 8443;
                assert_eq!(
                    peer.handshake(config, false).unwrap(),
                    rustls::HandshakeKind::Full
                );
            } else {
                config.hostname = "wrong.example".into();
                assert!(peer.handshake(config, false).is_err());
            }
        }
    }
}

#[test]
fn equivalent_trust_contents_in_a_new_allocation_still_resume() {
    for tls12 in [false, true] {
        let peer = Peer::new(tls12);
        let mut config = peer.client(Arc::new(InMemorySessionStore::new()));
        assert_eq!(
            peer.handshake(config.clone(), false).unwrap(),
            rustls::HandshakeKind::Full
        );
        config.custom_ca_anchors = Some(Arc::new(peer.anchors.as_ref().clone()));
        assert_eq!(
            peer.handshake(config, false).unwrap(),
            rustls::HandshakeKind::Resumed
        );
    }
}
