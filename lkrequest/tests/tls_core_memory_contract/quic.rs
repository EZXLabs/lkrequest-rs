//! TLS-over-QUIC ownership only: no packets, Quinn, sockets or runtime tasks.
//! Traffic-secret deliveries are released at their legal phase boundary;
//! authenticated metadata and post-handshake secrets remain client-owned.

use std::sync::Arc;

use lktls::config::{CompileOptions, CompiledClientConfig, ConnectionInputs, Transport};
use lktls::connection::{QuicClientConnection, QuicConnectionEstablished, QuicLevel};
use lktls::handshake::driver::QuicHandshakeDriver;
use lktls::profile::presets;
use lktls::session_store::InMemorySessionStore;
use lktls::verify::policy::VerificationPolicy;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::quic::KeyChange;

use super::accounting::{Owner, Snapshot};

const CLIENT_PARAMETERS: &[u8] = &[1, 1, 30];
const SERVER_PARAMETERS: &[u8] = &[1, 1, 60];

struct Peer {
    config: Arc<CompiledClientConfig>,
    server: Arc<rustls::ServerConfig>,
}

impl Peer {
    fn new() -> Self {
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let anchor =
            lktls::verify::certchain::parse_trust_anchor_from_der(identity.cert.der()).unwrap();
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
        server.alpn_protocols = vec![b"h3".to_vec()];
        server.ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
        server.max_early_data_size = 0;
        let config = CompiledClientConfig::compile(
            presets::chrome_155_quic(),
            Transport::Quic,
            CompileOptions {
                verification: VerificationPolicy::Strict,
                custom_ca_anchors: Some(Arc::new(vec![anchor])),
                ..CompileOptions::compatibility()
            },
        )
        .unwrap();
        Self {
            config,
            server: Arc::new(server),
        }
    }
}

struct Established {
    client: QuicClientConnection,
    metadata: QuicConnectionEstablished,
}

struct Stages {
    initial_pending: Snapshot,
    handshake_keys_pending: Snapshot,
    finished_pending: Snapshot,
    tickets_processed: Snapshot,
}

fn handshake(
    owner: Owner,
    peer: &Peer,
    store: Arc<InMemorySessionStore>,
    resumed: bool,
) -> (Established, Stages) {
    let mut server = rustls::quic::ServerConnection::new(
        peer.server.clone(),
        rustls::quic::Version::V1,
        SERVER_PARAMETERS.to_vec(),
    )
    .unwrap();
    // This is caller-owned CRYPTO delivery storage, excluded even while a core
    // write appends to it. Internal pending flights remain included.
    let mut output = Vec::with_capacity(256 * 1024);
    let mut client = owner.enter(|| {
        let mut inputs = ConnectionInputs::new("localhost", 443);
        inputs.session_store = Some(store);
        QuicClientConnection::new(
            QuicHandshakeDriver::from_compiled(
                peer.config.clone(),
                inputs,
                CLIENT_PARAMETERS.to_vec(),
            )
            .unwrap(),
        )
        .unwrap()
    });
    let initial_pending = owner.snapshot();
    assert_eq!(client.resumption_ticket().is_some(), resumed);
    assert!(client.early_data_offer().is_none());
    assert!(owner
        .enter(|| client.write_handshake(&mut output))
        .is_none());
    assert_eq!(output[0], 1, "Initial output must be ClientHello");
    server.read_hs(&output).unwrap();
    output.clear();
    assert_eq!(server.quic_transport_parameters(), Some(CLIENT_PARAMETERS));

    let mut initial = Vec::new();
    assert!(matches!(
        server.write_hs(&mut initial),
        Some(KeyChange::Handshake { .. })
    ));
    assert_eq!(initial[0], 2);
    assert!(owner.enter(|| client.read(&initial).unwrap()).is_none());
    let handshake_keys_pending = owner.snapshot();
    let (level, secrets) = owner
        .enter(|| client.write_handshake(&mut output))
        .expect("Handshake secrets must be delivered before Handshake input");
    assert_eq!(level, QuicLevel::Handshake);
    assert!(output.is_empty());
    assert_eq!(
        secrets.client_secret.len(),
        secrets.hkdf_algorithm.hash_len()
    );
    assert_eq!(
        secrets.server_secret.len(),
        secrets.hkdf_algorithm.hash_len()
    );
    drop(secrets);

    let mut encrypted = Vec::new();
    assert!(matches!(
        server.write_hs(&mut encrypted),
        Some(KeyChange::OneRtt { .. })
    ));
    assert_eq!(encrypted[0], 8, "Handshake flight begins with EE");
    let metadata = owner
        .enter(|| client.read(&encrypted).unwrap())
        .expect("authenticated server Finished must publish completion");
    assert!(!client.is_handshaking());
    assert_eq!(metadata.session_resumed, resumed);
    assert!(!metadata.early_data_accepted);
    assert_eq!(metadata.negotiated_alpn.as_deref(), Some("h3"));
    assert!(metadata.peer_transport_params.is_some());
    let finished_pending = owner.snapshot();
    let (level, secrets) = owner
        .enter(|| client.write_handshake(&mut output))
        .expect("Finished must precede the OneRtt key transition");
    assert_eq!(level, QuicLevel::OneRtt);
    assert_eq!(output[0], 20, "client Finished remains at Handshake level");
    let control = metadata.post_handshake.as_ref().unwrap();
    assert_eq!(secrets.client_secret, control.client_app_secret);
    assert_eq!(secrets.server_secret, control.server_app_secret);
    server.read_hs(&output).unwrap();
    drop(secrets);
    output.clear();
    assert!(!server.is_handshaking());
    assert_eq!(
        server.handshake_kind(),
        Some(if resumed {
            rustls::HandshakeKind::Resumed
        } else {
            rustls::HandshakeKind::Full
        })
    );
    assert!(owner
        .enter(|| client.write_handshake(&mut output))
        .is_none());
    assert!(output.is_empty());

    let mut tickets = Vec::new();
    assert!(server.write_hs(&mut tickets).is_none());
    assert!(
        !tickets.is_empty(),
        "real peer must issue a new session ticket"
    );
    assert!(owner.enter(|| client.read(&tickets).unwrap()).is_none());
    assert!(!client.has_pending_message());
    let tickets_processed = owner.snapshot();
    (
        Established { client, metadata },
        Stages {
            initial_pending,
            handshake_keys_pending,
            finished_pending,
            tickets_processed,
        },
    )
}

fn assert_released(owner: Owner) {
    assert_eq!(owner.snapshot().live, 0, "QUIC client-owned bytes leaked");
    assert_eq!(owner.snapshot().blocks, 0);
}

fn memory_case(peer: &Peer, resumed: bool, concurrent: usize) {
    let seed_owner = Owner::new();
    let client_owner = Owner::new();
    let mut stores = Vec::with_capacity(concurrent);
    for _ in 0..concurrent {
        stores.push(seed_owner.enter(|| Arc::new(InMemorySessionStore::new())));
    }
    if resumed {
        for store in &stores {
            drop(handshake(seed_owner, peer, store.clone(), false));
        }
    }
    let seed_before = seed_owner.snapshot();
    let mut clients = Vec::with_capacity(concurrent);
    let mut first_stages = None;
    for store in &stores {
        let (client, stages) = handshake(client_owner, peer, store.clone(), resumed);
        if first_stages.is_none() {
            first_stages = Some(stages);
        }
        clients.push(client);
    }
    let idle = client_owner.snapshot();
    let seed_idle = seed_owner.snapshot();
    assert!(idle.live > 0);
    assert!(idle.peak >= idle.live);
    for connection in &mut clients {
        assert!(!connection.client.is_handshaking());
        assert!(connection.metadata.post_handshake.is_some());
        assert!(client_owner
            .enter(|| connection.client.read(&[]).unwrap())
            .is_none());
    }
    assert_eq!(client_owner.snapshot().allocations, idle.allocations);
    assert_eq!(client_owner.snapshot().reallocations, idle.reallocations);
    assert_eq!(client_owner.snapshot().live, idle.live);
    drop(clients);
    let client_cache = client_owner.snapshot();
    let seed_cache = seed_owner.snapshot();
    assert!(client_cache.live < idle.live);
    drop(stores);
    assert_released(client_owner);
    assert_released(seed_owner);
    let stages = first_stages.unwrap();
    println!(
        "{}",
        serde_json::json!({
            "kind": "quic_tls_client_owned_memory",
            "version": "TLS1.3", "resumed": resumed,
            "concurrent_established": concurrent,
            "concurrency": "simultaneously_live_sequentially_driven",
            "scope": "dynamic_inputs_tls_core_metadata_control_secrets_private_cache",
            "unit": "requested_rust_heap_bytes",
            "peer_validated_handshake_kind": true,
            "strict_peer_authentication": true,
            "client_origin_allocations": idle.allocations,
            "client_origin_reallocations": idle.reallocations,
            "client_origin_requested_bytes": idle.requested,
            "client_origin_peak_bytes": idle.peak,
            "client_origin_idle_bytes": idle.live,
            "seed_origin_before_bytes": seed_before.live,
            "seed_origin_idle_bytes": seed_idle.live,
            "combined_idle_bytes": idle.live + seed_idle.live,
            "combined_peak_bytes": null,
            "first_connection_client_origin_stages": {
                "initial_pending_bytes": stages.initial_pending.live,
                "handshake_keys_pending_bytes": stages.handshake_keys_pending.live,
                "finished_pending_bytes": stages.finished_pending.live,
                "tickets_processed_bytes": stages.tickets_processed.live,
            },
            "client_origin_cache_after_endpoint_drop_bytes": client_cache.live,
            "seed_origin_cache_after_endpoint_drop_bytes": seed_cache.live,
            "all_owners_after_drop_bytes": 0,
            "inline_client_and_metadata_bytes": concurrent * std::mem::size_of::<Established>(),
            "packet_keys_quinn_socket_runtime_included": false,
            "caller_crypto_delivery_buffers_included": false,
            "shared_config_bytes": null, "c_backend_bytes": null,
            "copy_bytes": null, "elapsed_ns": null,
        })
    );
}

#[test]
#[ignore = "QUIC TLS memory matrix; explicitly run serially with --ignored --nocapture"]
fn quic_client_owned_peak_idle_and_concurrent_memory_matrix() {
    let peer = Peer::new();
    let warm = Owner::new();
    drop(handshake(warm, &peer, Arc::default(), false));
    assert_released(warm);
    let mut cases = 0;
    for resumed in [false, true] {
        for concurrent in [1, 8, 32, 128] {
            memory_case(&peer, resumed, concurrent);
            cases += 1;
        }
    }
    assert_eq!(cases, 8);
}
