//! Deterministic requested-heap accounting, never a wall-clock benchmark.
//! Client inputs, endpoint operations and private session caches are included.
//! The lifecycle matrix excludes shared config, rustls peers and test payloads;
//! the separate config_measurement module measures compiler-owned allocations.
//! Headers/allocator rounding, C crypto allocation, stacks, sockets, runtime tasks,
//! copied bytes and process RSS are not measured. Origin ownership survives moves.

use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use lktls::config::{CompileOptions, CompiledClientConfig, ConnectionInputs, Transport};
use lktls::connection::{ClientConnection, HandshakeProgress, ReadProgress};
use lktls::profile::{presets, types::TlsVersion};
use lktls::session_store::InMemorySessionStore;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

#[path = "tls_core_memory_contract/accounting.rs"]
mod accounting;
use accounting::Owner;

#[path = "tls_core_memory_contract/config.rs"]
mod config_measurement;

#[path = "tls_core_memory_contract/stages.rs"]
mod stage_measurement;

#[cfg(feature = "quic-h3")]
#[path = "tls_core_memory_contract/quic.rs"]
mod quic_measurement;

#[path = "tls_core_memory_contract/workload.rs"]
mod workload_measurement;

#[global_allocator]
static ALLOCATOR: accounting::Allocator = accounting::Allocator;

#[test]
fn allocation_origins_survive_scope_changes_reallocation_and_cross_thread_drop() {
    use std::alloc::{alloc, alloc_zeroed, dealloc, realloc, Layout};

    let first = Owner::new();
    let other = Owner::new();
    let layout = Layout::from_size_align(37, 4096).unwrap();
    let unrelated = unsafe { alloc(layout) };
    assert!(!unrelated.is_null());
    let pointer = first.enter(|| unsafe { alloc_zeroed(layout) });
    assert!(!pointer.is_null());
    assert_eq!(pointer as usize % 4096, 0);
    assert!(unsafe { std::slice::from_raw_parts(pointer, 37) }
        .iter()
        .all(|byte| *byte == 0));
    assert_eq!(first.snapshot().live, 37);
    first.enter(|| unsafe { dealloc(unrelated, layout) });
    assert_eq!(first.snapshot().live, 37);
    unsafe { pointer.write_bytes(0x5a, 37) };
    let pointer = other.enter(|| unsafe { realloc(pointer, layout, 113) });
    assert!(!pointer.is_null());
    assert_eq!(pointer as usize % 4096, 0);
    assert!(unsafe { std::slice::from_raw_parts(pointer, 37) }
        .iter()
        .all(|byte| *byte == 0x5a));
    assert_eq!(first.snapshot().live, 113);
    assert_eq!(first.snapshot().peak, 113);
    assert_eq!(other.snapshot().live, 0);
    let grown = Layout::from_size_align(113, 4096).unwrap();
    let pointer = unsafe { realloc(pointer, grown, 19) };
    assert!(!pointer.is_null());
    assert_eq!(first.snapshot().live, 19);
    assert_eq!(first.snapshot().reallocations, 2);
    assert_eq!(first.snapshot().requested, 37 + 113 + 19);
    unsafe { dealloc(pointer, Layout::from_size_align(19, 4096).unwrap()) };
    assert_eq!(first.snapshot().live, 0);
    assert_eq!(first.snapshot().blocks, 0);

    let small = Layout::from_size_align(16, 1).unwrap();
    let pointer = first.enter(|| unsafe { alloc(small) });
    assert!(!pointer.is_null());
    // Adding the header to this valid payload layout overflows. Failure must
    // leave the old allocation and its original owner intact.
    let failed = other.enter(|| unsafe { realloc(pointer, small, isize::MAX as usize) });
    assert!(failed.is_null());
    assert_eq!(first.snapshot().live, 16);
    assert_eq!(other.snapshot().live, 0);
    unsafe { dealloc(pointer, small) };

    let buffer = first.enter(|| vec![0x7c; 257]);
    std::thread::spawn(move || {
        assert_eq!(buffer[256], 0x7c);
        drop(buffer);
    })
    .join()
    .unwrap();
    assert_eq!(first.snapshot().live, 0);
    assert_eq!(other.snapshot().live, 0);
}

struct Peer {
    server: Arc<rustls::ServerConfig>,
    client: Arc<CompiledClientConfig>,
}

impl Peer {
    fn new(tls12: bool) -> Self {
        Self::with_provider(tls12, rustls::crypto::ring::default_provider())
    }

    fn with_provider(tls12: bool, provider: rustls::crypto::CryptoProvider) -> Self {
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let anchor =
            lktls::verify::certchain::parse_trust_anchor_from_der(identity.cert.der()).unwrap();
        let mut server = rustls::ServerConfig::builder_with_provider(provider.into())
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
        let client = CompiledClientConfig::compile(
            Arc::new(profile),
            Transport::Tcp,
            CompileOptions {
                custom_ca_anchors: Some(Arc::new(vec![anchor])),
                ..CompileOptions::compatibility()
            },
        )
        .unwrap();
        Self {
            server: Arc::new(server),
            client,
        }
    }
}

struct Established {
    client: ClientConnection,
    server: rustls::ServerConnection,
}

fn peer_output(server: &mut rustls::ServerConnection) -> Vec<u8> {
    let mut bytes = Vec::new();
    while server.wants_write() {
        assert!(server.write_tls(&mut bytes).unwrap() > 0);
    }
    bytes
}

fn send_client(owner: Owner, connection: &mut Established) {
    while !connection.client.output().is_empty() {
        let count = connection
            .server
            .read_tls(&mut Cursor::new(connection.client.output()))
            .unwrap();
        assert!(count > 0);
        connection.server.process_new_packets().unwrap();
        owner.enter(|| connection.client.consume_output(count));
    }
}

fn handshake(
    owner: Owner,
    peer: &Peer,
    store: Arc<InMemorySessionStore>,
    resumed: bool,
) -> Established {
    let client = owner.enter(|| {
        let mut inputs = ConnectionInputs::new("localhost", 443);
        inputs.session_store = Some(store);
        ClientConnection::from_compiled(peer.client.clone(), inputs).unwrap()
    });
    let mut connection = Established {
        client,
        server: rustls::ServerConnection::new(peer.server.clone()).unwrap(),
    };
    for _ in 0..32 {
        match owner.enter(|| connection.client.progress_handshake().unwrap()) {
            HandshakeProgress::NeedOutput => send_client(owner, &mut connection),
            HandshakeProgress::NeedInput => {
                let bytes = peer_output(&mut connection.server);
                assert!(!bytes.is_empty());
                assert_eq!(
                    owner.enter(|| connection.client.feed_bounded(&bytes)),
                    bytes.len()
                );
            }
            HandshakeProgress::Complete => {
                assert!(!connection.server.is_handshaking());
                assert_eq!(
                    connection.server.handshake_kind(),
                    Some(if resumed {
                        rustls::HandshakeKind::Resumed
                    } else {
                        rustls::HandshakeKind::Full
                    })
                );
                let tickets = peer_output(&mut connection.server);
                assert_eq!(
                    owner.enter(|| connection.client.feed_bounded(&tickets)),
                    tickets.len()
                );
                assert_eq!(
                    owner.enter(|| connection.client.process_read().unwrap()),
                    ReadProgress::NeedInput
                );
                return connection;
            }
        }
    }
    panic!("memory measurement handshake did not finish");
}

fn queue_application(owner: Owner, connections: &mut [Established], payload: &[u8]) {
    for connection in connections {
        assert_eq!(
            owner.enter(|| connection.client.write_application(payload).unwrap()),
            payload.len()
        );
        connection.server.writer().write_all(payload).unwrap();
        let incoming = peer_output(&mut connection.server);
        assert_eq!(
            owner.enter(|| connection.client.feed_bounded(&incoming)),
            incoming.len()
        );
        assert!(!connection.client.output().is_empty());
    }
}

fn drain_application(owner: Owner, connections: &mut [Established], payload: &[u8]) {
    for connection in connections {
        send_client(owner, connection);
        let mut received = vec![0; payload.len()];
        connection
            .server
            .reader()
            .read_exact(&mut received)
            .unwrap();
        assert_eq!(received, payload);
        assert_eq!(
            owner.enter(|| connection.client.process_read().unwrap()),
            ReadProgress::Plaintext
        );
        assert_eq!(connection.client.plaintext(), payload);
        owner.enter(|| connection.client.consume_plaintext(payload.len()));
        assert_eq!(
            owner.enter(|| connection.client.process_read().unwrap()),
            ReadProgress::NeedInput
        );
        assert!(connection.client.output().is_empty());
        assert!(connection.client.plaintext().is_empty());
    }
}

fn memory_case(peer: &Peer, tls12: bool, resumed: bool, concurrent: usize) {
    let owner = Owner::new();
    let mut stores = Vec::with_capacity(concurrent);
    for _ in 0..concurrent {
        stores.push(owner.enter(|| Arc::new(InMemorySessionStore::new())));
    }
    if resumed {
        for store in &stores {
            drop(handshake(owner, peer, store.clone(), false));
        }
    }
    let baseline = owner.snapshot();
    owner.reset_peak();
    let mut connections = Vec::with_capacity(concurrent);
    for store in &stores {
        connections.push(handshake(owner, peer, store.clone(), resumed));
    }
    let idle = owner.snapshot();
    assert!(idle.live > baseline.live);
    assert!(idle.peak >= idle.live);
    assert_eq!(connections.len(), concurrent);

    // Keep all connections alive while each holds a full record in each
    // direction. Test input/output buffers and peer work stay outside the scope.
    let payload = vec![0x42; 16 * 1024];
    queue_application(owner, &mut connections, &payload);
    let queued = owner.snapshot();
    assert!(queued.live > idle.live);
    drain_application(owner, &mut connections, &payload);
    let idle_after_io = owner.snapshot();
    for size in [1, 1024, 16384, 16384] {
        queue_application(owner, &mut connections, &payload[..size]);
        drain_application(owner, &mut connections, &payload[..size]);
    }
    for connection in &mut connections {
        assert_eq!(
            owner.enter(|| connection.client.process_read().unwrap()),
            ReadProgress::NeedInput
        );
    }
    assert_eq!(owner.snapshot().live, idle_after_io.live);
    assert_eq!(owner.snapshot().allocations, idle_after_io.allocations);
    assert_eq!(owner.snapshot().reallocations, idle_after_io.reallocations);

    // Deallocation is deliberately outside the scope: header origin, not the
    // current thread's active owner, determines which total must decrease.
    drop(connections);
    let cache_only = owner.snapshot();
    assert!(cache_only.live < idle_after_io.live);
    drop(stores);
    let released = owner.snapshot();
    assert_eq!(released.live, 0, "connection/cache-owned Rust bytes leaked");
    assert_eq!(released.blocks, 0);
    println!(
        "{}",
        serde_json::json!({
            "kind": "client_owned_memory",
            "version": if tls12 { "TLS1.2" } else { "TLS1.3" },
            "resumed": resumed,
            "concurrent_established": concurrent,
            "concurrency": "simultaneously_live_sequentially_driven",
            "scope": "dynamic_inputs_endpoint_private_session_cache",
            "unit": "requested_rust_heap_bytes",
            "pre_handshake_cache_bytes": baseline.live,
            "handshake_peak_bytes": idle.peak,
            "idle_after_handshake_bytes": idle.live,
            "bidirectional_16k_queued_bytes": queued.live,
            "idle_after_io_bytes": idle_after_io.live,
            "lifecycle_peak_bytes": idle_after_io.peak,
            "warm_roundtrip_count": 4,
            "warm_roundtrip_allocations": released.allocations - idle_after_io.allocations,
            "warm_roundtrip_reallocations": released.reallocations - idle_after_io.reallocations,
            "cache_after_endpoint_drop_bytes": cache_only.live,
            "after_all_owners_drop_bytes": released.live,
            "handshake_rust_allocations": idle.allocations - baseline.allocations,
            "handshake_rust_reallocations": idle.reallocations - baseline.reallocations,
            "handshake_requested_bytes": idle.requested - baseline.requested,
            "inline_client_bytes": concurrent * std::mem::size_of::<ClientConnection>(),
            "shared_config_bytes": null,
            "c_backend_bytes": null,
            "copy_bytes": null,
            "elapsed_ns": null,
        })
    );
}

#[test]
#[ignore = "Deterministic memory matrix; explicitly run serially with --ignored --nocapture"]
fn client_owned_peak_idle_and_concurrent_memory_matrix() {
    for tls12 in [false, true] {
        let peer = Peer::new(tls12);
        // Prime provider/global setup with a separate owner. This does not
        // suppress accounting of fresh endpoint keys in the measured cases.
        let warm = Owner::new();
        drop(handshake(warm, &peer, Arc::default(), false));
        assert_eq!(warm.snapshot().live, 0);
        for resumed in [false, true] {
            for concurrent in [1, 8, 32, 128] {
                memory_case(&peer, tls12, resumed, concurrent);
            }
        }
    }
}
