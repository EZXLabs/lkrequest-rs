//! Allocation and ownership under sustained traffic and concurrent handshakes.
//! No timer is sampled; cache call overlap is not internal mutex wait time.

use std::io::{Cursor, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Barrier};

use lktls::config::ConnectionInputs;
use lktls::connection::{ClientConnection, HandshakeProgress, ReadProgress};
use lktls::session_store::{
    ClientSession, ClientSessionStore, InMemorySessionStore, SessionStore, SessionTicketData,
};

use super::{accounting::Owner, handshake, peer_output, send_client, Established, Peer};

const TRANSFER_BYTES: usize = 16 * 1024 * 1024;
const OUTPUT_LIMIT: usize = 256 * 1024;
const INPUT_LIMIT: usize = 64 * 1024;

fn assert_released(owner: Owner) {
    assert_eq!(owner.snapshot().live, 0, "workload owner retained bytes");
    assert_eq!(owner.snapshot().blocks, 0);
}

#[test]
fn worker_scope_accounts_only_explicit_work_and_keeps_origin_on_return() {
    let owner = Owner::new();
    let (unrelated, owned) = std::thread::spawn(move || {
        let unrelated = vec![1u8; 193];
        assert_eq!(owner.snapshot().live, 0);
        let owned = owner.enter(|| vec![2u8; 257]);
        assert_eq!(owner.snapshot().live, 257);
        (unrelated, owned)
    })
    .join()
    .unwrap();
    assert_eq!(owner.snapshot().allocations, 1);
    assert_eq!(owner.snapshot().live, owned.len());
    owner.enter(|| drop(unrelated));
    assert_eq!(owner.snapshot().live, 257);
    drop(owned);
    assert_released(owner);
}

#[derive(Default)]
struct Transfer {
    accepted_calls: usize,
    capacity_stops: usize,
    max_output: usize,
    max_input: usize,
    consumed_ciphertext: usize,
}

fn transfer(
    owner: Owner,
    connection: &mut Established,
    payload: &[u8],
    transport_chunk: usize,
    stats: &mut Transfer,
) {
    let mut accepted = 0;
    let mut peer_received = 0;
    let mut client_received = 0;
    let mut peer_plaintext = [0; 16384];
    while accepted < payload.len() || !connection.client.output().is_empty() {
        if accepted < payload.len() {
            let count = owner.enter(|| {
                connection
                    .client
                    .write_application(&payload[accepted..])
                    .unwrap()
            });
            accepted += count;
            stats.accepted_calls += usize::from(count != 0);
            stats.capacity_stops += usize::from(count == 0);
        }
        stats.max_output = stats.max_output.max(connection.client.output().len());
        assert!(connection.client.output().len() <= OUTPUT_LIMIT);
        let pending = connection.client.output().len().min(transport_chunk);
        assert!(pending > 0, "transfer stopped without pending output");
        let consumed = connection
            .server
            .read_tls(&mut Cursor::new(&connection.client.output()[..pending]))
            .unwrap();
        assert!(consumed > 0);
        connection.server.process_new_packets().unwrap();
        owner.enter(|| connection.client.consume_output(consumed));
        stats.consumed_ciphertext += consumed;
        loop {
            let count = match connection.server.reader().read(&mut peer_plaintext) {
                Ok(0) => panic!("peer closed during sustained transfer"),
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("peer plaintext read failed: {error}"),
            };
            assert_eq!(
                &peer_plaintext[..count],
                &payload[peer_received..peer_received + count]
            );
            peer_received += count;
            connection
                .server
                .writer()
                .write_all(&peer_plaintext[..count])
                .unwrap();
            let incoming = peer_output(&mut connection.server);
            for fragment in incoming.chunks(transport_chunk) {
                assert_eq!(
                    owner.enter(|| connection.client.feed_bounded(fragment)),
                    fragment.len()
                );
                stats.max_input = stats
                    .max_input
                    .max(INPUT_LIMIT - connection.client.input_capacity());
                loop {
                    match owner.enter(|| connection.client.process_read().unwrap()) {
                        ReadProgress::NeedInput => break,
                        ReadProgress::Plaintext => {
                            let count = connection.client.plaintext().len().min(377);
                            assert!(count > 0);
                            assert_eq!(
                                &connection.client.plaintext()[..count],
                                &payload[client_received..client_received + count]
                            );
                            client_received += count;
                            owner.enter(|| connection.client.consume_plaintext(count));
                        }
                        ReadProgress::Yield => {}
                        other => panic!("unexpected sustained-transfer progress: {other:?}"),
                    }
                }
            }
        }
    }
    assert_eq!(accepted, payload.len());
    assert_eq!(peer_received, payload.len());
    assert_eq!(client_received, payload.len());
    assert!(connection.client.plaintext().is_empty());
}

#[test]
#[ignore = "Count-only sustained transfer; run explicitly with --ignored --nocapture"]
fn sustained_multi_record_transfer_allocation_and_retention() {
    let owner = Owner::new();
    let mut cases = 0;
    for tls12 in [false, true] {
        let peer = Peer::new(tls12);
        for (call_size, transport_chunk) in [(64 * 1024, 16384), (512 * 1024, 1024)] {
            assert_released(owner);
            let store = owner.enter(|| Arc::new(InMemorySessionStore::new()));
            let mut connection = handshake(owner, &peer, store.clone(), false);
            let payload: Vec<_> = (0..call_size).map(|i| (i % 251) as u8).collect();
            transfer(
                owner,
                &mut connection,
                &payload,
                transport_chunk,
                &mut Transfer::default(),
            );
            let before = owner.snapshot();
            owner.reset_peak();
            let mut stats = Transfer::default();
            let rounds = TRANSFER_BYTES / call_size;
            for _ in 0..rounds {
                transfer(
                    owner,
                    &mut connection,
                    &payload,
                    transport_chunk,
                    &mut stats,
                );
            }
            let after = owner.snapshot();
            assert_eq!(after.allocations, before.allocations);
            assert_eq!(after.reallocations, before.reallocations);
            assert_eq!(after.live, before.live);
            assert!(stats.max_input <= INPUT_LIMIT);
            if call_size > OUTPUT_LIMIT {
                assert!(
                    stats.capacity_stops > 0,
                    "large writes must exercise backpressure"
                );
            }
            drop(connection);
            let cache_only = owner.snapshot().live;
            drop(store);
            assert_released(owner);
            println!(
                "{}",
                serde_json::json!({
                    "kind": "sustained_tls_transfer", "version": if tls12 { "TLS1.2" } else { "TLS1.3" },
                    "plaintext_bytes_per_direction": rounds * call_size, "call_bytes": call_size,
                    "transport_drain_bytes": transport_chunk, "warmup_calls": 1,
                    "accepted_prefix_calls": stats.accepted_calls, "capacity_stops": stats.capacity_stops,
                    "consumed_ciphertext_bytes": stats.consumed_ciphertext,
                    "observed_pending_output_max": stats.max_output, "pending_output_limit": OUTPUT_LIMIT,
                    "observed_buffered_input_max": stats.max_input, "buffered_input_limit": INPUT_LIMIT,
                    "rust_allocations": after.allocations - before.allocations,
                    "rust_reallocations": after.reallocations - before.reallocations,
                    "requested_bytes": after.requested - before.requested,
                    "idle_before_bytes": before.live, "idle_after_bytes": after.live, "peak_bytes": after.peak,
                    "cache_after_endpoint_drop_bytes": cache_only, "after_all_drop_bytes": 0,
                    "scope": "client_endpoint_calls_and_private_cache_excluding_peer_harness_config",
                    "retained_capacity_bytes": null, "queue_measurement": "public_pending_bytes_not_capacity",
                    "copy_bytes": null, "c_backend_bytes": null, "elapsed_ns": null,
                })
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

#[derive(Debug, Default)]
struct CacheStats {
    active: AtomicUsize,
    max_active: AtomicUsize,
    takes: AtomicUsize,
    hits: AtomicUsize,
    stores: AtomicUsize,
}

struct CacheCall<'a>(&'a CacheStats);
impl Drop for CacheCall<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Relaxed);
    }
}

impl CacheStats {
    fn enter(&self) -> CacheCall<'_> {
        let active = self.active.fetch_add(1, Relaxed) + 1;
        self.max_active.fetch_max(active, Relaxed);
        CacheCall(self)
    }

    fn reset(&self) {
        assert_eq!(self.active.load(Relaxed), 0);
        self.max_active.store(0, Relaxed);
        self.takes.store(0, Relaxed);
        self.hits.store(0, Relaxed);
        self.stores.store(0, Relaxed);
    }
}

#[derive(Debug)]
struct ObservedStore {
    inner: Arc<InMemorySessionStore>,
    seeding: AtomicBool,
    stats: CacheStats,
}

impl SessionStore for ObservedStore {
    fn store(&self, _: &str, _: SessionTicketData) {
        panic!("the workload must publish versioned authenticated sessions");
    }
    fn take(&self, _: &str) -> Option<SessionTicketData> {
        panic!("the workload must consume versioned authenticated sessions");
    }
    fn client_sessions(&self) -> Option<&dyn ClientSessionStore> {
        Some(self)
    }
}

impl ClientSessionStore for ObservedStore {
    fn store_session(&self, host: &str, session: ClientSession) {
        let _call = self.stats.enter();
        self.inner.store_session(host, session);
        self.stats.stores.fetch_add(1, Relaxed);
    }
    fn take_session(&self, host: &str) -> Option<ClientSession> {
        let _call = self.stats.enter();
        self.stats.takes.fetch_add(1, Relaxed);
        let session = if self.seeding.load(Relaxed) {
            None
        } else {
            self.inner.take_session(host)
        };
        self.stats
            .hits
            .fetch_add(usize::from(session.is_some()), Relaxed);
        session
    }
}

fn burst_handshake(
    owner: Owner,
    peer: &Peer,
    store: Arc<ObservedStore>,
    resumed: bool,
    gates: Option<&(Barrier, Barrier)>,
) -> Established {
    if let Some((start, _)) = gates {
        start.wait();
    }
    // Every worker reaches the second gate even if construction panics. It
    // prevents early ticket publication from changing a full batch into PSK.
    let created = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let client = owner.enter(|| {
            let mut inputs = ConnectionInputs::new("localhost", 443);
            inputs.session_store = Some(store);
            ClientConnection::from_compiled(peer.client.clone(), inputs).unwrap()
        });
        Established {
            client,
            server: rustls::ServerConnection::new(peer.server.clone()).unwrap(),
        }
    }));
    if let Some((_, initialized)) = gates {
        initialized.wait();
    }
    let mut connection = created.unwrap();
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
    panic!("concurrent handshake failed to finish");
}

fn burst_case(
    client_owner: Owner,
    seed_owner: Owner,
    peer: &Peer,
    tls12: bool,
    resumed: bool,
    workers: usize,
    shared: bool,
) {
    assert_released(client_owner);
    assert_released(seed_owner);
    let stores: Vec<_> = (0..if shared { 1 } else { workers })
        .map(|_| {
            let inner =
                seed_owner.enter(|| Arc::new(InMemorySessionStore::with_max_tickets(2 * workers)));
            Arc::new(ObservedStore {
                inner,
                seeding: AtomicBool::new(resumed),
                stats: CacheStats::default(),
            })
        })
        .collect();
    if resumed {
        for store in &stores {
            let needed = if shared { workers } else { 1 };
            for _ in 0..needed {
                drop(burst_handshake(
                    seed_owner,
                    peer,
                    store.clone(),
                    false,
                    None,
                ));
            }
            assert!(store.stats.stores.load(Relaxed) >= needed);
            store.seeding.store(false, Relaxed);
        }
    }
    for store in &stores {
        store.stats.reset();
    }
    let seed_before = seed_owner.snapshot();
    let before = client_owner.snapshot();
    client_owner.reset_peak();
    let gates = (Barrier::new(workers), Barrier::new(workers));
    let clients = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|worker| {
                let store = stores[if shared { 0 } else { worker }].clone();
                let gates = &gates;
                scope
                    .spawn(move || burst_handshake(client_owner, peer, store, resumed, Some(gates)))
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    let idle = client_owner.snapshot();
    let seed_idle = seed_owner.snapshot();
    assert_eq!(clients.len(), workers);
    assert!(idle.live > 0);
    let takes: usize = stores.iter().map(|s| s.stats.takes.load(Relaxed)).sum();
    let hits: usize = stores.iter().map(|s| s.stats.hits.load(Relaxed)).sum();
    let stored: usize = stores.iter().map(|s| s.stats.stores.load(Relaxed)).sum();
    let overlap = stores
        .iter()
        .map(|s| s.stats.max_active.load(Relaxed))
        .max()
        .unwrap();
    assert_eq!(takes, workers);
    assert_eq!(hits, if resumed { workers } else { 0 });
    assert!(stored > 0);
    drop(clients);
    let cache = client_owner.snapshot().live;
    let seed_cache = seed_owner.snapshot().live;
    drop(stores);
    assert_released(client_owner);
    assert_released(seed_owner);
    println!(
        "{}",
        serde_json::json!({
            "kind": "concurrent_tls_handshake_burst", "version": if tls12 { "TLS1.2" } else { "TLS1.3" },
            "resumed": resumed, "workers": workers, "cache": if shared { "shared_origin" } else { "private" },
            "concurrency": "OS_threads_barrier_start_and_constructor_barrier",
            "strict_peer_authentication": true, "peer_validated_handshake_kind_count": workers,
            "cache_takes": takes, "cache_hits": hits, "cache_misses": takes - hits, "cache_stores": stored,
            "max_overlapping_calls_to_one_cache": overlap, "mutex_wait_ns": null, "lock_contention_rate": null,
            "client_origin_allocations": idle.allocations - before.allocations,
            "client_origin_reallocations": idle.reallocations - before.reallocations,
            "client_origin_requested_bytes": idle.requested - before.requested,
            "client_origin_peak_bytes": idle.peak, "client_origin_idle_bytes": idle.live,
            "seed_origin_before_bytes": seed_before.live, "seed_origin_idle_bytes": seed_idle.live,
            "combined_idle_bytes": idle.live + seed_idle.live, "combined_peak_bytes": null,
            "client_origin_cache_after_drop_bytes": cache, "seed_origin_cache_after_drop_bytes": seed_cache,
            "all_owners_after_drop_bytes": 0, "inline_client_bytes": workers * std::mem::size_of::<ClientConnection>(),
            "scope": "explicit_client_scopes_on_each_worker_and_private_or_shared_real_cache",
            "peer_threads_barriers_stats_wrapper_shared_config_included": false,
            "copy_bytes": null, "c_backend_bytes": null, "elapsed_ns": null,
        })
    );
}

#[test]
#[ignore = "Count-only parallel full/resumed handshakes and shared-cache load"]
fn concurrent_handshake_burst_private_and_shared_cache_memory() {
    let client_owner = Owner::new();
    let seed_owner = Owner::new();
    let mut cases = 0;
    for tls12 in [false, true] {
        let peer = Peer::new(tls12);
        drop(handshake(seed_owner, &peer, Arc::default(), false));
        assert_released(seed_owner);
        for resumed in [false, true] {
            for workers in [1, 8, 32] {
                for shared in [false, true] {
                    burst_case(
                        client_owner,
                        seed_owner,
                        &peer,
                        tls12,
                        resumed,
                        workers,
                        shared,
                    );
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 24);
}
