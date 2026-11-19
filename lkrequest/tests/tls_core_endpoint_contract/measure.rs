//! Client-only allocation/CPU sampling; the independent peer runs outside every
//! counted/timed region. Inline owner sizes explicitly exclude owned heap memory.
//! Build with --release --no-run, then select
//! client_handshake_allocation_cpu_and_inline_owner_sizes with --ignored
//! --nocapture --test-threads=1 and TLS_HANDSHAKE_MEASURE_IDLE=1 after builds stop.
//! The counter covers Rust GlobalAlloc, not C backend allocations. Timing excludes
//! counting but retains the allocator's enabled check and per-call Instant cost.
//! Peer/configuration setup, input construction and final owner drop are excluded.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::time::Instant;

use super::*;

#[derive(Clone, Copy, Default)]
struct Counts {
    allocations: u64,
    reallocations: u64,
    requested_bytes: u64,
}

thread_local! {
    static ENABLED: Cell<bool> = const { Cell::new(false) };
    static COUNTS: Cell<Counts> = const { Cell::new(Counts { allocations: 0, reallocations: 0, requested_bytes: 0 }) };
}

fn count(bytes: usize, realloc: bool) {
    let _ = ENABLED.try_with(|enabled| {
        if enabled.get() {
            let _ = COUNTS.try_with(|counts| {
                let mut value = counts.get();
                value.allocations += u64::from(!realloc);
                value.reallocations += u64::from(realloc);
                value.requested_bytes += bytes as u64;
                counts.set(value);
            });
        }
    });
}

struct Allocator;
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            count(layout.size(), false);
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            count(layout.size(), false);
        }
        pointer
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(pointer, layout, size) };
        if !result.is_null() {
            count(size, true);
        }
        result
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

struct CounterGuard;
impl Drop for CounterGuard {
    fn drop(&mut self) {
        ENABLED.with(|enabled| enabled.set(false));
    }
}

#[derive(Default)]
struct Sample {
    counts: Counts,
    client_calls: u64,
    elapsed_ns: u128,
    count_allocations: bool,
}

impl Sample {
    fn client<T>(&mut self, operation: impl FnOnce() -> T) -> T {
        COUNTS.with(|counts| counts.set(Counts::default()));
        ENABLED.with(|enabled| enabled.set(self.count_allocations));
        let guard = CounterGuard;
        let started = Instant::now();
        let value = operation();
        let elapsed = started.elapsed().as_nanos();
        drop(guard);
        let count = COUNTS.with(Cell::get);
        self.counts.allocations += count.allocations;
        self.counts.reallocations += count.reallocations;
        self.counts.requested_bytes += count.requested_bytes;
        self.client_calls += 1;
        if !self.count_allocations {
            self.elapsed_ns += elapsed;
        }
        value
    }
}

fn handshake_sample(
    peer: &Peer,
    store: Arc<ObservedStore>,
    count_allocations: bool,
    resumed: bool,
) -> Sample {
    let mut sample = Sample {
        count_allocations,
        ..Sample::default()
    };
    let mut inputs = ConnectionInputs::new("localhost", 443);
    inputs.session_store = Some(store);
    let mut client =
        sample.client(|| ClientConnection::from_compiled(peer.client.clone(), inputs).unwrap());
    let mut server = rustls::ServerConnection::new(peer.server.clone()).unwrap();
    for _ in 0..32 {
        match sample.client(|| client.progress_handshake().unwrap()) {
            HandshakeProgress::NeedOutput => {
                let count = server.read_tls(&mut Cursor::new(client.output())).unwrap();
                server.process_new_packets().unwrap();
                sample.client(|| client.consume_output(count));
            }
            HandshakeProgress::NeedInput => {
                let bytes = server_output(&mut server);
                assert!(!bytes.is_empty());
                assert_eq!(sample.client(|| client.feed_bounded(&bytes)), bytes.len());
            }
            HandshakeProgress::Complete => {
                assert!(!server.is_handshaking());
                assert_eq!(
                    server.handshake_kind(),
                    Some(if resumed {
                        rustls::HandshakeKind::Resumed
                    } else {
                        rustls::HandshakeKind::Full
                    })
                );
                let tickets = server_output(&mut server);
                assert_eq!(
                    sample.client(|| client.feed_bounded(&tickets)),
                    tickets.len()
                );
                assert_eq!(
                    sample.client(|| client.process_read().unwrap()),
                    ReadProgress::NeedInput
                );
                return sample;
            }
        }
    }
    panic!("measured handshake failed to finish");
}

#[test]
#[ignore = "Performance gate: run serially in release mode after all builds stop"]
fn client_handshake_allocation_cpu_and_inline_owner_sizes() {
    let allocation_only = std::env::var_os("TLS_MEASURE_ALLOCATIONS_ONLY").is_some();
    assert!(
        allocation_only || std::env::var_os("TLS_HANDSHAKE_MEASURE_IDLE").is_some(),
        "use TLS_MEASURE_ALLOCATIONS_ONLY=1 or set TLS_HANDSHAKE_MEASURE_IDLE=1 on an idle machine"
    );
    let iterations: usize = std::env::var("TLS_HANDSHAKE_MEASURE_ITERATIONS")
        .ok()
        .map(|value| value.parse().unwrap())
        .unwrap_or(10);
    assert!(iterations > 0);
    println!(
        "{}",
        serde_json::json!({
            "kind": "inline_owner_bytes", "ClientConnection": std::mem::size_of::<ClientConnection>(),
            "TcpConnection": std::mem::size_of::<lktls::connection::TcpConnection>(),
            "HandshakeDriver": std::mem::size_of::<lktls::handshake::driver::HandshakeDriver>(),
            "QuicHandshakeDriver": std::mem::size_of::<lktls::handshake::driver::QuicHandshakeDriver>(),
            "QuicClientConnection": std::mem::size_of::<lktls::connection::QuicClientConnection>(),
            "Tls12Handshake": std::mem::size_of::<lktls::handshake::tls12::Tls12Handshake>(),
            "Tls13Handshake": std::mem::size_of::<lktls::handshake::tls13::Tls13Handshake>(),
            "retained_heap_bytes": null,
        })
    );
    for tls12 in [false, true] {
        let peer = Peer::new(tls12);
        // Prime crypto/provider paths before sampling. Configuration is shared.
        handshake_sample(&peer, Arc::default(), false, false);
        for resumed in [false, true] {
            for iteration in 0..iterations {
                let mut allocation = None;
                let mut timing = None;
                for counting in [true, false] {
                    if !counting && allocation_only {
                        continue;
                    }
                    let store = Arc::new(ObservedStore::default());
                    if resumed {
                        handshake_sample(&peer, store.clone(), false, false);
                    }
                    let sample = handshake_sample(&peer, store, counting, resumed);
                    if counting {
                        allocation = Some(sample);
                    } else {
                        timing = Some(sample);
                    }
                }
                let allocation = allocation.unwrap();
                println!(
                    "{}",
                    serde_json::json!({
                        "kind": "client_handshake", "version": if tls12 { "TLS1.2" } else { "TLS1.3" },
                        "resumed": resumed, "iteration": iteration, "config": "shared_compiled", "verification": "strict",
                        "rust_allocations": allocation.counts.allocations, "rust_reallocations": allocation.counts.reallocations,
                        "requested_bytes": allocation.counts.requested_bytes, "client_calls": allocation.client_calls,
                        "client_elapsed_ns": timing.map(|sample| sample.elapsed_ns), "peer_cost_included": false, "retained_heap_bytes": null,
                    })
                );
            }
        }
    }
}
