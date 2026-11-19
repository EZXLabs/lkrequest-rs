//! Serial, opt-in warm record measurements. Compile during development; run only
//! after all builds have stopped, in release mode with --test-threads=1.
//! Counts Rust GlobalAlloc calls on this thread, not allocator calls inside C.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;
use std::time::{Duration, Instant};

use lktls::crypto::aead::{Aead, AeadAlgorithm};
use lktls::crypto::tls12_cipher::{CbcMacMode, Tls12CipherSuite};
use lktls::handshake::tls12::{create_tls12_record_cipher, Tls12TrafficKeys};
use lktls::record::{
    reader::RecordReader,
    writer::{RecordWriter, WriteStop},
};

#[derive(Clone, Copy, Default)]
struct Counts {
    allocations: u64,
    reallocations: u64,
    requested_bytes: u64,
}

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static COUNTS: Cell<Counts> = const { Cell::new(Counts { allocations: 0, reallocations: 0, requested_bytes: 0 }) };
}

struct CountingAllocator;

fn allocated(bytes: usize, reallocation: bool) {
    let _ = COUNTING.try_with(|enabled| {
        if enabled.get() {
            let _ = COUNTS.try_with(|counts| {
                let mut value = counts.get();
                value.allocations += u64::from(!reallocation);
                value.reallocations += u64::from(reallocation);
                value.requested_bytes += bytes as u64;
                counts.set(value);
            });
        }
    });
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let result = unsafe { System.alloc(layout) };
        if !result.is_null() {
            allocated(layout.size(), false);
        }
        result
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let result = unsafe { System.alloc_zeroed(layout) };
        if !result.is_null() {
            allocated(layout.size(), false);
        }
        result
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(pointer, layout, size) };
        if !result.is_null() {
            allocated(size, true);
        }
        result
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct CountingGuard;
impl CountingGuard {
    fn start() -> Self {
        COUNTS.with(|counts| counts.set(Counts::default()));
        COUNTING.with(|enabled| enabled.set(true));
        Self
    }
}
impl Drop for CountingGuard {
    fn drop(&mut self) {
        COUNTING.with(|enabled| enabled.set(false));
    }
}

#[derive(Clone, Copy)]
enum Suite {
    Tls13(AeadAlgorithm),
    Tls12(u16),
    Tls12Cbc(u16, CbcMacMode),
}

impl Suite {
    fn name(self) -> String {
        match self {
            Self::Tls13(algorithm) => format!("tls13-{algorithm:?}"),
            Self::Tls12(code) => format!("tls12-{code:04x}"),
            Self::Tls12Cbc(code, mode) => format!("tls12-{code:04x}-{mode:?}"),
        }
    }
    fn pair(self) -> (RecordWriter, RecordReader) {
        let mut writer = RecordWriter::new();
        let mut reader = RecordReader::new();
        match self {
            Self::Tls13(algorithm) => {
                let key = vec![0x42; algorithm.key_len()];
                writer.set_keys(Aead::new(algorithm, &key, &[0x24; 12]).unwrap());
                reader.set_keys(Aead::new(algorithm, &key, &[0x24; 12]).unwrap());
            }
            Self::Tls12(code) => {
                let suite = Tls12CipherSuite::from_code_point(code).unwrap();
                let key = vec![0x42; suite.enc_key_len()];
                let iv = vec![0x24; suite.fixed_iv_len()];
                let cipher = || create_tls12_record_cipher(&suite, &key, &iv, &[]).unwrap();
                writer.set_tls12_keys(cipher());
                reader.set_tls12_keys(cipher());
            }
            Self::Tls12Cbc(code, mode) => {
                let suite = Tls12CipherSuite::from_code_point(code).unwrap();
                assert!(suite.is_cbc());
                let keys = Tls12TrafficKeys {
                    cipher_suite: suite,
                    client_write_key: vec![0x42; suite.enc_key_len()],
                    server_write_key: vec![0x42; suite.enc_key_len()],
                    client_write_iv: vec![0x24; suite.fixed_iv_len()],
                    server_write_iv: vec![0x24; suite.fixed_iv_len()],
                    client_write_mac_key: vec![0x53; suite.mac_key_len()],
                    server_write_mac_key: vec![0x53; suite.mac_key_len()],
                };
                writer.set_tls12_keys(keys.to_record_cipher_with_mode(true, mode).unwrap());
                reader.set_tls12_keys(keys.to_record_cipher_with_mode(false, mode).unwrap());
            }
        }
        (writer, reader)
    }
}

struct Fixture {
    writer: RecordWriter,
    reader: RecordReader,
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
    decrypted: Vec<u8>,
    limit: usize,
}

impl Fixture {
    fn new(suite: Suite, size: usize) -> Self {
        let (writer, reader) = suite.pair();
        let limit = size + 128;
        Self {
            writer,
            reader,
            plaintext: vec![0x31; size],
            ciphertext: Vec::with_capacity(limit),
            decrypted: Vec::with_capacity(size + 32),
            limit,
        }
    }
    fn write(&mut self, reusable: bool) {
        self.ciphertext.clear();
        if reusable {
            let progress = self.writer.write_into(
                23,
                black_box(&self.plaintext),
                &mut self.ciphertext,
                self.limit,
            );
            assert_eq!(progress.accepted_plaintext, self.plaintext.len());
            assert!(matches!(progress.stop, WriteStop::Complete));
        } else {
            self.ciphertext = self
                .writer
                .write_record(23, black_box(&self.plaintext))
                .unwrap();
        }
        black_box(&self.ciphertext);
    }
    fn read(&mut self, reusable: bool) {
        if reusable {
            assert_eq!(
                self.reader.feed_bounded(&self.ciphertext, self.limit),
                self.ciphertext.len()
            );
            assert_eq!(
                self.reader.next_record_into(&mut self.decrypted).unwrap(),
                Some(23)
            );
        } else {
            self.reader.feed(&self.ciphertext);
            let record = self.reader.next_record().unwrap().unwrap();
            assert_eq!(record.content_type, 23);
            self.decrypted = record.payload;
        }
        black_box(&self.decrypted);
    }
}

fn measure(suite: Suite, size: usize, read: bool, reusable: bool, iterations: usize) {
    let mut fixture = Fixture::new(suite, size);
    for _ in 0..32 {
        fixture.write(reusable);
        if read {
            fixture.read(reusable);
        }
    }
    let mut total = Counts::default();
    for _ in 0..iterations {
        if read {
            fixture.write(true);
        }
        let guard = CountingGuard::start();
        if read {
            fixture.read(reusable);
        } else {
            fixture.write(reusable);
        }
        drop(guard);
        let counts = COUNTS.with(Cell::get);
        total.allocations += counts.allocations;
        total.reallocations += counts.reallocations;
        total.requested_bytes += counts.requested_bytes;
        if read {
            assert_eq!(fixture.decrypted, fixture.plaintext);
        }
    }
    // Legacy diagnostic only: per-record clocks and the disabled counting
    // allocator still add overhead. Acceptance uses record_legacy_timing.rs.
    let allocation_only = std::env::var_os("TLS_MEASURE_ALLOCATIONS_ONLY").is_some();
    let mut elapsed = Duration::ZERO;
    for _ in 0..if allocation_only { 0 } else { iterations } {
        if read {
            fixture.write(true);
        }
        let started = Instant::now();
        if read {
            fixture.read(reusable);
        } else {
            fixture.write(reusable);
        }
        elapsed += started.elapsed();
    }
    println!(
        "{}",
        serde_json::json!({
            "suite": suite.name(), "payload_bytes": size, "operation": if read { "read" } else { "write" },
            "path": if reusable { "reusable" } else { "legacy" }, "iterations": iterations,
            "rust_allocations": total.allocations, "rust_reallocations": total.reallocations,
            "requested_bytes": total.requested_bytes, "elapsed_ns": (!allocation_only).then_some(elapsed.as_nanos()),
            "timing_acceptance_eligible": false,
            "timing_scope": "legacy diagnostic aggregate, wall time only; not an old-version baseline or acceptance distribution",
            "copy_bytes": null, "allocator_scope": "Rust GlobalAlloc on current thread",
            "requires_zero_warm_allocations": reusable && !matches!(suite, Suite::Tls12Cbc(..)),
            "cbc_timing_resistance": matches!(suite, Suite::Tls12Cbc(..)).then_some("unmeasured"),
        })
    );
    if reusable && !matches!(suite, Suite::Tls12Cbc(..)) {
        assert_eq!(
            total.allocations + total.reallocations,
            0,
            "warm reusable {} size={size} read={read}",
            suite.name()
        );
    }
}

#[test]
#[ignore = "Performance gate: run serially in release mode on an idle machine"]
fn warm_aead_record_allocation_and_cpu_matrix() {
    assert_eq!(
        measure_suites(
            &[
                Suite::Tls13(AeadAlgorithm::Aes128Gcm),
                Suite::Tls13(AeadAlgorithm::Aes256Gcm),
                Suite::Tls13(AeadAlgorithm::Chacha20Poly1305),
                Suite::Tls12(0xc02b),
                Suite::Tls12(0xc02c),
                Suite::Tls12(0xcca9),
            ],
            &[1, 64, 1024, 16384],
        ),
        96
    );
}

#[test]
#[ignore = "Performance gate: run serially in release mode on an idle machine"]
fn warm_cbc_record_allocation_and_cpu_matrix() {
    let suites: Vec<_> = [0xc009, 0xc023, 0xc024]
        .into_iter()
        .flat_map(|code| {
            [CbcMacMode::MacThenEncrypt, CbcMacMode::EncryptThenMac]
                .map(|mode| Suite::Tls12Cbc(code, mode))
        })
        .collect();
    assert_eq!(
        measure_suites(&suites, &[1, 15, 16, 17, 64, 1024, 16384]),
        168
    );
}

fn measure_suites(suites: &[Suite], sizes: &[usize]) -> usize {
    assert!(
        std::env::var_os("TLS_RECORD_MEASURE_IDLE").is_some()
            || std::env::var_os("TLS_MEASURE_ALLOCATIONS_ONLY").is_some(),
        "use TLS_MEASURE_ALLOCATIONS_ONLY=1 or set TLS_RECORD_MEASURE_IDLE=1 on an idle machine"
    );
    let iterations = std::env::var("TLS_RECORD_MEASURE_ITERATIONS")
        .ok()
        .map(|value| value.parse().unwrap())
        .unwrap_or(2000);
    assert!(iterations > 0);
    let mut rows = 0;
    for &suite in suites {
        for &size in sizes {
            for read in [false, true] {
                for reusable in [false, true] {
                    measure(suite, size, read, reusable, iterations);
                    rows += 1;
                }
            }
        }
    }
    rows
}

#[test]
fn warm_endpoint_bytewise_backpressure_has_no_rust_allocations() {
    use lktls::connection::ClientConnection;
    use lktls::handshake::driver::HandshakeResult;
    use lktls::profile::types::TlsClientHelloStyle;

    for (suite, retry_size) in [
        Suite::Tls13(AeadAlgorithm::Aes128Gcm),
        Suite::Tls13(AeadAlgorithm::Aes256Gcm),
        Suite::Tls13(AeadAlgorithm::Chacha20Poly1305),
        Suite::Tls12(0xc02b),
        Suite::Tls12(0xc02c),
        Suite::Tls12(0xcca9),
    ]
    .into_iter()
    .flat_map(|suite| [1, 16384].map(|size| (suite, size)))
    {
        let (writer, reader) = suite.pair();
        let result = HandshakeResult {
            reader,
            writer,
            negotiated_alpn: None,
            negotiated_cipher_suite: None,
            negotiated_version: None,
            peer_certificates: Vec::new(),
            post_handshake: None,
            session_ticket_ctx: None,
        };
        let mut endpoint = ClientConnection::from_handshake(result, TlsClientHelloStyle::Generic);
        let retry = vec![0x31; retry_size];
        endpoint.write_application(&vec![0x31; 512 * 1024]).unwrap();
        while endpoint.write_application(&retry).unwrap() != 0 {}
        let guard = CountingGuard::start();
        for _ in 0..2048 {
            endpoint.consume_output(1);
            black_box(endpoint.write_application(&retry).unwrap());
        }
        for _ in 0..4 {
            endpoint.consume_output(endpoint.output().len().div_ceil(2));
            assert_eq!(endpoint.write_application(&retry).unwrap(), retry_size);
        }
        drop(guard);
        let counts = COUNTS.with(Cell::get);
        assert_eq!(counts.allocations, 0, "{}", suite.name());
        assert_eq!(counts.reallocations, 0, "{}", suite.name());
        assert_eq!(counts.requested_bytes, 0, "{}", suite.name());
    }
}
