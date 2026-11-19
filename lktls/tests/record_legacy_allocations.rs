//! Identical-source allocation comparison for pre-refactor and current records.
//!
//! This file uses only public APIs present at 70db5785. Copy it unchanged into
//! either checkout's lktls/tests, use separate Cargo targets, then run:
//! cargo test -p lktls --test record_legacy_allocations -- --ignored --nocapture --test-threads=1
//! Key construction, plaintext/ciphertext preparation and warmup are uncounted.
//! Read measurements include feed plus next_record; write measurements include
//! write_record. These are legacy allocating APIs in BOTH revisions. There is
//! no clock, CPU measurement, or claim about backend allocations or copy counts.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;

use lktls::crypto::aead::{Aead, AeadAlgorithm};
use lktls::crypto::tls12_cipher::{
    CbcMacAlgorithm, Tls12CbcCipher, Tls12Chacha20Cipher, Tls12GcmCipher,
};
use lktls::record::{reader::RecordReader, writer::RecordWriter, Tls12RecordCipher};

#[derive(Clone, Copy, Default)]
struct Counts {
    allocations: u64,
    reallocations: u64,
    requested_bytes: u64,
}

thread_local! {
    static ENABLED: Cell<bool> = const { Cell::new(false) };
    static COUNTS: Cell<Counts> = const { Cell::new(Counts {
        allocations: 0, reallocations: 0, requested_bytes: 0,
    }) };
}

fn record_allocation(bytes: usize, reallocation: bool) {
    let _ = ENABLED.try_with(|enabled| {
        if enabled.get() {
            let _ = COUNTS.try_with(|counts| {
                let mut count = counts.get();
                count.allocations += u64::from(!reallocation);
                count.reallocations += u64::from(reallocation);
                // Realloc counts the requested new size, not its size delta.
                count.requested_bytes += bytes as u64;
                counts.set(count);
            });
        }
    });
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let result = unsafe { System.alloc(layout) };
        if !result.is_null() {
            record_allocation(layout.size(), false);
        }
        result
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let result = unsafe { System.alloc_zeroed(layout) };
        if !result.is_null() {
            record_allocation(layout.size(), false);
        }
        result
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(pointer, layout, size) };
        if !result.is_null() {
            record_allocation(size, true);
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
        ENABLED.with(|enabled| enabled.set(true));
        Self
    }
}

impl Drop for CountingGuard {
    fn drop(&mut self) {
        ENABLED.with(|enabled| enabled.set(false));
    }
}

#[derive(Clone, Copy)]
enum Suite {
    Tls13(AeadAlgorithm),
    Tls12Gcm(bool),
    Tls12Chacha20,
    Tls12Cbc(usize, CbcMacAlgorithm),
}

impl Suite {
    fn name(self) -> &'static str {
        match self {
            Self::Tls13(AeadAlgorithm::Aes128Gcm) => "tls13-aes128-gcm",
            Self::Tls13(AeadAlgorithm::Aes256Gcm) => "tls13-aes256-gcm",
            Self::Tls13(AeadAlgorithm::Chacha20Poly1305) => "tls13-chacha20-poly1305",
            Self::Tls12Gcm(false) => "tls12-aes128-gcm",
            Self::Tls12Gcm(true) => "tls12-aes256-gcm",
            Self::Tls12Chacha20 => "tls12-chacha20-poly1305",
            Self::Tls12Cbc(16, CbcMacAlgorithm::HmacSha1) => "tls12-aes128-cbc-sha1-mte",
            Self::Tls12Cbc(16, CbcMacAlgorithm::HmacSha256) => "tls12-aes128-cbc-sha256-mte",
            Self::Tls12Cbc(32, CbcMacAlgorithm::HmacSha384) => "tls12-aes256-cbc-sha384-mte",
            _ => unreachable!("the matrix contains only named variants"),
        }
    }

    fn pair(self) -> (RecordWriter, RecordReader) {
        let mut writer = RecordWriter::new();
        let mut reader = RecordReader::new();
        if let Self::Tls13(algorithm) = self {
            let key = vec![0x42; algorithm.key_len()];
            writer.set_keys(Aead::new(algorithm, &key, &[0x24; 12]).unwrap());
            reader.set_keys(Aead::new(algorithm, &key, &[0x24; 12]).unwrap());
        } else {
            let cipher = || match self {
                Self::Tls12Gcm(aes256) => Tls12RecordCipher::Gcm(
                    Tls12GcmCipher::new(
                        &vec![0x42; if aes256 { 32 } else { 16 }],
                        &[0x24; 4],
                        aes256,
                    )
                    .unwrap(),
                ),
                Self::Tls12Chacha20 => Tls12RecordCipher::Chacha20(
                    Tls12Chacha20Cipher::new(&[0x42; 32], &[0x24; 12]).unwrap(),
                ),
                Self::Tls12Cbc(key_bytes, mac) => Tls12RecordCipher::Cbc(Tls12CbcCipher::new(
                    &vec![0x42; key_bytes],
                    &vec![0x53; mac.mac_len()],
                    mac,
                )),
                Self::Tls13(_) => unreachable!(),
            };
            writer.set_tls12_keys(cipher());
            reader.set_tls12_keys(cipher());
        }
        (writer, reader)
    }
}

fn consume(reader: &mut RecordReader, ciphertext: &[u8]) -> Vec<u8> {
    reader.feed(black_box(ciphertext));
    let record = reader.next_record().unwrap().unwrap();
    assert_eq!(record.content_type, 23);
    black_box(record.payload)
}

fn measure(suite: Suite, size: usize, read: bool, iterations: usize, revision: &str) {
    let (mut writer, mut reader) = suite.pair();
    let plaintext = vec![0x31; size];
    // Consume every record so both peers advance together, including warmup.
    // This also warms reader.feed capacity before the allocation sample.
    for _ in 0..32 {
        let ciphertext = writer.write_record(23, &plaintext).unwrap();
        assert_eq!(consume(&mut reader, &ciphertext), plaintext);
    }
    let mut total = Counts::default();
    let mut ciphertext_bytes = 0;
    for _ in 0..iterations {
        let (ciphertext, decrypted, counts) = if read {
            let ciphertext = writer.write_record(23, &plaintext).unwrap();
            let guard = CountingGuard::start();
            let decrypted = consume(&mut reader, &ciphertext);
            drop(guard);
            (ciphertext, decrypted, COUNTS.with(Cell::get))
        } else {
            let guard = CountingGuard::start();
            let ciphertext = writer.write_record(23, black_box(&plaintext)).unwrap();
            drop(guard);
            let counts = COUNTS.with(Cell::get);
            let decrypted = consume(&mut reader, &ciphertext);
            (ciphertext, decrypted, counts)
        };
        assert_eq!(decrypted, plaintext);
        assert_eq!(reader.buffered_len(), 0);
        ciphertext_bytes = ciphertext.len();
        total.allocations += counts.allocations;
        total.reallocations += counts.reallocations;
        total.requested_bytes += counts.requested_bytes;
        black_box(ciphertext);
    }
    println!(
        "{}",
        serde_json::json!({
            "revision": revision,
            "suite": suite.name(),
            "payload_bytes": size,
            "ciphertext_bytes": ciphertext_bytes,
            "operation": if read { "read" } else { "write" },
            "path": "legacy",
            "iterations": iterations,
            "rust_allocations": total.allocations,
            "rust_reallocations": total.reallocations,
            "requested_bytes": total.requested_bytes,
            "elapsed_ns": null,
            "copy_bytes": null,
            "backend_allocations": null,
            "allocator_scope": "successful Rust GlobalAlloc requests on current thread",
            "cbc_timing_resistance": matches!(suite, Suite::Tls12Cbc(..)).then_some("unmeasured"),
        })
    );
}

#[test]
#[ignore = "Opt-in cross-revision Rust allocation evidence; never measures CPU time"]
fn legacy_record_allocation_matrix() {
    let revision = std::env::var("TLS_RECORD_BASELINE_REVISION")
        .expect("set TLS_RECORD_BASELINE_REVISION to the checkout's exact git revision");
    let iterations = std::env::var("TLS_RECORD_BASELINE_ITERATIONS")
        .map(|value| value.parse::<usize>().unwrap())
        .unwrap_or(2000);
    assert!(iterations > 0);
    for suite in [
        Suite::Tls13(AeadAlgorithm::Aes128Gcm),
        Suite::Tls13(AeadAlgorithm::Aes256Gcm),
        Suite::Tls13(AeadAlgorithm::Chacha20Poly1305),
        Suite::Tls12Gcm(false),
        Suite::Tls12Gcm(true),
        Suite::Tls12Chacha20,
        Suite::Tls12Cbc(16, CbcMacAlgorithm::HmacSha1),
        Suite::Tls12Cbc(16, CbcMacAlgorithm::HmacSha256),
        Suite::Tls12Cbc(32, CbcMacAlgorithm::HmacSha384),
    ] {
        for size in [1, 1024, 16384] {
            for read in [false, true] {
                measure(suite, size, read, iterations, &revision);
            }
        }
    }
}
