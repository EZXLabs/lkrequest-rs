//! Test-only evidence for explicit dynamic-buffer copies and retained capacity.
//! These hooks count executed source-level record copies and TLS 1.2 AEAD
//! plaintext appends, not memory-bus traffic. Stack/AAD copies, allocator
//! relocation and crypto backend work are excluded.
//! No instrumentation, layout changes or timing overhead reach production builds.

use std::cell::Cell;

use serde::Serialize;

use super::buffer::RecordBuffer;
use super::reader::RecordReader;
use super::writer::{RecordWriter, WriteStop};
use crate::crypto::aead::{Aead, AeadAlgorithm};
use crate::crypto::tls12_cipher::Tls12CipherSuite;

mod endpoint;
mod header;

const AEAD_SUITES: [Suite; 6] = [
    Suite::Tls13(AeadAlgorithm::Aes128Gcm),
    Suite::Tls13(AeadAlgorithm::Aes256Gcm),
    Suite::Tls13(AeadAlgorithm::Chacha20Poly1305),
    Suite::Tls12(0xc02b),
    Suite::Tls12(0xc02c),
    Suite::Tls12(0xcca9),
];

#[derive(Clone, Copy)]
pub(super) enum CopySite {
    InputFeed,
    CiphertextOpen,
    PlaintextSeal,
    RecordHeader,
    AuthTag,
    OutputAppend,
    InputCompact,
    OutputCompact,
}

const SITE_NAMES: [&str; 8] = [
    "wire_input_feed",
    "ciphertext_into_open_buffer",
    "plaintext_into_seal_buffer",
    "record_header_into_output",
    "authentication_tag_into_output",
    "output_queue_append",
    "input_cursor_compaction",
    "output_cursor_compaction",
];

#[derive(Clone, Copy, Default)]
struct Copies {
    bytes: [u64; 8],
    calls: [u64; 8],
}

impl Copies {
    fn add(&mut self, other: Self) {
        for index in 0..SITE_NAMES.len() {
            self.bytes[index] += other.bytes[index];
            self.calls[index] += other.calls[index];
        }
    }

    fn json(self) -> serde_json::Value {
        let sites: serde_json::Map<_, _> = SITE_NAMES
            .iter()
            .enumerate()
            .map(|(index, name)| {
                (
                    (*name).to_owned(),
                    serde_json::json!({ "bytes": self.bytes[index], "calls": self.calls[index] }),
                )
            })
            .collect();
        serde_json::json!({
            "observed_record_copy_bytes": self.bytes.iter().sum::<u64>(),
            "sites": sites,
            "copy_bytes": null,
            "crypto_backend_copy_bytes": null,
            "allocator_relocation_copy_bytes": null,
            "scope": "executed record-layer dynamic-buffer copy sites and TLS 1.2 AEAD plaintext appends; excludes stack/AAD, crypto backend and allocator relocation",
        })
    }
}

thread_local! {
    static COPIES: Cell<Option<Copies>> = const { Cell::new(None) };
}

pub(super) fn copied(site: CopySite, bytes: usize) {
    if bytes == 0 {
        return;
    }
    COPIES.with(|slot| {
        if let Some(mut counts) = slot.get() {
            counts.bytes[site as usize] += bytes as u64;
            counts.calls[site as usize] += 1;
            slot.set(Some(counts));
        }
    });
}

struct CopyScope;

impl Drop for CopyScope {
    fn drop(&mut self) {
        COPIES.with(|slot| slot.set(None));
    }
}

fn observe<T>(operation: impl FnOnce() -> T) -> (T, Copies) {
    COPIES.with(|slot| assert!(slot.replace(Some(Copies::default())).is_none()));
    let guard = CopyScope;
    let result = operation();
    let copies = COPIES.with(|slot| slot.get().unwrap());
    drop(guard);
    (result, copies)
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct BufferSnapshot {
    retained_capacity_bytes: usize,
    storage_len_bytes: usize,
    consumed_prefix_bytes: usize,
    pending_bytes: usize,
}

impl BufferSnapshot {
    pub(super) fn new(capacity: usize, length: usize, consumed: usize) -> Self {
        Self {
            retained_capacity_bytes: capacity,
            storage_len_bytes: length,
            consumed_prefix_bytes: consumed,
            pending_bytes: length - consumed,
        }
    }

    fn from_vec(bytes: &Vec<u8>) -> Self {
        Self::new(bytes.capacity(), bytes.len(), 0)
    }
}

#[derive(Clone, Copy, Debug)]
enum Suite {
    Tls13(AeadAlgorithm),
    Tls12(u16),
}

impl Suite {
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
                let cipher = || suite.descriptor().record_cipher(&key, &iv, &[]).unwrap();
                writer.set_tls12_keys(cipher());
                reader.set_tls12_keys(cipher());
            }
        }
        (writer, reader)
    }

    fn source_derived_crypto_copies(self, read: bool) -> usize {
        // Model only for tag and (GCM only) explicit nonce Vec appends.
        // TLS 1.2 AEAD plaintext appends now have runtime test hooks.
        // GCM open_within's offset handling is inside the unobserved backend.
        match (self, read) {
            (Self::Tls12(0xcca9), false) => 16,
            (Self::Tls12(_), false) => 24,
            _ => 0,
        }
    }
}

struct Fixture {
    writer: RecordWriter,
    reader: RecordReader,
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
    opened: Vec<u8>,
    limit: usize,
}

impl Fixture {
    fn new(suite: Suite, size: usize) -> Self {
        let (writer, reader) = suite.pair();
        Self {
            writer,
            reader,
            plaintext: vec![0x31; size],
            ciphertext: Vec::with_capacity(size + 64),
            opened: Vec::with_capacity(size + 32),
            limit: size + 64,
        }
    }

    fn seal(&mut self, reusable: bool) {
        self.ciphertext.clear();
        if reusable {
            let progress =
                self.writer
                    .write_into(23, &self.plaintext, &mut self.ciphertext, self.limit);
            assert!(matches!(progress.stop, WriteStop::Complete));
            assert_eq!(progress.accepted_plaintext, self.plaintext.len());
        } else {
            self.ciphertext = self.writer.write_record(23, &self.plaintext).unwrap();
        }
    }

    fn open(&mut self, reusable: bool) {
        assert_eq!(
            self.reader.feed_bounded(&self.ciphertext, self.limit),
            self.ciphertext.len()
        );
        if reusable {
            assert_eq!(
                self.reader.next_record_into(&mut self.opened).unwrap(),
                Some(23)
            );
        } else {
            self.opened = self.reader.next_record().unwrap().unwrap().payload;
        }
        assert_eq!(self.opened, self.plaintext);
    }

    fn retained(&self) -> serde_json::Value {
        let input = self.reader.measurement_snapshot();
        let coalesced = self.writer.measurement_snapshot();
        serde_json::json!({
            "record_input": input,
            "legacy_coalesced_output": coalesced,
            "caller_ciphertext": BufferSnapshot::from_vec(&self.ciphertext),
            "caller_opened": BufferSnapshot::from_vec(&self.opened),
            "retained_io_capacity_bytes": input.retained_capacity_bytes + coalesced.retained_capacity_bytes
                + self.ciphertext.capacity() + self.opened.capacity(),
            "scope": "Vec capacities of record I/O buffers; excludes plaintext fixture, crypto state, allocator overhead and RSS",
            "retained_heap_bytes": null,
        })
    }
}

#[test]
fn explicit_copy_counts_include_feed_and_open_even_with_reused_buffers() {
    let mut fixture = Fixture::new(Suite::Tls13(AeadAlgorithm::Aes128Gcm), 1024);
    let (_, sealing) = observe(|| fixture.seal(true));
    assert_eq!(sealing.bytes[CopySite::PlaintextSeal as usize], 1024);
    assert_eq!(sealing.bytes[CopySite::RecordHeader as usize], 5);
    assert_eq!(sealing.bytes[CopySite::AuthTag as usize], 16);
    let (_, opening) = observe(|| fixture.open(true));
    assert_eq!(opening.bytes[CopySite::InputFeed as usize], 1024 + 22);
    assert_eq!(opening.bytes[CopySite::CiphertextOpen as usize], 1024 + 17);
    assert_eq!(opening.bytes[CopySite::InputCompact as usize], 0);
}

#[test]
fn cursor_compaction_moves_only_pending_output_bytes() {
    let mut buffer = RecordBuffer::new(128);
    buffer.append(&[1; 64]);
    let before = buffer.measurement_snapshot();
    let (_, consume) = observe(|| buffer.consume(8));
    assert_eq!(consume.bytes, [0; 8]);
    let (_, append) = observe(|| buffer.append(&[2]));
    assert_eq!(append.bytes[CopySite::OutputCompact as usize], 0);
    buffer.consume(32);
    let (_, compact) = observe(|| buffer.append(&[3; 8]));
    assert_eq!(compact.bytes[CopySite::OutputCompact as usize], 25);
    assert_eq!(compact.bytes[CopySite::OutputAppend as usize], 8);
    buffer.consume(1);
    let (_, explicit) = observe(|| {
        let _ = buffer.output_storage();
    });
    assert_eq!(explicit.bytes[CopySite::OutputCompact as usize], 32);
    let before_clear = buffer.measurement_snapshot();
    assert!(before_clear.retained_capacity_bytes >= before.retained_capacity_bytes);
    let (_, cleared) = observe(|| buffer.clear());
    assert_eq!(cleared.bytes, [0; 8]);
    assert_eq!(
        buffer.measurement_snapshot().retained_capacity_bytes,
        before_clear.retained_capacity_bytes
    );
}

fn reader_compaction(consumed: usize, records_in_budget: usize) -> serde_json::Value {
    let (mut writer, mut reader) = Suite::Tls13(AeadAlgorithm::Aes128Gcm).pair();
    let frames: Vec<_> = (0..4)
        .map(|_| writer.write_record(23, &[7; 100]).unwrap())
        .collect();
    let wire_length = frames[0].len();
    let limit = records_in_budget * wire_length;
    let input = frames[..3].concat();
    assert_eq!(reader.feed_bounded(&input, limit), input.len());
    let mut opened = Vec::with_capacity(128);
    for _ in 0..consumed {
        reader.next_record_into(&mut opened).unwrap().unwrap();
    }
    let before = reader.measurement_snapshot();
    let (_, counts) = observe(|| assert_eq!(reader.feed_bounded(&frames[3], limit), wire_length));
    assert_eq!(
        counts.bytes[CopySite::InputCompact as usize],
        ((3 - consumed) * wire_length) as u64
    );
    assert_eq!(
        counts.bytes[CopySite::InputFeed as usize],
        wire_length as u64
    );
    let after_compaction = reader.measurement_snapshot();
    while reader.next_record_into(&mut opened).unwrap().is_some() {
        assert_eq!(opened, [7; 100]);
    }
    let drained = reader.measurement_snapshot();
    assert_eq!(drained.pending_bytes, 0);
    assert_eq!(
        drained.retained_capacity_bytes,
        before.retained_capacity_bytes
    );
    serde_json::json!({ "input_limit": limit, "before": before, "after_compaction": after_compaction,
        "after_drain": drained, "copies": counts.json() })
}

#[test]
fn reader_cursor_compacts_for_half_consumed_or_bounded_growth() {
    let forced = reader_compaction(1, 3);
    let half = reader_compaction(2, 4);
    assert_eq!(
        forced["copies"]["sites"]["input_cursor_compaction"]["bytes"]
            .as_u64()
            .unwrap(),
        2 * half["copies"]["sites"]["input_cursor_compaction"]["bytes"]
            .as_u64()
            .unwrap()
    );
}

#[test]
fn large_then_small_records_retain_capacity_after_drain() {
    let mut fixture = Fixture::new(Suite::Tls13(AeadAlgorithm::Aes128Gcm), 16384);
    fixture.seal(true);
    fixture.open(true);
    let input_capacity = fixture
        .reader
        .measurement_snapshot()
        .retained_capacity_bytes;
    let ciphertext_capacity = fixture.ciphertext.capacity();
    let open_capacity = fixture.opened.capacity();
    fixture.plaintext.resize(1, 0x31);
    fixture.seal(true);
    fixture.open(true);
    fixture.ciphertext.clear();
    fixture.opened.clear();
    assert_eq!(
        fixture
            .reader
            .measurement_snapshot()
            .retained_capacity_bytes,
        input_capacity
    );
    assert_eq!(fixture.ciphertext.capacity(), ciphertext_capacity);
    assert_eq!(fixture.opened.capacity(), open_capacity);
    assert_eq!(fixture.reader.buffered_len(), 0);
}

#[test]
fn bounded_growth_output_cursor_does_not_allocate_past_pending_budget() {
    let limit = 256 * 1024;
    let mut queue = RecordBuffer::new(limit);
    queue.append(&vec![0; 192 * 1024]);
    queue.consume(64 * 1024);
    assert_eq!(queue.append(&vec![1; 96 * 1024]), 96 * 1024);
    assert!(queue.measurement_snapshot().retained_capacity_bytes <= limit);
    assert_eq!(queue.len(), 224 * 1024);
}

#[test]
fn bounded_growth_record_sealing_does_not_allocate_past_output_budget() {
    let (mut writer, _) = Suite::Tls13(AeadAlgorithm::Aes128Gcm).pair();
    let limit = 256 * 1024;
    let mut output = vec![0; 192 * 1024];
    let progress = writer.write_into(23, &vec![7; 128 * 1024], &mut output, limit);
    assert!(matches!(progress.stop, WriteStop::NeedOutputCapacity));
    assert!(progress.accepted_plaintext != 0);
    assert!(output.len() <= limit);
    assert!(output.capacity() <= limit);
}

#[test]
fn bounded_growth_record_input_does_not_allocate_past_feed_budget() {
    let mut reader = RecordReader::new();
    let limit = 24 * 1024;
    assert_eq!(reader.feed_bounded(&vec![0; 16 * 1024], limit), 16 * 1024);
    assert_eq!(reader.feed_bounded(&vec![1; 16 * 1024], limit), 8 * 1024);
    assert_eq!(reader.buffered_len(), limit);
    assert!(reader.measurement_snapshot().retained_capacity_bytes <= limit);
}

#[test]
fn bounded_growth_preserves_larger_caller_allocations() {
    let (mut writer, mut reader) = Suite::Tls13(AeadAlgorithm::Aes128Gcm).pair();
    let mut output = Vec::with_capacity(64 * 1024);
    let before = output.capacity();
    let progress = writer.write_into(23, b"small", &mut output, 1024);
    assert!(matches!(progress.stop, WriteStop::Complete));
    assert_eq!(output.capacity(), before);
    let input_capacity = reader.measurement_snapshot().retained_capacity_bytes;
    assert_eq!(reader.feed_bounded(&output, 1024), output.len());
    assert_eq!(reader.next_record().unwrap().unwrap().payload, b"small");
    assert_eq!(
        reader.measurement_snapshot().retained_capacity_bytes,
        input_capacity
    );
}

#[test]
fn bounded_growth_remains_geometric_for_small_appends() {
    let mut queue = RecordBuffer::new(4096);
    let mut capacity = 0;
    let mut growths = 0;
    for _ in 0..4096 {
        assert_eq!(queue.append(&[7]), 1);
        let next = queue.measurement_snapshot().retained_capacity_bytes;
        if next != capacity {
            growths += 1;
            capacity = next;
        }
    }
    assert!(growths <= 13, "small writes caused {growths} allocations");
    assert_eq!(queue.len(), 4096);
    assert!(capacity <= 4096);
}

#[test]
fn amortized_output_tail_preserves_physical_capacity_and_linear_movement() {
    let (mut writer, mut peer) = Suite::Tls13(AeadAlgorithm::Aes128Gcm).pair();
    let mut queue = RecordBuffer::new(1024);
    let mut expected = Vec::new();
    loop {
        let (output, limit) = queue.application_output_storage();
        let result = writer.write_into(23, &[7], output, limit);
        if result.accepted_plaintext == 0 {
            break;
        }
        expected.push(7);
    }
    let capacity = queue.measurement_snapshot().retained_capacity_bytes;
    let mut wire = Vec::new();
    let mut copies = Copies::default();
    for _ in 0..4096 {
        wire.push(queue.as_slice()[0]);
        queue.consume(1);
        let (result, observed) = observe(|| {
            let (output, limit) = queue.application_output_storage();
            writer.write_into(23, &[8], output, limit)
        });
        expected.extend(std::iter::repeat_n(8, result.accepted_plaintext));
        copies.add(observed);
        let snapshot = queue.measurement_snapshot();
        assert!(snapshot.storage_len_bytes <= 1024);
        assert!(snapshot.retained_capacity_bytes <= 1024);
        assert_eq!(snapshot.retained_capacity_bytes, capacity);
        assert!(copies.bytes[CopySite::OutputCompact as usize] <= wire.len() as u64);
    }
    wire.extend_from_slice(queue.as_slice());
    peer.feed(&wire);
    let mut plaintext = Vec::new();
    while let Some(record) = peer.next_record().unwrap() {
        plaintext.extend_from_slice(&record.payload);
    }
    assert_eq!(plaintext, expected);
}

#[test]
#[ignore = "Structural copy/capacity evidence; no CPU timings, run with --nocapture"]
fn record_copy_and_retained_capacity_matrix() {
    println!();
    let suites = AEAD_SUITES;
    let iterations = 64;
    let mut rows = 0;
    for suite in suites {
        for size in [1, 64, 1024, 16384] {
            for reusable in [false, true] {
                for read in [false, true] {
                    let mut fixture = Fixture::new(suite, size);
                    for _ in 0..4 {
                        fixture.seal(reusable);
                        fixture.open(reusable);
                    }
                    let mut counts = Copies::default();
                    for _ in 0..iterations {
                        if read {
                            fixture.seal(true);
                        }
                        let (_, observed) = observe(|| {
                            if read {
                                fixture.open(reusable)
                            } else {
                                fixture.seal(reusable)
                            }
                        });
                        counts.add(observed);
                    }
                    println!(
                        "{}",
                        serde_json::json!({
                            "kind": "record_copy_capacity", "suite": format!("{suite:?}"),
                            "payload_bytes": size, "operation": if read { "read" } else { "write" },
                            "path": if reusable { "reusable" } else { "legacy" }, "iterations": iterations,
                            "copies": counts.json(), "retained": fixture.retained(),
                            "source_derived_crypto_buffer_copy_bytes": suite.source_derived_crypto_copies(read) * iterations,
                            "source_derived_scope": "non-instrumented model of TLS 1.2 explicit nonce and tag Vec appends; excludes separately instrumented plaintext; not a total or backend measurement",
                            "elapsed_ns": null,
                        })
                    );
                    rows += 1;
                }
            }
        }
    }
    assert_eq!(rows, 96);
    for suite in suites {
        let mut fixture = Fixture::new(suite, 16384);
        fixture.seal(true);
        fixture.open(true);
        let large = fixture.retained();
        fixture.plaintext.resize(1, 0x31);
        let (_, copies) = observe(|| {
            fixture.seal(true);
            fixture.open(true);
        });
        let small = fixture.retained();
        fixture.ciphertext.clear();
        fixture.opened.clear();
        let drained = fixture.retained();
        assert_eq!(
            large["retained_io_capacity_bytes"],
            drained["retained_io_capacity_bytes"]
        );
        println!(
            "{}",
            serde_json::json!({ "kind": "record_retention_after_peak", "suite": format!("{suite:?}"),
            "large_payload_bytes": 16384, "small_payload_bytes": 1, "after_large": large,
            "after_small": small, "after_drain": drained, "small_record_copies": copies.json() })
        );
    }
    println!(
        "{}",
        serde_json::json!({"kind": "reader_cursor_capacity", "trigger": "bounded_growth", "sample": reader_compaction(1, 3)})
    );
    println!(
        "{}",
        serde_json::json!({"kind": "reader_cursor_capacity", "trigger": "half_consumed", "sample": reader_compaction(2, 4)})
    );

    let mut queue = RecordBuffer::new(256 * 1024);
    queue.append(&vec![0; 192 * 1024]);
    queue.consume(64 * 1024);
    let before = queue.measurement_snapshot();
    let (_, copies) = observe(|| queue.append(&vec![1; 96 * 1024]));
    let compacted = queue.measurement_snapshot();
    queue.consume(queue.len());
    println!(
        "{}",
        serde_json::json!({"kind": "output_cursor_capacity", "pending_limit": 256 * 1024,
        "before": before, "compacted": compacted, "drained": queue.measurement_snapshot(), "copies": copies.json()})
    );
}
