//! Identical-source optional record timing for 70db578 and current candidates.
//! This binary intentionally has no counting allocator. Smoke never starts a
//! clock. See design/tls-core-record-timing.md for boundaries and release flags.

use std::hint::black_box;

use lktls::crypto::aead::{Aead, AeadAlgorithm};
use lktls::crypto::tls12_cipher::{
    CbcMacAlgorithm, Tls12CbcCipher, Tls12Chacha20Cipher, Tls12GcmCipher,
};
use lktls::record::{reader::RecordReader, writer::RecordWriter, Tls12RecordCipher};
use serde::Serialize;

#[path = "../../tools/tls_measure/clock.rs"]
mod clock;

#[derive(Clone, Copy)]
enum Suite {
    Tls13(AeadAlgorithm),
    Tls12Gcm(bool),
    Tls12Chacha20,
    Tls12Cbc(usize, CbcMacAlgorithm),
}

const SUITES: [Suite; 9] = [
    Suite::Tls13(AeadAlgorithm::Aes128Gcm),
    Suite::Tls13(AeadAlgorithm::Aes256Gcm),
    Suite::Tls13(AeadAlgorithm::Chacha20Poly1305),
    Suite::Tls12Gcm(false),
    Suite::Tls12Gcm(true),
    Suite::Tls12Chacha20,
    Suite::Tls12Cbc(16, CbcMacAlgorithm::HmacSha1),
    Suite::Tls12Cbc(16, CbcMacAlgorithm::HmacSha256),
    Suite::Tls12Cbc(32, CbcMacAlgorithm::HmacSha384),
];

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
            _ => unreachable!(),
        }
    }

    fn install(self, writer: &mut RecordWriter, reader: &mut RecordReader) {
        // Fixed stack material keeps fixture heap allocation outside key setup.
        // Allocations performed by the key constructors remain inside setup.
        const KEY: [u8; 32] = [0x42; 32];
        const IV: [u8; 16] = [0x24; 16];
        const MAC: [u8; 48] = [0x53; 48];
        if let Self::Tls13(algorithm) = self {
            writer.set_keys(Aead::new(algorithm, &KEY[..algorithm.key_len()], &IV[..12]).unwrap());
            reader.set_keys(Aead::new(algorithm, &KEY[..algorithm.key_len()], &IV[..12]).unwrap());
        } else {
            let cipher = || match self {
                Self::Tls12Gcm(aes256) => Tls12RecordCipher::Gcm(
                    Tls12GcmCipher::new(&KEY[..if aes256 { 32 } else { 16 }], &[0x24; 4], aes256)
                        .unwrap(),
                ),
                Self::Tls12Chacha20 => Tls12RecordCipher::Chacha20(
                    Tls12Chacha20Cipher::new(&KEY, &[0x24; 12]).unwrap(),
                ),
                Self::Tls12Cbc(length, mac) => Tls12RecordCipher::Cbc(Tls12CbcCipher::new(
                    &KEY[..length],
                    &MAC[..mac.mac_len()],
                    mac,
                )),
                Self::Tls13(_) => unreachable!(),
            };
            writer.set_tls12_keys(cipher());
            reader.set_tls12_keys(cipher());
        }
    }

    fn pair(self) -> (RecordWriter, RecordReader) {
        let mut writer = RecordWriter::new();
        let mut reader = RecordReader::new();
        self.install(&mut writer, &mut reader);
        (writer, reader)
    }
}

struct Settings {
    timing: bool,
    revision: String,
    samples: usize,
    batch: usize,
    warmup: usize,
}

fn positive_env(name: &str, default: usize) -> usize {
    let value = std::env::var(name)
        .map(|value| value.parse().unwrap())
        .unwrap_or(default);
    assert!(value > 0, "{name} must be positive");
    value
}

impl Settings {
    fn from_env() -> Self {
        let mode = std::env::var("TLS_RECORD_TIMING_MODE").unwrap_or_else(|_| "smoke".into());
        assert!(matches!(mode.as_str(), "smoke" | "measure"));
        let timing = mode == "measure";
        if timing {
            if cfg!(debug_assertions) {
                panic!("timing requires a release build");
            }
            assert_eq!(
                std::env::var("TLS_RECORD_MEASURE_IDLE").as_deref(),
                Ok("1"),
                "timing requires an explicitly idle host; use smoke while busy"
            );
        }
        let samples = if timing {
            positive_env("TLS_RECORD_TIMING_SAMPLES", 41)
        } else {
            2
        };
        assert!(
            !timing || samples >= 20,
            "timing requires at least 20 samples"
        );
        Self {
            timing,
            revision: std::env::var("TLS_RECORD_TIMING_REVISION")
                .expect("set TLS_RECORD_TIMING_REVISION to the exact source revision"),
            samples,
            batch: if timing {
                positive_env("TLS_RECORD_TIMING_BATCH", 128)
            } else {
                4
            },
            warmup: if timing {
                positive_env("TLS_RECORD_TIMING_WARMUP", 32)
            } else {
                2
            },
        }
    }

    fn start(&self) -> Option<clock::ClockStart> {
        if self.timing {
            Some(clock::ClockStart::start())
        } else {
            None
        }
    }
}

#[derive(Serialize)]
struct Sample {
    wall_ns: Option<u128>,
    thread_cpu_ns: Option<u64>,
}

impl Sample {
    fn finish(start: Option<clock::ClockStart>) -> Self {
        match start {
            Some(start) => {
                let elapsed = start.elapsed();
                Self {
                    wall_ns: Some(elapsed.wall_ns),
                    thread_cpu_ns: elapsed.thread_cpu_ns,
                }
            }
            None => Self {
                wall_ns: None,
                thread_cpu_ns: None,
            },
        }
    }
}

fn distribution(mut values: Vec<u128>, batch: usize) -> serde_json::Value {
    if values.is_empty() {
        return serde_json::Value::Null;
    }
    values.sort_unstable();
    let median = values[values.len() / 2];
    let p95 = values[(values.len() * 95).div_ceil(100) - 1];
    serde_json::json!({
        "available_samples": values.len(), "zero_samples": values.iter().filter(|value| **value == 0).count(),
        "batch_ns": { "min": values[0], "median_upper": median, "p95_nearest_rank": p95, "max": values[values.len() - 1] },
        "per_operation_ns": { "median_upper": median as f64 / batch as f64, "p95_nearest_rank": p95 as f64 / batch as f64 },
    })
}

#[test]
fn distribution_preserves_zero_samples_without_reading_clocks() {
    let summary = distribution(vec![30, 0, 10, 0], 2);
    assert_eq!(summary["available_samples"], 4);
    assert_eq!(summary["zero_samples"], 2);
    assert_eq!(summary["batch_ns"]["median_upper"], 10);
    assert_eq!(summary["batch_ns"]["p95_nearest_rank"], 30);
    assert_eq!(summary["per_operation_ns"]["median_upper"], 5.0);
    assert!(distribution(Vec::new(), 2).is_null());
}

fn report(
    settings: &Settings,
    suite: Suite,
    size: Option<usize>,
    stage: &str,
    samples: Vec<Sample>,
) {
    assert_eq!(samples.len(), settings.samples);
    let wall = distribution(
        samples.iter().filter_map(|sample| sample.wall_ns).collect(),
        settings.batch,
    );
    let cpu = distribution(
        samples
            .iter()
            .filter_map(|sample| sample.thread_cpu_ns.map(u128::from))
            .collect(),
        settings.batch,
    );
    println!(
        "{}",
        serde_json::json!({
            "kind": "legacy_record_timing", "revision": settings.revision, "suite": suite.name(),
            "payload_bytes": size, "stage": stage, "path": "legacy", "batch_operations": settings.batch,
            "warmup_operations": settings.warmup, "sample_count": settings.samples,
            "mode": if settings.timing { "measure" } else { "smoke" }, "timing_performed": settings.timing,
            "wall_clock": "std::time::Instant", "thread_cpu_clock": clock::THREAD_CPU_CLOCK,
            "wall": wall, "thread_cpu": cpu, "samples": samples,
            "cpu_resolution_note": "CPU accounting is quantized, especially GetThreadTimes; preserve zeros, which do not establish zero cost",
            "counting_allocator": false, "elapsed_clock_overhead_included": settings.timing,
            "architecture": std::env::consts::ARCH, "os": std::env::consts::OS,
            "debug_assertions": cfg!(debug_assertions), "copy_bytes": null, "allocations": null,
        })
    );
}

fn verify(reader: &mut RecordReader, ciphertext: &[u8], plaintext: &[u8]) {
    reader.feed(ciphertext);
    let record = reader.next_record().unwrap().unwrap();
    assert_eq!(record.content_type, 23);
    assert_eq!(record.payload, plaintext);
    assert_eq!(reader.buffered_len(), 0);
}

fn setup_samples(settings: &Settings, suite: Suite) -> Vec<Sample> {
    for _ in 0..settings.warmup {
        black_box(suite.pair());
    }
    (0..settings.samples)
        .map(|_| {
            let mut endpoints: Vec<_> = (0..settings.batch)
                .map(|_| (RecordWriter::new(), RecordReader::new()))
                .collect();
            let start = settings.start();
            for (writer, reader) in &mut endpoints {
                suite.install(black_box(writer), black_box(reader));
            }
            let elapsed = Sample::finish(start);
            for (writer, reader) in &mut endpoints {
                let ciphertext = writer.write_record(23, b"setup check").unwrap();
                verify(reader, &ciphertext, b"setup check");
            }
            elapsed
        })
        .collect()
}

fn steady_samples(settings: &Settings, suite: Suite, size: usize, read: bool) -> Vec<Sample> {
    let plaintext = vec![0x31; size];
    (0..settings.samples)
        .map(|_| {
            let (mut writer, mut reader) = suite.pair();
            for _ in 0..settings.warmup {
                let ciphertext = writer.write_record(23, &plaintext).unwrap();
                verify(&mut reader, &ciphertext, &plaintext);
            }
            // Result slots are allocated before timing. The returned payload/record
            // allocations belong to the API and remain inside the timed interval.
            let mut results = Vec::with_capacity(settings.batch);
            if read {
                let input: Vec<_> = (0..settings.batch)
                    .map(|_| writer.write_record(23, &plaintext).unwrap())
                    .collect();
                let start = settings.start();
                for ciphertext in &input {
                    reader.feed(black_box(ciphertext));
                    results.push(black_box(reader.next_record().unwrap().unwrap()));
                }
                let elapsed = Sample::finish(start);
                for record in &results {
                    assert_eq!(record.content_type, 23);
                    assert_eq!(record.payload, plaintext);
                }
                assert_eq!(reader.buffered_len(), 0);
                elapsed
            } else {
                let mut ciphertexts = Vec::with_capacity(settings.batch);
                let start = settings.start();
                for _ in 0..settings.batch {
                    ciphertexts.push(black_box(
                        writer.write_record(23, black_box(&plaintext)).unwrap(),
                    ));
                }
                let elapsed = Sample::finish(start);
                for ciphertext in &ciphertexts {
                    verify(&mut reader, ciphertext, &plaintext);
                }
                elapsed
            }
        })
        .collect()
}

#[test]
#[ignore = "Identical-source legacy timing; defaults to no-clock smoke, measure only on an idle host"]
fn legacy_record_timing_matrix() {
    let settings = Settings::from_env();
    println!();
    let mut rows = 0;
    for suite in SUITES {
        report(
            &settings,
            suite,
            None,
            "key_setup_pair",
            setup_samples(&settings, suite),
        );
        rows += 1;
        for size in [1, 1024, 16384] {
            for read in [false, true] {
                report(
                    &settings,
                    suite,
                    Some(size),
                    if read { "steady_read" } else { "steady_write" },
                    steady_samples(&settings, suite, size, read),
                );
                rows += 1;
            }
        }
    }
    assert_eq!(rows, 63);
}
