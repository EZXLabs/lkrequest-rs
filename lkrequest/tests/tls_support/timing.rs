//! Shared measurement mechanics and strict peer using only baseline public APIs.
use lktls::handshake::driver::HandshakeConfig;
use lktls::profile::{presets, types::TlsVersion};
use lktls::verify::policy::VerificationPolicy;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::Serialize;
use std::io::{Cursor, Read, Write};
use std::sync::{Arc, Barrier};
#[path = "../../../tools/tls_measure/clock.rs"]
mod clock;
pub const TRANSFER_BYTES: usize = 16 * 1024 * 1024;
pub const CALL_BYTES: usize = 64 * 1024;

pub struct Settings {
    pub timing: bool,
    pub revision: String,
    pub samples: usize,
    pub per_worker: usize,
}

fn positive_env(name: &str, default: usize) -> usize {
    let value = std::env::var(name)
        .map(|value| value.parse().unwrap())
        .unwrap_or(default);
    assert!(value > 0, "{name} must be positive");
    value
}

impl Settings {
    pub fn from_env() -> Self {
        let mode = std::env::var("TLS_CLIENT_TIMING_MODE").unwrap_or_else(|_| "smoke".into());
        assert!(matches!(mode.as_str(), "smoke" | "measure"));
        let timing = mode == "measure";
        if timing {
            if cfg!(debug_assertions) {
                panic!("timing requires release");
            }
            assert_eq!(
                std::env::var("TLS_CLIENT_MEASURE_IDLE").as_deref(),
                Ok("1"),
                "use smoke while the machine is busy"
            );
        }
        let samples = if timing {
            positive_env("TLS_CLIENT_TIMING_SAMPLES", 21)
        } else {
            1
        };
        assert!(!timing || samples >= 20);
        Self {
            timing,
            revision: std::env::var("TLS_CLIENT_TIMING_REVISION")
                .expect("set TLS_CLIENT_TIMING_REVISION to the tested source revision"),
            samples,
            per_worker: if timing {
                positive_env("TLS_CLIENT_TIMING_BATCH", 8)
            } else {
                1
            },
        }
    }
}

pub fn start(timing: bool) -> Option<clock::ClockStart> {
    timing.then(clock::ClockStart::start)
}

#[derive(Serialize)]
pub struct Segments {
    pub wall_ns: Option<u128>,
    pub cpu_ns: Option<u64>,
    pub calls: usize,
}

impl Segments {
    pub fn new(timing: bool) -> Self {
        Self {
            wall_ns: timing.then_some(0),
            cpu_ns: timing.then_some(0),
            calls: 0,
        }
    }

    pub fn measure<T>(&mut self, operation: impl FnOnce() -> T) -> T {
        let clock = start(self.wall_ns.is_some());
        let result = operation();
        if let Some(clock) = clock {
            let elapsed = clock.elapsed();
            self.wall_ns = self
                .wall_ns
                .and_then(|sum| sum.checked_add(elapsed.wall_ns));
            self.cpu_ns = self
                .cpu_ns
                .zip(elapsed.thread_cpu_ns)
                .and_then(|(sum, elapsed)| sum.checked_add(elapsed));
        }
        self.calls += 1;
        result
    }

    pub fn merge(&mut self, other: &Self) {
        self.wall_ns = self
            .wall_ns
            .zip(other.wall_ns)
            .and_then(|(left, right)| left.checked_add(right));
        self.cpu_ns = self
            .cpu_ns
            .zip(other.cpu_ns)
            .and_then(|(left, right)| left.checked_add(right));
        self.calls += other.calls;
    }
}

#[derive(Serialize)]
pub struct Sample {
    pub wall_ns: Option<u128>,
    pub client: Segments,
    pub peer: Segments,
    pub verified_connections: usize,
    pub plaintext_bytes_per_direction: usize,
    pub negotiated_cipher_suites: Vec<u16>,
}

pub struct Peer {
    server: Arc<rustls::ServerConfig>,
    pub client: HandshakeConfig,
    pub version: u16,
}

impl Peer {
    pub fn new(tls12: bool) -> Self {
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
        Self {
            server: Arc::new(server),
            client: HandshakeConfig {
                profile,
                hostname: "localhost".into(),
                port: 443,
                verification_policy: VerificationPolicy::Strict,
                custom_ca_anchors: Some(Arc::new(vec![anchor])),
                session_store: None,
                alps_payload: None,
                ech_config_list: None,
                keylog_callback: None,
                client_hello_callback: None,
                trust_anchor_observer: None,
            },
            version: if tls12 { 0x0303 } else { 0x0304 },
        }
    }

    pub fn server(&self) -> rustls::ServerConnection {
        let mut server = rustls::ServerConnection::new(self.server.clone()).unwrap();
        server.set_buffer_limit(None);
        server
    }
}

pub fn peer_output(server: &mut rustls::ServerConnection) -> Vec<u8> {
    let mut output = Vec::new();
    while server.wants_write() {
        assert!(server.write_tls(&mut output).unwrap() > 0);
    }
    output
}

pub fn peer_input(server: &mut rustls::ServerConnection, bytes: &[u8]) {
    let mut input = Cursor::new(bytes);
    while input.position() < bytes.len() as u64 {
        assert!(server.read_tls(&mut input).unwrap() > 0);
        server.process_new_packets().unwrap();
    }
}

pub fn peer_echo(
    server: &mut rustls::ServerConnection,
    bytes: &[u8],
    echoed: &mut [u8],
) -> Vec<u8> {
    let mut received = 0;
    for fragment in bytes.chunks(16384) {
        peer_input(server, fragment);
        while received < echoed.len() {
            match server.reader().read(&mut echoed[received..]) {
                Ok(0) => panic!("peer closed during transfer"),
                Ok(count) => received += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("peer read failed: {error}"),
            }
        }
    }
    assert_eq!(received, echoed.len());
    server.writer().write_all(echoed).unwrap();
    peer_output(server)
}

pub struct WorkerResult<T> {
    pub client: Segments,
    pub peer: Segments,
    pub connections: Vec<T>,
}

pub fn concurrent<J: Send, T: Send>(
    jobs: Vec<Vec<J>>,
    timing: bool,
    drive: impl Fn(J, &mut Segments, &mut Segments) -> T + Sync,
) -> (Option<u128>, Vec<WorkerResult<T>>) {
    let workers = jobs.len();
    assert!(workers > 0);
    let ready = Barrier::new(workers + 1);
    let go = Barrier::new(workers + 1);
    let done = Barrier::new(workers + 1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = jobs
            .into_iter()
            .map(|jobs| {
                let (ready, go, done, drive) = (&ready, &go, &done, &drive);
                scope.spawn(move || {
                    let mut client = Segments::new(timing);
                    let mut peer = Segments::new(timing);
                    let mut connections = Vec::with_capacity(jobs.len());
                    ready.wait();
                    go.wait();
                    // A failed worker must still release the controller's final gate.
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        for job in jobs {
                            connections.push(drive(job, &mut client, &mut peer));
                        }
                    }));
                    done.wait();
                    outcome.unwrap();
                    WorkerResult {
                        client,
                        peer,
                        connections,
                    }
                })
            })
            .collect();
        ready.wait();
        let clock = start(timing);
        go.wait();
        done.wait();
        let wall_ns = clock.map(|clock| clock.elapsed().wall_ns);
        let reports = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        (wall_ns, reports)
    })
}

pub fn finish_burst<T>(
    wall_ns: Option<u128>,
    reports: Vec<WorkerResult<T>>,
    timing: bool,
    expected: usize,
    verify: impl Fn(&T) -> u16,
) -> Sample {
    let mut sample = Sample {
        wall_ns,
        client: Segments::new(timing),
        peer: Segments::new(timing),
        verified_connections: 0,
        plaintext_bytes_per_direction: 0,
        negotiated_cipher_suites: Vec::new(),
    };
    for report in reports {
        sample.client.merge(&report.client);
        sample.peer.merge(&report.peer);
        for connection in report.connections {
            let suite = verify(&connection);
            if !sample.negotiated_cipher_suites.contains(&suite) {
                sample.negotiated_cipher_suites.push(suite);
            }
            sample.verified_connections += 1;
        }
    }
    assert_eq!(sample.verified_connections, expected);
    sample
}

fn distribution(mut values: Vec<u128>) -> serde_json::Value {
    if values.is_empty() {
        return serde_json::Value::Null;
    }
    values.sort_unstable();
    serde_json::json!({
        "available_samples": values.len(), "zero_samples": values.iter().filter(|v| **v == 0).count(),
        "min_ns": values[0], "median_upper_ns": values[values.len() / 2],
        "p95_nearest_rank_ns": values[(values.len() * 95).div_ceil(100) - 1],
        "max_ns": values[values.len() - 1],
    })
}

#[test]
fn segment_aggregation_preserves_unavailable_and_quantized_zero_cpu() {
    let mut sum = Segments::new(true);
    sum.merge(&Segments {
        wall_ns: Some(19),
        cpu_ns: Some(0),
        calls: 2,
    });
    sum.merge(&Segments {
        wall_ns: Some(23),
        cpu_ns: Some(7),
        calls: 3,
    });
    assert_eq!(sum.wall_ns, Some(42));
    assert_eq!(sum.cpu_ns, Some(7));
    assert_eq!(sum.calls, 5);
    sum.merge(&Segments {
        wall_ns: Some(11),
        cpu_ns: None,
        calls: 1,
    });
    assert_eq!(sum.wall_ns, Some(53));
    assert_eq!(sum.cpu_ns, None);
    let summary = distribution(vec![30, 0, 10, 0]);
    assert_eq!(summary["zero_samples"], 2);
    assert_eq!(summary["median_upper_ns"], 10);
    assert_eq!(summary["p95_nearest_rank_ns"], 30);
    assert!(distribution(Vec::new()).is_null());
}

pub struct PathMetadata {
    pub kind: &'static str,
    pub name: &'static str,
    pub continuous_owner: bool,
    pub compiled_plan_reused: bool,
}

pub fn report(
    settings: &Settings,
    version: u16,
    resumed: Option<bool>,
    workers: usize,
    samples: Vec<Sample>,
    path: PathMetadata,
) {
    assert_eq!(samples.len(), settings.samples);
    if !settings.timing {
        assert!(samples.iter().all(|s| s.wall_ns.is_none()
            && s.client.wall_ns.is_none()
            && s.client.cpu_ns.is_none()
            && s.peer.wall_ns.is_none()
            && s.peer.cpu_ns.is_none()));
    }
    let wall = distribution(samples.iter().filter_map(|s| s.wall_ns).collect());
    let client_cpu = distribution(
        samples
            .iter()
            .filter_map(|s| s.client.cpu_ns.map(u128::from))
            .collect(),
    );
    let peer_cpu = distribution(
        samples
            .iter()
            .filter_map(|s| s.peer.cpu_ns.map(u128::from))
            .collect(),
    );
    println!(
        "{}",
        serde_json::json!({
            "kind": path.kind, "revision": settings.revision,
            "version": if version == 0x0303 { "TLS1.2" } else { "TLS1.3" },
            "stage": if resumed.is_some() { "handshake_burst" } else { "sustained_records" },
            "resumed": resumed, "workers": workers,
            "handshakes_per_worker": resumed.map(|_| settings.per_worker),
            "record_call_bytes": if resumed.is_none() { Some(CALL_BYTES) } else { None },
            "path": path.name,
            "continuous_owner_path": path.continuous_owner, "compiled_plan_reused": path.compiled_plan_reused, "shared_cache_contention": false,
            "strict_peer_authentication": true, "preparation_profile_clone_and_peer_setup_included": false,
            "client_construction_and_ticket_processing_included": resumed.is_some(),
            "client_cpu": client_cpu, "peer_cpu": peer_cpu, "whole_workload_wall": wall,
            "samples": samples, "sample_count": settings.samples,
            "warmup_handshakes_per_worker": resumed.map(|_| 1),
            "warmup_transfer_bytes_per_sample": if resumed.is_none() { Some(CALL_BYTES) } else { None },
            "mode": if settings.timing { "measure" } else { "smoke" }, "timing_performed": settings.timing,
            "wall_clock": "std::time::Instant", "thread_cpu_clock": clock::THREAD_CPU_CLOCK,
            "cpu_scope": "sum_of_separate_client_and_peer_segments_on_each_worker_thread",
            "cpu_note": "scheduled CPU is quantized; preserve zeros, not evidence of zero cost",
            "clock_overhead_included": settings.timing, "counting_allocator": false,
            "allocations": null, "copy_bytes": null, "architecture": std::env::consts::ARCH,
            "os": std::env::consts::OS, "debug_assertions": cfg!(debug_assertions),
        })
    );
}
