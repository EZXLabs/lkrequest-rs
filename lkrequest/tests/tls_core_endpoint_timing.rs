//! Current-only compiled-plan and continuous-owner workload timing.
//! The shared mechanics are baseline-compatible; this endpoint is not.
use std::sync::Arc;

use lktls::config::{CompileOptions, CompiledClientConfig, ConnectionInputs, Transport};
use lktls::connection::{ClientConnection, HandshakeProgress, ReadProgress};
use lktls::session_store::InMemorySessionStore;

#[path = "tls_support/timing.rs"]
mod timing;
use timing::{
    concurrent, finish_burst, peer_echo, peer_input, peer_output, report, start, PathMetadata,
    Peer, Sample, Segments, Settings, CALL_BYTES, TRANSFER_BYTES,
};

const PATH: PathMetadata = PathMetadata {
    kind: "current_only_endpoint_workload_timing",
    name: "ClientConnection_from_compiled_continuous_owner",
    continuous_owner: true,
    compiled_plan_reused: true,
};

struct Job {
    config: Arc<CompiledClientConfig>,
    inputs: ConnectionInputs,
    server: rustls::ServerConnection,
}

struct Established {
    client: ClientConnection,
    server: rustls::ServerConnection,
}

fn job(peer: &Peer, config: &Arc<CompiledClientConfig>, resumed: bool) -> Job {
    let mut inputs = ConnectionInputs::new("localhost", 443);
    inputs.session_store = Some(Arc::new(InMemorySessionStore::new()));
    if resumed {
        let seed = drive(
            Job {
                config: config.clone(),
                inputs: inputs.clone(),
                server: peer.server(),
            },
            &mut Segments::new(false),
            &mut Segments::new(false),
        );
        verify(&seed, peer.version, false);
    }
    Job {
        config: config.clone(),
        inputs,
        server: peer.server(),
    }
}

fn drive(job: Job, client_time: &mut Segments, peer_time: &mut Segments) -> Established {
    let mut client =
        client_time.measure(|| ClientConnection::from_compiled(job.config, job.inputs).unwrap());
    let mut server = job.server;
    for _ in 0..32 {
        match client_time.measure(|| client.progress_handshake().unwrap()) {
            HandshakeProgress::NeedOutput => {
                let count = client.output().len();
                peer_time.measure(|| peer_input(&mut server, client.output()));
                client_time.measure(|| client.consume_output(count));
            }
            HandshakeProgress::NeedInput => {
                let bytes = peer_time.measure(|| peer_output(&mut server));
                assert!(!bytes.is_empty());
                assert_eq!(
                    client_time.measure(|| client.feed_bounded(&bytes)),
                    bytes.len()
                );
            }
            HandshakeProgress::Complete => {
                let tickets = peer_time.measure(|| peer_output(&mut server));
                assert_eq!(
                    client_time.measure(|| client.feed_bounded(&tickets)),
                    tickets.len()
                );
                assert_eq!(
                    client_time.measure(|| client.process_read().unwrap()),
                    ReadProgress::NeedInput
                );
                return Established { client, server };
            }
        }
    }
    panic!("endpoint handshake failed to finish");
}

fn verify(connection: &Established, version: u16, resumed: bool) {
    assert!(!connection.server.is_handshaking());
    assert_eq!(connection.client.negotiated_version(), Some(version));
    assert!(connection.client.negotiated_cipher_suite().is_some());
    assert_eq!(
        connection.server.handshake_kind(),
        Some(if resumed {
            rustls::HandshakeKind::Resumed
        } else {
            rustls::HandshakeKind::Full
        })
    );
}

fn burst(
    peer: &Peer,
    config: &Arc<CompiledClientConfig>,
    resumed: bool,
    workers: usize,
    batch: usize,
    timing: bool,
) -> Sample {
    let jobs = (0..workers)
        .map(|_| (0..batch).map(|_| job(peer, config, resumed)).collect())
        .collect();
    let (wall, reports) = concurrent(jobs, timing, drive);
    finish_burst(wall, reports, timing, workers * batch, |connection| {
        verify(connection, peer.version, resumed);
        connection.client.negotiated_cipher_suite().unwrap()
    })
}

fn transfer(connection: &mut Established, payload: &[u8], timing: bool) -> Sample {
    let mut seen_by_peer = vec![0; payload.len()];
    let mut seen_by_client = vec![0; payload.len()];
    let mut client = Segments::new(timing);
    let mut peer = Segments::new(timing);
    let mut received = 0;
    let clock = start(timing);
    for (index, chunk) in payload.chunks(CALL_BYTES).enumerate() {
        assert_eq!(
            client.measure(|| connection.client.write_application(chunk).unwrap()),
            chunk.len()
        );
        let count = connection.client.output().len();
        let incoming = peer.measure(|| {
            let offset = index * CALL_BYTES;
            peer_echo(
                &mut connection.server,
                connection.client.output(),
                &mut seen_by_peer[offset..offset + chunk.len()],
            )
        });
        client.measure(|| connection.client.consume_output(count));
        for fragment in incoming.chunks(16384) {
            assert_eq!(
                client.measure(|| connection.client.feed_bounded(fragment)),
                fragment.len()
            );
            loop {
                match client.measure(|| connection.client.process_read().unwrap()) {
                    ReadProgress::NeedInput => break,
                    ReadProgress::Plaintext => {
                        let plaintext = connection.client.plaintext();
                        let count = plaintext.len();
                        assert!(count > 0);
                        seen_by_client[received..received + count].copy_from_slice(plaintext);
                        received += count;
                        client.measure(|| connection.client.consume_plaintext(count));
                    }
                    ReadProgress::Yield => {}
                    other => panic!("unexpected transfer progress: {other:?}"),
                }
            }
        }
    }
    let wall_ns = clock.map(|clock| clock.elapsed().wall_ns);
    assert_eq!(received, payload.len());
    assert_eq!(seen_by_peer, payload);
    assert_eq!(seen_by_client, payload);
    assert!(connection.client.output().is_empty());
    assert!(connection.client.plaintext().is_empty());
    Sample {
        wall_ns,
        client,
        peer,
        verified_connections: 1,
        plaintext_bytes_per_direction: payload.len(),
        negotiated_cipher_suites: vec![connection.client.negotiated_cipher_suite().unwrap()],
    }
}

#[test]
#[ignore = "Current-only endpoint timing; smoke by default, explicit idle release opt-in for clocks"]
fn current_endpoint_workload_samples() {
    let settings = Settings::from_env();
    let payload: Vec<_> = (0..TRANSFER_BYTES).map(|i| (i % 251) as u8).collect();
    let mut rows = 0;
    for tls12 in [false, true] {
        let peer = Peer::new(tls12);
        let config = CompiledClientConfig::compile(
            Arc::new(peer.client.profile.clone()),
            Transport::Tcp,
            CompileOptions {
                verification: peer.client.verification_policy,
                custom_ca_anchors: peer.client.custom_ca_anchors.clone(),
                ..CompileOptions::compatibility()
            },
        )
        .unwrap();
        for resumed in [false, true] {
            for workers in [1, 8, 32] {
                burst(&peer, &config, resumed, workers, 1, false);
                let samples = (0..settings.samples)
                    .map(|_| {
                        burst(
                            &peer,
                            &config,
                            resumed,
                            workers,
                            settings.per_worker,
                            settings.timing,
                        )
                    })
                    .collect();
                report(
                    &settings,
                    peer.version,
                    Some(resumed),
                    workers,
                    samples,
                    PATH,
                );
                rows += 1;
            }
        }
        let samples = (0..settings.samples)
            .map(|_| {
                let mut connection = drive(
                    job(&peer, &config, false),
                    &mut Segments::new(false),
                    &mut Segments::new(false),
                );
                verify(&connection, peer.version, false);
                transfer(&mut connection, &payload[..CALL_BYTES], false);
                transfer(&mut connection, &payload, settings.timing)
            })
            .collect();
        report(&settings, peer.version, None, 1, samples, PATH);
        rows += 1;
    }
    assert_eq!(rows, 14);
}
