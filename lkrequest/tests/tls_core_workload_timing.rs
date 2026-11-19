//! Identical-source legacy client timing for 70db578 and current candidates.
//! No counting allocator. Smoke never samples a measurement clock.
//! This does not measure the current continuous-owner endpoint path.
use lktls::handshake::driver::{
    HandshakeConfig, HandshakeDriver, HandshakeOutput, HandshakeResult,
};
use lktls::session_store::InMemorySessionStore;
use std::sync::Arc;
#[path = "tls_support/timing.rs"]
mod timing;
use timing::{
    concurrent, finish_burst, peer_echo, peer_input, peer_output, report, start, PathMetadata,
    Peer, Sample, Segments, Settings, CALL_BYTES, TRANSFER_BYTES,
};
const PATH: PathMetadata = PathMetadata {
    kind: "legacy_client_workload_timing",
    name: "legacy_HandshakeDriver_and_returned_RecordReader_RecordWriter",
    continuous_owner: false,
    compiled_plan_reused: false,
};

impl Peer {
    fn job(&self, resumed: bool) -> Job {
        let store = Arc::new(InMemorySessionStore::new());
        let mut config = self.client.clone();
        config.session_store = Some(store);
        if resumed {
            let seed = drive(
                Job {
                    config: config.clone(),
                    server: self.server(),
                },
                &mut Segments::new(false),
                &mut Segments::new(false),
            );
            verify(&seed, self.version, false);
        }
        Job {
            config,
            server: self.server(),
        }
    }
}

struct Job {
    config: HandshakeConfig,
    server: rustls::ServerConnection,
}

struct Established {
    client: Box<HandshakeResult>,
    server: rustls::ServerConnection,
}

fn process_tickets(result: &mut HandshakeResult, bytes: &[u8]) {
    result.reader.feed(bytes);
    let mut messages = Vec::new();
    while let Some(record) = result.reader.next_record().unwrap() {
        assert_eq!(record.content_type, 22);
        messages.extend_from_slice(&record.payload);
        assert!(messages.len() <= 65536);
    }
    let mut position = 0;
    while position < messages.len() {
        assert!(messages.len() - position >= 4);
        assert_eq!(messages[position], 4);
        let length = u32::from_be_bytes([
            0,
            messages[position + 1],
            messages[position + 2],
            messages[position + 3],
        ]) as usize;
        let end = position + 4 + length;
        assert!(end <= messages.len());
        result
            .session_ticket_ctx
            .as_ref()
            .unwrap()
            .process_new_session_ticket(&messages[position..end]);
        position = end;
    }
    assert_eq!(result.reader.buffered_len(), 0);
}

fn drive(job: Job, client: &mut Segments, peer: &mut Segments) -> Established {
    let mut server = job.server;
    let (mut driver, hello) = client.measure(|| {
        let mut driver = HandshakeDriver::new(job.config);
        let hello = driver.start().unwrap();
        (driver, hello)
    });
    peer.measure(|| peer_input(&mut server, &hello));
    for _ in 0..32 {
        match client.measure(|| driver.progress().unwrap()) {
            HandshakeOutput::SendData(bytes) => peer.measure(|| peer_input(&mut server, &bytes)),
            HandshakeOutput::NeedData => {
                let bytes = peer.measure(|| peer_output(&mut server));
                assert!(!bytes.is_empty());
                client.measure(|| driver.feed(&bytes));
            }
            HandshakeOutput::Done {
                to_send,
                mut result,
            } => {
                peer.measure(|| peer_input(&mut server, &to_send));
                let tickets = peer.measure(|| peer_output(&mut server));
                client.measure(|| process_tickets(&mut result, &tickets));
                client.measure(|| drop(driver));
                return Established {
                    client: result,
                    server,
                };
            }
        }
    }
    panic!("legacy handshake failed to finish");
}

fn verify(connection: &Established, version: u16, resumed: bool) {
    assert!(!connection.server.is_handshaking());
    assert_eq!(connection.client.negotiated_version, Some(version));
    assert!(connection.client.negotiated_cipher_suite.is_some());
    assert_eq!(
        connection.server.handshake_kind(),
        Some(if resumed {
            rustls::HandshakeKind::Resumed
        } else {
            rustls::HandshakeKind::Full
        })
    );
}

fn burst(peer: &Peer, resumed: bool, workers: usize, batch: usize, timing: bool) -> Sample {
    let jobs = (0..workers)
        .map(|_| (0..batch).map(|_| peer.job(resumed)).collect())
        .collect();
    let (wall, reports) = concurrent(jobs, timing, drive);
    finish_burst(wall, reports, timing, workers * batch, |connection| {
        verify(connection, peer.version, resumed);
        connection.client.negotiated_cipher_suite.unwrap()
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
        let bytes = client.measure(|| connection.client.writer.write_record(23, chunk).unwrap());
        let incoming = peer.measure(|| {
            let offset = index * CALL_BYTES;
            let echoed = &mut seen_by_peer[offset..offset + chunk.len()];
            peer_echo(&mut connection.server, &bytes, echoed)
        });
        client.measure(|| connection.client.reader.feed(&incoming));
        while let Some(record) = client.measure(|| connection.client.reader.next_record().unwrap())
        {
            assert_eq!(record.content_type, 23);
            seen_by_client[received..received + record.payload.len()]
                .copy_from_slice(&record.payload);
            received += record.payload.len();
        }
    }
    let wall_ns = clock.map(|clock| clock.elapsed().wall_ns);
    assert_eq!(received, payload.len());
    assert_eq!(seen_by_peer, payload);
    assert_eq!(seen_by_client, payload);
    assert_eq!(connection.client.reader.buffered_len(), 0);
    Sample {
        wall_ns,
        client,
        peer,
        verified_connections: 1,
        plaintext_bytes_per_direction: payload.len(),
        negotiated_cipher_suites: vec![connection.client.negotiated_cipher_suite.unwrap()],
    }
}

#[test]
#[ignore = "Legacy full/resumed/transfer comparison; smoke by default, explicit idle release opt-in for clocks"]
fn legacy_client_workload_samples() {
    let settings = Settings::from_env();
    let payload: Vec<_> = (0..TRANSFER_BYTES).map(|i| (i % 251) as u8).collect();
    let mut rows = 0;
    for tls12 in [false, true] {
        let peer = Peer::new(tls12);
        for resumed in [false, true] {
            for workers in [1, 8, 32] {
                burst(&peer, resumed, workers, 1, false);
                let samples = (0..settings.samples)
                    .map(|_| {
                        burst(
                            &peer,
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
                    peer.job(false),
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
