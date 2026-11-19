//! Client configuration and encoding-stage timing, separate from memory-origin
//! accounting. Smoke runs execute all assertions without reading either clock.
//! This executable's existing allocator enabled-check remains in the timing path.

#[path = "../../../tools/tls_measure/clock.rs"]
mod clock;

use lktls::config::{ClientConfigTemplate, ClientHelloOverrides};
use lktls::handshake::client_hello_wire::ClientHelloWire;
use lktls::profile::types::{ext_type, EchMode, ExtensionSource, TlsProfile};

use super::*;

struct Case {
    name: &'static str,
    profile: Arc<TlsProfile>,
    hostname: &'static str,
}

fn compile(profile: Arc<TlsProfile>) -> Arc<CompiledClientConfig> {
    CompiledClientConfig::compile(profile, Transport::Tcp, CompileOptions::compatibility()).unwrap()
}

fn cases() -> Vec<Case> {
    let mut ordered = presets::chrome_155();
    ordered.randomization = None;
    ordered.ech = Some(EchMode::Disabled);
    let mut shuffled = ordered.clone();
    shuffled.randomization = presets::chrome_155().randomization;
    let mut opaque = ordered.clone();
    opaque.alps_protocols = None;
    opaque
        .extensions
        .iter_mut()
        .find(|ext| ext.extension_type == ext_type::ALPN)
        .unwrap()
        .source = ExtensionSource::RawBytes {
        data: "00020180".into(),
    };
    vec![
        Case {
            name: "editable_ordered",
            profile: Arc::new(ordered),
            hostname: "localhost",
        },
        Case {
            name: "editable_shuffled",
            profile: Arc::new(shuffled),
            hostname: "localhost",
        },
        Case {
            name: "opaque_raw_alpn",
            profile: Arc::new(opaque),
            hostname: "localhost",
        },
    ]
}

fn inputs(hostname: &str) -> ConnectionInputs {
    let mut inputs = ConnectionInputs::new(hostname, 443);
    inputs.alps_payload = Some(Vec::new());
    inputs
}

fn sample<T>(timed: bool, operation: impl FnOnce() -> T) -> (T, Option<clock::Elapsed>) {
    let start = timed.then(clock::ClockStart::start);
    let result = std::hint::black_box(operation());
    (result, start.map(clock::ClockStart::elapsed))
}

fn report(
    case: &str,
    stage: &str,
    iteration: usize,
    elapsed: Option<clock::Elapsed>,
    bytes: usize,
) {
    println!(
        "{}",
        serde_json::json!({
            "kind": "config_encoding_stage_timing", "case": case, "stage": stage,
            "iteration": iteration, "mode": if elapsed.is_some() { "measurement" } else { "smoke" },
            "wall_ns": elapsed.as_ref().map(|value| value.wall_ns),
            "thread_cpu_ns": elapsed.as_ref().and_then(|value| value.thread_cpu_ns),
            "thread_cpu_clock": clock::THREAD_CPU_CLOCK, "output_bytes": bytes,
            "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
            "debug_assertions": cfg!(debug_assertions), "package_version": env!("CARGO_PKG_VERSION"),
            "peer_setup_verification_and_drop_included": false,
            "native_crypto_included": stage != "cold_compile" && stage != "cached_plan",
            "allocator_counter_enabled": false,
            "scope": "client operation only; starts include inputs, keys, snapshots and framing; CH2 includes feed/progress",
            "copy_bytes": null, "accepted_ech_handshake": false,
        })
    );
}

fn plaintext_handshake(mut records: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !records.is_empty() {
        assert!(records.len() >= 5);
        let length = usize::from(u16::from_be_bytes([records[3], records[4]]));
        let end = 5 + length;
        assert!(records.len() >= end);
        match records[0] {
            22 => bytes.extend_from_slice(&records[5..end]),
            20 => assert_eq!(&records[5..end], &[1]),
            other => panic!("unexpected plaintext record {other}"),
        }
        records = &records[end..];
    }
    bytes
}

fn verify_hello(client: &ClientConnection) -> ClientHelloWire {
    let wire = ClientHelloWire::parse(&plaintext_handshake(client.output())).unwrap();
    assert_eq!(wire.handshake[0], 1);
    wire
}

fn basic_cases(timed: bool, iterations: usize) -> usize {
    let mut rows = 0;
    for case in cases() {
        let shared = compile(case.profile.clone());
        let template = ClientConfigTemplate::from_compiled(shared.clone());
        drop(ClientConnection::from_compiled(shared.clone(), inputs(case.hostname)).unwrap());
        for iteration in 0..iterations {
            let (cold, elapsed) = sample(timed, || compile(case.profile.clone()));
            assert!(std::ptr::eq(cold.profile(), case.profile.as_ref()));
            report(case.name, "cold_compile", iteration, elapsed, 0);
            drop(cold);
            let (cached, elapsed) = sample(timed, || template.compile().unwrap());
            assert!(Arc::ptr_eq(&cached, &shared));
            report(case.name, "cached_plan", iteration, elapsed, 0);
            let (client, elapsed) = sample(timed, || {
                ClientConnection::from_compiled(cached, inputs(case.hostname)).unwrap()
            });
            let wire = verify_hello(&client);
            if case.name == "opaque_raw_alpn" {
                let extension = wire
                    .extensions
                    .iter()
                    .find(|ext| ext.extension_type == ext_type::ALPN)
                    .unwrap();
                assert_eq!(&wire.handshake[extension.payload.clone()], &[0, 2, 1, 0x80]);
            }
            report(
                case.name,
                "reused_first_flight",
                iteration,
                elapsed,
                client.output().len(),
            );
            rows += 3;
        }
    }
    rows
}

fn ech_config() -> Vec<u8> {
    let name = b"public.invalid";
    let mut contents = vec![1, 0, 32, 0, 32];
    contents.extend_from_slice(&[0x42; 32]);
    contents.extend_from_slice(&[0, 4, 0, 1, 0, 1, 64, name.len() as u8]);
    contents.extend_from_slice(name);
    contents.extend_from_slice(&[0, 0]);
    let mut list = Vec::new();
    list.extend_from_slice(&((contents.len() + 4) as u16).to_be_bytes());
    list.extend_from_slice(&[0xfe, 0x0d]);
    list.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    list.extend_from_slice(&contents);
    list
}

fn dynamic_cases(timed: bool, iterations: usize) -> usize {
    let peer = Peer::new(false);
    let ech = ech_config();
    let mut rows = 0;
    for iteration in 0..iterations {
        let store = Arc::new(ObservedStore::default());
        let mut seed = peer.connect(store.clone(), Arc::default());
        let mut server = rustls::ServerConnection::new(peer.server.clone()).unwrap();
        authenticate(&mut seed, &mut server);
        send_output(&mut seed, &mut server);
        assert!(!server.is_handshaking());
        let tickets = server_output(&mut server);
        assert_eq!(seed.feed_bounded(&tickets), tickets.len());
        assert_eq!(seed.process_read().unwrap(), ReadProgress::NeedInput);
        drop(seed);
        let (mut resumed, elapsed) = sample(timed, || {
            let mut input = inputs("localhost");
            input.session_store = Some(store.clone());
            ClientConnection::from_compiled(peer.client.clone(), input).unwrap()
        });
        let wire = verify_hello(&resumed);
        assert_eq!(
            wire.extensions.last().unwrap().extension_type,
            ext_type::PRE_SHARED_KEY
        );
        assert_eq!(store.takes.load(Ordering::Relaxed), 2);
        report(
            "authenticated_psk",
            "reused_first_flight",
            iteration,
            elapsed,
            resumed.output().len(),
        );
        let mut server = rustls::ServerConnection::new(peer.server.clone()).unwrap();
        send_output(&mut resumed, &mut server);
        assert_eq!(
            server.handshake_kind(),
            Some(rustls::HandshakeKind::Resumed)
        );

        let mut provider = rustls::crypto::ring::default_provider();
        provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP384R1];
        let server_config = rustls::ServerConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(peer.server.cert_resolver.clone());
        let mut server = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
        let mut client =
            ClientConnection::from_compiled(peer.client.clone(), inputs("localhost")).unwrap();
        assert!(verify_hello(&client)
            .key_shares()
            .unwrap()
            .iter()
            .all(|share| share.group != 0x0018));
        send_output(&mut client, &mut server);
        assert_eq!(
            client.progress_handshake().unwrap(),
            HandshakeProgress::NeedInput
        );
        let retry = server_output(&mut server);
        let hello = plaintext_handshake(&retry);
        assert!(
            lktls::handshake::server_hello::parse_server_hello(&hello[4..])
                .unwrap()
                .is_hello_retry_request
        );
        let (progress, elapsed) = sample(timed, || {
            assert_eq!(client.feed_bounded(&retry), retry.len());
            client.progress_handshake().unwrap()
        });
        assert_eq!(progress, HandshakeProgress::NeedOutput);
        let wire = verify_hello(&client);
        assert_eq!(wire.key_shares().unwrap()[0].group, 0x0018);
        report(
            "hrr_p384",
            "feed_and_build_ch2",
            iteration,
            elapsed,
            client.output().len(),
        );
        send_output(&mut client, &mut server);
        assert_eq!(
            server.negotiated_key_exchange_group().unwrap().name(),
            rustls::NamedGroup::secp384r1
        );

        let (client, elapsed) = sample(timed, || {
            let mut input = inputs("localhost");
            input.ech_config_list = Some(ech.clone());
            ClientConnection::from_compiled(peer.client.clone(), input).unwrap()
        });
        let wire = verify_hello(&client);
        let extension = wire
            .extensions
            .iter()
            .find(|ext| ext.extension_type == ext_type::ENCRYPTED_CLIENT_HELLO)
            .unwrap();
        let payload = &wire.handshake[extension.payload.clone()];
        assert_eq!(&payload[..8], &[0, 0, 1, 0, 1, 1, 0, 32]);
        assert!(payload.len() > 58);
        report(
            "real_ech_offer",
            "reused_first_flight",
            iteration,
            elapsed,
            client.output().len(),
        );
        rows += 3;
    }
    rows
}

fn overlay_cases(timed: bool, iterations: usize) -> usize {
    let mut profile = presets::chrome_155();
    profile.ech = Some(EchMode::Disabled);
    let shared = compile(Arc::new(profile));
    let mut rows = 0;
    for iteration in 0..iterations {
        for alpn in [true, false] {
            let (client, elapsed) = sample(timed, || {
                let mut input = inputs("localhost");
                input.hello_overrides = if alpn {
                    ClientHelloOverrides {
                        alpn_protocols: Some(vec!["http/1.1".into()]),
                        alps_protocols: Some(Vec::new()),
                        ..Default::default()
                    }
                } else {
                    ClientHelloOverrides {
                        trust_anchor_ids: Some(vec![lktls::trust_anchor::TrustAnchorId::from_hex(
                            "01",
                        )
                        .unwrap()]),
                        ..Default::default()
                    }
                };
                ClientConnection::from_compiled(shared.clone(), input).unwrap()
            });
            let wire = verify_hello(&client);
            let code = if alpn {
                ext_type::ALPN
            } else {
                ext_type::TRUST_ANCHOR_IDS
            };
            let extension = wire
                .extensions
                .iter()
                .find(|ext| ext.extension_type == code)
                .unwrap();
            let expected: &[u8] = if alpn {
                b"\x00\x09\x08http/1.1"
            } else {
                &[0, 2, 1, 1]
            };
            assert_eq!(&wire.handshake[extension.payload.clone()], expected);
            report(
                if alpn {
                    "generated_alpn_overlay"
                } else {
                    "generated_tai_overlay"
                },
                "reused_first_flight",
                iteration,
                elapsed,
                client.output().len(),
            );
            rows += 1;
        }
    }
    rows
}

fn run(timed: bool, iterations: usize) -> usize {
    assert!(iterations > 0);
    basic_cases(timed, iterations)
        + dynamic_cases(timed, iterations)
        + overlay_cases(timed, iterations)
}

#[test]
fn config_measurement_smoke_emits_no_timing() {
    assert_eq!(run(false, 1), 14);
}

#[test]
#[ignore = "Run release executable serially on an idle machine; never during compilation"]
fn config_encoding_wall_and_thread_cpu_samples() {
    assert_eq!(
        std::env::var("TLS_CONFIG_MEASURE_IDLE").as_deref(),
        Ok("1"),
        "TLS_CONFIG_MEASURE_IDLE=1 requires an idle machine"
    );
    if cfg!(debug_assertions) {
        panic!("timing requires release mode");
    }
    let iterations: usize = std::env::var("TLS_CONFIG_MEASURE_ITERATIONS")
        .map(|value| value.parse().unwrap())
        .unwrap_or(20);
    assert!(iterations >= 20, "timing requires at least 20 samples");
    assert_eq!(run(false, 1), 14, "prime all paths without sampling clocks");
    assert_eq!(run(true, iterations), iterations * 14);
}
