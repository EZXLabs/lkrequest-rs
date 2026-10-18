//! Controlled TLS 1.3 CCS peers for browser capture and local regressions.

use lkrequest::TlsConnector;
use lktls::crypto::aead::{Aead, AeadAlgorithm};
use lktls::crypto::hkdf::{hkdf_expand_label, HkdfAlgorithm};
use lktls::profile::presets;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Copy)]
struct Case {
    port: u16,
    browser: &'static str,
    phase: &'static str,
    name: &'static str,
    payload: &'static [u8],
    ccs_count: usize,
}

fn cases(phase: &str) -> Vec<Case> {
    if phase == "record-version" {
        let mut result = Vec::new();
        for browser in ["chrome", "firefox"] {
            for name in [
                "valid",
                "minor_retag",
                "minor_flip",
                "future_retag",
                "major_retag",
                "major_overflow",
                "ccs_minor",
                "ccs_major",
                "oversize_bad_version",
                "oversize_good_version",
            ] {
                result.push(Case {
                    port: 48860 + result.len() as u16,
                    browser,
                    phase: "record-version",
                    name,
                    payload: &[],
                    ccs_count: 0,
                });
            }
        }
        return result;
    }
    if phase == "auth" {
        let mut result = Vec::new();
        for browser in ["chrome", "firefox"] {
            for name in [
                "valid",
                "bad_tag",
                "short_tag",
                "wrong_nonce",
                "missing_type",
            ] {
                result.push(Case {
                    port: 48790 + result.len() as u16,
                    browser,
                    phase: "auth",
                    name,
                    payload: &[],
                    ccs_count: 0,
                });
            }
        }
        return result;
    }
    if phase.starts_with("repeat-") {
        let (base, phase) = match phase {
            "repeat-initial" => (48730, "repeat-initial"),
            "repeat-hrr" => (48740, "repeat-hrr"),
            "repeat-keys" => (48750, "repeat-keys"),
            _ => panic!("unknown CCS repetition phase"),
        };
        let mut result = Vec::new();
        for browser in ["chrome", "firefox"] {
            for (name, ccs_count) in [
                ("zero", 0),
                ("one", 1),
                ("two", 2),
                ("thirty_two", 32),
                ("thirty_three", 33),
            ] {
                result.push(Case {
                    port: base + result.len() as u16,
                    browser,
                    phase,
                    name,
                    payload: &[1],
                    ccs_count,
                });
            }
        }
        return result;
    }
    let base = match phase {
        "hrr" => 48700,
        "keys" => 48710,
        "encrypted" => 48720,
        _ => panic!("unknown CCS phase"),
    };
    let variants: &[(&str, &[u8])] = if phase == "encrypted" {
        &[
            ("empty", &[]),
            ("value", &[2]),
            ("long", &[1, 1]),
            ("one", &[1]),
        ]
    } else {
        &[("empty", &[]), ("value", &[2]), ("long", &[1, 1])]
    };
    let phase = match phase {
        "hrr" => "hrr",
        "keys" => "keys",
        _ => "encrypted",
    };
    let mut result = Vec::new();
    for browser in ["chrome", "firefox"] {
        for &(name, payload) in variants {
            result.push(Case {
                port: base + result.len() as u16,
                browser,
                phase,
                name,
                payload,
                ccs_count: 1,
            });
        }
    }
    result
}

fn plain_record(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut record = vec![kind, 3, 3];
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

async fn client_hello(socket: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    for _ in 0..4 {
        let mut header = [0; 5];
        socket.read_exact(&mut header).await?;
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        assert!(length < 16_384);
        let mut payload = vec![0; length];
        socket.read_exact(&mut payload).await?;
        if header[0] == 20 && payload == [1] {
            continue;
        }
        assert_eq!(header[0], 22);
        assert_eq!(payload.first(), Some(&1));
        return Ok(payload);
    }
    panic!("too many records before ClientHello");
}

#[derive(Default)]
struct HandshakeCiphers(Mutex<(Option<Aead>, Option<Aead>)>);

impl std::fmt::Debug for HandshakeCiphers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HandshakeCiphers")
    }
}

impl rustls::KeyLog for HandshakeCiphers {
    fn log(&self, label: &str, _: &[u8], secret: &[u8]) {
        if !matches!(
            label,
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET" | "SERVER_HANDSHAKE_TRAFFIC_SECRET"
        ) {
            return;
        }
        let key = hkdf_expand_label(HkdfAlgorithm::Sha256, secret, "key", &[], 16).unwrap();
        let iv = hkdf_expand_label(HkdfAlgorithm::Sha256, secret, "iv", &[], 12).unwrap();
        let cipher = Aead::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap();
        let mut ciphers = self.0.lock().unwrap();
        if label.starts_with("CLIENT_") {
            ciphers.0 = Some(cipher);
        } else {
            ciphers.1 = Some(cipher);
        }
    }
}

fn server_hello(ch: &[u8]) -> (Vec<u8>, Aead, Aead) {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        cert.signing_key.serialize_der(),
    ));
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
    provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .unwrap();
    let ciphers = Arc::new(HandshakeCiphers::default());
    config.key_log = ciphers.clone();
    let mut server = rustls::ServerConnection::new(Arc::new(config)).unwrap();
    server
        .read_tls(&mut std::io::Cursor::new(plain_record(22, ch)))
        .unwrap();
    server.process_new_packets().unwrap();
    let mut flight = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut flight).unwrap();
    }
    assert_eq!(&flight[..3], &[22, 3, 3]);
    assert_eq!(flight[5], 2);
    let hello_end = 5 + u16::from_be_bytes([flight[3], flight[4]]) as usize;
    flight.truncate(hello_end);
    let (client, server) = {
        let mut ciphers = ciphers.0.lock().unwrap();
        (ciphers.0.take().unwrap(), ciphers.1.take().unwrap())
    };
    (flight, client, server)
}

fn protected_record(cipher: &Aead, sequence: u64, inner: &[u8]) -> Vec<u8> {
    let mut record = vec![23, 3, 3];
    record.extend_from_slice(&((inner.len() + 16) as u16).to_be_bytes());
    let encrypted = cipher.encrypt(sequence, &record, inner).unwrap();
    record.extend_from_slice(&encrypted);
    record
}

#[derive(Debug, serde::Serialize)]
struct Observation {
    client: &'static str,
    browser: &'static str,
    phase: &'static str,
    scenario: &'static str,
    port: u16,
    sent_ccs: usize,
    record_types: Vec<u8>,
    record_versions: Vec<u16>,
    record_lengths: Vec<usize>,
    alerts: Vec<[u8; 2]>,
    flight_hex: String,
}

async fn observe(
    mut socket: tokio::net::TcpStream,
    ch: Vec<u8>,
    case: Case,
    library: bool,
) -> std::io::Result<Observation> {
    let repeat = case.phase.starts_with("repeat-");
    let mut ccs_records = plain_record(20, case.payload).repeat(case.ccs_count);
    if repeat {
        // A different fatal alert proves the preceding CCS records were consumed.
        ccs_records.extend_from_slice(&[23, 3, 3, 0xff, 0xff]);
    }
    let cipher = if case.phase == "repeat-initial" {
        socket.write_all(&ccs_records).await?;
        None
    } else if matches!(case.phase, "hrr" | "repeat-hrr") {
        let parsed = lkprofile::parse_client_hello(&ch).unwrap();
        let session_id = &ch[39..39 + parsed.session_id_length as usize];
        let mut body = vec![3, 3];
        body.extend_from_slice(&lktls::handshake::server_hello::HRR_RANDOM);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&[0x13, 1, 0, 0, 12, 0, 43, 0, 2, 3, 4, 0, 51, 0, 2, 0, 24]);
        let mut hrr = vec![2, 0, 0, body.len() as u8];
        hrr.extend_from_slice(&body);
        socket.write_all(&plain_record(22, &hrr)).await?;
        let second = client_hello(&mut socket).await?;
        let second_parsed = lkprofile::parse_client_hello(&second).unwrap();
        assert_eq!(
            &second[39..39 + second_parsed.session_id_length as usize],
            session_id
        );
        socket.write_all(&ccs_records).await?;
        None
    } else {
        let (mut flight, cipher, server) = server_hello(&ch);
        if case.phase == "record-version" {
            let version = match case.name {
                "minor_retag" | "minor_flip" => 0x0301u16,
                "future_retag" => 0x0304,
                "major_retag" | "major_overflow" => 0x0403,
                _ => 0x0303,
            };
            let mut record = if case.name.starts_with("oversize_") {
                let version = if case.name == "oversize_bad_version" {
                    1
                } else {
                    3
                };
                let mut record = vec![23, 3, version, 0x40, 0x20];
                record.resize(5 + 16416, 0);
                record
            } else if case.name.starts_with("ccs_") {
                let mut record = if case.name == "ccs_minor" {
                    vec![20, 3, 1, 0, 1, 1]
                } else {
                    vec![20, 4, 3, 0, 1, 1]
                };
                record.extend_from_slice(&protected_record(&server, 0, &[8, 0, 0, 2, 0, 0, 22]));
                record
            } else if case.name == "major_overflow" {
                vec![23, 4, 3, 0xff, 0xff]
            } else if case.name == "minor_flip" {
                let mut record = protected_record(&server, 0, &[8, 0, 0, 2, 0, 0, 22]);
                record[1..3].copy_from_slice(&version.to_be_bytes());
                record
            } else {
                let mut record = vec![23];
                record.extend_from_slice(&version.to_be_bytes());
                record.extend_from_slice(&[0, 23]);
                let encrypted = server.encrypt(0, &record, &[8, 0, 0, 2, 0, 0, 22]).unwrap();
                record.extend_from_slice(&encrypted);
                record
            };
            if case.name != "major_overflow" {
                record.extend_from_slice(&[23, 3, 3, 0xff, 0xff]);
            }
            flight.extend_from_slice(&record);
        } else if case.phase == "auth" {
            let mut record = if case.name == "short_tag" {
                plain_record(23, &[0; 15])
            } else {
                protected_record(
                    &server,
                    u64::from(case.name == "wrong_nonce"),
                    if case.name == "missing_type" {
                        &[0, 0]
                    } else {
                        &[8, 0, 0, 2, 0, 0, 22]
                    },
                )
            };
            if case.name == "bad_tag" {
                *record.last_mut().unwrap() ^= 1;
            }
            flight.extend_from_slice(&record);
            if case.name == "valid" {
                flight.extend_from_slice(&[23, 3, 3, 0xff, 0xff]);
            }
        } else if case.phase == "encrypted" {
            let mut inner = case.payload.to_vec();
            inner.push(20);
            flight.extend_from_slice(&protected_record(&server, 0, &inner));
        } else {
            flight.extend_from_slice(&ccs_records);
        }
        socket.write_all(&flight).await?;
        Some(cipher)
    };
    let mut observed = Observation {
        client: if library { "library" } else { "browser" },
        browser: case.browser,
        phase: case.phase,
        scenario: case.name,
        port: case.port,
        sent_ccs: case.ccs_count,
        record_types: Vec::new(),
        record_versions: Vec::new(),
        record_lengths: Vec::new(),
        alerts: Vec::new(),
        flight_hex: String::new(),
    };
    let mut sequence = 0;
    for _ in 0..8 {
        let mut header = [0; 5];
        if !matches!(
            tokio::time::timeout(Duration::from_secs(2), socket.read_exact(&mut header)).await,
            Ok(Ok(_))
        ) {
            break;
        }
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        assert!(length < 16_384);
        let mut payload = vec![0; length];
        socket.read_exact(&mut payload).await?;
        observed.record_types.push(header[0]);
        observed
            .record_versions
            .push(u16::from_be_bytes([header[1], header[2]]));
        observed.record_lengths.push(length);
        for byte in header.iter().chain(&payload) {
            use std::fmt::Write;
            write!(observed.flight_hex, "{byte:02x}").unwrap();
        }
        if header[0] == 23 {
            let inner = cipher
                .as_ref()
                .unwrap()
                .decrypt(sequence, &header, &payload)
                .unwrap();
            sequence += 1;
            let last = inner.iter().rposition(|byte| *byte != 0).unwrap();
            assert_eq!(inner[last], 21, "expected an authenticated alert");
            assert_eq!(last, 2);
            observed.alerts.push([inner[0], inner[1]]);
        } else if header[0] == 21 {
            assert_eq!(payload.len(), 2);
            observed.alerts.push([payload[0], payload[1]]);
        } else {
            assert_eq!((header[0], payload.as_slice()), (20, &[1][..]));
        }
        if !observed.alerts.is_empty() {
            break;
        }
    }
    Ok(observed)
}

#[tokio::test]
#[ignore = "Tier-1: isolated real-browser CCS capture"]
async fn local_browser_ccs_peer() {
    let phase = std::env::var("TEST_BROWSER_CCS_PHASE").unwrap();
    let library = std::env::var("TEST_BROWSER_ERROR_LIBRARY").ok().as_deref() == Some("1");
    let mut peers = Vec::new();
    for case in cases(&phase) {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, case.port))
            .await
            .unwrap();
        peers.push(tokio::spawn(async move {
            let observed = tokio::time::timeout(Duration::from_secs(180), async {
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    if let Ok(Ok(ch)) =
                        tokio::time::timeout(Duration::from_secs(3), client_hello(&mut socket))
                            .await
                    {
                        if let Ok(observed) = observe(socket, ch, case, library).await {
                            if library || !observed.alerts.is_empty() {
                                break observed;
                            }
                        }
                        eprintln!(
                            "CCS peer {}: retry after cancelled or quiet connection",
                            case.port
                        );
                    }
                }
            })
            .await
            .unwrap();
            println!("{}", serde_json::to_string(&observed).unwrap());
            observed
        }));
    }
    if library {
        for case in cases(&phase) {
            let profile = if case.browser == "chrome" {
                presets::chrome_155()
            } else {
                presets::firefox_156()
            };
            let socket = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, case.port))
                .await
                .unwrap();
            assert!(TlsConnector::new(profile)
                .connect("127.0.0.1", case.port, socket)
                .await
                .is_err());
        }
    }
    for peer in peers {
        let observed = peer.await.unwrap();
        assert_eq!(
            observed.alerts.len(),
            1,
            "controlled peer must receive an alert"
        );
    }
}

async fn local_observations(phase: &str) -> Vec<Observation> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut observations = Vec::new();
        for case in cases(phase) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let case = Case {
                port: address.port(),
                ..case
            };
            let peer = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let hello = client_hello(&mut socket).await.unwrap();
                observe(socket, hello, case, true).await.unwrap()
            });
            let profile = if case.browser == "chrome" {
                presets::chrome_155()
            } else {
                presets::firefox_156()
            };
            let socket = tokio::net::TcpStream::connect(address).await.unwrap();
            assert!(TlsConnector::new(profile)
                .connect("127.0.0.1", address.port(), socket)
                .await
                .is_err());
            observations.push(peer.await.unwrap());
        }
        observations
    })
    .await
    .expect("local CCS peer timed out")
}

fn assert_record_shape(observed: &Observation) {
    let plaintext = matches!(observed.phase, "hrr" | "repeat-hrr" | "repeat-initial");
    let types = if plaintext {
        vec![21]
    } else if observed.browser == "chrome" {
        vec![20, 23]
    } else {
        vec![23]
    };
    let lengths = if plaintext {
        vec![2]
    } else if observed.browser == "chrome" {
        vec![1, 19]
    } else {
        vec![19]
    };
    assert_eq!(observed.record_types, types);
    assert_eq!(observed.record_lengths, lengths);
    let version = if observed.phase == "repeat-initial" {
        0x0301
    } else {
        0x0303
    };
    assert_eq!(observed.record_versions, vec![version; types.len()]);
}

#[tokio::test]
async fn malformed_ccs_after_hrr_matches_browser_alerts() {
    let observed = local_observations("hrr").await;
    assert_eq!(observed.len(), 6);
    for record in observed {
        let description = if record.browser == "chrome" {
            10
        } else if record.scenario == "value" {
            47
        } else {
            50
        };
        assert_eq!(record.alerts, [[2, description]]);
        assert_record_shape(&record);
    }
}

#[tokio::test]
async fn malformed_plaintext_ccs_after_keys_matches_browser_alerts() {
    let observed = local_observations("keys").await;
    assert_eq!(observed.len(), 6);
    for record in observed {
        let description = if record.browser == "chrome" { 20 } else { 10 };
        assert_eq!(record.alerts, [[2, description]]);
        assert_record_shape(&record);
    }
}

#[tokio::test]
async fn protected_ccs_matches_browser_alerts() {
    let observed = local_observations("encrypted").await;
    assert_eq!(observed.len(), 8);
    for record in observed {
        let description = if record.browser == "chrome" || record.scenario == "one" {
            10
        } else if record.scenario == "value" {
            47
        } else {
            50
        };
        assert_eq!(record.alerts, [[2, description]]);
        assert_record_shape(&record);
    }
}

#[tokio::test]
async fn initial_ccs_is_rejected_before_the_overflow_control() {
    let observed = local_observations("repeat-initial").await;
    assert_eq!(observed.len(), 10);
    for record in observed {
        assert_eq!(
            record.alerts,
            [[2, if record.sent_ccs == 0 { 22 } else { 10 }]]
        );
        assert_record_shape(&record);
    }
}

#[tokio::test]
async fn ccs_repetition_after_hrr_matches_browser_limits() {
    let observed = local_observations("repeat-hrr").await;
    assert_eq!(observed.len(), 10);
    for record in observed {
        let rejected = record.browser == "chrome" && record.sent_ccs > 32;
        assert_eq!(record.alerts, [[2, if rejected { 10 } else { 22 }]]);
        assert_record_shape(&record);
    }
}

#[tokio::test]
async fn ccs_repetition_after_keys_matches_browser_limits() {
    let observed = local_observations("repeat-keys").await;
    assert_eq!(observed.len(), 10);
    for record in observed {
        let limit = if record.browser == "chrome" { 32 } else { 1 };
        assert_eq!(
            record.alerts,
            [[2, if record.sent_ccs > limit { 10 } else { 22 }]]
        );
        assert_record_shape(&record);
    }
}

#[tokio::test]
async fn handshake_record_authentication_matches_browser_alerts() {
    let observations = local_observations("auth").await;
    assert_eq!(observations.len(), 10);
    for record in observations {
        let description = match record.scenario {
            "valid" => 22,
            "missing_type" if record.browser == "chrome" => 51,
            "missing_type" => 10,
            _ => 20,
        };
        assert_eq!(record.alerts, [[2, description]]);
        assert_record_shape(&record);
    }
}

#[tokio::test]
async fn handshake_record_version_checks_match_browser_precedence() {
    let observations = local_observations("record-version").await;
    assert_eq!(observations.len(), 20);
    for record in observations {
        let expected = if record.browser == "chrome" {
            match record.scenario {
                "valid" => 22,
                "oversize_good_version" => 20,
                _ => 70,
            }
        } else {
            match record.scenario {
                "minor_retag" | "minor_flip" | "future_retag" | "major_retag" => 20,
                _ => 22,
            }
        };
        assert_eq!(
            record.alerts,
            [[2, expected]],
            "{} {}",
            record.browser,
            record.scenario
        );
        assert_record_shape(&record);
    }
}
