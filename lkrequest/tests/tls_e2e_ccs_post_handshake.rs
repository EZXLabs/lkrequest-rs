//! CCS probes after authenticated Finished and an actual HTTP/1.1 request.

use base64::Engine;
use lkrequest::TlsConnector;
use lktls::crypto::aead::{Aead, AeadAlgorithm};
use lktls::crypto::hkdf::{hkdf_expand_label, HkdfAlgorithm};
use lktls::profile::presets;
use rcgen::PublicKeyData;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 14\r\nConnection: close\r\n\r\nccs-control-ok";

#[path = "tls_e2e_ccs_post_handshake/lifecycle.rs"]
mod lifecycle;

#[path = "tls_e2e_ccs_post_handshake/h2_lifecycle.rs"]
mod h2_lifecycle;

#[derive(Clone, Copy)]
struct Case {
    port: u16,
    browser: &'static str,
    scenario: &'static str,
    handshake_ccs: bool,
}

fn cases() -> Vec<Case> {
    let mut result = Vec::new();
    for browser in ["chrome", "firefox"] {
        for (scenario, handshake_ccs) in [
            ("normal_with_ccs", true),
            ("normal_without_ccs", false),
            ("plain_with_ccs", true),
            ("plain_without_ccs", false),
            ("protected", false),
            ("malformed", false),
        ] {
            result.push(Case {
                port: 48770 + result.len() as u16,
                browser,
                scenario,
                handshake_ccs,
            });
        }
    }
    result
}

fn auth_cases() -> Vec<Case> {
    let mut result = Vec::new();
    for browser in ["chrome", "firefox"] {
        for scenario in [
            "normal_without_ccs",
            "bad_tag",
            "short_tag",
            "wrong_nonce",
            "missing_type",
        ] {
            result.push(Case {
                port: 48800 + result.len() as u16,
                browser,
                scenario,
                handshake_ccs: false,
            });
        }
    }
    result
}

fn version_cases() -> Vec<Case> {
    let mut result = Vec::new();
    for browser in ["chrome", "firefox"] {
        for scenario in [
            "normal_without_ccs",
            "minor_retag",
            "minor_flip",
            "future_retag",
            "major_retag",
            "major_overflow",
        ] {
            result.push(Case {
                port: 48900 + result.len() as u16,
                browser,
                scenario,
                handshake_ccs: false,
            });
        }
    }
    result
}

fn key_update_cases() -> Vec<Case> {
    let mut result = Vec::new();
    for browser in ["chrome", "firefox"] {
        for scenario in [
            "normal_without_ccs",
            "ku_valid0",
            "ku_valid1",
            "ku_fragmented0",
            "ku_empty",
            "ku_long0",
            "ku_long1",
            "ku_invalid2",
            "ku_double",
            "ku_partial_tail",
            "ku_bad_length_tail",
            "ku_invalid_tail",
            "ku_request_overflow",
        ] {
            result.push(Case {
                port: 48880 + result.len() as u16,
                browser,
                scenario,
                handshake_ccs: false,
            });
        }
    }
    result
}

fn repeated_key_update_cases() -> Vec<Case> {
    let mut result = Vec::new();
    for browser in ["chrome", "firefox"] {
        for scenario in [
            "repeat0_2",
            "repeat1_2",
            "repeat0_32",
            "repeat1_32",
            "repeat0_33",
            "repeat1_33",
            "repeat0_32_empty",
            "repeat0_32_data",
            "repeat0_32_ticket",
            "repeat1_2_overflow",
            "repeat1_32_overflow",
            "repeat1_33_overflow",
            "repeat0_32_invalid",
            "repeat0_31_invalid",
            "repeat0_31_ticket",
        ] {
            result.push(Case {
                port: 49100 + result.len() as u16,
                browser,
                scenario,
                handshake_ccs: false,
            });
        }
    }
    result
}

#[derive(Default)]
struct TrafficCiphers {
    client: Option<Aead>,
    server: Option<Aead>,
    client_secret: Vec<u8>,
    server_secret: Vec<u8>,
}
#[derive(Default)]
struct ApplicationCiphers(Mutex<TrafficCiphers>);
impl std::fmt::Debug for ApplicationCiphers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ApplicationCiphers")
    }
}
impl rustls::KeyLog for ApplicationCiphers {
    fn log(&self, label: &str, _: &[u8], secret: &[u8]) {
        if !matches!(label, "CLIENT_TRAFFIC_SECRET_0" | "SERVER_TRAFFIC_SECRET_0") {
            return;
        }
        let key = hkdf_expand_label(HkdfAlgorithm::Sha256, secret, "key", &[], 16).unwrap();
        let iv = hkdf_expand_label(HkdfAlgorithm::Sha256, secret, "iv", &[], 12).unwrap();
        let cipher = Aead::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap();
        let mut ciphers = self.0.lock().unwrap();
        if label.starts_with("CLIENT_") {
            ciphers.client = Some(cipher);
            ciphers.client_secret = secret.to_vec();
        } else {
            ciphers.server = Some(cipher);
            ciphers.server_secret = secret.to_vec();
        }
    }
}

struct Fixture {
    config: rustls::ServerConfig,
    certificate: Vec<u8>,
    spki_pin: String,
}
fn fixture() -> Fixture {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let spki_pin = base64::engine::general_purpose::STANDARD.encode(
        aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA256,
            &cert.signing_key.subject_public_key_info(),
        )
        .as_ref(),
    );
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
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.send_tls13_tickets = 0;
    Fixture {
        config,
        certificate: cert.cert.der().to_vec(),
        spki_pin,
    }
}

fn plain_record(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut result = vec![kind, 3, 3];
    result.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    result.extend_from_slice(payload);
    result
}

async fn read_record(socket: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let mut header = [0; 5];
    socket.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    assert!(len < 18_432);
    let mut record = header.to_vec();
    record.resize(5 + len, 0);
    socket.read_exact(&mut record[5..]).await?;
    Ok(record)
}

fn outgoing(server: &mut rustls::ServerConnection, allow_ccs: bool) -> (Vec<u8>, usize) {
    let mut raw = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut raw).unwrap();
    }
    let mut result = Vec::new();
    let mut offset = 0;
    let mut sent_ccs = 0;
    while offset < raw.len() {
        let end = offset + 5 + u16::from_be_bytes([raw[offset + 3], raw[offset + 4]]) as usize;
        assert!(end <= raw.len());
        if raw[offset] != 20 || allow_ccs {
            result.extend_from_slice(&raw[offset..end]);
            sent_ccs += usize::from(raw[offset] == 20);
        }
        offset = end;
    }
    (result, sent_ccs)
}

#[derive(Debug, serde::Serialize)]
struct Observation {
    client: &'static str,
    browser: &'static str,
    scenario: &'static str,
    port: u16,
    finished_verified: bool,
    request_received: bool,
    handshake_ccs_sent: usize,
    client_application_records: u64,
    normal_response_sent: bool,
    record_types: Vec<u8>,
    record_versions: Vec<u16>,
    record_lengths: Vec<usize>,
    alerts: Vec<[u8; 2]>,
    rustls_alert: Option<u8>,
    key_update_response: Option<u8>,
    key_update_response_hex: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    key_update_responses: Vec<String>,
    flight_hex: String,
}

async fn observe(
    mut socket: tokio::net::TcpStream,
    mut config: rustls::ServerConfig,
    case: Case,
    library: bool,
) -> std::io::Result<Observation> {
    let ciphers = Arc::new(ApplicationCiphers::default());
    config.key_log = ciphers.clone();
    let mut server = rustls::ServerConnection::new(Arc::new(config)).unwrap();
    let mut request = Vec::new();
    let mut application_sequence = 0;
    let mut handshake_ccs_sent = 0;
    while !request.ends_with(b"\r\n\r\n") {
        let record = read_record(&mut socket).await?;
        let handshaking = server.is_handshaking();
        server.read_tls(&mut std::io::Cursor::new(&record))?;
        server
            .process_new_packets()
            .map_err(std::io::Error::other)?;
        if !handshaking && record[0] == 23 {
            application_sequence += 1;
        }
        let (flight, ccs) = outgoing(&mut server, case.handshake_ccs);
        handshake_ccs_sent += ccs;
        socket.write_all(&flight).await?;
        let mut buffer = [0; 4096];
        loop {
            match server.reader().read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => request.extend_from_slice(&buffer[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
            assert!(request.len() < 16_384);
        }
    }
    assert!(!server.is_handshaking());
    assert_eq!(server.alpn_protocol(), Some(&b"http/1.1"[..]));
    assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
    assert!(application_sequence > 0);
    let normal = case.scenario.starts_with("normal_");
    let mut observed = Observation {
        client: if library { "library" } else { "browser" },
        browser: case.browser,
        scenario: case.scenario,
        port: case.port,
        finished_verified: true,
        request_received: true,
        handshake_ccs_sent,
        client_application_records: application_sequence,
        normal_response_sent: normal,
        record_types: Vec::new(),
        record_versions: Vec::new(),
        record_lengths: Vec::new(),
        alerts: Vec::new(),
        rustls_alert: None,
        key_update_response: None,
        key_update_response_hex: None,
        key_update_responses: Vec::new(),
        flight_hex: String::new(),
    };
    if normal {
        server.writer().write_all(RESPONSE)?;
        server.send_close_notify();
        socket.write_all(&outgoing(&mut server, false).0).await?;
        return Ok(observed);
    }
    if case.scenario.starts_with("repeat") {
        return observe_repeated_key_updates(socket, server, case, observed, ciphers).await;
    }
    let (mut client_cipher, server_cipher, mut client_secret) = {
        let mut ciphers = ciphers.0.lock().unwrap();
        (
            ciphers.client.take().unwrap(),
            ciphers.server.take().unwrap(),
            std::mem::take(&mut ciphers.client_secret),
        )
    };
    let version_probe = matches!(
        case.scenario,
        "minor_retag" | "minor_flip" | "future_retag" | "major_retag" | "major_overflow"
    );
    let key_update = case.scenario.starts_with("ku_");
    let valid_update = matches!(case.scenario, "ku_valid0" | "ku_valid1" | "ku_fragmented0");
    let injected = if key_update {
        let message = match case.scenario {
            "ku_empty" => vec![24, 0, 0, 0],
            "ku_long0" => vec![24, 0, 0, 2, 0, 0],
            "ku_long1" => vec![24, 0, 0, 2, 1, 0],
            "ku_invalid2" => vec![24, 0, 0, 1, 2],
            "ku_double" => vec![24, 0, 0, 1, 0, 24, 0, 0, 1, 0],
            "ku_partial_tail" => vec![24, 0, 0, 1, 0, 4],
            "ku_bad_length_tail" => vec![24, 0, 0, 1, 0, 4, 0xff, 0xff, 0xff],
            "ku_invalid_tail" => vec![24, 0, 0, 1, 2, 24, 0, 0, 1, 0],
            "ku_valid1" | "ku_request_overflow" => vec![24, 0, 0, 1, 1],
            _ => vec![24, 0, 0, 1, 0],
        };
        let protect = |sequence, bytes: &[u8]| {
            let mut inner = bytes.to_vec();
            inner.push(22);
            let mut record = vec![23, 3, 3];
            record.extend_from_slice(&((inner.len() + 16) as u16).to_be_bytes());
            record.extend_from_slice(&server_cipher.encrypt(sequence, &record, &inner).unwrap());
            record
        };
        let mut output = if case.scenario == "ku_fragmented0" {
            let mut first = protect(0, &message[..2]);
            first.extend_from_slice(&protect(1, &message[2..]));
            first
        } else {
            protect(0, &message)
        };
        if valid_update || case.scenario == "ku_request_overflow" {
            server.refresh_traffic_keys().unwrap();
            let generated = outgoing(&mut server, false).0;
            assert_eq!(
                server_cipher
                    .decrypt(0, &generated[..5], &generated[5..])
                    .unwrap(),
                [24, 0, 0, 1, 1, 22]
            );
            if valid_update {
                server.writer().write_all(RESPONSE)?;
                server.send_close_notify();
                output.extend_from_slice(&outgoing(&mut server, false).0);
            } else {
                output.extend_from_slice(&[23, 3, 3, 0xff, 0xff]);
            }
        }
        output
    } else if version_probe {
        if case.scenario == "major_overflow" {
            vec![23, 4, 3, 0xff, 0xff]
        } else {
            let version = if case.scenario.starts_with("minor_") {
                0x0301u16
            } else if case.scenario == "future_retag" {
                0x0304
            } else {
                0x0403
            };
            let mut inner = RESPONSE.to_vec();
            inner.push(23);
            let mut record = vec![23];
            record.extend_from_slice(&version.to_be_bytes());
            record.extend_from_slice(&((inner.len() + 16) as u16).to_be_bytes());
            let mut aad = record.clone();
            if case.scenario == "minor_flip" {
                aad[1..3].copy_from_slice(&[3, 3]);
            }
            record.extend_from_slice(&server_cipher.encrypt(0, &aad, &inner).unwrap());
            let close_header = [23, 3, 3, 0, 19];
            record.extend_from_slice(&close_header);
            record.extend_from_slice(
                &server_cipher
                    .encrypt(1, &close_header, &[1, 0, 21])
                    .unwrap(),
            );
            record
        }
    } else if matches!(
        case.scenario,
        "bad_tag" | "short_tag" | "wrong_nonce" | "missing_type"
    ) {
        if case.scenario == "short_tag" {
            plain_record(23, &[0; 15])
        } else {
            let inner: &[u8] = if case.scenario == "missing_type" {
                &[0, 0]
            } else {
                b"record-probe\x17"
            };
            let mut record = vec![23, 3, 3];
            record.extend_from_slice(&((inner.len() + 16) as u16).to_be_bytes());
            let encrypted = server_cipher
                .encrypt(u64::from(case.scenario == "wrong_nonce"), &record, inner)
                .unwrap();
            record.extend_from_slice(&encrypted);
            if case.scenario == "bad_tag" {
                *record.last_mut().unwrap() ^= 1;
            }
            record
        }
    } else if case.scenario == "protected" {
        let header = [23, 3, 3, 0, 18];
        let mut record = header.to_vec();
        record.extend_from_slice(&server_cipher.encrypt(0, &header, &[1, 20]).unwrap());
        record
    } else {
        plain_record(
            20,
            if case.scenario == "malformed" {
                &[2]
            } else {
                &[1]
            },
        )
    };
    socket.write_all(&injected).await?;
    if valid_update {
        socket.shutdown().await?;
        let mut updated_client = false;
        for _ in 0..4 {
            let Ok(Ok(record)) =
                tokio::time::timeout(Duration::from_secs(2), read_record(&mut socket)).await
            else {
                break;
            };
            assert_eq!(record[0], 23);
            if !updated_client {
                let inner = client_cipher
                    .decrypt(application_sequence, &record[..5], &record[5..])
                    .unwrap();
                application_sequence += 1;
                if inner == [24, 0, 0, 1, 0, 22] {
                    observed.key_update_response = Some(0);
                    observed.key_update_response_hex = Some(lktls::crypto::to_hex(&record));
                    updated_client = true;
                } else {
                    assert_eq!(inner, [1, 0, 21]);
                }
            }
            server.read_tls(&mut std::io::Cursor::new(record))?;
            if server
                .process_new_packets()
                .map_err(std::io::Error::other)?
                .peer_has_closed()
            {
                break;
            }
        }
        observed.normal_response_sent = true;
        return Ok(observed);
    }
    for _ in 0..4 {
        let Ok(Ok(record)) =
            tokio::time::timeout(Duration::from_secs(2), read_record(&mut socket)).await
        else {
            break;
        };
        assert_eq!(record[0], 23);
        let inner = client_cipher
            .decrypt(application_sequence, &record[..5], &record[5..])
            .unwrap();
        observed.record_types.push(23);
        observed
            .record_versions
            .push(u16::from_be_bytes([record[1], record[2]]));
        observed.record_lengths.push(record.len() - 5);
        observed
            .flight_hex
            .push_str(&lktls::crypto::to_hex(&record));
        server.read_tls(&mut std::io::Cursor::new(&record))?;
        if inner == [24, 0, 0, 1, 0, 22] {
            observed.key_update_response = Some(0);
            observed.key_update_response_hex = Some(lktls::crypto::to_hex(&record));
            server
                .process_new_packets()
                .map_err(std::io::Error::other)?;
            client_secret = hkdf_expand_label(
                HkdfAlgorithm::Sha256,
                &client_secret,
                "traffic upd",
                &[],
                32,
            )
            .unwrap();
            let key =
                hkdf_expand_label(HkdfAlgorithm::Sha256, &client_secret, "key", &[], 16).unwrap();
            let iv =
                hkdf_expand_label(HkdfAlgorithm::Sha256, &client_secret, "iv", &[], 12).unwrap();
            client_cipher = Aead::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap();
            application_sequence = 0;
            continue;
        }
        assert_eq!(inner.len(), 3);
        assert_eq!(inner[2], 21);
        assert!(inner[0] == 2 || (version_probe && inner[..2] == [1, 0]));
        observed.alerts.push([inner[0], inner[1]]);
        if inner[1] == 0 {
            assert!(server.process_new_packets().unwrap().peer_has_closed());
            observed.rustls_alert = Some(0);
        } else {
            let error = server
                .process_new_packets()
                .expect_err("Rustls must independently authenticate the fatal alert");
            let rustls::Error::AlertReceived(description) = error else {
                panic!("unexpected Rustls result: {error}");
            };
            observed.rustls_alert = Some(u8::from(description));
        }
        assert_eq!(observed.rustls_alert, Some(inner[1]));
        break;
    }
    Ok(observed)
}

fn cipher_from_secret(secret: &[u8]) -> Aead {
    let key = hkdf_expand_label(HkdfAlgorithm::Sha256, secret, "key", &[], 16).unwrap();
    let iv = hkdf_expand_label(HkdfAlgorithm::Sha256, secret, "iv", &[], 12).unwrap();
    Aead::new(AeadAlgorithm::Aes128Gcm, &key, &iv).unwrap()
}

fn next_secret(secret: &[u8]) -> Vec<u8> {
    hkdf_expand_label(HkdfAlgorithm::Sha256, secret, "traffic upd", &[], 32).unwrap()
}

fn protect_record(cipher: &Aead, sequence: u64, kind: u8, body: &[u8]) -> Vec<u8> {
    let mut inner = body.to_vec();
    inner.push(kind);
    let mut record = vec![23, 3, 3];
    record.extend_from_slice(&((inner.len() + 16) as u16).to_be_bytes());
    record.extend_from_slice(&cipher.encrypt(sequence, &record, &inner).unwrap());
    record
}

async fn observe_repeated_key_updates(
    mut socket: tokio::net::TcpStream,
    mut server: rustls::ServerConnection,
    case: Case,
    mut observed: Observation,
    ciphers: Arc<ApplicationCiphers>,
) -> std::io::Result<Observation> {
    let (mut client_secret, mut server_secret) = {
        let mut secrets = ciphers.0.lock().unwrap();
        (
            std::mem::take(&mut secrets.client_secret),
            std::mem::take(&mut secrets.server_secret),
        )
    };
    let (count, request) = match case.scenario {
        "repeat0_2" => (2, 0),
        "repeat1_2" | "repeat1_2_overflow" => (2, 1),
        "repeat1_32" | "repeat1_32_overflow" => (32, 1),
        "repeat1_33" | "repeat1_33_overflow" => (33, 1),
        "repeat0_33" => (33, 0),
        "repeat0_31_invalid" | "repeat0_31_ticket" => (31, 0),
        _ => (32, 0),
    };
    let extra_update = matches!(
        case.scenario,
        "repeat0_32_empty" | "repeat0_32_data" | "repeat0_32_ticket" | "repeat0_31_ticket"
    );
    let invalid_update = case.scenario.ends_with("_invalid");
    let overflow = case.scenario.ends_with("_overflow");
    let mut flight = Vec::new();
    for index in 0..count + usize::from(extra_update || invalid_update) {
        let cipher = cipher_from_secret(&server_secret);
        let mut sequence = 0;
        if index == count {
            let intermediate: Option<(u8, &[u8])> = match case.scenario {
                "repeat0_32_empty" => Some((23, &[])),
                "repeat0_32_data" => Some((23, &RESPONSE[..6])),
                "repeat0_32_ticket" | "repeat0_31_ticket" => Some((
                    22,
                    &[4, 0, 0, 14, 0, 0, 0, 60, 0, 0, 0, 0, 0, 0, 1, 0xaa, 0, 0],
                )),
                _ => None,
            };
            if let Some((kind, body)) = intermediate {
                flight.extend_from_slice(&protect_record(&cipher, sequence, kind, body));
                sequence += 1;
            }
        }
        let value = if index == count && invalid_update {
            2
        } else {
            request
        };
        flight.extend_from_slice(&protect_record(
            &cipher,
            sequence,
            22,
            &[24, 0, 0, 1, value],
        ));

        // Independently verify each derived server epoch against Rustls output.
        server.refresh_traffic_keys().unwrap();
        let native = outgoing(&mut server, false).0;
        assert_eq!(
            cipher.decrypt(0, &native[..5], &native[5..]).unwrap(),
            [24, 0, 0, 1, 1, 22]
        );
        server_secret = next_secret(&server_secret);
    }
    if overflow {
        flight.extend_from_slice(&[23, 3, 3, 0xff, 0xff]);
    } else {
        server
            .writer()
            .write_all(if case.scenario == "repeat0_32_data" {
                &RESPONSE[6..]
            } else {
                RESPONSE
            })?;
        server.send_close_notify();
        flight.extend_from_slice(&outgoing(&mut server, false).0);
        observed.normal_response_sent = true;
    }
    socket.write_all(&flight).await?;
    socket.shutdown().await?;
    let mut sequence = observed.client_application_records;
    for _ in 0..70 {
        let Ok(Ok(record)) =
            tokio::time::timeout(Duration::from_secs(2), read_record(&mut socket)).await
        else {
            break;
        };
        assert_eq!(record[0], 23);
        let inner = cipher_from_secret(&client_secret)
            .decrypt(sequence, &record[..5], &record[5..])
            .unwrap();
        observed.record_types.push(23);
        observed
            .record_versions
            .push(u16::from_be_bytes([record[1], record[2]]));
        observed.record_lengths.push(record.len() - 5);
        let hex = lktls::crypto::to_hex(&record);
        observed.flight_hex.push_str(&hex);
        server.read_tls(&mut std::io::Cursor::new(&record))?;
        if inner == [24, 0, 0, 1, 0, 22] {
            server
                .process_new_packets()
                .map_err(std::io::Error::other)?;
            observed.key_update_responses.push(hex);
            client_secret = next_secret(&client_secret);
            sequence = 0;
        } else {
            assert_eq!(inner.len(), 3);
            assert_eq!(inner[2], 21);
            observed.alerts.push([inner[0], inner[1]]);
            if inner[1] == 0 {
                assert!(server.process_new_packets().unwrap().peer_has_closed());
            } else {
                let rustls::Error::AlertReceived(description) =
                    server.process_new_packets().unwrap_err()
                else {
                    panic!("invalid peer alert")
                };
                assert_eq!(u8::from(description), inner[1]);
                observed.rustls_alert = Some(inner[1]);
            }
            break;
        }
    }
    Ok(observed)
}

async fn library_request(
    address: std::net::SocketAddr,
    case: Case,
    cert: &[u8],
) -> std::io::Result<Vec<u8>> {
    let profile = if case.browser == "chrome" {
        presets::chrome_155()
    } else {
        presets::firefox_156()
    };
    let anchor = lktls::verify::certchain::parse_trust_anchor_from_der(cert).unwrap();
    let connector = TlsConnector::new(profile).custom_ca_anchors(Arc::new(vec![anchor]));
    let socket = tokio::net::TcpStream::connect(address).await?;
    let mut stream = connector
        .connect("127.0.0.1", address.port(), socket)
        .await
        .map_err(std::io::Error::other)?;
    assert_eq!(stream.negotiated_alpn(), Some("http/1.1"));
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    stream.flush().await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

#[tokio::test]
#[ignore = "Tier-1: isolated browser CCS after Finished capture"]
async fn local_browser_post_ccs_peer() {
    let fixture = fixture();
    println!(
        "{}",
        serde_json::json!({"fixture":"post_ccs", "spki_pin":fixture.spki_pin})
    );
    let library = std::env::var("TEST_BROWSER_ERROR_LIBRARY").ok().as_deref() == Some("1");
    let active_cases = match std::env::var("TEST_POST_CCS_SCENARIOS").ok().as_deref() {
        Some("auth") => auth_cases(),
        Some("version") => version_cases(),
        Some("key-update") => key_update_cases(),
        Some("key-update-repeat") => repeated_key_update_cases(),
        _ => cases(),
    };
    let mut peers = Vec::new();
    for case in active_cases.iter().copied() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, case.port))
            .await
            .unwrap();
        let config = fixture.config.clone();
        peers.push(tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(240), async {
                loop {
                    let (socket, _) = listener.accept().await.unwrap();
                    if let Ok(Ok(observed)) = tokio::time::timeout(
                        Duration::from_secs(5),
                        observe(socket, config.clone(), case, library),
                    )
                    .await
                    {
                        println!("{}", serde_json::to_string(&observed).unwrap());
                        break observed;
                    }
                }
            })
            .await
            .unwrap()
        }));
    }
    if library {
        for case in active_cases {
            let result = library_request(
                ([127, 0, 0, 1], case.port).into(),
                case,
                &fixture.certificate,
            )
            .await;
            if case.scenario.starts_with("repeat") {
                println!(
                    "{}",
                    serde_json::json!({
                        "library_result": case.port,
                        "body_verified": result.as_ref().is_ok_and(|body| body == RESPONSE),
                        "failed": result.is_err()
                    })
                );
            }
            if case.scenario.starts_with("normal_")
                || matches!(case.scenario, "ku_valid0" | "ku_valid1" | "ku_fragmented0")
            {
                assert_eq!(result.unwrap(), RESPONSE);
            }
        }
    }
    for peer in peers {
        let observed = peer.await.unwrap();
        assert!(observed.finished_verified && observed.request_received);
    }
}

async fn local_case(fixture: &Fixture, mut case: Case) -> (Observation, std::io::Result<Vec<u8>>) {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        case.port = address.port();
        let config = fixture.config.clone();
        let peer = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            observe(socket, config, case, true).await.unwrap()
        });
        let result = library_request(address, case, &fixture.certificate).await;
        (peer.await.unwrap(), result)
    })
    .await
    .expect("post-handshake CCS case timed out")
}

#[tokio::test]
async fn strict_http_controls_complete_with_and_without_handshake_ccs() {
    let fixture = fixture();
    for case in cases()
        .into_iter()
        .filter(|case| case.scenario.starts_with("normal_"))
    {
        let (observed, result) = local_case(&fixture, case).await;
        assert_eq!(result.unwrap(), RESPONSE);
        assert!(
            observed.finished_verified
                && observed.request_received
                && observed.normal_response_sent
        );
        assert_eq!(observed.handshake_ccs_sent, usize::from(case.handshake_ccs));
        assert!(observed.alerts.is_empty());
    }
}

#[tokio::test]
async fn post_finished_ccs_sends_the_browser_application_alert() {
    let fixture = fixture();
    for case in cases()
        .into_iter()
        .filter(|case| !case.scenario.starts_with("normal_"))
    {
        let (observed, result) = local_case(&fixture, case).await;
        assert!(
            result.is_err(),
            "invalid CCS must terminate the application read"
        );
        let description = if case.browser == "chrome" && case.scenario != "protected" {
            20
        } else {
            10
        };
        assert!(observed.finished_verified && observed.request_received);
        assert_eq!(observed.handshake_ccs_sent, usize::from(case.handshake_ccs));
        assert_eq!(observed.alerts, [[2, description]]);
        assert_eq!(observed.rustls_alert, Some(description));
        assert_eq!(observed.record_types, [23]);
        assert_eq!(observed.record_versions, [0x0303]);
        assert_eq!(observed.record_lengths, [19]);
    }
}

#[tokio::test]
async fn application_record_authentication_matches_browser_alerts() {
    let fixture = fixture();
    for case in auth_cases() {
        let (observed, result) = local_case(&fixture, case).await;
        assert!(observed.finished_verified && observed.request_received);
        if case.scenario.starts_with("normal_") {
            assert_eq!(result.unwrap(), RESPONSE);
            assert!(observed.alerts.is_empty());
        } else {
            assert!(result.is_err());
            let description = if case.scenario == "missing_type" {
                if case.browser == "chrome" {
                    51
                } else {
                    10
                }
            } else {
                20
            };
            assert_eq!(observed.alerts, [[2, description]]);
            assert_eq!(observed.rustls_alert, Some(description));
            assert_eq!(observed.record_types, [23]);
            assert_eq!(observed.record_versions, [0x0303]);
            assert_eq!(observed.record_lengths, [19]);
        }
    }
}

#[tokio::test]
async fn application_record_version_checks_match_browser_precedence() {
    let fixture = fixture();
    for case in version_cases() {
        let (observed, result) = local_case(&fixture, case).await;
        assert!(observed.finished_verified && observed.request_received);
        if case.scenario.starts_with("normal_") {
            assert_eq!(result.unwrap(), RESPONSE);
        } else {
            assert!(
                result.is_err(),
                "invalid record version must fail for {} {}",
                case.browser,
                case.scenario
            );
            let expected = if case.browser == "chrome" {
                70
            } else if case.scenario == "major_overflow" {
                22
            } else {
                20
            };
            assert_eq!(observed.alerts, [[2, expected]]);
            assert_eq!(observed.rustls_alert, Some(expected));
            assert_eq!(observed.record_types, [23]);
            assert_eq!(observed.record_versions, [0x0303]);
            assert_eq!(observed.record_lengths, [19]);
        }
    }
}

#[tokio::test]
async fn key_update_messages_and_boundaries_match_browsers() {
    let fixture = fixture();
    for case in key_update_cases() {
        let (observed, result) = local_case(&fixture, case).await;
        let positive = case.scenario.starts_with("normal_")
            || matches!(case.scenario, "ku_valid0" | "ku_valid1" | "ku_fragmented0");
        if positive {
            assert_eq!(
                result.unwrap(),
                RESPONSE,
                "{} {}",
                case.browser,
                case.scenario
            );
            assert!(observed.normal_response_sent);
            assert_eq!(
                observed.key_update_response,
                if case.browser == "firefox" && case.scenario == "ku_valid1" {
                    Some(0)
                } else {
                    None
                }
            );
        } else {
            assert!(
                result.is_err(),
                "invalid KeyUpdate must terminate the read: {} {}",
                case.browser,
                case.scenario
            );
            let expected = match case.scenario {
                "ku_double" | "ku_partial_tail" | "ku_bad_length_tail" => 10,
                "ku_request_overflow" => 22,
                _ => 50,
            };
            assert_eq!(
                observed.alerts,
                [[2, expected]],
                "{} {}",
                case.browser,
                case.scenario
            );
            assert_eq!(observed.rustls_alert, Some(expected));
            if case.scenario == "ku_request_overflow" {
                assert_eq!(observed.key_update_response, Some(0));
                assert_eq!(observed.record_lengths, [22, 19]);
            } else {
                assert_eq!(observed.key_update_response, None);
                assert_eq!(observed.record_lengths, [19]);
            }
        }
    }
}

#[tokio::test]
async fn repeated_key_updates_match_browser_limits_and_reply_coalescing() {
    let fixture = fixture();
    for case in repeated_key_update_cases() {
        let (observed, result) = local_case(&fixture, case).await;
        let expected_alert = if case.browser == "chrome"
            && matches!(
                case.scenario,
                "repeat0_33"
                    | "repeat1_33"
                    | "repeat0_32_empty"
                    | "repeat0_32_ticket"
                    | "repeat1_33_overflow"
                    | "repeat0_32_invalid"
            ) {
            Some(10)
        } else if case.scenario.ends_with("_overflow") {
            Some(22)
        } else if case.scenario.ends_with("_invalid") {
            Some(50)
        } else {
            None
        };
        assert_eq!(
            observed.rustls_alert, expected_alert,
            "{} {}",
            case.browser, case.scenario
        );
        if let Some(alert) = expected_alert {
            assert!(result.is_err());
            assert_eq!(observed.alerts, [[2, alert]]);
        } else {
            assert_eq!(
                result.unwrap(),
                RESPONSE,
                "{} {}",
                case.browser,
                case.scenario
            );
        }
        let replies = usize::from(
            case.scenario.starts_with("repeat1")
                && (case.browser == "firefox" || expected_alert.is_some()),
        );
        assert_eq!(
            observed.key_update_responses.len(),
            replies,
            "{} {}",
            case.browser,
            case.scenario
        );
    }
}
