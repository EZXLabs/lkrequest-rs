//! Tier 1: independent local suite/EtM interoperability. Requires TEST_OPENSSL.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lktls::handshake::driver::{HandshakeConfig, HandshakeDriver, HandshakeOutput};
use lktls::profile::{
    presets,
    types::{ExtensionSource, ExtensionSpec, TlsVersion},
};
use lktls::session_store::InMemorySessionStore;
use lktls::verify::{certchain, policy::VerificationPolicy};

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "Tier 1: set TEST_OPENSSL to an OpenSSL executable"]
fn all_tls12_suites_full_and_resumed_with_both_cbc_mac_orders() {
    assert_eq!(run_matrix(false, false), 64);
}

#[test]
#[ignore = "Tier 1: set TEST_OPENSSL to an OpenSSL executable"]
fn p384_certificate_with_sha256_server_key_exchange() {
    assert_eq!(run_matrix(true, false), 2);
}

#[test]
#[ignore = "Tier 1: set TEST_OPENSSL to an OpenSSL executable"]
fn tls13_all_aead_suites_full_and_resumed() {
    assert_eq!(run_matrix(false, true), 6);
}

fn run_matrix(cross_curve: bool, tls13: bool) -> usize {
    let openssl = std::env::var_os("TEST_OPENSSL").expect("TEST_OPENSSL is required");
    let directory = std::env::temp_dir().join(format!(
        "lktls-suite-{cross_curve}-{tls13}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let key = rcgen::KeyPair::generate_for(if cross_curve {
        &rcgen::PKCS_ECDSA_P384_SHA384
    } else {
        &rcgen::PKCS_ECDSA_P256_SHA256
    })
    .unwrap();
    let certificate = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_path = directory.join("certificate.pem");
    let key_path = directory.join("key.pem");
    std::fs::write(&cert_path, certificate.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    let trust = Arc::new(vec![certchain::parse_trust_anchor_from_der(
        certificate.der(),
    )
    .unwrap()]);

    let rsa_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
    let rsa_certificate = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&rsa_key)
        .unwrap();
    let rsa_cert_path = directory.join("rsa-certificate.pem");
    let rsa_key_path = directory.join("rsa-key.pem");
    std::fs::write(&rsa_cert_path, rsa_certificate.pem()).unwrap();
    std::fs::write(&rsa_key_path, rsa_key.serialize_pem()).unwrap();
    let rsa_trust = Arc::new(vec![certchain::parse_trust_anchor_from_der(
        rsa_certificate.der(),
    )
    .unwrap()]);

    let mut handshakes = 0;
    for (suite, cipher, rsa, mac_len) in [
        (0xc009, "ECDHE-ECDSA-AES128-SHA", false, 20),
        (0xc00a, "ECDHE-ECDSA-AES256-SHA", false, 20),
        (0xc023, "ECDHE-ECDSA-AES128-SHA256", false, 32),
        (0xc024, "ECDHE-ECDSA-AES256-SHA384", false, 48),
        (0xc013, "ECDHE-RSA-AES128-SHA", true, 20),
        (0xc014, "ECDHE-RSA-AES256-SHA", true, 20),
        (0xc027, "ECDHE-RSA-AES128-SHA256", true, 32),
        (0xc028, "ECDHE-RSA-AES256-SHA384", true, 48),
        (0x002f, "AES128-SHA", true, 20),
        (0x0035, "AES256-SHA", true, 20),
        (0x003c, "AES128-SHA256", true, 32),
        (0x003d, "AES256-SHA256", true, 32),
        (0xc02b, "ECDHE-ECDSA-AES128-GCM-SHA256", false, 0),
        (0xc02c, "ECDHE-ECDSA-AES256-GCM-SHA384", false, 0),
        (0xc02f, "ECDHE-RSA-AES128-GCM-SHA256", true, 0),
        (0xc030, "ECDHE-RSA-AES256-GCM-SHA384", true, 0),
        (0x009c, "AES128-GCM-SHA256", true, 0),
        (0x009d, "AES256-GCM-SHA384", true, 0),
        (0xcca9, "ECDHE-ECDSA-CHACHA20-POLY1305", false, 0),
        (0xcca8, "ECDHE-RSA-CHACHA20-POLY1305", true, 0),
        (0x1301, "TLS_AES_128_GCM_SHA256", false, 0),
        (0x1302, "TLS_AES_256_GCM_SHA384", false, 0),
        (0x1303, "TLS_CHACHA20_POLY1305_SHA256", false, 0),
    ] {
        if (0x1301..=0x1303).contains(&suite) != tls13 {
            continue;
        }
        if cross_curve && suite != 0xc02b {
            continue;
        }
        for etm in [false, true] {
            if etm && mac_len == 0 {
                continue;
            }
            let address = TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap();
            let mut command = Command::new(&openssl);
            command
                .args([
                    "s_server",
                    "-accept",
                    &address.to_string(),
                    if tls13 { "-tls1_3" } else { "-tls1_2" },
                    if tls13 { "-ciphersuites" } else { "-cipher" },
                    cipher,
                    "-www",
                    "-quiet",
                    "-naccept",
                    "2",
                ])
                .arg("-cert")
                .arg(if rsa { &rsa_cert_path } else { &cert_path })
                .arg("-key")
                .arg(if rsa { &rsa_key_path } else { &key_path })
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit());
            if cross_curve {
                command.args(["-sigalgs", "ECDSA+SHA256"]);
            }
            if !etm {
                command.arg("-no_etm");
            }
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                command.creation_flags(0x08000000);
            }
            let _server = Server(command.spawn().unwrap());
            let mut profile = presets::chrome_144();
            profile.tls_min_version = if tls13 {
                TlsVersion::Tls13
            } else {
                TlsVersion::Tls12
            };
            profile.tls_max_version = profile.tls_min_version;
            profile.cipher_suites = vec![suite];
            profile.extensions.retain(|e| {
                [0, 5, 10, 11, 13, 16, 18, 23, 35, 0xff01].contains(&e.extension_type)
                    || (tls13 && [43, 45, 51].contains(&e.extension_type))
            });
            if !tls13 {
                profile.extensions.push(ExtensionSpec {
                    extension_type: 22,
                    source: ExtensionSource::RawBytes {
                        data: String::new(),
                    },
                });
            }
            let store = Arc::new(InMemorySessionStore::new());
            for resumed in [false, true] {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut socket = loop {
                    match TcpStream::connect(address) {
                        Ok(stream) => break stream,
                        Err(error) if Instant::now() >= deadline => {
                            panic!("OpenSSL startup: {error}")
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(20)),
                    }
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let config = HandshakeConfig {
                    profile: profile.clone(),
                    hostname: "localhost".into(),
                    port: address.port(),
                    verification_policy: VerificationPolicy::Strict,
                    custom_ca_anchors: Some(if rsa {
                        rsa_trust.clone()
                    } else {
                        trust.clone()
                    }),
                    session_store: Some(store.clone()),
                    alps_payload: None,
                    ech_config_list: None,
                    keylog_callback: None,
                    client_hello_callback: None,
                    trust_anchor_observer: None,
                };
                let mut driver = HandshakeDriver::new(config);
                socket.write_all(&driver.start().unwrap()).unwrap();
                let mut input = [0; 16384];
                let mut captured = Vec::new();
                let mut result = loop {
                    match driver
                        .progress()
                        .unwrap_or_else(|e| panic!("{cipher} etm={etm} resumed={resumed}: {e}"))
                    {
                        HandshakeOutput::SendData(bytes) => socket.write_all(&bytes).unwrap(),
                        HandshakeOutput::NeedData => {
                            let count = socket.read(&mut input).unwrap();
                            assert!(
                                count > 0,
                                "premature EOF: {cipher}, etm={etm}, resumed={resumed}"
                            );
                            driver.feed(&input[..count]);
                            captured.extend_from_slice(&input[..count]);
                        }
                        HandshakeOutput::Done { to_send, result } => {
                            socket.write_all(&to_send).unwrap();
                            break result;
                        }
                    }
                };
                assert_eq!(result.negotiated_cipher_suite, Some(suite));
                assert_eq!(result.peer_certificates.is_empty(), resumed);
                assert_eq!(
                    result.negotiated_version,
                    Some(if tls13 { 0x0304 } else { 0x0303 })
                );
                if cross_curve && !resumed {
                    assert_eq!(server_key_exchange_scheme(&captured), 0x0403);
                }
                let bytes = result
                    .writer
                    .write_record(23, b"GET / HTTP/1.0\r\n\r\n")
                    .unwrap();
                let expected_length = if tls13 {
                    18 + 1 + 16
                } else if mac_len == 0 {
                    if matches!(suite, 0xcca8 | 0xcca9) {
                        18 + 16
                    } else {
                        18 + 8 + 16
                    }
                } else if etm {
                    16 + 32 + mac_len
                } else {
                    16 + ((18 + mac_len) / 16 + 1) * 16
                };
                assert_eq!(bytes.len() - 5, expected_length);
                socket.write_all(&bytes).unwrap();
                let mut post_handshake = lktls::handshake::framing::HandshakeDeframer::new(65536);
                let response = loop {
                    if let Some(record) = result.reader.next_record().unwrap() {
                        if tls13 && record.content_type == 22 {
                            post_handshake.push(&record.payload).unwrap();
                            while let Some(ticket) = post_handshake.take_message().unwrap() {
                                assert_eq!(ticket[0], 4);
                                result
                                    .session_ticket_ctx
                                    .as_ref()
                                    .unwrap()
                                    .process_new_session_ticket(&ticket);
                            }
                            continue;
                        }
                        assert_eq!(record.content_type, 23);
                        break record.payload;
                    }
                    let count = socket.read(&mut input).unwrap();
                    assert!(count > 0, "EOF before application response");
                    result.reader.feed(&input[..count]);
                };
                assert!(response.starts_with(b"HTTP/1.0 200 ok"));
                handshakes += 1;
                eprintln!("{cipher}: etm={etm}, resumed={resumed}: handshake + HTTP passed");
            }
        }
    }
    std::fs::remove_file(cert_path).unwrap();
    std::fs::remove_file(key_path).unwrap();
    std::fs::remove_file(rsa_cert_path).unwrap();
    std::fs::remove_file(rsa_key_path).unwrap();
    std::fs::remove_dir(directory).unwrap();
    handshakes
}

fn server_key_exchange_scheme(mut records: &[u8]) -> u16 {
    let mut messages = Vec::new();
    while records.len() >= 5 {
        let length = usize::from(u16::from_be_bytes([records[3], records[4]]));
        let (record, rest) = records.split_at(5 + length);
        if record[0] == 20 {
            break;
        }
        if record[0] == 22 {
            messages.extend_from_slice(&record[5..]);
        }
        records = rest;
    }
    let mut messages = messages.as_slice();
    while !messages.is_empty() {
        let length = lktls::handshake::framing::message_length(messages, 0xff_ffff)
            .unwrap()
            .unwrap();
        let (message, rest) = messages.split_at(length);
        if message[0] == 12 {
            let signature_offset = 8 + usize::from(message[7]);
            return u16::from_be_bytes([message[signature_offset], message[signature_offset + 1]]);
        }
        messages = rest;
    }
    panic!("no ServerKeyExchange in full ECDHE handshake");
}
