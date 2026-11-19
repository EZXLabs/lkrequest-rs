//! Tier 1: independent TLS 1.2 signature and repeated-resumption interoperability.
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lktls::handshake::driver::{HandshakeConfig, HandshakeDriver, HandshakeOutput};
use lktls::profile::{presets, types::TlsVersion};
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
fn strict_legacy_signatures_and_repeated_ticket_and_session_id_resumption() {
    let openssl = std::env::var_os("TEST_OPENSSL").expect("TEST_OPENSSL");
    let directory = std::env::temp_dir().join(format!("issue29-openssl-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    for (scheme, sigalgs, rsa, no_ticket) in [
        (0x0203u16, "ECDSA+SHA1", false, false),
        (0x0603, "ECDSA+SHA512", false, false),
        (0x0201, "RSA+SHA1", true, false),
        (0x0401, "RSA+SHA256", true, true),
    ] {
        let key = rcgen::KeyPair::generate_for(if rsa {
            &rcgen::PKCS_RSA_SHA256
        } else {
            &rcgen::PKCS_ECDSA_P256_SHA256
        })
        .unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cert_path = directory.join("cert.pem");
        let key_path = directory.join("key.pem");
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        if scheme == 0x0201 || scheme == 0x0203 {
            let content = b"TLS 1.2 ServerKeyExchange signature control";
            let message_path = directory.join("message.bin");
            std::fs::write(&message_path, content).unwrap();
            let mut sign = Command::new(&openssl);
            sign.args(["dgst", "-sha1", "-sign"])
                .arg(&key_path)
                .arg(&message_path);
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                sign.creation_flags(0x08000000);
            }
            let output = sign.output().unwrap();
            assert!(output.status.success());
            let verify = |message: &[u8], signature: &[u8]| {
                certchain::verify_server_key_exchange_signature(
                    cert.der(),
                    scheme,
                    message,
                    signature,
                )
            };
            verify(content, &output.stdout).unwrap();
            assert!(verify(b"altered message", &output.stdout).is_err());
            assert!(certchain::verify_certificate_verify(
                scheme,
                cert.der(),
                &[0x42; 32],
                &output.stdout
            )
            .is_err());
            let mut corrupted = output.stdout;
            *corrupted.last_mut().unwrap() ^= 1;
            assert!(verify(content, &corrupted).is_err());
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
                "-tls1_2",
                "-www",
                "-quiet",
                "-naccept",
                "4",
                "-sigalgs",
                sigalgs,
                "-cipher",
                if rsa {
                    "ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0"
                } else {
                    "ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=0"
                },
            ])
            .arg("-cert")
            .arg(&cert_path)
            .arg("-key")
            .arg(&key_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        if no_ticket {
            command.arg("-no_ticket");
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let _server = Server(command.spawn().unwrap());
        let mut profile = if no_ticket {
            presets::safari_26()
        } else {
            presets::firefox_156()
        };
        profile.tls_min_version = TlsVersion::Tls12;
        profile.tls_max_version = TlsVersion::Tls12;
        profile.cipher_suites = vec![if rsa { 0xc02f } else { 0xc02b }];
        profile.signature_algorithms = vec![scheme];
        profile.extensions.retain(|extension| {
            [0, 5, 10, 11, 13, 16, 18, 23, 35, 0xff01].contains(&extension.extension_type)
        });
        let store = Arc::new(InMemorySessionStore::new());
        let trust = Arc::new(vec![
            certchain::parse_trust_anchor_from_der(cert.der()).unwrap()
        ]);
        for attempt in 0..4 {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match TcpStream::connect(address) {
                    Ok(socket) => break socket,
                    Err(error) if Instant::now() >= deadline => panic!("server startup: {error}"),
                    Err(_) => std::thread::sleep(Duration::from_millis(20)),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut driver = HandshakeDriver::new(HandshakeConfig {
                profile: profile.clone(),
                hostname: "localhost".into(),
                port: address.port(),
                verification_policy: VerificationPolicy::Strict,
                custom_ca_anchors: Some(trust.clone()),
                session_store: Some(store.clone()),
                alps_payload: None,
                ech_config_list: None,
                keylog_callback: None,
                client_hello_callback: None,
                trust_anchor_observer: None,
            });
            socket.write_all(&driver.start().unwrap()).unwrap();
            let mut input = [0; 16384];
            let mut result = loop {
                match driver.progress().unwrap_or_else(|error| {
                    panic!("{sigalgs} no_ticket={no_ticket} attempt={attempt}: {error}")
                }) {
                    HandshakeOutput::SendData(bytes) => socket.write_all(&bytes).unwrap(),
                    HandshakeOutput::NeedData => {
                        let n = socket.read(&mut input).unwrap();
                        assert!(n > 0, "EOF during handshake");
                        driver.feed(&input[..n]);
                    }
                    HandshakeOutput::Done { to_send, result } => {
                        socket.write_all(&to_send).unwrap();
                        break result;
                    }
                }
            };
            assert_eq!(
                result.peer_certificates.is_empty(),
                attempt > 0,
                "{sigalgs} no_ticket={no_ticket} attempt={attempt} did not resume"
            );
            socket
                .write_all(
                    &result
                        .writer
                        .write_record(23, b"GET / HTTP/1.0\r\n\r\n")
                        .unwrap(),
                )
                .unwrap();
            loop {
                if let Some(record) = result.reader.next_record().unwrap() {
                    assert!(record.payload.starts_with(b"HTTP/1.0 200 ok"));
                    break;
                }
                let n = socket.read(&mut input).unwrap();
                assert!(n > 0, "EOF before HTTP response");
                result.reader.feed(&input[..n]);
            }
            eprintln!("{sigalgs} no_ticket={no_ticket} attempt={attempt}: strict handshake and HTTP passed");
        }
    }
    std::fs::remove_dir_all(directory).unwrap();
}
