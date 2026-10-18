//! TLS 1.2 record encryption end-to-end test.
//!
//! Tests TLS 1.2 full handshake + encrypted data transfer against httpbin.org
//! (which negotiates TLS 1.2) and other servers.

use lkrequest::{TlsConnector, TlsStream};
use lktls::profile::presets;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_RETRIES: usize = 3;

#[tokio::test]
async fn local_tls12_authenticated_record_errors_emit_fatal_alerts() {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::time::Duration;

    tokio::time::timeout(Duration::from_secs(30), async {
        let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let mut completed = 0;
        for chacha in [false, true] {
            let mut provider = rustls::crypto::ring::default_provider();
            provider.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
            provider.cipher_suites = vec![if chacha {
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            } else { rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 }];
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS12]).unwrap().with_no_client_auth()
                .with_single_cert(vec![certificate.cert.der().clone()], rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()))).unwrap();
            let mut config = config;
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let config = Arc::new(config);
            for profile in [presets::chrome_155(), presets::firefox_156()] {
                for handshake in [true, false] {
                    for scenario in ["normal", "corrupt_tail", "short_record", "minor_flip", "major_overflow"] {
                        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                        let address = listener.local_addr().unwrap();
                        let config = Arc::clone(&config);
                        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
                        let peer = tokio::spawn(async move {
                            let (mut socket, _) = listener.accept().await.unwrap();
                            let mut server = rustls::ServerConnection::new(config).unwrap();
                            let mut encrypted = false;
                            let mut injected = false;
                            let mut request = Vec::new();
                            let mut responded = false;
                            loop {
                                let mut header = [0; 5];
                                if socket.read_exact(&mut header).await.is_err() { return None; }
                                let length = u16::from_be_bytes([header[3], header[4]]) as usize;
                                assert!(length < 18_432);
                                let mut record = header.to_vec(); record.resize(5 + length, 0);
                                socket.read_exact(&mut record[5..]).await.unwrap();
                                server.read_tls(&mut std::io::Cursor::new(record)).unwrap();
                                if let Err(error) = server.process_new_packets() {
                                    assert!(injected);
                                    assert_eq!(header[0], 21);
                                    assert_eq!(length, if chacha { 18 } else { 26 });
                                    let rustls::Error::AlertReceived(description) = error else { panic!("unexpected peer error: {error}"); };
                                    return Some(u8::from(description));
                                }
                                let mut plain = [0; 4096];
                                loop {
                                    match server.reader().read(&mut plain) {
                                        Ok(0) => break,
                                        Ok(n) => request.extend_from_slice(&plain[..n]),
                                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                                        Err(error) => panic!("peer read failed: {error}"),
                                    }
                                    assert!(request.len() < 16_384);
                                }
                                if request.ends_with(b"\r\n\r\n") && !responded && !injected {
                                    server.writer().write_all(response).unwrap();
                                    if scenario == "normal" { server.send_close_notify(); }
                                    responded = true;
                                }
                                let mut output = Vec::new();
                                while server.wants_write() { server.write_tls(&mut output).unwrap(); }
                                let mut offset = 0;
                                while offset < output.len() {
                                    let end = offset + 5 + u16::from_be_bytes([output[offset + 3], output[offset + 4]]) as usize;
                                    assert!(end <= output.len());
                                    let mut record = output[offset..end].to_vec();
                                    let kind = record[0];
                                    if encrypted && !injected && scenario != "normal" && kind == if handshake { 22 } else { 23 } {
                                        if scenario == "corrupt_tail" { *record.last_mut().unwrap() ^= 1; }
                                        else if scenario == "minor_flip" { record[1..3].copy_from_slice(&[3, 1]); }
                                        else if scenario == "major_overflow" { record = vec![kind, 4, 3, 0xff, 0xff]; }
                                        else {
                                            let short = if chacha { 15 } else { 23 };
                                            record.truncate(5); record[3..5].copy_from_slice(&(short as u16).to_be_bytes());
                                            record.resize(5 + short, 0);
                                        }
                                        injected = true;
                                    }
                                    socket.write_all(&record).await.unwrap();
                                    if kind == 20 { encrypted = true; }
                                    offset = end;
                                }
                                if responded && scenario == "normal" { return Some(0); }
                            }
                        });
                        let anchor = lktls::verify::certchain::parse_trust_anchor_from_der(certificate.cert.der()).unwrap();
                        let connector = TlsConnector::new(profile.clone()).custom_ca_anchors(Arc::new(vec![anchor]));
                        let result = async {
                            let socket = TcpStream::connect(address).await.unwrap();
                            let mut stream = connector.connect("127.0.0.1", address.port(), socket).await.map_err(|e| e.to_string())?;
                            assert_eq!(stream.negotiated_version(), Some(0x0303));
                            stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await.map_err(|e| e.to_string())?;
                            stream.flush().await.map_err(|e| e.to_string())?;
                            let mut body = Vec::new(); stream.read_to_end(&mut body).await.map_err(|e| e.to_string())?;
                            Ok::<_, String>(body)
                        }.await;
                        let alert = peer.await.unwrap();
                        if scenario == "normal" { assert_eq!(result.unwrap(), response); assert_eq!(alert, Some(0)); }
                        else {
                            assert!(result.is_err());
                            let expected = if matches!(scenario, "minor_flip" | "major_overflow") {
                                if profile.tls_client_hello_style == lktls::profile::types::TlsClientHelloStyle::ChromiumBoringssl { 70 }
                                else if scenario == "major_overflow" { 22 } else { 20 }
                            } else { 20 };
                            assert_eq!(alert, Some(expected));
                        }
                        completed += 1;
                    }
                }
            }
        }
        assert_eq!(completed, 40);
    }).await.expect("local TLS 1.2 record matrix timed out");
}

#[tokio::test]
#[ignore = "Tier-1: local OpenSSL record peer configured by TEST_TLS12_PEER_LOG"]
async fn local_openssl_tls12_record_client() {
    use base64::Engine;
    use std::sync::Arc;

    let peer_log = std::env::var("TEST_TLS12_PEER_LOG").expect("TEST_TLS12_PEER_LOG is required");
    let log = std::fs::read_to_string(peer_log).unwrap();
    let ready: serde_json::Value = log
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value.get("fixture").and_then(|v| v.as_str()) == Some("tls12_record"))
        .unwrap();
    let certificate = base64::engine::general_purpose::STANDARD
        .decode(ready["certificate_der"].as_str().unwrap())
        .unwrap();
    let anchor = lktls::verify::certchain::parse_trust_anchor_from_der(&certificate).unwrap();
    let request_size = std::env::var("TEST_TLS12_REQUEST_BYTES")
        .ok()
        .map(|value| value.parse::<usize>().unwrap());
    for case in ready["cases"].as_array().unwrap() {
        let port = case["port"].as_u64().unwrap() as u16;
        assert!((48820..=48859).contains(&port) || (48920..=48995).contains(&port));
        let profile = match case["browser"].as_str().unwrap() {
            "chrome" => presets::chrome_155(),
            "firefox" => presets::firefox_156(),
            _ => unreachable!(),
        };
        let connector =
            TlsConnector::new(profile).custom_ca_anchors(Arc::new(vec![anchor.clone()]));
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let socket = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
                .await
                .map_err(|e| e.to_string())?;
            let mut stream = connector
                .connect("127.0.0.1", port, socket)
                .await
                .map_err(|e| e.to_string())?;
            assert_eq!(stream.negotiated_version(), Some(0x0303));
            assert_eq!(stream.negotiated_alpn(), Some("http/1.1"));
            let request = if let Some(size) = request_size {
                assert!((63..=16_384).contains(&size));
                let mut request =
                    b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nX-Pad: ".to_vec();
                request.resize(size - 4, b'x');
                request.extend_from_slice(b"\r\n\r\n");
                assert_eq!(request.len(), size);
                request
            } else {
                b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec()
            };
            stream
                .write_all(&request)
                .await
                .map_err(|e| e.to_string())?;
            stream.flush().await.map_err(|e| e.to_string())?;
            let mut body = Vec::new();
            stream
                .read_to_end(&mut body)
                .await
                .map_err(|e| e.to_string())?;
            Ok::<_, String>(body)
        })
        .await
        .expect("OpenSSL record case timed out");
        if case["scenario"] == "long_padding" {
            let response = outcome.unwrap();
            assert_eq!(response.len(), 16_384);
            assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
            assert!(response.ends_with(b"ccs-control-ok"));
        } else if case["scenario"] == "normal" {
            assert_eq!(outcome.unwrap(), b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 14\r\nConnection: close\r\n\r\nccs-control-ok");
        } else if ready["family"] == "version" {
            let body_verified = outcome
                .as_ref()
                .is_ok_and(|body| body.ends_with(b"ccs-control-ok"));
            println!(
                "{}",
                serde_json::json!({"version_case":port, "body_verified":body_verified, "failed":outcome.is_err()})
            );
        } else {
            assert!(outcome.is_err());
        }
        println!(
            "{}",
            serde_json::json!({"client_case":port, "scenario":case["scenario"], "completed":true})
        );
    }
}

/// Try to establish a TCP + TLS connection with retries.
///
/// Retries up to `MAX_RETRIES` times on TCP connect or TLS handshake failure
/// to tolerate transient server issues. Returns `None` (with SKIP message)
/// only when all attempts are exhausted.
async fn connect_with_retry(
    connector: &TlsConnector,
    host: &str,
    port: u16,
    addr: &str,
) -> Option<TlsStream<TcpStream>> {
    let mut last_err = String::new();
    for attempt in 1..=MAX_RETRIES {
        let tcp = match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(tcp)) => tcp,
            Ok(Err(e)) => {
                last_err = format!("TCP connect error: {e}");
                println!("  attempt {attempt}/{MAX_RETRIES}: {last_err}");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
            Err(_) => {
                last_err = "TCP connect timed out".to_string();
                println!("  attempt {attempt}/{MAX_RETRIES}: {last_err}");
                continue;
            }
        };

        match connector.connect(host, port, tcp).await {
            Ok(tls) => return Some(tls),
            Err(e) => {
                last_err = format!("TLS handshake failed: {e}");
                println!("  attempt {attempt}/{MAX_RETRIES}: {last_err}");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        }
    }
    println!("SKIP: {addr} all {MAX_RETRIES} attempts failed — last error: {last_err}");
    None
}

/// Test TLS 1.2 handshake + application data with httpbin.org (direct, no proxy).
///
/// httpbin.org typically negotiates TLS 1.2. This tests:
/// 1. TLS 1.2 handshake (with correct GCM record encryption)
/// 2. Sending an HTTP request (encrypted with TLS 1.2 record format)
/// 3. Reading the response (decrypted with TLS 1.2 record format)
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls12_httpbin_direct() {
    let profile = presets::chrome_144();
    let connector = TlsConnector::new(profile);

    let mut tls = match connect_with_retry(&connector, "httpbin.org", 443, "httpbin.org:443").await
    {
        Some(tls) => tls,
        None => return,
    };

    let alpn = tls.negotiated_alpn().map(|s| s.to_string());
    println!("httpbin.org ALPN: {:?}", alpn);

    // Send a request appropriate for the negotiated ALPN
    let request = if alpn.as_deref() == Some("h2") {
        // H2 preface — server should respond with H2 SETTINGS
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice()
    } else {
        b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            .as_slice()
    };
    tls.write_all(request).await.expect("TLS write failed");
    tls.flush().await.expect("TLS flush failed");

    // Read the response — we just need to verify data flows over the encrypted connection
    let mut buf = [0u8; 4096];
    match tokio::time::timeout(std::time::Duration::from_secs(10), tls.read(&mut buf)).await {
        Ok(Ok(n)) => {
            assert!(n > 0, "httpbin.org closed connection without data");
            println!("httpbin.org: received {n} bytes (TLS data transfer works)");
            println!("=== PASSED: httpbin.org TLS handshake + data transfer ===");
        }
        Ok(Err(e)) => panic!("httpbin.org TLS read failed: {e}"),
        Err(_) => panic!("httpbin.org response timed out"),
    }
}

/// Test TLS 1.2 record encryption against badssl.com TLS 1.2 endpoint.
///
/// tls-v1-2.badssl.com:1012 ONLY supports TLS 1.2, forcing our code to use
/// the TLS 1.2 record encryption path (GCM nonce, AAD, explicit nonce).
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls12_badssl_forced() {
    let profile = presets::chrome_144();
    let connector = TlsConnector::new(profile).insecure_skip_verify(true);

    let mut tls = match connect_with_retry(
        &connector,
        "tls-v1-2.badssl.com",
        1012,
        "tls-v1-2.badssl.com:1012",
    )
    .await
    {
        Some(tls) => tls,
        None => return,
    };

    let alpn = tls.negotiated_alpn().map(|s| s.to_string());
    println!("tls-v1-2.badssl.com ALPN: {:?}", alpn);

    // Send HTTP/1.1 request
    let request = b"GET / HTTP/1.1\r\nHost: tls-v1-2.badssl.com:1012\r\nConnection: close\r\n\r\n";
    tls.write_all(request).await.expect("TLS write failed");
    tls.flush().await.expect("TLS flush failed");

    let mut response = Vec::new();
    match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tls.read_to_end(&mut response),
    )
    .await
    {
        Ok(Ok(n)) => {
            println!("tls-v1-2.badssl.com: received {n} bytes");
            let text = String::from_utf8_lossy(&response);
            println!(
                "Response (first 500 chars): {}",
                &text[..text.len().min(500)]
            );
            assert!(n > 0, "Should receive data");
            assert!(
                text.contains("HTTP/1") || text.contains("html") || text.contains("tls-v1-2"),
                "Should get an HTTP response"
            );
            println!(
                "=== PASSED: TLS 1.2 badssl.com full request (record encryption verified) ==="
            );
        }
        Ok(Err(e)) => panic!("Read error: {e}"),
        Err(_) => panic!("Read timeout"),
    }
}

/// Test TLS 1.2 full data transfer with a server known to work.
///
/// This connects to tls.browserleaks.com and sends an HTTP request.
/// The server negotiates whatever version it prefers (1.2 or 1.3).
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls_data_transfer_browserleaks() {
    let profile = presets::chrome_144();
    let connector = TlsConnector::new(profile);

    let mut tls = match connect_with_retry(
        &connector,
        "tls.browserleaks.com",
        443,
        "tls.browserleaks.com:443",
    )
    .await
    {
        Some(tls) => tls,
        None => return,
    };

    let alpn = tls.negotiated_alpn().map(|s| s.to_string());
    println!("tls.browserleaks.com ALPN: {:?}", alpn);

    let request: &[u8] = if alpn.as_deref() == Some("h2") {
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    } else {
        b"GET /json HTTP/1.1\r\nHost: tls.browserleaks.com\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    };
    tls.write_all(request).await.expect("write failed");
    tls.flush().await.expect("flush failed");

    let mut buf = [0u8; 8192];
    match tokio::time::timeout(std::time::Duration::from_secs(10), tls.read(&mut buf)).await {
        Ok(Ok(n)) => {
            assert!(n > 0, "Should receive some data (got 0 bytes)");
            let text = String::from_utf8_lossy(&buf[..n]);
            println!("browserleaks: received {n} bytes");
            println!(
                "Response (first 500 chars): {}",
                &text[..text.len().min(500)]
            );
            assert!(n > 10, "Should receive substantial data");
            println!("=== PASSED: Full data transfer works ===");
        }
        Ok(Err(e)) => panic!("Read error: {e}"),
        Err(_) => panic!("Read timeout"),
    }
}
