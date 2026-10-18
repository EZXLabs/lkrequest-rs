//! End-to-end TLS 1.2 handshake tests.
//!
//! These tests verify that the TLS 1.2 handshake engine works correctly
//! with various servers. The Chrome 131/144 profile supports TLS 1.3 as
//! the preferred version, but the engine automatically falls back to
//! TLS 1.2 when the server selects it.
//!
//! Note: Most modern servers prefer TLS 1.3, so we test TLS 1.2 by
//! connecting to servers that support both and verifying the engine can
//! handle TLS 1.2 negotiation when it happens. We also test the auto-
//! negotiation logic.
//!
//! Public probes are ignored; the local regression requires no network access.

mod tls_support;
use tls_support::{tls_connect_with_retry, MAX_RETRIES};

use lkrequest::TlsConnector;
use lktls::profile::presets;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn local_tls12_alpn_full_and_resumed_connections_work() {
    use std::sync::Arc;
    use std::time::Duration;

    tokio::time::timeout(Duration::from_secs(15), async {
        for negotiate_alpn in [false, true] {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let anchor =
                lktls::verify::certchain::parse_trust_anchor_from_der(cert.cert.der()).unwrap();
            let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
            );
            let mut config = rustls::ServerConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .unwrap();
            if negotiate_alpn {
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
            }
            config.ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let mut kinds = Vec::new();
                for _ in 0..2 {
                    let (tcp, _) = listener.accept().await.unwrap();
                    let mut tls = acceptor.accept(tcp).await.unwrap();
                    assert_eq!(
                        tls.get_ref().1.protocol_version(),
                        Some(rustls::ProtocolVersion::TLSv1_2)
                    );
                    assert_eq!(
                        tls.get_ref().1.alpn_protocol(),
                        negotiate_alpn.then_some(b"http/1.1".as_slice())
                    );
                    kinds.push(tls.get_ref().1.handshake_kind().unwrap());
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        tls.read_exact(&mut byte).await.unwrap();
                        request.push(byte[0]);
                        assert!(request.len() < 16_384);
                    }
                    assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
                    tls.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                    )
                    .await
                    .unwrap();
                    tls.shutdown().await.unwrap();
                }
                kinds
            });
            let store = Arc::new(lktls::session_store::InMemorySessionStore::new());
            let connector = TlsConnector::new(presets::chrome_155())
                .custom_ca_anchors(Arc::new(vec![anchor]))
                .session_store(store);
            for resumed in [false, true] {
                let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
                let mut tls = connector
                    .connect("localhost", address.port(), tcp)
                    .await
                    .unwrap();
                assert_eq!(tls.negotiated_version(), Some(0x0303));
                assert_eq!(tls.negotiated_alpn(), negotiate_alpn.then_some("http/1.1"));
                assert_eq!(tls.peer_certificates().is_empty(), resumed);
                tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                let mut response = Vec::new();
                tls.read_to_end(&mut response).await.unwrap();
                assert_eq!(
                    response,
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
                );
            }
            assert_eq!(
                server.await.unwrap(),
                [rustls::HandshakeKind::Full, rustls::HandshakeKind::Resumed]
            );
        }
    })
    .await
    .expect("local TLS 1.2 ALPN/resumption test timed out");
}

#[tokio::test]
async fn local_invalid_tls12_choices_send_precise_alerts() {
    use lktls::error::{AlertDescription, TlsError};
    use std::time::Duration;

    tokio::time::timeout(Duration::from_secs(15), async {
        for case in 0..5 {
            let mut profile = presets::chrome_155();
            let expected = match case {
                0 => { profile.cipher_suites.retain(|suite| *suite != 0xc02f); AlertDescription::IllegalParameter },
                1 => AlertDescription::IllegalParameter,
                2 => { profile.tls_min_version = lktls::profile::types::TlsVersion::Tls13; AlertDescription::ProtocolVersion },
                3 => AlertDescription::DecodeError,
                _ => {
                    profile.extensions.iter_mut().find(|extension| extension.extension_type == 43).unwrap().source = lktls::profile::types::ExtensionSource::RawBytes { data: "020304".into() };
                    AlertDescription::ProtocolVersion
                }
            };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let peer = tokio::spawn(async move {
                let (mut tcp, _) = listener.accept().await.unwrap();
                let mut header = [0; 5];
                tcp.read_exact(&mut header).await.unwrap();
                assert_eq!(header[0], 22);
                let length = u16::from_be_bytes([header[3], header[4]]) as usize;
                assert!(length < 16_384);
                let mut client_hello = vec![0; length];
                tcp.read_exact(&mut client_hello).await.unwrap();
                assert_eq!(client_hello[0], 1);
                let sid_len = if case == 3 { 33 } else { 0 };
                let mut body = vec![3, 3];
                body.extend_from_slice(&[0x55; 32]);
                body.push(sid_len);
                body.extend(std::iter::repeat_n(0xa5, sid_len as usize));
                body.extend_from_slice(&[0xc0, 0x2f, if case == 1 { 1 } else { 0 }]);
                let mut message = vec![2, 0, 0, body.len() as u8];
                message.extend_from_slice(&body);
                let mut record = vec![22, 3, 3];
                record.extend_from_slice(&(message.len() as u16).to_be_bytes());
                record.extend_from_slice(&message);
                tcp.write_all(&record).await.unwrap();
                tcp.read_exact(&mut header).await.unwrap();
                assert_eq!(header[0], 21, "peer receives a TLS alert");
                assert_eq!(u16::from_be_bytes([header[3], header[4]]), 2);
                let mut alert = [0; 2];
                tcp.read_exact(&mut alert).await.unwrap();
                alert
            });
            let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
            let error = match TlsConnector::new(profile).connect("example.com", address.port(), tcp).await {
                Ok(_) => panic!("invalid ServerHello cannot produce a connection"),
                Err(error) => error,
            };
            assert!(matches!(error, TlsError::LocalAlert { alert, .. } if alert.description == expected), "case {case}");
            assert_eq!(peer.await.unwrap(), [2, expected.as_byte()], "case {case} wire alert");
        }
    }).await.expect("local TLS 1.2 scalar validation timed out");
}

/// Test that our TLS engine can complete a handshake with Cloudflare.
///
/// Cloudflare typically negotiates TLS 1.3, but this test verifies the
/// overall handshake pipeline works (including version negotiation).
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls_handshake_cloudflare() {
    let profile = presets::chrome_131();
    let connector = TlsConnector::new(profile);

    let mut tls = tls_connect_with_retry(&connector, "www.cloudflare.com", 443, MAX_RETRIES).await;
    assert!(tls.negotiated_cipher_suite().is_some());
    assert!(tls.negotiated_alpn().is_some());

    // Send an HTTP/1.1-ish request to verify the connection works.
    // Note: ALPN negotiated h2, so this will likely get an H2 error,
    // but we're testing TLS data transfer, not HTTP.
    let request = b"GET / HTTP/1.1\r\nHost: www.cloudflare.com\r\n\r\n";
    tls.write_all(request).await.expect("write failed");
    tls.flush().await.expect("flush failed");

    let mut buf = [0u8; 4096];
    match tokio::time::timeout(std::time::Duration::from_secs(5), tls.read(&mut buf)).await {
        Ok(Ok(n)) => println!("Received {n} bytes (TLS data transfer works)"),
        Ok(Err(e)) => println!("Read error (expected for h2 mismatch): {e}"),
        Err(_) => println!("Read timeout (expected for h2 mismatch)"),
    }

    println!("=== PASSED: Cloudflare handshake (auto-negotiate) ===");
}

/// Test TLS handshake with GitHub (typically negotiates TLS 1.3).
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls_handshake_github() {
    let profile = presets::chrome_131();
    let connector = TlsConnector::new(profile);

    let tls = tls_connect_with_retry(&connector, "github.com", 443, MAX_RETRIES).await;
    assert!(tls.negotiated_cipher_suite().is_some());
    assert!(tls.negotiated_alpn().is_some());

    println!("=== PASSED: GitHub handshake ===");
}

/// Test TLS handshake with tls.browserleaks.com (TLS 1.3 server).
///
/// This server is used for fingerprint analysis and always supports TLS 1.3.
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls_handshake_browserleaks() {
    let profile = presets::chrome_144();
    let connector = TlsConnector::new(profile);

    let tls = tls_connect_with_retry(&connector, "tls.browserleaks.com", 443, MAX_RETRIES).await;
    assert!(tls.negotiated_cipher_suite().is_some());
    assert!(tls.negotiated_alpn().is_some());

    println!("=== PASSED: browserleaks handshake ===");
}

/// Test TLS handshake in insecure mode (skip certificate verification).
///
/// This verifies the handshake state machine works independently of cert
/// verification.
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls_handshake_insecure_mode() {
    let profile = presets::chrome_144();
    let connector = TlsConnector::new(profile).insecure_skip_verify(true);

    let mut tls = tls_connect_with_retry(&connector, "www.google.com", 443, MAX_RETRIES).await;

    // Verify we can write and read data
    let request = b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n";
    tls.write_all(request).await.expect("write failed");
    tls.flush().await.expect("flush failed");

    let mut buf = [0u8; 4096];
    match tokio::time::timeout(std::time::Duration::from_secs(5), tls.read(&mut buf)).await {
        Ok(Ok(n)) => {
            assert!(n > 0, "should receive some data");
            println!("Received {n} bytes in insecure mode");
        }
        Ok(Err(e)) => println!("Read error (expected for h2): {e}"),
        Err(_) => println!("Timeout (expected for h2)"),
    }

    println!("=== PASSED: Insecure mode handshake ===");
}

/// Test that certificate verification correctly rejects mismatched hostnames.
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls_cert_verification_rejects_wrong_hostname() {
    use lktls::verify::policy::VerificationPolicy;

    let profile = presets::chrome_131();
    let connector = TlsConnector::new(profile).verification_policy(VerificationPolicy::Strict); // cert verification enabled

    // Connect to 1.1.1.1 (Cloudflare DNS) but claim hostname is "wrong.invalid"
    let tcp = tokio::net::TcpStream::connect("1.1.1.1:443")
        .await
        .expect("TCP connect failed");

    let result = connector.connect("wrong.invalid", 443, tcp).await;

    assert!(
        result.is_err(),
        "TLS handshake should fail with wrong hostname"
    );

    let err = result.unwrap_err();
    let err_msg = format!("{err}");
    println!("Expected error: {err_msg}");

    assert!(
        err_msg.contains("hostname")
            || err_msg.contains("certificate")
            || err_msg.contains("verify")
            || err_msg.contains("closed"),
        "error should indicate handshake rejection: {err_msg}"
    );

    println!("=== PASSED: Cert verification rejects wrong hostname ===");
}

/// Test TLS handshake with Chrome 144 profile (includes X25519MLKEM768 post-quantum).
///
/// Chrome 144 includes the post-quantum key exchange group X25519MLKEM768
/// in its key_share. This test verifies the complete handshake including
/// potential HRR (if server doesn't support the PQ group).
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls_chrome144_with_postquantum() {
    let profile = presets::chrome_144();
    let connector = TlsConnector::new(profile);

    // Chrome 144 key_share includes X25519MLKEM768 + X25519.
    // Cloudflare supports X25519MLKEM768, so this should succeed directly.
    // Other servers may send HRR requesting a different group.
    let tls = tls_connect_with_retry(&connector, "www.cloudflare.com", 443, MAX_RETRIES).await;
    assert!(tls.negotiated_cipher_suite().is_some());
    assert!(tls.negotiated_alpn().is_some());

    println!("=== PASSED: Chrome 144 post-quantum handshake ===");
}

/// Test connecting to multiple servers sequentially with the same profile.
///
/// This tests the robustness of the TLS engine across different server
/// configurations and certificate chains. Each server is retried up to
/// `MAX_RETRIES` times to tolerate transient network errors; failures
/// after retries are recorded but do not abort the remaining servers.
/// The test passes when at least half of the servers succeed.
#[tokio::test]
#[ignore = "Tier-2: public TLS endpoints"]
async fn test_tls_multiple_servers_robust() {
    let profile = presets::chrome_144();

    let servers = [
        ("www.cloudflare.com", 443),
        ("github.com", 443),
        ("www.google.com", 443),
        ("www.apple.com", 443),
        ("www.microsoft.com", 443),
        ("www.amazon.com", 443),
        ("www.mozilla.org", 443),
        ("one.one.one.one", 443),
    ];

    let mut passed = 0;
    let mut failed = 0;

    for (host, port) in &servers {
        let connector = TlsConnector::new(profile.clone());

        let result = async {
            let tcp = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tokio::net::TcpStream::connect(format!("{host}:{port}")),
            )
            .await
            .map_err(|_| "TCP connect timed out".to_string())?
            .map_err(|e| format!("TCP connect failed: {e}"))?;

            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                connector.connect(host, *port, tcp),
            )
            .await
            .map_err(|_| "TLS handshake timed out".to_string())?
            .map_err(|e| format!("TLS handshake failed: {e}"))
        }
        .await;

        match result {
            Ok(_tls) => {
                println!("[OK]   {host}:{port}");
                passed += 1;
            }
            Err(e) => {
                println!("[FAIL] {host}:{port} - {e}");
                failed += 1;
            }
        }
    }

    let total = servers.len();
    let min_required = total / 2;
    println!("\n=== Results: {passed}/{total} passed, {failed} failed ===");
    assert!(
        passed >= min_required,
        "At least {min_required}/{total} servers should pass, but only {passed} did"
    );
}
