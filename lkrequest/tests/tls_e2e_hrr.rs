//! End-to-end HelloRetryRequest (HRR) test.
//!
//! Tests the TLS 1.3 HelloRetryRequest flow where the server asks the client
//! to retry with a different key share group.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use lkrequest::TlsConnector;
use lktls::profile::presets;

mod tls_support;
use tls_support::{tls_connect_with_retry, MAX_RETRIES};

struct ObservedSocket {
    socket: std::net::TcpStream,
    received: Vec<u8>,
}

impl std::io::Read for ObservedSocket {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let length = std::io::Read::read(&mut self.socket, buffer)?;
        self.received.extend_from_slice(&buffer[..length]);
        assert!(self.received.len() < 65_536, "bounded local TLS capture");
        Ok(length)
    }
}

impl std::io::Write for ObservedSocket {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.socket, buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.socket)
    }
}

struct ObservedAsyncSocket {
    socket: tokio::net::TcpStream,
    written: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl tokio::io::AsyncRead for ObservedAsyncSocket {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncRead::poll_read(std::pin::Pin::new(&mut self.socket), cx, buffer)
    }
}

impl tokio::io::AsyncWrite for ObservedAsyncSocket {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let result =
            tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.socket), cx, buffer);
        if let std::task::Poll::Ready(Ok(length)) = result {
            let mut written = self.written.lock().unwrap();
            written.extend_from_slice(&buffer[..length]);
            assert!(written.len() < 65_536);
        }
        result
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.socket), cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.socket), cx)
    }
}

#[tokio::test]
#[ignore = "Tier-1: local OpenSSL HRR peer configured with TEST_HRR_* variables"]
async fn local_openssl_hrr_psk_hash_filter_completes_authenticated_http() {
    use lktls::crypto::aead::AeadAlgorithm;
    use lktls::crypto::hkdf::HkdfAlgorithm;
    use lktls::session_store::{
        InMemorySessionStore, SessionStore, SessionTicketData, TicketTlsVersion,
    };
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    tokio::time::timeout(Duration::from_secs(30), async {
        let port = std::env::var("TEST_HRR_SERVER_PORT")
            .unwrap()
            .parse::<u16>()
            .unwrap();
        let server_sha384 = std::env::var("TEST_HRR_SERVER_SHA384").unwrap() == "1";
        let certificate = std::fs::read(std::env::var("TEST_HRR_CA_DER").unwrap()).unwrap();
        let anchor = lktls::verify::certchain::parse_trust_anchor_from_der(&certificate).unwrap();
        for profile in [presets::chrome_155(), presets::firefox_156()] {
            for ticket_sha384 in [false, true] {
                let store = Arc::new(InMemorySessionStore::new());
                store.store(
                    &format!("127.0.0.1:{port}"),
                    SessionTicketData {
                        ticket: b"local-openssl-hrr-test".to_vec(),
                        resumption_psk: vec![0xa5; if ticket_sha384 { 48 } else { 32 }],
                        tls_version: TicketTlsVersion::Tls13,
                        cipher_suite: if ticket_sha384 { 0x1302 } else { 0x1301 },
                        lifetime_secs: 3600,
                        age_add: 0,
                        received_at: std::time::Instant::now(),
                        alpn: None,
                        alps: Default::default(),
                        hkdf_algorithm: if ticket_sha384 {
                            HkdfAlgorithm::Sha384
                        } else {
                            HkdfAlgorithm::Sha256
                        },
                        aead_algorithm: if ticket_sha384 {
                            AeadAlgorithm::Aes256Gcm
                        } else {
                            AeadAlgorithm::Aes128Gcm
                        },
                        master_secret: Vec::new(),
                        max_early_data_size: 0,
                        peer_transport_parameters: None,
                        used_extended_master_secret: None,
                    },
                );
                let connector = TlsConnector::new(profile.clone())
                    .session_store(store)
                    .custom_ca_anchors(Arc::new(vec![anchor.clone()]));
                let written = Arc::new(Mutex::new(Vec::new()));
                let socket = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
                    .await
                    .unwrap();
                let socket = ObservedAsyncSocket {
                    socket,
                    written: written.clone(),
                };
                let mut tls = connector.connect("127.0.0.1", port, socket).await.unwrap();
                assert_eq!(
                    tls.negotiated_cipher_suite(),
                    Some(if server_sha384 { 0x1302 } else { 0x1301 })
                );
                tls.write_all(
                    b"GET /index.txt HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
                let mut response = Vec::new();
                loop {
                    let mut buffer = [0; 1024];
                    let length = tls.read(&mut buffer).await.unwrap();
                    if length == 0 {
                        break;
                    }
                    response.extend_from_slice(&buffer[..length]);
                    assert!(response.len() < 16_384);
                }
                assert!(response.starts_with(b"HTTP/1.0 200 ok\r\n"));
                assert!(response.ends_with(b"hello\n"));
                let hellos = observed_client_hellos(&written.lock().unwrap());
                assert_eq!(hellos.len(), 2, "OpenSSL P-384 forced HRR");
                assert!(hellos[0]
                    .extensions
                    .iter()
                    .any(|extension| extension.extension_type == 41));
                assert_eq!(
                    hellos[1]
                        .extensions
                        .iter()
                        .any(|extension| extension.extension_type == 41),
                    ticket_sha384 == server_sha384
                );
            }
        }
    })
    .await
    .expect("local OpenSSL HRR PSK test timed out");
}

fn observed_client_hellos(records: &[u8]) -> Vec<lkprofile::ParsedClientHello> {
    let mut offset = 0;
    let mut handshakes = Vec::new();
    while offset + 5 <= records.len() {
        let length = u16::from_be_bytes([records[offset + 3], records[offset + 4]]) as usize;
        let end = offset + 5 + length;
        assert!(end <= records.len());
        if records[offset] == 22 {
            handshakes.extend_from_slice(&records[offset + 5..end]);
        }
        offset = end;
    }
    assert_eq!(offset, records.len());
    let mut hellos = Vec::new();
    let mut offset = 0;
    while offset + 4 <= handshakes.len() {
        let length = ((handshakes[offset + 1] as usize) << 16)
            | ((handshakes[offset + 2] as usize) << 8)
            | handshakes[offset + 3] as usize;
        let end = offset + 4 + length;
        assert_eq!(handshakes[offset], 1);
        assert!(end <= handshakes.len());
        hellos.push(lkprofile::parse_client_hello(&handshakes[offset..end]).unwrap());
        offset = end;
    }
    assert_eq!(offset, handshakes.len());
    hellos
}

async fn read_plain_client_hello(socket: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    loop {
        let mut header = [0; 5];
        socket.read_exact(&mut header).await?;
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        assert!(length < 16_384);
        let mut payload = vec![0; length];
        socket.read_exact(&mut payload).await?;
        if header[0] == 20 {
            assert_eq!(payload, [1]);
            continue;
        }
        assert_eq!(header[0], 22);
        assert_eq!(payload[0], 1);
        return Ok(payload);
    }
}

fn controlled_server_hello_record(
    random: &[u8; 32],
    session_id: &[u8],
    cipher: u16,
    share: Option<&[u8]>,
    version: &[u8],
) -> Vec<u8> {
    let mut extensions = vec![0, 43];
    extensions.extend_from_slice(&(version.len() as u16).to_be_bytes());
    extensions.extend_from_slice(version);
    if let Some(share) = share {
        extensions.extend_from_slice(&[0, 51]);
        extensions.extend_from_slice(&(share.len() as u16).to_be_bytes());
        extensions.extend_from_slice(share);
    }
    let mut body = vec![3, 3];
    body.extend_from_slice(random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&cipher.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    assert!(body.len() < (1 << 24));
    let mut message = vec![
        2,
        (body.len() >> 16) as u8,
        (body.len() >> 8) as u8,
        body.len() as u8,
    ];
    message.extend_from_slice(&body);
    let mut record = vec![22, 3, 3];
    record.extend_from_slice(&(message.len() as u16).to_be_bytes());
    record.extend_from_slice(&message);
    record
}

#[tokio::test]
async fn local_hrr_cipher_changes_send_illegal_parameter() {
    use lktls::crypto::kx::{generate_key_pair, KxGroup};
    use lktls::error::{AlertDescription, TlsError};
    use std::time::Duration;

    tokio::time::timeout(Duration::from_secs(15), async {
        for profile in [presets::chrome_155(), presets::firefox_156()] {
            for cipher in [0x1303, 0x1302] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let peer = tokio::spawn(async move {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let ch1 = read_plain_client_hello(&mut socket).await.unwrap();
                    let parsed = lkprofile::parse_client_hello(&ch1).unwrap();
                    assert!(parsed.cipher_suites.contains(&0x1301));
                    assert!(parsed.cipher_suites.contains(&cipher));
                    let session_id = &ch1[39..39 + parsed.session_id_length as usize];
                    socket
                        .write_all(&controlled_server_hello_record(
                            &lktls::handshake::server_hello::HRR_RANDOM,
                            session_id,
                            0x1301,
                            Some(&[0, 24]),
                            &[3, 4],
                        ))
                        .await
                        .unwrap();
                    let ch2 = read_plain_client_hello(&mut socket).await.unwrap();
                    let parsed = lkprofile::parse_client_hello(&ch2).unwrap();
                    assert!(parsed.cipher_suites.contains(&cipher));
                    let share = &parsed
                        .extensions
                        .iter()
                        .find(|extension| extension.extension_type == 51)
                        .unwrap()
                        .data;
                    assert_eq!(&share[2..4], &[0, 24]);
                    let key = generate_key_pair(KxGroup::Secp384r1).unwrap();
                    let mut share = vec![0, 24];
                    share.extend_from_slice(&(key.public_key.len() as u16).to_be_bytes());
                    share.extend_from_slice(&key.public_key);
                    socket
                        .write_all(&controlled_server_hello_record(
                            &[0x55; 32],
                            session_id,
                            cipher,
                            Some(&share),
                            &[3, 4],
                        ))
                        .await
                        .unwrap();
                    let mut header = [0; 5];
                    socket.read_exact(&mut header).await.unwrap();
                    assert_eq!(header[0], 21);
                    assert_eq!(u16::from_be_bytes([header[3], header[4]]), 2);
                    let mut alert = [0; 2];
                    socket.read_exact(&mut alert).await.unwrap();
                    assert_eq!(alert, [2, AlertDescription::IllegalParameter.as_byte()]);
                });
                let socket = tokio::net::TcpStream::connect(address).await.unwrap();
                let result = TlsConnector::new(profile.clone())
                    .connect("localhost", address.port(), socket)
                    .await;
                assert!(matches!(result, Err(TlsError::LocalAlert { alert, .. })
                    if alert.description == AlertDescription::IllegalParameter));
                peer.await.unwrap();
            }
        }
    })
    .await
    .expect("local HRR cipher-change test timed out");
}

#[tokio::test]
#[ignore = "Tier-1: controlled real-browser TLS error capture"]
async fn local_browser_error_peer() {
    use lktls::crypto::kx::{generate_key_pair, KxGroup};
    use std::time::Duration;

    let seconds = std::env::var("TEST_BROWSER_ERROR_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(40);
    let library = std::env::var("TEST_BROWSER_ERROR_LIBRARY").ok().as_deref() == Some("1");
    let scenario_set =
        std::env::var("TEST_BROWSER_ERROR_SCENARIOS").unwrap_or_else(|_| "shares".into());
    let cases = [
        (48651, "chrome", "missing_key_share"),
        (48652, "chrome", "unoffered_p384"),
        (48653, "firefox", "missing_key_share"),
        (48654, "firefox", "unoffered_p384"),
        (48655, "chrome", "unsupported_cipher"),
        (48656, "chrome", "invalid_compression"),
        (48657, "chrome", "hrr_bad_share_length"),
        (48658, "chrome", "version_short"),
        (48659, "chrome", "version_long"),
        (48660, "chrome", "version_tls12"),
        (48661, "firefox", "version_short"),
        (48662, "firefox", "version_long"),
        (48663, "firefox", "version_tls12"),
        (48664, "chrome", "key_zero"),
        (48665, "chrome", "key_short"),
        (48666, "chrome", "key_one"),
        (48667, "firefox", "key_zero"),
        (48668, "firefox", "key_short"),
        (48669, "firefox", "key_one"),
        (48670, "chrome", "hybrid_short"),
        (48671, "chrome", "hybrid_zero"),
        (48672, "chrome", "hybrid_one"),
        (48673, "firefox", "hybrid_short"),
        (48674, "firefox", "hybrid_zero"),
        (48675, "firefox", "hybrid_one"),
        (48676, "chrome", "ccs_empty"),
        (48677, "chrome", "ccs_value"),
        (48678, "chrome", "ccs_long"),
        (48679, "firefox", "ccs_empty"),
        (48680, "firefox", "ccs_value"),
        (48681, "firefox", "ccs_long"),
    ]
    .into_iter()
    .filter(|(_, _, scenario)| match scenario_set.as_str() {
        "versions" => scenario.starts_with("version_"),
        "key-values" => scenario.starts_with("key_"),
        "hybrid-values" => scenario.starts_with("hybrid_"),
        "ccs" => scenario.starts_with("ccs_"),
        _ => {
            !scenario.starts_with("version_")
                && !scenario.starts_with("key_")
                && !scenario.starts_with("hybrid_")
                && !scenario.starts_with("ccs_")
        }
    })
    .collect::<Vec<_>>();
    let mut peers = Vec::new();
    for &(port, browser, scenario) in &cases {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        peers.push(tokio::spawn(async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
            let mut count = 0;
            while tokio::time::Instant::now() < deadline {
                let accepted = tokio::time::timeout_at(deadline, listener.accept()).await;
                let Ok(Ok((mut socket, _))) = accepted else {
                    break;
                };
                let ch = tokio::time::timeout(
                    Duration::from_secs(3),
                    read_plain_client_hello(&mut socket),
                )
                .await;
                let Ok(Ok(ch)) = ch else {
                    continue;
                };
                let parsed = lkprofile::parse_client_hello(&ch).unwrap();
                assert!(parsed.cipher_suites.contains(&0x1301));
                assert!(!parsed
                    .extensions
                    .iter()
                    .any(|extension| extension.extension_type == 41));
                let session_id = &ch[39..39 + parsed.session_id_length as usize];
                let mut share = Vec::new();
                if scenario == "hrr_bad_share_length" {
                    share.extend_from_slice(&[0, 24, 0xa5]);
                } else if scenario.starts_with("hybrid_") {
                    let mut public = vec![0; if scenario == "hybrid_short" { 1119 } else { 1120 }];
                    if scenario == "hybrid_one" { public[1088] = 1; }
                    share.extend_from_slice(&[0x11,0xec]);
                    share.extend_from_slice(&(public.len() as u16).to_be_bytes());
                    share.extend_from_slice(&public);
                } else if scenario.starts_with("key_") {
                    let mut public = vec![0; if scenario == "key_short" { 31 } else { 32 }];
                    if scenario == "key_one" { public[0] = 1; }
                    share.extend_from_slice(&[0,29]);
                    share.extend_from_slice(&(public.len() as u16).to_be_bytes());
                    share.extend_from_slice(&public);
                } else if scenario != "missing_key_share" && !scenario.starts_with("version_") {
                    let group = if scenario == "unoffered_p384" {
                        KxGroup::Secp384r1
                    } else {
                        KxGroup::X25519
                    };
                    let key = generate_key_pair(group).unwrap();
                    share.extend_from_slice(&group.code_point().to_be_bytes());
                    share.extend_from_slice(&(key.public_key.len() as u16).to_be_bytes());
                    share.extend_from_slice(&key.public_key);
                }
                let mut response = controlled_server_hello_record(
                    if scenario.starts_with("hrr_") {
                        &lktls::handshake::server_hello::HRR_RANDOM
                    } else {
                        &[0x55; 32]
                    },
                    if scenario == "version_tls12" { &[] } else { session_id },
                    if scenario == "unsupported_cipher" {
                        0xffff
                    } else if scenario == "version_tls12" {
                        0xc02f
                    } else {
                        0x1301
                    },
                    if share.is_empty() { None } else { Some(&share) },
                    match scenario { "version_short" => &[3], "version_long" => &[3,4,0],
                        "version_tls12" => &[3,3], _ => &[3,4] },
                );
                if scenario == "invalid_compression" {
                    response[46 + session_id.len()] = 1;
                }
                if scenario.starts_with("ccs_") {
                    let payload: &[u8] = match scenario {
                        "ccs_empty" => &[],
                        "ccs_value" => &[2],
                        "ccs_long" => &[1, 1],
                        _ => unreachable!(),
                    };
                    response = vec![20, 3, 3, 0, payload.len() as u8];
                    response.extend_from_slice(payload);
                }
                socket.write_all(&response).await.unwrap();
                let mut types = Vec::new();
                let mut alerts = Vec::new();
                for _ in 0..8 {
                    let mut header = [0; 5];
                    let read = tokio::time::timeout(
                        Duration::from_secs(2),
                        socket.read_exact(&mut header),
                    )
                    .await;
                    if !matches!(read, Ok(Ok(_))) {
                        break;
                    }
                    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
                    assert!(length < 16_384);
                    let mut payload = vec![0; length];
                    if !matches!(
                        tokio::time::timeout(
                            Duration::from_secs(2),
                            socket.read_exact(&mut payload)
                        )
                        .await,
                        Ok(Ok(_))
                    ) {
                        break;
                    }
                    types.push(header[0]);
                    if header[0] == 21 && payload.len() == 2 {
                        alerts.push([payload[0], payload[1]]);
                    }
                }
                println!(
                    "{}",
                    serde_json::json!({"client": if library { "library" } else { "browser" }, "browser": browser, "scenario": scenario,
                    "port": port, "record_types": types, "alerts": alerts})
                );
                count += 1;
                break;
            }
            assert!(count > 0, "browser did not reach port {port}");
            count
        }));
    }
    if library {
        for (port, browser, _) in cases {
            let profile = if browser == "chrome" {
                presets::chrome_155()
            } else {
                presets::firefox_156()
            };
            let socket = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap();
            let result = TlsConnector::new(profile)
                .connect("127.0.0.1", port, socket)
                .await;
            assert!(result.is_err(), "controlled invalid SH must fail");
        }
    }
    for peer in peers {
        assert!(peer.await.unwrap() > 0);
    }
}

#[tokio::test]
async fn local_normal_ccs_waits_for_server_flight_and_completes_http() {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::time::Duration;

    tokio::time::timeout(Duration::from_secs(15), async {
        for profile in [presets::chrome_155(), presets::firefox_156()] {
            let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
            let anchor =
                lktls::verify::certchain::parse_trust_anchor_from_der(cert.cert.der()).unwrap();
            let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
            );
            let mut provider = rustls::crypto::ring::default_provider();
            provider.kx_groups = vec![rustls::crypto::ring::kx_group::X25519];
            provider.cipher_suites =
                vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.cert.der().clone()], key)
                .unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let response =
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
            let server = tokio::task::spawn_blocking(move || {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut socket = ObservedSocket {
                    socket,
                    received: Vec::new(),
                };
                let mut conn = rustls::ServerConnection::new(Arc::new(config)).unwrap();
                while !conn.wants_write() {
                    assert!(conn.read_tls(&mut socket).unwrap() > 0);
                    conn.process_new_packets().unwrap();
                }
                let mut flight = Vec::new();
                while conn.wants_write() {
                    conn.write_tls(&mut flight).unwrap();
                }
                assert_eq!(flight[0], 22);
                assert_eq!(flight[5], 2);
                let hello_end = 5 + u16::from_be_bytes([flight[3], flight[4]]) as usize;
                socket.write_all(&flight[..hello_end]).unwrap();
                socket.flush().unwrap();
                socket
                    .socket
                    .set_read_timeout(Some(Duration::from_millis(150)))
                    .unwrap();
                let mut probe = [0];
                let early = socket.read(&mut probe);
                assert!(
                    matches!(early, Err(ref error) if matches!(error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)),
                    "client emitted data before the remaining server flight: {early:?}"
                );
                socket
                    .socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket.write_all(&flight[hello_end..]).unwrap();
                socket.flush().unwrap();
                let mut tls = rustls::StreamOwned::new(conn, socket);
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    tls.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                    assert!(request.len() < 16_384);
                }
                tls.write_all(response).unwrap();
                tls.flush().unwrap();
                tls.sock.received
            });
            let connector = TlsConnector::new(profile).custom_ca_anchors(Arc::new(vec![anchor]));
            let socket = tokio::net::TcpStream::connect(address).await.unwrap();
            let mut tls = connector
                .connect("127.0.0.1", address.port(), socket)
                .await
                .unwrap();
            tls.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut received = vec![0; response.len()];
            tls.read_exact(&mut received).await.unwrap();
            assert_eq!(received, response);
            let wire = server.await.unwrap();
            let ch_end = 5 + u16::from_be_bytes([wire[3], wire[4]]) as usize;
            assert_eq!(
                &wire[ch_end..ch_end + 11],
                &[20, 3, 3, 0, 1, 1, 23, 3, 3, 0, 53]
            );
            assert_eq!(observed_client_hellos(&wire).len(), 1);
        }
    })
    .await
    .expect("split TLS server-flight test timed out");
}

#[tokio::test]
async fn local_hrr_psk_hash_filter_records_rustls_peer_outcomes() {
    use lktls::crypto::aead::AeadAlgorithm;
    use lktls::crypto::hkdf::HkdfAlgorithm;
    use lktls::session_store::{
        InMemorySessionStore, SessionStore, SessionTicketData, TicketTlsVersion,
    };
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::time::Duration;

    tokio::time::timeout(Duration::from_secs(30), async {
        for profile in [presets::chrome_155(), presets::firefox_156()] {
            for ticket_sha384 in [false, true] {
                for server_sha384 in [true, false] {
                    let cert =
                        rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
                    let anchor =
                        lktls::verify::certchain::parse_trust_anchor_from_der(cert.cert.der())
                            .unwrap();
                    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(
                            cert.signing_key.serialize_der(),
                        ),
                    );
                    let mut provider = rustls::crypto::ring::default_provider();
                    provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP384R1];
                    provider.cipher_suites = vec![if server_sha384 {
                        rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384
                    } else {
                        rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
                    }];
                    let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                        .with_protocol_versions(&[&rustls::version::TLS13])
                        .unwrap()
                        .with_no_client_auth()
                        .with_single_cert(vec![cert.cert.der().clone()], key)
                        .unwrap();
                    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                    let address = listener.local_addr().unwrap();
                    let response =
                        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
                    let server = tokio::task::spawn_blocking(move || {
                        let (socket, _) = listener.accept().unwrap();
                        socket
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        socket
                            .set_write_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        let socket = ObservedSocket {
                            socket,
                            received: Vec::new(),
                        };
                        let conn = rustls::ServerConnection::new(Arc::new(config)).unwrap();
                        let mut tls = rustls::StreamOwned::new(conn, socket);
                        let mut request = Vec::new();
                        let mut failure = None;
                        while !request.ends_with(b"\r\n\r\n") {
                            let mut byte = [0];
                            if let Err(error) = tls.read_exact(&mut byte) {
                                failure = Some(error);
                                break;
                            }
                            request.push(byte[0]);
                            assert!(request.len() < 16_384);
                        }
                        if failure.is_none() {
                        assert_eq!(
                            tls.conn.negotiated_key_exchange_group().unwrap().name(),
                            rustls::NamedGroup::secp384r1
                        );
                        assert_eq!(
                            tls.conn.negotiated_cipher_suite().unwrap().suite(),
                            if server_sha384 {
                                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                            } else {
                                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
                            }
                        );
                        tls.write_all(response).unwrap();
                        tls.flush().unwrap();
                        }
                        (tls.sock.received, failure)
                    });
                    let store = Arc::new(InMemorySessionStore::new());
                    store.store(
                        &format!("127.0.0.1:{}", address.port()),
                        SessionTicketData {
                            ticket: b"local-hrr-test".to_vec(),
                            resumption_psk: vec![0xa5; if ticket_sha384 { 48 } else { 32 }],
                            tls_version: TicketTlsVersion::Tls13,
                            cipher_suite: if ticket_sha384 { 0x1302 } else { 0x1301 },
                            lifetime_secs: 3600,
                            age_add: 0,
                            received_at: std::time::Instant::now(),
                            alpn: None,
                            alps: Default::default(),
                            hkdf_algorithm: if ticket_sha384 {
                                HkdfAlgorithm::Sha384
                            } else {
                                HkdfAlgorithm::Sha256
                            },
                            aead_algorithm: if ticket_sha384 {
                                AeadAlgorithm::Aes256Gcm
                            } else {
                                AeadAlgorithm::Aes128Gcm
                            },
                            master_secret: Vec::new(),
                            max_early_data_size: 0,
                            peer_transport_parameters: None,
                            used_extended_master_secret: None,
                        },
                    );
                    let connector = TlsConnector::new(profile.clone())
                        .session_store(store)
                        .custom_ca_anchors(Arc::new(vec![anchor]));
                    let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
                    let connected = connector.connect("127.0.0.1", address.port(), tcp).await;
                    let compatible = ticket_sha384 == server_sha384;
                    if compatible {
                    let mut tls = connected.unwrap();
                    tls.write_all(
                        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
                    let mut received = vec![0; response.len()];
                    tls.read_exact(&mut received).await.unwrap();
                    assert_eq!(received, response);
                    } else {
                        assert!(matches!(connected, Err(lktls::error::TlsError::Alert(alert))
                            if alert.description == lktls::error::AlertDescription::MissingExtension));
                    }
                    let (wire, failure) = server.await.unwrap();
                    if compatible { assert!(failure.is_none()); }
                    else {
                        assert!(matches!(failure.as_ref().unwrap().get_ref()
                            .and_then(|error| error.downcast_ref::<rustls::Error>()),
                            Some(rustls::Error::PeerMisbehaved(rustls::PeerMisbehaved::MissingPskExtensionInSecondClientHello))));
                    }
                    let hellos = observed_client_hellos(&wire);
                    assert_eq!(hellos.len(), 2);
                    assert!(hellos[0]
                        .extensions
                        .iter()
                        .any(|extension| extension.extension_type == 41));
                    assert_eq!(
                        hellos[1]
                            .extensions
                            .iter()
                            .any(|extension| extension.extension_type == 41),
                        ticket_sha384 == server_sha384
                    );
                }
            }
        }
    })
    .await
    .expect("local HRR PSK hash test timed out");
}

#[tokio::test]
async fn local_hrr_preserves_unchanged_client_hello_extensions() {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::time::Duration;

    tokio::time::timeout(Duration::from_secs(15), async {
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let ca = cert.cert.der().to_vec();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
        );
        let mut provider = rustls::crypto::ring::default_provider();
        provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP384R1];
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key)
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::task::spawn_blocking(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let socket = ObservedSocket {
                socket,
                received: Vec::new(),
            };
            let conn = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, socket);
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                tls.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 16_384);
            }
            assert_eq!(
                tls.conn.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            assert_eq!(
                tls.conn.negotiated_key_exchange_group().unwrap().name(),
                rustls::NamedGroup::secp384r1
            );
            tls.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
            )
            .unwrap();
            tls.flush().unwrap();
            tls.sock.received
        });
        let client = lkrequest::Client::builder()
            .preset(lkrequest::preset::chrome_155())
            .add_ca_cert_der(&ca)
            .build();
        let session = client.session().http1_only().build();
        let response = session
            .get(&format!("https://{address}/hrr"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.bytes(), b"hello");
        let wire = server.await.unwrap();
        let hellos = observed_client_hellos(&wire);
        assert_eq!(hellos.len(), 2, "P-384 forced a real HRR");
        let unchanged = |hello: &lkprofile::ParsedClientHello| {
            hello
                .extensions
                .iter()
                .filter(|extension| !matches!(extension.extension_type, 21 | 51))
                .map(|extension| (extension.extension_type, extension.data.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            unchanged(&hellos[0]),
            unchanged(&hellos[1]),
            "ordered unchanged extensions differ"
        );
        assert!(hellos[0]
            .extensions
            .iter()
            .any(|extension| extension.extension_type == 0xca34));
        assert_eq!(hellos[0].cipher_suites, hellos[1].cipher_suites);
        assert_eq!(hellos[0].session_id_length, hellos[1].session_id_length);
    })
    .await
    .expect("local HRR test timed out");
}

/// Test multi-server handshake resilience.
///
/// Connects to multiple servers with different TLS configurations
/// to verify the handshake state machine handles various server behaviors.
/// Some servers may trigger HRR depending on the key share groups offered.
#[tokio::test]
#[ignore]
async fn test_multi_server_robustness() {
    let profile = presets::chrome_144();
    let servers = vec![
        ("www.cloudflare.com", 443),
        ("www.google.com", 443),
        ("github.com", 443),
    ];

    for (host, port) in &servers {
        let connector = TlsConnector::new(profile.clone());
        let tls = tls_connect_with_retry(&connector, host, *port, MAX_RETRIES).await;

        assert!(
            tls.negotiated_alpn().is_some(),
            "ALPN should be negotiated for {host}:{port}"
        );

        println!("  [OK] {host}:{port}");
    }

    println!("=== PASSED: multi-server robustness ===");
}

/// Test handshake with different profiles on the same server.
///
/// Verifies that Chrome, Firefox, and Safari profiles all complete
/// handshakes successfully on the same server.
#[tokio::test]
#[ignore]
async fn test_all_profiles_handshake() {
    let profiles = vec![
        ("Chrome 144", presets::chrome_144()),
        ("Firefox 147", presets::firefox_147()),
        ("Firefox 156", presets::firefox_156()),
        ("Safari 26", presets::safari_26()),
    ];
    let host = "www.cloudflare.com";

    for (name, profile) in profiles {
        let connector = TlsConnector::new(profile);
        let mut tls = tls_connect_with_retry(&connector, host, 443, MAX_RETRIES).await;

        assert!(
            tls.negotiated_alpn().is_some(),
            "{name}: ALPN should be negotiated"
        );

        // Verify data transfer works
        let req = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        tls.write_all(req.as_bytes()).await.unwrap();

        let mut buf = vec![0u8; 8192];
        let n = tls.read(&mut buf).await.unwrap();
        assert!(n > 0, "{name}: should receive response data");

        println!("  [OK] {name}");
    }

    println!("=== PASSED: all profiles handshake ===");
}
