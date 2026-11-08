use super::*;

fn untrusted_certificate() -> rcgen::CertifiedKey<rcgen::KeyPair> {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Untrusted lifecycle CA");
    let signing_key = rcgen::KeyPair::generate().unwrap();
    rcgen::CertifiedKey {
        cert: params.self_signed(&signing_key).unwrap(),
        signing_key,
    }
}

#[derive(Clone, Copy)]
enum ProxyKind {
    Connect,
    Socks5h,
}

fn proxy_handshake(socket: &mut std::net::TcpStream, kind: ProxyKind, port: u16) {
    match kind {
        ProxyKind::Connect => {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                head.push(byte[0]);
                assert!(head.len() < 4096);
            }
            assert!(head.starts_with(format!("CONNECT localhost:{port} HTTP/1.1\r\n").as_bytes()));
            socket
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .unwrap();
        }
        ProxyKind::Socks5h => {
            let mut greeting = [0; 2];
            socket.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting[0], 5);
            let mut methods = vec![0; greeting[1] as usize];
            socket.read_exact(&mut methods).unwrap();
            socket.write_all(&[5, 0]).unwrap();
            let mut header = [0; 5];
            socket.read_exact(&mut header).unwrap();
            assert_eq!(&header[..4], &[5, 1, 0, 3]);
            let mut target = vec![0; header[4] as usize + 2];
            socket.read_exact(&mut target).unwrap();
            assert_eq!(&target[..target.len() - 2], b"localhost");
            assert_eq!(&target[target.len() - 2..], &port.to_be_bytes());
            socket.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1]).unwrap();
        }
    }
}

struct NoOriginDns;
#[async_trait::async_trait]
impl lkrequest::DnsResolver for NoOriginDns {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<std::net::SocketAddr>> {
        assert_eq!(host, "127.0.0.1", "remote-DNS origin was resolved locally");
        Ok(vec![([127, 0, 0, 1], port).into()])
    }
}

pub(super) fn server_config(
    cert: &rcgen::CertifiedKey<rcgen::KeyPair>,
) -> Arc<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
    )
    .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

pub(super) fn profile() -> lktls::profile::types::TlsProfile {
    let mut profile = lktls::profile::presets::chrome_157();
    profile.alpn_protocols = vec!["http/1.1".into()];
    profile.key_share_curves = vec![29];
    profile.alps_protocols = None;
    profile
}

fn read_http(stream: &mut impl Read) -> Vec<u8> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
        assert!(head.len() < 4096);
    }
    head
}

fn respond(socket: std::net::TcpStream, hello: Vec<u8>, tls: Arc<rustls::ServerConfig>) {
    let mut connection = rustls::ServerConnection::new(tls).unwrap();
    connection
        .read_tls(&mut std::io::Cursor::new(hello))
        .unwrap();
    connection.process_new_packets().unwrap();
    let mut stream = rustls::StreamOwned::new(connection, socket);
    assert!(read_http(&mut stream).starts_with(b"POST / HTTP/1.1"));
    let mut body = [0; 7];
    stream.read_exact(&mut body).unwrap();
    assert_eq!(&body, b"payload");
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .unwrap();
    stream.flush().unwrap();
}

async fn proxy_recovery(kind: ProxyKind) -> String {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let other = untrusted_certificate();
    let id = TrustAnchorId::from_hex("81fd5901").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let tls = server_config(&cert);
    let server_id = id.clone();
    let server = tokio::task::spawn_blocking(move || {
        for attempt in 0..2 {
            let mut socket = accept_bounded(&listener);
            proxy_handshake(&mut socket, kind, 443);
            let hello = read_hello(&mut socket);
            let parsed = lkprofile::parse_client_hello(&hello).unwrap();
            let sni = &parsed
                .extensions
                .iter()
                .find(|e| e.extension_type == 0)
                .unwrap()
                .data;
            assert_eq!(&sni[5..], b"localhost");
            if attempt == 0 {
                socket
                    .write_all(&rejected_chain_flight(
                        &hello,
                        &other,
                        std::slice::from_ref(&server_id),
                    ))
                    .unwrap();
            } else {
                assert_eq!(ids(&hello), vec![server_id.clone()]);
                respond(socket, hello, tls.clone());
            }
        }
    });
    let anchor = lktls::verify::certchain::parse_trust_anchor_from_der(cert.cert.der()).unwrap();
    let client = Client::builder()
        .fingerprint(profile())
        .dns_resolver(Arc::new(NoOriginDns))
        .add_ca_cert_der(cert.cert.der())
        .trust_anchor_binding(TrustAnchorBinding {
            anchor_identity: anchor_identity(&anchor),
            id,
        })
        .trust_anchor_policy(TrustAnchorPolicy {
            recovery: TrustAnchorRecovery::Once,
            ..Default::default()
        })
        .try_build()
        .unwrap();
    let scheme = match kind {
        ProxyKind::Connect => "http",
        ProxyKind::Socks5h => "socks5h",
    };
    let session = client
        .session()
        .http1_only()
        .max_connections(1)
        .proxy(&format!("{scheme}://{proxy_addr}"))
        .build();
    let response = session
        .post("https://localhost/")
        .body("payload")
        .collect_diagnostics(true)
        .send()
        .await
        .unwrap();
    assert!(
        response
            .diagnostics()
            .unwrap()
            .trust_anchor
            .as_ref()
            .unwrap()
            .recovered
    );
    let body = response.text().unwrap().to_owned();
    server.await.unwrap();
    body
}

#[tokio::test]
async fn tai_http_connect_recovery_keeps_route_with_one_connection_slot() {
    assert_eq!(proxy_recovery(ProxyKind::Connect).await, "ok");
}

#[tokio::test]
async fn tai_socks5h_recovery_keeps_remote_dns_with_one_connection_slot() {
    assert_eq!(proxy_recovery(ProxyKind::Socks5h).await, "ok");
}

#[tokio::test]
async fn tai_recovery_uses_remaining_connection_deadline() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let other = untrusted_certificate();
    let id = TrustAnchorId::from_hex("81fd5901").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_id = id.clone();
    let server = tokio::task::spawn_blocking(move || {
        let mut socket = accept_bounded(&listener);
        let hello = read_hello(&mut socket);
        std::thread::sleep(Duration::from_millis(1000));
        socket
            .write_all(&rejected_chain_flight(&hello, &other, &[server_id]))
            .unwrap();
        drop(socket);
        let mut socket = accept_bounded(&listener);
        let _ = read_hello(&mut socket);
        let mut byte = [0];
        let _ = socket.read(&mut byte);
    });
    let anchor = lktls::verify::certchain::parse_trust_anchor_from_der(cert.cert.der()).unwrap();
    let client = Client::builder()
        .fingerprint(profile())
        .dns_resolver(Arc::new(LocalDns))
        .add_ca_cert_der(cert.cert.der())
        .trust_anchor_binding(TrustAnchorBinding {
            anchor_identity: anchor_identity(&anchor),
            id,
        })
        .trust_anchor_policy(TrustAnchorPolicy {
            recovery: TrustAnchorRecovery::Once,
            ..Default::default()
        })
        .tcp_connect_timeout(Duration::from_millis(200))
        .tls_handshake_timeout(Duration::from_millis(1400))
        .try_build()
        .unwrap();
    let started = std::time::Instant::now();
    let error = client
        .session()
        .http1_only()
        .max_connections(1)
        .build()
        .get(&format!("https://localhost:{port}/"))
        .send()
        .await
        .unwrap_err();
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1400) && elapsed < Duration::from_millis(2200),
        "{elapsed:?}: {error}"
    );
    assert!(error.is_timeout(), "{error}");
    let lkrequest::error::Error::TrustAnchorRecovery { info, .. } = error else {
        panic!("missing recovery diagnostics")
    };
    assert!(info.failure.is_some());
    assert!(info.previous_attempt.unwrap().recovery_eligible);
    server.await.unwrap();
}

#[tokio::test]
async fn tai_policy_preserves_real_tcp_psk_resumption_without_early_data() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let tls = server_config(&cert);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::task::spawn_blocking(move || {
        for attempt in 0..2 {
            let mut socket = accept_bounded(&listener);
            let hello = read_hello(&mut socket);
            let parsed = lkprofile::parse_client_hello(&hello).unwrap();
            assert_eq!(
                parsed.extensions.iter().any(|e| e.extension_type == 41),
                attempt == 1
            );
            assert!(!parsed.extensions.iter().any(|e| e.extension_type == 42));
            let mut connection = rustls::ServerConnection::new(tls.clone()).unwrap();
            connection
                .read_tls(&mut std::io::Cursor::new(hello))
                .unwrap();
            connection.process_new_packets().unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            let _ = read_http(&mut stream);
            assert_eq!(
                stream.conn.handshake_kind(),
                Some(if attempt == 1 {
                    rustls::HandshakeKind::Resumed
                } else {
                    rustls::HandshakeKind::Full
                })
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
            stream.flush().unwrap();
        }
    });
    let client = Client::builder()
        .fingerprint(profile())
        .dns_resolver(Arc::new(LocalDns))
        .add_ca_cert_der(cert.cert.der())
        .trust_anchor_policy(TrustAnchorPolicy {
            recovery: TrustAnchorRecovery::Once,
            ..Default::default()
        })
        .try_build()
        .unwrap();
    let session = client.session().http1_only().build();
    for _ in 0..2 {
        assert_eq!(
            session
                .get(&format!("https://localhost:{port}/"))
                .send()
                .await
                .unwrap()
                .text()
                .unwrap(),
            "ok"
        );
        session.pool_clear();
    }
    server.await.unwrap();
}

#[tokio::test]
async fn tai_concurrent_connections_keep_server_hints_and_diagnostics_isolated() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let tls = server_config(&cert);
    let anchor = lktls::verify::certchain::parse_trust_anchor_from_der(cert.cert.der()).unwrap();
    let mut builder = Client::builder()
        .fingerprint(profile())
        .dns_resolver(Arc::new(LocalDns))
        .add_ca_cert_der(cert.cert.der())
        .trust_anchor_policy(TrustAnchorPolicy {
            recovery: TrustAnchorRecovery::Once,
            ..Default::default()
        });
    let mut origins = Vec::new();
    let mut servers = Vec::new();
    for number in 1..=4 {
        let id = TrustAnchorId::new(vec![0x81, 0xfd, 0x59, number]).unwrap();
        builder = builder.trust_anchor_binding(TrustAnchorBinding {
            anchor_identity: anchor_identity(&anchor),
            id: id.clone(),
        });
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        origins.push((listener.local_addr().unwrap().port(), id.clone()));
        let tls = tls.clone();
        servers.push(tokio::task::spawn_blocking(move || {
            let mut socket = accept_bounded(&listener);
            let hello = read_hello(&mut socket);
            socket
                .write_all(&rejected_chain_flight(
                    &hello,
                    &untrusted_certificate(),
                    std::slice::from_ref(&id),
                ))
                .unwrap();
            drop(socket);
            let mut socket = accept_bounded(&listener);
            let hello = read_hello(&mut socket);
            assert_eq!(ids(&hello), vec![id]);
            respond(socket, hello, tls);
        }));
    }
    let session = builder
        .try_build()
        .unwrap()
        .session()
        .http1_only()
        .max_connections(4)
        .build();
    let requests: Vec<_> = origins
        .into_iter()
        .map(|(port, id)| {
            let session = session.clone();
            tokio::spawn(async move {
                let response = session
                    .post(&format!("https://localhost:{port}/"))
                    .body("payload")
                    .collect_diagnostics(true)
                    .send()
                    .await
                    .unwrap();
                let info = response
                    .diagnostics()
                    .unwrap()
                    .trust_anchor
                    .as_ref()
                    .unwrap();
                assert_eq!(info.requested_ids, vec![id.clone()]);
                assert_eq!(
                    info.previous_attempt.as_ref().unwrap().available_ids,
                    vec![id]
                );
                assert!(info.recovered && info.authenticated);
                assert_eq!(response.text().unwrap(), "ok");
            })
        })
        .collect();
    for request in requests {
        request.await.unwrap();
    }
    for server in servers {
        server.await.unwrap();
    }
}

#[tokio::test]
async fn tai_cancelled_recovery_releases_single_slot_and_fresh_request_budget() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let tls = server_config(&cert);
    let other = untrusted_certificate();
    let id = TrustAnchorId::from_hex("81fd5901").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (ready, waiting) = tokio::sync::oneshot::channel();
    let server_id = id.clone();
    let server = tokio::task::spawn_blocking(move || {
        let mut ready = Some(ready);
        for attempt in 0..4 {
            let mut socket = accept_bounded(&listener);
            let hello = read_hello(&mut socket);
            if attempt % 2 == 0 {
                assert_ne!(ids(&hello), vec![server_id.clone()]);
                socket
                    .write_all(&rejected_chain_flight(
                        &hello,
                        &other,
                        std::slice::from_ref(&server_id),
                    ))
                    .unwrap();
            } else {
                assert_eq!(ids(&hello), vec![server_id.clone()]);
                if attempt == 1 {
                    ready.take().unwrap().send(()).unwrap();
                    let mut byte = [0];
                    assert_eq!(
                        socket.read(&mut byte).unwrap(),
                        0,
                        "cancellation must close the recovering socket"
                    );
                } else {
                    respond(socket, hello, tls.clone());
                }
            }
        }
    });
    let anchor = lktls::verify::certchain::parse_trust_anchor_from_der(cert.cert.der()).unwrap();
    let client = Client::builder()
        .fingerprint(profile())
        .dns_resolver(Arc::new(LocalDns))
        .add_ca_cert_der(cert.cert.der())
        .trust_anchor_binding(TrustAnchorBinding {
            anchor_identity: anchor_identity(&anchor),
            id,
        })
        .trust_anchor_policy(TrustAnchorPolicy {
            recovery: TrustAnchorRecovery::Once,
            ..Default::default()
        })
        .try_build()
        .unwrap();
    let session = client.session().http1_only().max_connections(1).build();
    let request_session = session.clone();
    let pending = tokio::spawn(async move {
        request_session
            .post(&format!("https://localhost:{port}/"))
            .body("payload")
            .send()
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .unwrap()
        .unwrap();
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    let response = session
        .post(&format!("https://localhost:{port}/"))
        .body("payload")
        .collect_diagnostics(true)
        .send()
        .await
        .unwrap();
    assert!(
        response
            .diagnostics()
            .unwrap()
            .trust_anchor
            .as_ref()
            .unwrap()
            .recovered
    );
    assert_eq!(response.text().unwrap(), "ok");
    server.await.unwrap();
}

#[tokio::test]
async fn tai_preconnect_recovers_and_request_reuses_the_verified_connection() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let tls = server_config(&cert);
    let other = untrusted_certificate();
    let id = TrustAnchorId::from_hex("81fd5901").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_id = id.clone();
    let server = tokio::task::spawn_blocking(move || {
        let mut socket = accept_bounded(&listener);
        let hello = read_hello(&mut socket);
        socket
            .write_all(&rejected_chain_flight(
                &hello,
                &other,
                std::slice::from_ref(&server_id),
            ))
            .unwrap();
        drop(socket);
        let mut socket = accept_bounded(&listener);
        let hello = read_hello(&mut socket);
        assert_eq!(ids(&hello), vec![server_id]);
        respond(socket, hello, tls);
        listener.set_nonblocking(true).unwrap();
        assert!(listener.accept().is_err());
    });
    let anchor = lktls::verify::certchain::parse_trust_anchor_from_der(cert.cert.der()).unwrap();
    let client = Client::builder()
        .fingerprint(profile())
        .dns_resolver(Arc::new(LocalDns))
        .add_ca_cert_der(cert.cert.der())
        .trust_anchor_binding(TrustAnchorBinding {
            anchor_identity: anchor_identity(&anchor),
            id,
        })
        .trust_anchor_policy(TrustAnchorPolicy {
            recovery: TrustAnchorRecovery::Once,
            ..Default::default()
        })
        .try_build()
        .unwrap();
    let session = client.session().http1_only().max_connections(1).build();
    let url = format!("https://localhost:{port}/");
    let (preconnect, diagnostics) =
        lkrequest::diagnostics::capture_request_diagnostics(session.preconnect(&url)).await;
    preconnect.unwrap();
    assert!(diagnostics.trust_anchor.unwrap().recovered);
    let response = session
        .post(&url)
        .body("payload")
        .collect_diagnostics(true)
        .send()
        .await
        .unwrap();
    assert!(response.diagnostics().unwrap().trust_anchor.is_none());
    assert_eq!(response.text().unwrap(), "ok");
    server.await.unwrap();
}

#[tokio::test]
async fn tai_recovery_budget_survives_redirect_to_another_origin() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let tls = server_config(&cert);
    let other = untrusted_certificate();
    let id = TrustAnchorId::from_hex("81fd5901").unwrap();
    let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let first_port = first.local_addr().unwrap().port();
    let next = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let next_port = next.local_addr().unwrap().port();
    let server_id = id.clone();
    let server = tokio::task::spawn_blocking(move || {
        let mut socket = accept_bounded(&first);
        let hello = read_hello(&mut socket);
        socket
            .write_all(&rejected_chain_flight(
                &hello,
                &other,
                std::slice::from_ref(&server_id),
            ))
            .unwrap();
        drop(socket);
        let mut socket = accept_bounded(&first);
        let hello = read_hello(&mut socket);
        assert_eq!(ids(&hello), vec![server_id.clone()]);
        let mut connection = rustls::ServerConnection::new(tls).unwrap();
        connection
            .read_tls(&mut std::io::Cursor::new(hello))
            .unwrap();
        connection.process_new_packets().unwrap();
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let _ = read_http(&mut stream);
        stream.write_all(format!("HTTP/1.1 302 Found\r\nLocation: https://localhost:{next_port}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
        stream.flush().unwrap();
        drop(stream);
        let mut socket = accept_bounded(&next);
        let hello = read_hello(&mut socket);
        assert_ne!(ids(&hello), vec![server_id.clone()]);
        socket
            .write_all(&rejected_chain_flight(&hello, &other, &[server_id]))
            .unwrap();
        drop(socket);
        next.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_millis(150);
        while std::time::Instant::now() < deadline {
            assert!(
                next.accept().is_err(),
                "redirect granted another TAI recovery"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let anchor = lktls::verify::certchain::parse_trust_anchor_from_der(cert.cert.der()).unwrap();
    let client = Client::builder()
        .fingerprint(profile())
        .dns_resolver(Arc::new(LocalDns))
        .add_ca_cert_der(cert.cert.der())
        .trust_anchor_binding(TrustAnchorBinding {
            anchor_identity: anchor_identity(&anchor),
            id,
        })
        .trust_anchor_policy(TrustAnchorPolicy {
            recovery: TrustAnchorRecovery::Once,
            ..Default::default()
        })
        .try_build()
        .unwrap();
    let error = client
        .session()
        .http1_only()
        .build()
        .get(&format!("https://localhost:{first_port}/"))
        .send()
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        lkrequest::error::Error::Tls(lktls::error::TlsError::TrustAnchorFailure { .. })
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn tai_singleton_request_is_stable_across_recovery_hello_retry_request() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP384R1];
    let tls = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                    .into(),
            )
            .unwrap(),
    );
    let other = untrusted_certificate();
    let id = TrustAnchorId::from_hex("81fd5901").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_id = id.clone();
    let server = tokio::task::spawn_blocking(move || {
        let mut socket = accept_bounded(&listener);
        let hello = read_hello(&mut socket);
        socket
            .write_all(&rejected_chain_flight(
                &hello,
                &other,
                std::slice::from_ref(&server_id),
            ))
            .unwrap();
        drop(socket);
        let mut socket = accept_bounded(&listener);
        let hello = read_hello(&mut socket);
        assert_eq!(ids(&hello), vec![server_id.clone()]);
        let mut connection = rustls::ServerConnection::new(tls).unwrap();
        connection
            .read_tls(&mut std::io::Cursor::new(hello))
            .unwrap();
        connection.process_new_packets().unwrap();
        while connection.wants_write() {
            connection.write_tls(&mut socket).unwrap();
        }
        let mut header = [0; 5];
        socket.read_exact(&mut header).unwrap();
        if header[0] == 20 {
            let mut ccs = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
            socket.read_exact(&mut ccs).unwrap();
            assert_eq!(ccs, vec![1]);
            socket.read_exact(&mut header).unwrap();
        }
        assert_eq!(header[0], 22);
        let mut second = header.to_vec();
        second.resize(5 + u16::from_be_bytes([header[3], header[4]]) as usize, 0);
        socket.read_exact(&mut second[5..]).unwrap();
        assert_eq!(ids(&second), vec![server_id]);
        connection
            .read_tls(&mut std::io::Cursor::new(second))
            .unwrap();
        connection.process_new_packets().unwrap();
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let _ = read_http(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
        stream.flush().unwrap();
    });
    let anchor = lktls::verify::certchain::parse_trust_anchor_from_der(cert.cert.der()).unwrap();
    let client = Client::builder()
        .fingerprint(profile())
        .dns_resolver(Arc::new(LocalDns))
        .add_ca_cert_der(cert.cert.der())
        .trust_anchor_binding(TrustAnchorBinding {
            anchor_identity: anchor_identity(&anchor),
            id,
        })
        .trust_anchor_policy(TrustAnchorPolicy {
            recovery: TrustAnchorRecovery::Once,
            ..Default::default()
        })
        .try_build()
        .unwrap();
    let response = client
        .session()
        .http1_only()
        .max_connections(1)
        .build()
        .get(&format!("https://localhost:{port}/"))
        .collect_diagnostics(true)
        .send()
        .await
        .unwrap();
    assert!(
        response
            .diagnostics()
            .unwrap()
            .trust_anchor
            .as_ref()
            .unwrap()
            .recovered
    );
    assert_eq!(response.text().unwrap(), "ok");
    server.await.unwrap();
}
