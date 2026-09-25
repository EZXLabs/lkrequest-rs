use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::Once;

use async_trait::async_trait;
use h3::server;
use http::StatusCode;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::Endpoint;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::{mpsc, oneshot};

fn localhost_addr(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

fn ensure_rustls_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[derive(Clone)]
struct LocalIpv4Dns;

#[async_trait]
impl lkrequest::DnsResolver for LocalIpv4Dns {
    async fn resolve(&self, _host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(vec![localhost_addr(port)])
    }
}

#[tokio::test]
async fn lkrequest_http3_only_reaches_local_h3_server() {
    ensure_rustls_provider();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));

    let server = Endpoint::server(server_config, localhost_addr(0)).unwrap();
    let server_addr = server.local_addr().unwrap();

    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let mut h3_conn =
                server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                    .await
                    .unwrap();

            if let Some(resolver) = h3_conn.accept().await.unwrap() {
                let (_request, mut stream) = resolver.resolve_request().await.unwrap();
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .unwrap();
                stream.send_response(response).await.unwrap();
                stream
                    .send_data(bytes::Bytes::from_static(b"hello-h3"))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    });

    let client = lkrequest::Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .quic_profile(lkh3::chrome_quic())
        .add_ca_cert_der(cert_der.as_ref())
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .build();

    let session = client.session().http3_only().build();
    let url = format!("https://localhost:{}/test", server_addr.port());
    let response = session.get(&url).send().await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), lkrequest::HttpVersion::H3);
    assert_eq!(response.text().unwrap(), "hello-h3");

    server_task.await.unwrap();
    server.wait_idle().await;
}

#[tokio::test]
async fn lkrequest_http3_template_injects_default_priority_header() {
    ensure_rustls_provider();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));

    let server = Endpoint::server(server_config, localhost_addr(0)).unwrap();
    let server_addr = server.local_addr().unwrap();
    let (priority_tx, priority_rx) = oneshot::channel();

    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let mut h3_conn =
                server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                    .await
                    .unwrap();

            if let Some(resolver) = h3_conn.accept().await.unwrap() {
                let (request, mut stream) = resolver.resolve_request().await.unwrap();
                let priority = request
                    .headers()
                    .get("priority")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string);
                let _ = priority_tx.send(priority);

                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .unwrap();
                stream.send_response(response).await.unwrap();
                stream.finish().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    });

    let mut preset = lkrequest::preset::chrome_146();
    preset
        .quic_profile
        .as_mut()
        .expect("chrome_146 preset should include QUIC profile")
        .h3
        .priority_updates
        .clear();

    let client = lkrequest::Client::builder()
        .preset(preset)
        .add_ca_cert_der(cert_der.as_ref())
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .build();

    let session = client.session().http3_only().build();
    let url = format!("https://localhost:{}/priority", server_addr.port());
    let response = session.get(&url).send().await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        priority_rx.await.unwrap(),
        Some("u=1, i".to_string()),
        "chrome_146 HTTP/3 template should inject fetch-style priority header"
    );

    server_task.await.unwrap();
    server.wait_idle().await;
}

#[tokio::test]
async fn lkrequest_http3_get_replays_when_zero_rtt_is_rejected() {
    ensure_rustls_provider();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| {
            "lkrequest=trace,lktls_quic=trace,lkh3=trace,lkquic=trace,h3=debug,quinn=debug".into()
        }))
        .with_test_writer()
        .try_init();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    server_tls.max_early_data_size = u32::MAX;
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));

    let server = Endpoint::server(server_config, localhost_addr(0)).unwrap();
    let server_addr = server.local_addr().unwrap();
    let (stream_tx, mut stream_rx) = mpsc::channel(3);
    let (event_tx, mut event_rx) = mpsc::channel(32);

    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            for idx in 0..3 {
                let _ = event_tx.send(format!("accept_wait_{idx}")).await;
                let incoming = server.accept().await.unwrap();
                let _ = event_tx.send(format!("incoming_{idx}")).await;
                let conn = incoming.await.unwrap();
                let _ = event_tx.send(format!("connected_{idx}")).await;
                let Ok(mut h3_conn) =
                    server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                        .await
                else {
                    let _ = event_tx.send(format!("h3_rejected_{idx}")).await;
                    continue;
                };
                let _ = event_tx.send(format!("h3_ready_{idx}")).await;

                let resolver = match h3_conn.accept().await {
                    Ok(Some(resolver)) => resolver,
                    Ok(None) => {
                        let _ = event_tx.send(format!("h3_closed_{idx}")).await;
                        continue;
                    }
                    Err(error) if error.is_h3_no_error() => {
                        let _ = event_tx.send(format!("h3_no_error_{idx}")).await;
                        continue;
                    }
                    Err(error) => panic!("server h3 accept failed: {error}"),
                };
                let (request, mut stream) = resolver.resolve_request().await.unwrap();
                let _ = event_tx.send(format!("request_{idx}")).await;
                let _ = stream_tx
                    .send((idx, request.method().clone(), stream.is_0rtt()))
                    .await;
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .unwrap();
                stream.send_response(response).await.unwrap();
                stream
                    .send_data(bytes::Bytes::from_static(b"zero-rtt-ok"))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    });

    let client = lkrequest::Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .quic_profile(lkh3::chrome_quic())
        .add_ca_cert_der(cert_der.as_ref())
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .build();

    let session = client.session().http3_only().build();
    let url = format!("https://localhost:{}/zerortt", server_addr.port());

    let first = session.get(&url).send().await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(first.text().unwrap(), "zero-rtt-ok");
    let first_seen = stream_rx.recv().await.unwrap();
    assert_eq!(first_seen.0, 0);
    assert_eq!(first_seen.1, http::Method::GET);
    assert!(
        !first_seen.2,
        "first full handshake request must not be 0-RTT"
    );

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    drop(session);

    let session = client.session().http3_only().build();
    let second = session.get(&url).send().await.unwrap_or_else(|error| {
        let mut events = Vec::new();
        while let Ok(event) = event_rx.try_recv() {
            events.push(event);
        }
        panic!("second h3 request failed: {error}; server events: {events:?}");
    });
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(second.version(), lkrequest::HttpVersion::H3);
    assert_eq!(second.text().unwrap(), "zero-rtt-ok");
    let second_seen = stream_rx.recv().await.unwrap();
    assert_eq!(second_seen.0, 2);
    assert_eq!(second_seen.1, http::Method::GET);
    assert!(
        !second_seen.2,
        "replayed request must be sent after the server rejects 0-RTT"
    );

    server_task.await.unwrap();
    server.wait_idle().await;
}

#[tokio::test]
async fn http3_only_without_quic_profile_fails_fast() {
    let client = lkrequest::Client::builder()
        .preset(lkrequest::preset::firefox_147())
        .build();

    let session = client.session().http3_only().build();
    let err = session
        .get("https://example.com/")
        .send()
        .await
        .expect_err("http3_only should fail when the preset has no QUIC/H3 profile");

    assert!(matches!(err, lkrequest::error::Error::InvalidConfig(_)));
    assert!(
        err.to_string().contains("no QUIC/H3 profile"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn lkrequest_http3_streaming_reads_chunks() {
    ensure_rustls_provider();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));

    let server = Endpoint::server(server_config, localhost_addr(0)).unwrap();
    let server_addr = server.local_addr().unwrap();

    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let mut h3_conn =
                server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                    .await
                    .unwrap();

            if let Some(resolver) = h3_conn.accept().await.unwrap() {
                let (_request, mut stream) = resolver.resolve_request().await.unwrap();
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .unwrap();
                stream.send_response(response).await.unwrap();
                stream
                    .send_data(bytes::Bytes::from_static(b"hello-"))
                    .await
                    .unwrap();
                stream
                    .send_data(bytes::Bytes::from_static(b"stream"))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    });

    let client = lkrequest::Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .quic_profile(lkh3::chrome_quic())
        .add_ca_cert_der(cert_der.as_ref())
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .build();

    let session = client.session().http3_only().build();
    let url = format!("https://localhost:{}/stream", server_addr.port());
    let mut response = session.get(&url).send_streaming().await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.unwrap() {
        body.extend_from_slice(&chunk);
    }
    assert_eq!(body, b"hello-stream");

    server_task.await.unwrap();
    server.wait_idle().await;
}

#[tokio::test]
async fn lkrequest_http3_preconnect_warms_h3_pool() {
    ensure_rustls_provider();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));

    let server = Endpoint::server(server_config, localhost_addr(0)).unwrap();
    let server_addr = server.local_addr().unwrap();

    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let mut h3_conn =
                server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                    .await
                    .unwrap();

            if let Some(resolver) = h3_conn.accept().await.unwrap() {
                let (_request, mut stream) = resolver.resolve_request().await.unwrap();
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .unwrap();
                stream.send_response(response).await.unwrap();
                stream
                    .send_data(bytes::Bytes::from_static(b"preconnected-h3"))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    });

    let client = lkrequest::Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .quic_profile(lkh3::chrome_quic())
        .add_ca_cert_der(cert_der.as_ref())
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .build();

    let session = client.session().http3_only().build();
    let url = format!("https://localhost:{}/preconnect", server_addr.port());

    session.preconnect(&url).await.unwrap();
    assert!(
        session.pool_stats().h3_connections > 0,
        "http3 preconnect should warm the h3 pool"
    );

    let response = session.get(&url).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), lkrequest::HttpVersion::H3);
    assert_eq!(response.text().unwrap(), "preconnected-h3");

    server_task.await.unwrap();
    server.wait_idle().await;
}

#[tokio::test]
async fn lkrequest_http3_preconnect_is_idempotent() {
    ensure_rustls_provider();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));

    let server = Endpoint::server(server_config, localhost_addr(0)).unwrap();
    let server_addr = server.local_addr().unwrap();

    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            drop(conn);
        }
    });

    let client = lkrequest::Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .quic_profile(lkh3::chrome_quic())
        .add_ca_cert_der(cert_der.as_ref())
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .build();

    let session = client.session().http3_only().build();
    let url = format!("https://localhost:{}/preconnect", server_addr.port());

    session.preconnect(&url).await.unwrap();
    let warmed = session.pool_stats().h3_connections;
    session.preconnect(&url).await.unwrap();
    let rewarmed = session.pool_stats().h3_connections;

    assert_eq!(warmed, 1, "first preconnect should warm one h3 connection");
    assert_eq!(
        rewarmed, 1,
        "second preconnect should reuse the warmed h3 connection instead of opening another"
    );

    server_task.await.unwrap();
    server.wait_idle().await;
}

/// Wire-level regression for the Chrome HTTP/3 control-stream fingerprint.
///
/// Chrome sends, after SETTINGS on the control stream, a reserved GREASE frame
/// followed by a default RFC 9218 PRIORITY_UPDATE (`element_id=0`,
/// `field_value="u=1, i"`) — browserleaks renders this as `…;GREASE|GREASE|984832|…`.
/// This test drives a *raw* QUIC server (no h3 layer) so it can read the exact
/// bytes lkrequest's `chrome_146` template writes on its control stream and
/// guards several regressions:
///
///  1. **PRIORITY_UPDATE emission** — the frame must actually be sent
///     (profile → builder → control stream), not silently dropped.
///  2. **encode duplication** — `field_value` used to be written into the frame
///     header buffer *and* streamed again as the payload, emitting `"u=1, i"`
///     twice and corrupting every control-stream frame boundary after it.
///  3. **GREASE frame emission + ordering** — a reserved GREASE frame must be
///     present and precede the PRIORITY_UPDATE (Chrome's order).
#[tokio::test]
async fn lkrequest_http3_emits_chrome_control_stream_frames() {
    for (preset, priority) in [
        (lkrequest::preset::chrome_144(), "u=1, i"),
        (lkrequest::preset::chrome_146(), "u=1, i"),
        (lkrequest::preset::chrome_150(), "u=0, i"),
        (lkrequest::preset::chrome_151(), "u=0, i"),
        (lkrequest::preset::chrome_152(), "u=0, i"),
        (lkrequest::preset::chrome_153(), "u=0, i"),
        (lkrequest::preset::chrome_154(), "u=0, i"),
    ] {
        let mut expected_priority = vec![0];
        expected_priority.extend_from_slice(priority.as_bytes());
        assert_eq!(
            captured_chrome_control_stream(preset, priority).await,
            (0xF0700, expected_priority),
            "navigation PRIORITY_UPDATE for {priority}"
        );
    }
}

/// Run one H3 request with `preset` against a local server, validate the
/// captured control stream's SETTINGS and GREASE frames, and return the
/// trailing PRIORITY_UPDATE frame as `(frame type, payload)`.
async fn captured_chrome_control_stream(
    preset: lkrequest::preset::ClientPreset,
    priority: &str,
) -> (u64, Vec<u8>) {
    use std::time::Duration;

    ensure_rustls_provider();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));

    let server = Endpoint::server(server_config, localhost_addr(0)).unwrap();
    let server_addr = server.local_addr().unwrap();
    let (control_tx, control_rx) = oneshot::channel::<Vec<u8>>();

    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();

            // Read client-initiated unidirectional streams until we find the H3
            // control stream (stream type 0x00) and capture its leading bytes.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let mut captured = Vec::new();
            while let Ok(Ok(mut recv)) = tokio::time::timeout_at(deadline, conn.accept_uni()).await
            {
                let mut bytes = Vec::new();
                let mut buf = [0u8; 256];
                // The control stream is never closed, so bound the read by size
                // and a short idle timeout rather than reading to end.
                while bytes.len() < 64 {
                    match tokio::time::timeout(Duration::from_millis(500), recv.read(&mut buf))
                        .await
                    {
                        Ok(Ok(Some(n))) => bytes.extend_from_slice(&buf[..n]),
                        _ => break,
                    }
                }
                if bytes.first() == Some(&0x00) {
                    captured = bytes;
                    break;
                }
            }
            let _ = control_tx.send(captured);
        }
    });

    let client = lkrequest::Client::builder()
        .preset(preset)
        .add_ca_cert_der(cert_der.as_ref())
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .build();

    // Sanity: the template really does carry the PRIORITY_UPDATE we expect on
    // the wire. If this ever changes, the byte assertions below must too.
    assert_eq!(
        client
            .quic_profile()
            .expect("captured Chrome preset has a QUIC profile")
            .h3
            .priority_updates,
        vec![(0, priority.to_string())],
    );

    let session = client.session().http3_only().build();
    let url = format!("https://localhost:{}/priority", server_addr.port());
    // The raw server never answers H3, so the request itself will not complete;
    // we only care about the control-stream bytes it wrote during connect.
    let client_task = tokio::spawn(async move {
        let _ = session.get(&url).send().await;
    });

    let control = tokio::time::timeout(Duration::from_secs(8), control_rx)
        .await
        .expect("server should observe the H3 control stream")
        .expect("control-stream bytes channel");
    client_task.abort();

    use lktls::extensions::quic_transport_params::decode_varint;
    let read_varint = |input: &mut &[u8]| {
        let mut length = 0;
        let value = decode_varint(input, &mut length).expect("complete QUIC varint");
        *input = &input[length..];
        value
    };
    let mut input = control.as_slice();
    assert_eq!(read_varint(&mut input), 0, "control stream type");
    let mut frames = Vec::new();
    while !input.is_empty() {
        let frame_type = read_varint(&mut input);
        let length = read_varint(&mut input) as usize;
        assert!(length <= input.len(), "complete HTTP/3 frame");
        frames.push((frame_type, input[..length].to_vec()));
        input = &input[length..];
    }
    assert_eq!(frames.len(), 3, "SETTINGS, GREASE, PRIORITY_UPDATE only");
    assert_eq!(frames[0].0, 4);
    let mut settings = frames[0].1.as_slice();
    let mut entries = Vec::new();
    while !settings.is_empty() {
        entries.push((read_varint(&mut settings), read_varint(&mut settings)));
    }
    assert_eq!(
        &entries[..4],
        &[(1, 65_536), (6, 262_144), (7, 100), (51, 1)]
    );
    assert_eq!(entries.len(), 5);
    let (reserved, value) = entries[4];
    assert!(reserved >= 33 && (reserved - 33) % 31 == 0);
    assert!((reserved - 33) / 31 <= u32::MAX as u64);
    assert!(value <= u32::MAX as u64);
    let (frame_type, payload) = &frames[1];
    assert!(*frame_type >= 33 && (*frame_type - 33) % 31 == 0);
    let random = (*frame_type - 33) / 31;
    assert!(random <= u32::MAX as u64);
    assert_eq!(payload.len(), (random % 4) as usize);

    server_task.await.unwrap();
    server.wait_idle().await;
    frames.swap_remove(2)
}

/// Resolver that advertises H3 at a **different** hostname than the origin, the
/// way an HTTPS RR with an explicit `TargetName` does. Every name still resolves
/// to the local server, so only the TLS identity distinguishes the two.
#[derive(Clone)]
struct AlternativeTargetDns {
    https_lookups: Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait]
impl lkrequest::DnsResolver for AlternativeTargetDns {
    async fn resolve(&self, _host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(vec![localhost_addr(port)])
    }

    async fn lookup_https(
        &self,
        _host: &str,
    ) -> std::io::Result<Option<lkrequest::dns::HttpsRecord>> {
        self.https_lookups
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(Some(lkrequest::dns::HttpsRecord {
            target: Some("alt.invalid".to_string()),
            alpn: vec!["h3".to_string()],
            ..Default::default()
        }))
    }
}

/// An alternative service selects the dial target, never the TLS identity.
///
/// RFC 7838 §3.1 and RFC 9460 §2.3 both require the alternative endpoint to
/// prove it may serve the *origin*; the client authenticates the origin name.
/// Sending the alternative's own name as SNI let it authenticate as itself, and
/// broke conforming deployments, where a CDN target holds a certificate for the
/// origin rather than for its internal name.
///
/// The server here holds a certificate for `localhost` only, and reports the SNI
/// it actually received.
#[tokio::test]
async fn alt_service_target_does_not_become_the_tls_identity() {
    assert_eq!(
        dns_alt_service_origin_identity(lkrequest::ProtocolPolicy::h3_strict()).await,
        lkrequest::HttpVersion::H3,
    );
}

#[tokio::test]
async fn dns_advertised_h3_is_acquired_automatically() {
    assert_eq!(
        dns_alt_service_origin_identity(lkrequest::ProtocolPolicy::chrome_standard()).await,
        lkrequest::HttpVersion::H3,
    );
}

async fn dns_alt_service_origin_identity(
    policy: lkrequest::ProtocolPolicy,
) -> lkrequest::HttpVersion {
    ensure_rustls_provider();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap()));

    let server = Endpoint::server(server_config, localhost_addr(0)).unwrap();
    let server_addr = server.local_addr().unwrap();

    let (sni_tx, sni_rx) = oneshot::channel::<Option<String>>();

    let server_task = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept().await.unwrap();
            let conn = incoming.await.unwrap();

            // What the client actually put in the ClientHello.
            let sni = conn
                .handshake_data()
                .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|data| data.server_name.clone());
            let _ = sni_tx.send(sni);

            let mut h3_conn =
                server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                    .await
                    .unwrap();
            if let Some(resolver) = h3_conn.accept().await.unwrap() {
                let (_request, mut stream) = resolver.resolve_request().await.unwrap();
                stream
                    .send_response(
                        http::Response::builder()
                            .status(StatusCode::OK)
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                stream
                    .send_data(bytes::Bytes::from_static(b"origin-identity"))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    });

    let https_lookups = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let client = lkrequest::Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .quic_profile(lkh3::chrome_quic())
        // Verification stays on: the certificate names `localhost`, so an SNI of
        // `alt.invalid` also fails the identity check, not just this assertion.
        .add_ca_cert_der(cert_der.as_ref())
        .dns_resolver(Arc::new(AlternativeTargetDns {
            https_lookups: https_lookups.clone(),
        }))
        .build();

    let session = client.session().protocol_policy(policy).build();
    let url = format!("https://localhost:{}/alt", server_addr.port());
    let response = session
        .get(&url)
        .send()
        .await
        .expect("the origin identity must be used, so the localhost certificate matches");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), lkrequest::HttpVersion::H3);
    assert_eq!(response.text().unwrap(), "origin-identity");
    assert_eq!(
        https_lookups.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "pool selection and connection establishment must share DNS discovery"
    );

    let sni = sni_rx.await.expect("server reports the SNI it received");
    assert_eq!(
        sni.as_deref(),
        Some("localhost"),
        "SNI must name the origin, not the alternative service target"
    );

    server_task.await.unwrap();
    server.wait_idle().await;
    response.version()
}
