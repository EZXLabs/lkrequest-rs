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

#[path = "quic_local_e2e/blocked_local_close.rs"]
mod blocked_local_close;
#[path = "quic_local_e2e/browser_flow.rs"]
mod browser_flow;
#[path = "quic_local_e2e/browser_retry.rs"]
mod browser_retry;
#[path = "quic_local_e2e/browser_retry_routing.rs"]
mod browser_retry_routing;
#[path = "quic_local_e2e/client_auth.rs"]
mod client_auth;
#[path = "quic_local_e2e/completion.rs"]
mod completion;
#[path = "quic_local_e2e/early_rejection.rs"]
mod early_rejection;
#[path = "quic_local_e2e/incomplete_header.rs"]
mod incomplete_header;
#[path = "quic_local_e2e/qpack_completion.rs"]
mod qpack_completion;
#[path = "quic_local_e2e/retry_resumption.rs"]
mod retry_resumption;
#[path = "quic_local_e2e/stop_completion.rs"]
mod stop_completion;
#[path = "quic_local_e2e/upload_completion.rs"]
mod upload_completion;

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

// Decode actual QPACK requests at the peer, including requests reusing the
// connection and uploads that take the H3 streaming sender path.
async fn observed_h3_priorities(
    automatic: bool,
    streaming_response: bool,
    default_header: bool,
) -> Vec<Vec<String>> {
    use bytes::Buf;

    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        ensure_rustls_provider();
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der =
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let server = Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap())),
            localhost_addr(0),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let task = tokio::spawn({
            let server = server.clone();
            async move {
                let conn = server.accept().await.unwrap().await.unwrap();
                let mut h3 =
                    server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(conn))
                        .await
                        .unwrap();
                let mut priorities = Vec::new();
                for _ in 0..4 {
                    let (request, mut stream) = h3
                        .accept()
                        .await
                        .unwrap()
                        .unwrap()
                        .resolve_request()
                        .await
                        .unwrap();
                    priorities.push(
                        request
                            .headers()
                            .get_all("priority")
                            .iter()
                            .map(|value| value.to_str().unwrap().to_owned())
                            .collect(),
                    );
                    let mut body = Vec::new();
                    while let Some(mut data) = stream.recv_data().await.unwrap() {
                        body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                    }
                    assert_eq!(body, b"upload");
                    stream.send_response(http::Response::new(())).await.unwrap();
                    stream.send_data(bytes::Bytes::from(body)).await.unwrap();
                    stream.finish().await.unwrap();
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                priorities
            }
        });

        let mut preset = lkrequest::preset::chrome_155();
        preset.h2_profile.priority_config.auto_priority_header = automatic;
        let mut builder = lkrequest::Client::builder()
            .preset(preset)
            .add_ca_cert_der(cert_der.as_ref())
            .dns_resolver(Arc::new(LocalIpv4Dns));
        if default_header {
            builder = builder.default_header("priority", "u=5");
        }
        let session = builder.build().session().http3_only().build();
        let url = format!("https://localhost:{}/priority", addr.port());
        for index in 0..4 {
            let mut request = session.post(&url);
            request = match index {
                1 => request.priority(lkh2::RequestPriority::custom(4, false)),
                2 => request.header("priority", "u=7, i"),
                3 => request.header("sec-fetch-dest", "document"),
                _ => request,
            };
            request = if index < 2 {
                request.body_reader(&b"upload"[..], Some(6))
            } else {
                request.body(bytes::Bytes::from_static(b"upload"))
            };
            let body = if streaming_response {
                let response = request.send_streaming().await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                response.bytes().await.unwrap()
            } else {
                let response = request.send().await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(response.version(), lkrequest::HttpVersion::H3);
                bytes::Bytes::copy_from_slice(response.bytes())
            };
            assert_eq!(body, "upload");
        }
        let priorities = task.await.unwrap();
        drop(session);
        server.wait_idle().await;
        priorities
    })
    .await
    .expect("local H3 priority sequence timed out")
}

#[tokio::test]
async fn h3_disabled_auto_priority_preserves_only_supplied_headers() {
    for streaming in [false, true] {
        assert_eq!(
            observed_h3_priorities(false, streaming, false).await,
            vec![vec![], vec![], vec!["u=7, i".to_owned()], vec![]],
            "automatic=false, streaming={streaming}",
        );
        assert_eq!(
            observed_h3_priorities(false, streaming, true).await,
            vec![vec!["u=5"], vec!["u=5"], vec!["u=7, i"], vec!["u=5"]],
            "default header, streaming={streaming}",
        );
    }
}

#[tokio::test]
async fn h3_enabled_auto_priority_resolves_without_duplicate_headers() {
    for streaming in [false, true] {
        assert_eq!(
            observed_h3_priorities(true, streaming, false).await,
            vec![vec!["u=1, i"], vec!["u=4"], vec!["u=7, i"], vec!["u=0, i"]],
            "automatic=true, streaming={streaming}",
        );
        assert_eq!(
            observed_h3_priorities(true, streaming, true).await,
            vec![vec!["u=5"], vec!["u=5"], vec!["u=7, i"], vec!["u=5"]],
            "default header, streaming={streaming}",
        );
    }
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
    let mut rejecting_tls = server_tls.clone();
    rejecting_tls.max_early_data_size = 0;
    let rejecting_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(rejecting_tls).unwrap(),
    ));
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
                if idx == 1 {
                    // Preserve the server ticket store while explicitly refusing
                    // early data offered by the resumed QUIC ClientHello.
                    server.set_server_config(Some(rejecting_config.clone()));
                }
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
                let priority = request
                    .headers()
                    .get("priority")
                    .map(|value| value.to_str().unwrap().to_owned());
                let _ = stream_tx
                    .send((idx, request.method().clone(), stream.is_0rtt(), priority))
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

    let mut h2_profile = lkh2::profile::chrome_155_h2();
    h2_profile.priority_config.auto_priority_header = false;
    // Keep this replacement-path/header-policy control alongside the reuse tests.
    let mut quic_profile = lkh3::chrome_155_quic();
    quic_profile.packetization.reuse_rejected_0rtt_streams = false;
    let client = lkrequest::Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .quic_fingerprint(lktls::profile::presets::chrome_155_quic())
        .h2_profile(h2_profile)
        .quic_profile(quic_profile)
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
    assert_eq!(first_seen.3, None, "automatic priority is disabled");

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
    assert_eq!(second_seen.3, None, "replay retains the disabled switch");

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
    let mut generic = lkrequest::preset::chrome_144();
    generic.quic_profile = Some(lkh3::chrome_quic());
    for (preset, basename) in [
        (generic, "chrome_generic_quic"),
        (lkrequest::preset::chrome_144(), "chrome_146_quic"),
        (lkrequest::preset::chrome_146(), "chrome_146_quic"),
        (lkrequest::preset::chrome_150(), "chrome_150_quic"),
        (lkrequest::preset::chrome_151(), "chrome_151_quic"),
        (lkrequest::preset::chrome_152(), "chrome_152_quic"),
        (lkrequest::preset::chrome_153(), "chrome_153_quic"),
        (lkrequest::preset::chrome_154(), "chrome_154_quic"),
        (lkrequest::preset::chrome_155(), "chrome_155_quic"),
    ] {
        let control = captured_h3_control_stream(preset).await;
        assert_eq!(
            verify_h3_control_golden(&control, basename),
            Ok(()),
            "{basename}"
        );
    }
}

/// Capture actual decrypted control-stream bytes, without deriving observations
/// from the profile or calling the sending backend's frame/varint decoder.
async fn captured_h3_control_stream(preset: lkrequest::preset::ClientPreset) -> Vec<u8> {
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
                while bytes.len() < 65_536 {
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

    let session = client.session().http3_only().build();
    let url = format!("https://localhost:{}/priority", server_addr.port());
    // The raw server never answers H3, so the request itself will not complete;
    // we only care about the control-stream bytes it wrote during connect.
    let client_task = tokio::spawn(async move {
        let _ = session.get(&url).header("priority", "u=0, i").send().await;
    });

    let control = tokio::time::timeout(Duration::from_secs(8), control_rx)
        .await
        .expect("server should observe the H3 control stream")
        .expect("control-stream bytes channel");
    client_task.abort();
    let _ = client_task.await;

    server_task.await.unwrap();
    server.wait_idle().await;
    control
}

fn verify_h3_control_golden(control: &[u8], basename: &str) -> Result<(), String> {
    let golden: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/fingerprints")
                .join(format!("{basename}.json")),
        )
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let parsed = lkprofile::parse_h3_control_stream(control).map_err(|error| error.to_string())?;
    let reserved = |id: u64| id >= 33 && (id - 33).is_multiple_of(31);
    let stable: Vec<_> = parsed
        .settings
        .iter()
        .copied()
        .filter(|(id, _)| !reserved(*id))
        .collect();
    let expected: Vec<(u64, u64)> =
        serde_json::from_value(golden["h3_settings"].clone()).map_err(|error| error.to_string())?;
    if stable != expected {
        return Err("ordered H3 SETTINGS mismatch".into());
    }
    let grease: Vec<_> = parsed
        .settings
        .iter()
        .copied()
        .filter(|(id, _)| reserved(*id))
        .collect();
    if grease.len() != usize::from(golden["grease_settings"] == true) {
        return Err("H3 GREASE setting count mismatch".into());
    }
    if let Some(&(id, value)) = grease.first() {
        if parsed.settings.last() != Some(&(id, value))
            || (id - 33) / 31 > u32::MAX as u64
            || value > u32::MAX as u64
        {
            return Err("H3 GREASE setting position/shape mismatch".into());
        }
    }
    let updates: Vec<(u64, String)> = serde_json::from_value(golden["priority_updates"].clone())
        .map_err(|error| error.to_string())?;
    let control_grease = golden["send_control_grease_frame"] == true;
    let mut index = 1;
    if control_grease {
        let frame = parsed
            .frames
            .get(index)
            .ok_or("missing control GREASE frame")?;
        if !reserved(frame.frame_type) {
            return Err("control GREASE frame order mismatch".into());
        }
        let random = (frame.frame_type - 33) / 31;
        if random > u32::MAX as u64 || frame.payload.len() != (random % 4) as usize {
            return Err("Chromium control GREASE shape mismatch".into());
        }
        index += 1;
    }
    if parsed.frames.len() != index + updates.len()
        || parsed.priority_updates.len() != updates.len()
    {
        return Err("control frame count mismatch".into());
    }
    for (offset, (id, value)) in updates.iter().enumerate() {
        let observed = &parsed.priority_updates[offset];
        if parsed.frames[index + offset].frame_type != 0xf0700
            || observed.frame_type != 0xf0700
            || observed.element_id != *id
            || observed.field_value != value.as_bytes()
        {
            return Err("PRIORITY_UPDATE type/target/payload mismatch".into());
        }
    }
    Ok(())
}

async fn dynamic_h3_control_sequence(
    streaming: bool,
    concurrent: bool,
    automatic: bool,
) -> (Vec<u8>, Vec<u64>) {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        ensure_rustls_provider();
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der =
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
        let mut transport = quinn::TransportConfig::default();
        transport.stream_receive_window(16u32.into());
        config.transport_config(Arc::new(transport));
        let server = Endpoint::server(config, localhost_addr(0)).unwrap();
        let addr = server.local_addr().unwrap();
        let count = if concurrent { 8 } else { 4 };
        let (prelude_tx, prelude_rx) = oneshot::channel();
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let conn = server.accept().await.unwrap().await.unwrap();
                let control_conn = conn.clone();
                let control_task = tokio::spawn(async move {
                    let mut recv = control_conn.accept_uni().await.unwrap();
                    assert_eq!(u64::from(recv.id()), 2, "single client control stream");
                    let mut bytes = Vec::new();
                    let mut prelude_tx = Some(prelude_tx);
                    let mut buffer = [0u8; 1024];
                    loop {
                        let length = recv.read(&mut buffer).await.unwrap().unwrap();
                        bytes.extend_from_slice(&buffer[..length]);
                        if let Ok(parsed) = lkprofile::parse_h3_control_stream(&bytes) {
                            if let Some(tx) = prelude_tx.take() {
                                let _ = tx.send(parsed.priority_updates.len());
                            }
                            if parsed.priority_updates.len() == count {
                                break;
                            }
                        }
                        assert!(bytes.len() < 65_536, "bounded control prefix");
                    }
                    (bytes, recv)
                });
                let mut ids = Vec::new();
                for _ in 0..count {
                    let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                    ids.push(u64::from(recv.id()));
                    let bytes = recv.read_to_end(65_536).await.unwrap();
                    assert!(!bytes.is_empty(), "request emitted HEADERS and upload");
                    // Literal stateless QPACK :status=200 and a DATA response.
                    send.write_all(b"\x01\x03\x00\x00\xd9\x00\x05hello")
                        .await
                        .unwrap();
                    send.finish().unwrap();
                }
                let (control, _control_recv) = control_task.await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                (control, ids)
            }
        });
        let mut preset = lkrequest::preset::chrome_155();
        preset.h2_profile.priority_config.auto_priority_header = automatic;
        let client = lkrequest::Client::builder()
            .preset(preset)
            .add_ca_cert_der(cert_der.as_ref())
            .dns_resolver(Arc::new(LocalIpv4Dns))
            .default_header("sec-fetch-dest", "document")
            .build();
        let session = client.session().http3_only().build();
        let url = format!("https://localhost:{}/priority", addr.port());
        session.preconnect(&url).await.unwrap();
        assert_eq!(
            prelude_rx.await.unwrap(),
            0,
            "preconnect must not prioritize an unallocated request"
        );
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..count {
            let session = session.clone();
            let url = url.clone();
            let task = async move {
                let request = session.post(&url);
                let request = if concurrent {
                    request.priority(lkh2::RequestPriority::custom(3, false))
                } else {
                    match index {
                        0 => request.priority(lkh2::RequestPriority::custom(4, false)),
                        1 => request.header("priority", "u=1, i"),
                        2 => request,
                        _ => request.priority(lkh2::RequestPriority::custom(2, true)),
                    }
                };
                let request = if index % 2 == 0 {
                    request.body_reader(&b"upload"[..], Some(6))
                } else {
                    request.body(bytes::Bytes::from_static(b"upload"))
                };
                let body = if streaming {
                    let response = request.send_streaming().await.unwrap();
                    assert_eq!(response.status(), StatusCode::OK);
                    response.bytes().await.unwrap()
                } else {
                    let response = request.send().await.unwrap();
                    assert_eq!(response.version(), lkrequest::HttpVersion::H3);
                    assert_eq!(response.status(), StatusCode::OK);
                    bytes::Bytes::copy_from_slice(response.bytes())
                };
                assert_eq!(body, "hello");
            };
            if concurrent {
                tasks.spawn(task);
            } else {
                task.await;
            }
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        let result = server_task.await.unwrap();
        drop(session);
        server.wait_idle().await;
        result
    })
    .await
    .expect("dynamic H3 control sequence timed out")
}

#[tokio::test]
async fn h3_updates_follow_actual_streams_for_both_response_modes() {
    for (streaming, automatic) in [(false, false), (true, false), (false, true), (true, true)] {
        let (bytes, ids) = dynamic_h3_control_sequence(streaming, false, automatic).await;
        assert_eq!(ids, [0, 4, 8, 12]);
        let parsed = lkprofile::parse_h3_control_stream(&bytes).unwrap();
        assert_eq!(parsed.frames.len(), 6, "SETTINGS, GREASE and four updates");
        let updates: Vec<_> = parsed
            .priority_updates
            .iter()
            .map(|update| {
                (
                    update.element_id,
                    std::str::from_utf8(update.field_value).unwrap(),
                )
            })
            .collect();
        assert_eq!(
            updates,
            [(0, "u=4"), (4, "u=1, i"), (8, "u=0, i"), (12, "u=2, i")]
        );
    }
}

#[tokio::test]
async fn h3_concurrent_sender_clones_prioritize_allocated_streams_once() {
    for streaming in [false, true] {
        let (bytes, mut ids) = dynamic_h3_control_sequence(streaming, true, false).await;
        ids.sort_unstable();
        assert_eq!(ids, [0, 4, 8, 12, 16, 20, 24, 28]);
        let parsed = lkprofile::parse_h3_control_stream(&bytes).unwrap();
        assert_eq!(parsed.priority_updates.len(), ids.len());
        let mut targets: Vec<_> = parsed
            .priority_updates
            .iter()
            .map(|update| {
                assert_eq!(update.field_value, b"u=3");
                update.element_id
            })
            .collect();
        targets.sort_unstable();
        assert_eq!(
            targets, ids,
            "no predicted IDs, missing or duplicate updates"
        );
    }
}

#[tokio::test]
async fn h3_control_golden_rejects_wire_mutations() {
    use lktls::extensions::quic_transport_params::encode_varint;

    let control = captured_h3_control_stream(lkrequest::preset::chrome_155()).await;
    assert_eq!(
        verify_h3_control_golden(&control, "chrome_155_quic"),
        Ok(())
    );
    let parsed = lkprofile::parse_h3_control_stream(&control).unwrap();
    let frames: Vec<_> = parsed
        .frames
        .iter()
        .map(|frame| (frame.frame_type, frame.payload.to_vec()))
        .collect();
    let emit = |frames: &[(u64, Vec<u8>)]| {
        let mut bytes = vec![0];
        for (kind, payload) in frames {
            encode_varint(*kind, &mut bytes);
            encode_varint(payload.len() as u64, &mut bytes);
            bytes.extend_from_slice(payload);
        }
        bytes
    };
    let mut mutations = Vec::new();
    let mut changed = frames.clone();
    changed.pop();
    mutations.push(("missing update", emit(&changed)));
    let mut changed = frames.clone();
    changed.swap(1, 2);
    mutations.push(("wrong frame order", emit(&changed)));
    let mut changed = frames.clone();
    let field_value = changed[2].1[1..].to_vec();
    changed[2].1.extend_from_slice(&field_value);
    mutations.push(("duplicated priority payload", emit(&changed)));
    let mut changed = frames.clone();
    changed[2].1[0] = 4;
    mutations.push(("wrong request target", emit(&changed)));
    let mut settings = parsed.settings.clone();
    settings.swap(0, 1);
    let mut changed = frames.clone();
    changed[0].1.clear();
    for (id, value) in settings {
        encode_varint(id, &mut changed[0].1);
        encode_varint(value, &mut changed[0].1);
    }
    mutations.push(("wrong SETTINGS order", emit(&changed)));
    let mut truncated = control.clone();
    truncated.pop();
    mutations.push(("truncated frame", truncated));
    for (name, bytes) in mutations {
        assert!(
            verify_h3_control_golden(&bytes, "chrome_155_quic").is_err(),
            "{name}"
        );
    }
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
