//! Connection pool tests — local HTTPS server (Tier 0).
//!
//! Covers: pool_stats, connection reuse verification, capacity tracking.

mod support;

#[cfg(feature = "quic-h3")]
#[path = "e2e_connection_pool/h3_race.rs"]
mod h3_race;

#[cfg(feature = "quic-h3")]
#[path = "e2e_connection_pool/h3_coalesce.rs"]
mod h3_coalesce;

use lkrequest::h2::profile::chrome_144_h2;
#[cfg(feature = "quic-h3")]
use lkrequest::TimeoutConfig;
use lkrequest::{Client, HttpVersion, PreferredHttpVersion, ProtocolPolicy, Session};
use lktls::profile::presets;
use support::local_https::{start_local_https_server, url_join};
use support::local_proxy::start_local_proxy;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
#[cfg(feature = "quic-h3")]
use std::time::Duration;

#[cfg(feature = "quic-h3")]
use quinn::crypto::rustls::QuicServerConfig;
#[cfg(feature = "quic-h3")]
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

fn chrome_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .build()
}

struct LocalDns;

#[async_trait::async_trait]
impl lkrequest::DnsResolver for LocalDns {
    async fn resolve(&self, _host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
    }
}

fn chrome_preset_client() -> Client {
    Client::builder()
        .preset(lkrequest::preset::chrome_150())
        .dns_resolver(Arc::new(LocalDns))
        .verify(false)
        .build()
}

async fn consume_h2_response(session: &Session, url: &str, streaming: bool) {
    if streaming {
        let response = session
            .get(url)
            .send_streaming()
            .await
            .expect("streaming H2 request");
        assert_eq!(response.status().as_u16(), 200);
        assert!(!response
            .bytes()
            .await
            .expect("streaming response body")
            .is_empty());
    } else {
        let response = session.get(url).send().await.expect("buffered H2 request");
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.version(), HttpVersion::H2);
        assert!(!response.bytes().is_empty());
    }
    assert_eq!(session.pool_stats().h2_connections, 1);
}

// ---------------------------------------------------------------------------
// pool_stats after requests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pool_stats_after_h2_request() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http2_only().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status().as_u16(), 200);

    let stats = session.pool_stats();
    assert!(
        stats.h2_connections > 0 || stats.total > 0,
        "pool should have at least 1 connection after request, stats={stats:?}"
    );
}

#[tokio::test]
async fn test_pool_stats_after_h1_request() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/get"))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status().as_u16(), 200);

    let stats = session.pool_stats();
    assert!(
        stats.total > 0,
        "pool should have at least 1 connection, stats={stats:?}"
    );
}

// ---------------------------------------------------------------------------
// Connection reuse (multiple requests, same pool)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pool_connection_reuse_h2() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http2_only().build();

    for i in 0..5 {
        let resp = session
            .get(&url_join(&srv.base_url, "/get"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("request {i}: {e}"));
        assert_eq!(resp.status().as_u16(), 200);
    }

    let stats = session.pool_stats();
    assert!(
        stats.h2_connections <= 2,
        "H2 should multiplex on ≤2 connections, got {stats:?}"
    );
    assert_eq!(
        srv.tcp_accept_counter.load(Ordering::Relaxed),
        1,
        "sequential H2 requests should reuse one physical connection"
    );
}

async fn chrome_preset_h2_connection_count(streaming: bool, connection_limit: usize) -> u32 {
    let srv = start_local_https_server().await;
    let session = chrome_preset_client()
        .session()
        .max_connections(connection_limit)
        .build();
    let url = url_join(&srv.base_url, "/get");

    for _ in 0..3 {
        consume_h2_response(&session, &url, streaming).await;
    }

    srv.tcp_accept_counter.load(Ordering::Relaxed)
}

#[tokio::test]
async fn test_chrome_preset_reuses_h2_without_h3_advertisement() {
    assert_eq!(
        chrome_preset_h2_connection_count(false, 8).await,
        1,
        "Chrome preset must reuse H2 when no H3 route is advertised"
    );
}

#[tokio::test]
async fn test_chrome_preset_streaming_reuses_h2_without_h3_advertisement() {
    assert_eq!(
        chrome_preset_h2_connection_count(true, 8).await,
        1,
        "streaming requests must reuse H2 when no H3 route is advertised"
    );
}

#[tokio::test]
async fn test_chrome_preset_reuses_h2_at_connection_limit() {
    assert_eq!(
        chrome_preset_h2_connection_count(false, 1).await,
        1,
        "warm H2 requests must succeed at the physical connection limit"
    );
}

#[tokio::test]
async fn test_chrome_preset_streaming_reuses_h2_at_connection_limit() {
    assert_eq!(
        chrome_preset_h2_connection_count(true, 1).await,
        1,
        "warm streaming H2 requests must succeed at the physical connection limit"
    );
}

async fn h3_acquisition_http_connect_connection_count(streaming: bool) -> u32 {
    let srv = start_local_https_server().await;
    let proxy = start_local_proxy(Default::default()).await;
    let session = chrome_preset_client()
        .session()
        .protocol_policy(ProtocolPolicy::chrome_standard())
        .proxy(&proxy.url)
        .build();
    let url = url_join(&srv.base_url, "/alt-svc?port=9");

    for _ in 0..3 {
        consume_h2_response(&session, &url, streaming).await;
    }

    srv.tcp_accept_counter.load(Ordering::Relaxed)
}

#[tokio::test]
async fn test_h3_acquisition_reuses_h2_through_http_connect() {
    assert_eq!(
        h3_acquisition_http_connect_connection_count(false).await,
        1,
        "H3 advertisement unusable through HTTP CONNECT must not prevent H2 reuse"
    );
}

#[tokio::test]
async fn test_h3_acquisition_streaming_reuses_h2_through_http_connect() {
    assert_eq!(
        h3_acquisition_http_connect_connection_count(true).await,
        1,
        "H3 advertisement unusable through HTTP CONNECT must not prevent streaming H2 reuse"
    );
}

#[tokio::test]
async fn test_pool_connection_reuse_h1() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    for i in 0..3 {
        let resp = session
            .get(&url_join(&srv.base_url, "/get"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("request {i}: {e}"));
        assert_eq!(resp.status().as_u16(), 200);
    }

    let stats = session.pool_stats();
    assert!(
        stats.total >= 1,
        "H1 pool should have connections, stats={stats:?}"
    );
}

#[tokio::test]
async fn test_chrome_policy_reuses_h1_without_quic_profile() {
    let srv = start_local_https_server().await;
    let mut profile = presets::chrome_144();
    profile.alpn_protocols = vec!["http/1.1".into()];
    let session = Client::builder()
        .fingerprint(profile)
        .protocol_policy(ProtocolPolicy::chrome_standard())
        .dns_resolver(Arc::new(LocalDns))
        .verify(false)
        .build()
        .session()
        .build();
    let url = url_join(&srv.base_url, "/get");
    for _ in 0..3 {
        let response = session.get(&url).send().await.expect("H1 response");
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.version(), HttpVersion::Http11);
    }
    session.preconnect(&url).await.expect("reuse warm H1");
    assert_eq!(srv.tcp_accept_counter.load(Ordering::Relaxed), 1);
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn test_h3_fallback_reuses_pooled_h2_after_quic_is_marked_broken() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let srv = start_local_https_server().await;
    let quic_cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let quic_cert_der = CertificateDer::from(quic_cert.cert.der().to_vec());
    let quic_key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        quic_cert.signing_key.serialize_der(),
    ));
    let mut quic_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![quic_cert_der], quic_key_der)
        .unwrap();
    quic_tls.alpn_protocols = vec![b"not-h3".to_vec()];
    let quic_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(quic_tls).unwrap()));
    let quic_server = quinn::Endpoint::server(quic_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let quic_port = quic_server.local_addr().unwrap().port();
    let quic_task = tokio::spawn({
        let quic_server = quic_server.clone();
        async move {
            if let Some(incoming) = quic_server.accept().await {
                let _ = incoming.await;
            }
        }
    });
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .quic_profile(lkh3::chrome_quic())
        .verify(false)
        .timeout_config(
            TimeoutConfig::default().with_quic_connect_timeout(Duration::from_millis(200)),
        )
        .build();
    let session = client.session().http3_with_fallback().build();
    let url = url_join(&srv.base_url, &format!("/alt-svc?port={quic_port}"));

    for request_index in 0..3 {
        let response = session
            .get(&url)
            .send()
            .await
            .unwrap_or_else(|error| panic!("request {request_index}: {error}"));
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.version(), HttpVersion::H2);
    }

    for _ in 0..2 {
        session
            .preconnect(&srv.base_url)
            .await
            .expect("preconnect during QUIC cooldown");
    }

    assert_eq!(
        srv.tcp_accept_counter.load(Ordering::Relaxed),
        2,
        "the initial H2 connection and QUIC-fallback H2 connection are expected; later requests must reuse the pooled fallback connection"
    );

    quic_server.close(0u32.into(), b"done");
    let _ = quic_task.await;
}

#[cfg(feature = "quic-h3")]
enum ProbeTrigger {
    Buffered,
    Streaming,
    Preconnect,
}

#[cfg(feature = "quic-h3")]
async fn advertised_h3_probe_with_pooled_h2(trigger: ProbeTrigger) -> bool {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let srv = start_local_https_server().await;
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut quic_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    quic_tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(quic_tls).unwrap()));
    let quic_server = quinn::Endpoint::server(quic_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let quic_port = quic_server.local_addr().unwrap().port();
    let quic_task = tokio::spawn({
        let quic_server = quic_server.clone();
        async move {
            let Some(incoming) = quic_server.accept().await else {
                return;
            };
            // The test closes this endpoint as its last step, so a handshake
            // or H3 setup that loses the race is a normal shutdown, not a
            // failure. Panicking here used to mask the only interesting
            // outcome: `LocallyClosed` surfaced through `quic_task.await`
            // before the probe assertion ran, so a probe that never fired was
            // reported as a broken QUIC handshake.
            let Ok(connection) = incoming.await else {
                return;
            };
            let Ok(mut h3_connection) = h3::server::Connection::<_, bytes::Bytes>::new(
                h3_quinn::Connection::new(connection),
            )
            .await
            else {
                return;
            };
            while let Ok(Some(resolver)) = h3_connection.accept().await {
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                stream
                    .send_response(http::Response::builder().status(200).body(()).unwrap())
                    .await
                    .unwrap();
                stream
                    .send_data(bytes::Bytes::from_static(b"local-h3"))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
            }
        }
    });
    let session = chrome_preset_client()
        .session()
        .protocol_policy(
            ProtocolPolicy::chrome_standard()
                .with_acquisition(lkrequest::AcquisitionPolicy::ReuseExistingFirst),
        )
        .build();
    let warmup = session
        .get(&url_join(
            &srv.base_url,
            &format!("/alt-svc?port={quic_port}"),
        ))
        .preferred_http_version(PreferredHttpVersion::Http2Only)
        .send()
        .await
        .expect("learn H3 advertisement over H2");
    assert_eq!(warmup.version(), HttpVersion::H2);
    assert!(!warmup.bytes().is_empty());
    assert_eq!(session.pool_stats().h2_connections, 1);
    assert_eq!(session.pool_stats().h3_connections, 0);

    let url = url_join(&srv.base_url, "/get");
    match trigger {
        ProbeTrigger::Buffered => consume_h2_response(&session, &url, false).await,
        ProbeTrigger::Streaming => consume_h2_response(&session, &url, true).await,
        ProbeTrigger::Preconnect => session.preconnect(&url).await.expect("preconnect"),
    }
    let probe_result = tokio::time::timeout(Duration::from_secs(3), async {
        while session.pool_stats().h3_connections == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;

    // Check the probe before the server task: its outcome is what this test is
    // about, and a task that noticed the close first must not speak over it.
    let probed = probe_result.is_ok();
    quic_server.close(0u32.into(), b"done");
    quic_task.await.expect("local H3 server task");
    probed
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn test_advertised_h3_probe_with_pooled_h2_buffered() {
    assert!(
        advertised_h3_probe_with_pooled_h2(ProbeTrigger::Buffered).await,
        "buffered requests must preserve the background probe for advertised, viable H3"
    );
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn test_advertised_h3_probe_with_pooled_h2_streaming() {
    assert!(
        advertised_h3_probe_with_pooled_h2(ProbeTrigger::Streaming).await,
        "streaming requests must preserve the background probe for advertised, viable H3"
    );
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn test_advertised_h3_probe_with_pooled_h2_preconnect() {
    assert!(
        advertised_h3_probe_with_pooled_h2(ProbeTrigger::Preconnect).await,
        "preconnect must preserve the background probe for advertised, viable H3"
    );
}

// ---------------------------------------------------------------------------
// Pool stats initially empty
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pool_stats_empty_initially() {
    let client = chrome_client();
    let session = client.session().build();

    let stats = session.pool_stats();
    assert_eq!(stats.total, 0, "pool starts empty");
}

// ---------------------------------------------------------------------------
// Preconnect warms pool
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_chrome_preset_preconnect_reuses_h2() {
    let srv = start_local_https_server().await;
    let session = chrome_preset_client().session().build();

    for _ in 0..3 {
        session.preconnect(&srv.base_url).await.expect("preconnect");
    }
    assert_eq!(
        srv.tcp_accept_counter.load(Ordering::Relaxed),
        1,
        "repeated preconnect must reuse the warmed H2 connection"
    );

    let url = url_join(&srv.base_url, "/get");
    for streaming in [false, true] {
        consume_h2_response(&session, &url, streaming).await;
    }
    assert_eq!(
        srv.tcp_accept_counter.load(Ordering::Relaxed),
        1,
        "requests must reuse the preconnected H2 connection"
    );
}

#[tokio::test]
async fn test_preconnect_increases_pool_stats() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let stats_before = session.pool_stats();
    assert_eq!(stats_before.total, 0);

    session.preconnect(&srv.base_url).await.expect("preconnect");

    let stats_after = session.pool_stats();
    assert!(
        stats_after.total > 0,
        "preconnect should warm the pool, stats={stats_after:?}"
    );
}

#[tokio::test]
async fn test_preconnect_http1_only_warms_h1_pool() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    session.preconnect(&srv.base_url).await.expect("preconnect");

    let stats = session.pool_stats();
    assert_eq!(
        stats.h2_connections, 0,
        "http1_only preconnect must not warm h2: {stats:?}"
    );
    assert!(
        stats.h1_connections > 0,
        "http1_only preconnect should warm an h1 connection: {stats:?}"
    );
}

#[tokio::test]
async fn test_request_http11_override_ignores_pooled_h2() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();
    let url = url_join(&srv.base_url, "/get");

    let warmup = session.get(&url).send().await.expect("warmup h2 request");
    assert_eq!(warmup.version(), HttpVersion::H2);
    assert!(
        session.pool_stats().h2_connections > 0,
        "expected pooled h2 connection after warmup"
    );

    let resp = session
        .get(&url)
        .preferred_http_version(PreferredHttpVersion::Http1Only)
        .send()
        .await
        .expect("http/1.1 override request");

    assert_eq!(resp.version(), HttpVersion::Http11);
}
