//! Connection pool tests — local HTTPS server (Tier 0).
//!
//! Covers: pool_stats, connection reuse verification, capacity tracking.

mod support;

use lkrequest::h2::profile::chrome_144_h2;
#[cfg(feature = "quic-h3")]
use lkrequest::TimeoutConfig;
use lkrequest::{Client, HttpVersion, PreferredHttpVersion};
use lktls::profile::presets;
use support::local_https::{start_local_https_server, url_join};

#[cfg(feature = "quic-h3")]
use std::sync::atomic::Ordering;
#[cfg(feature = "quic-h3")]
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

    assert_eq!(
        srv.tcp_accept_counter.load(Ordering::Relaxed),
        2,
        "the initial H2 connection and QUIC-fallback H2 connection are expected; later requests must reuse the pooled fallback connection"
    );

    quic_server.close(0u32.into(), b"done");
    let _ = quic_task.await;
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
