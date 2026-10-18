//! A failed QUIC handshake must release its physical slot before TCP fallback.
#![cfg(feature = "quic-h3")]

mod support;

#[path = "e2e_quic_fallback_budget/coalesced.rs"]
mod coalesced;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use lkrequest::{
    AcquisitionPolicy, Client, FallbackPolicy, HttpVersion, PreferredHttpVersion, ProtocolPolicy,
};
use support::local_https::{start_local_https_server, url_join};

struct LocalDns;

#[async_trait::async_trait]
impl lkrequest::DnsResolver for LocalDns {
    async fn resolve(&self, _host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
    }
}

async fn observe_quic_fallback_connection_counts(streaming: bool) -> (u32, usize, usize) {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.cert.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            cert.signing_key.serialize_der(),
        )),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"not-h3".to_vec()];
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let quic = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let rejected_handshake = tokio::spawn({
        let quic = quic.clone();
        async move {
            let incoming = quic.accept().await.expect("one QUIC connection attempt");
            assert!(incoming.await.is_err(), "incompatible ALPN must reject H3");
        }
    });

    let server = start_local_https_server().await;
    let session = Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .h2_profile(lkrequest::h2::profile::chrome_144_h2())
        .quic_profile(lkh3::chrome_quic())
        .dns_resolver(Arc::new(LocalDns))
        .verify(false)
        .timeout_config(
            lkrequest::TimeoutConfig::default().with_quic_connect_timeout(Duration::from_secs(3)),
        )
        .build()
        .session()
        .protocol_policy(
            ProtocolPolicy::chrome_standard()
                .with_acquisition(AcquisitionPolicy::EstablishBestAvailable)
                .with_fallback(FallbackPolicy::AllowFallback),
        )
        .max_connections(1)
        .build();
    let url = url_join(
        &server.base_url,
        &format!("/alt-svc?port={}", quic.local_addr().unwrap().port()),
    );
    let warmup = session
        .get(&url)
        .preferred_http_version(PreferredHttpVersion::Http1Only)
        .send()
        .await
        .expect("learn the local H3 advertisement over H1");
    assert_eq!(warmup.status().as_u16(), 200);
    // Retain discovery while ensuring the next request must establish QUIC.
    session.pool_clear();
    assert_eq!(session.pool_stats().total, 0);

    let result: lkrequest::error::Result<()> = async {
        if streaming {
            let response = session.get(&url).send_streaming().await?;
            assert_eq!(response.status().as_u16(), 200);
            assert!(!response.bytes().await?.is_empty());
        } else {
            let response = session.get(&url).send().await?;
            assert_eq!(response.status().as_u16(), 200);
            assert_eq!(response.version(), HttpVersion::H2);
        }
        Ok(())
    }
    .await;

    tokio::time::timeout(Duration::from_secs(3), rejected_handshake)
        .await
        .expect("the request must reach the rejecting QUIC server")
        .expect("QUIC handshake rejection");
    quic.close(0u32.into(), b"done");
    result.expect("failed QUIC handshake must release its slot before TCP fallback");
    let stats = session.pool_stats();
    (
        server.tcp_accept_counter.load(Ordering::Relaxed),
        stats.h2_connections,
        stats.total,
    )
}

#[tokio::test]
async fn buffered_quic_fallback_releases_connection_slot() {
    assert_eq!(
        observe_quic_fallback_connection_counts(false).await,
        (2, 1, 1)
    );
}

#[tokio::test]
async fn streaming_quic_fallback_releases_connection_slot() {
    assert_eq!(
        observe_quic_fallback_connection_counts(true).await,
        (2, 1, 1)
    );
}
