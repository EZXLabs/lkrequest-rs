//! Replay safety across protocol races, connection recovery, and redirects.
//! All servers and DNS answers are loopback-only (Tier 0).

mod support;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use lkrequest::{Client, HttpVersion, Idempotency};

struct LocalDns;

#[async_trait::async_trait]
impl lkrequest::DnsResolver for LocalDns {
    async fn resolve(&self, _host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
    }
}

fn local_client() -> Client {
    Client::builder()
        .preset(lkrequest::preset::chrome_150())
        .dns_resolver(Arc::new(LocalDns))
        .verify(false)
        .build()
}

#[derive(Default)]
struct RequestCounts {
    h1: AtomicUsize,
    h2: AtomicUsize,
    post: AtomicUsize,
    get: AtomicUsize,
}

struct RecoveryServer {
    url: String,
    counts: Arc<RequestCounts>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for RecoveryServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn recovery_server(redirect: Option<String>) -> RecoveryServer {
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
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}/", listener.local_addr().unwrap());
    let counts = Arc::new(RequestCounts::default());
    let task = tokio::spawn({
        let counts = counts.clone();
        async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((socket, _)) = accepted else { break };
                        let acceptor = acceptor.clone();
                        let counts = counts.clone();
                        let redirect = redirect.clone();
                        connections.spawn(async move {
                            let tls = acceptor.accept(socket).await.unwrap();
                            let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                                let counts = counts.clone();
                                let redirect = redirect.clone();
                                async move {
                                    let method = req.method().clone();
                                    let version = req.version();
                                    let body = req.into_body().collect().await.unwrap().to_bytes();
                                    if method == http::Method::POST {
                                        assert_eq!(body, "one-mutation");
                                        counts.post.fetch_add(1, Ordering::SeqCst);
                                    } else {
                                        assert_eq!(method, http::Method::GET);
                                        assert!(body.is_empty());
                                        counts.get.fetch_add(1, Ordering::SeqCst);
                                    }
                                    if version == http::Version::HTTP_2 {
                                        counts.h2.fetch_add(1, Ordering::SeqCst);
                                    } else {
                                        counts.h1.fetch_add(1, Ordering::SeqCst);
                                    }
                                    if let Some(location) = redirect {
                                        return Ok::<_, std::io::Error>(http::Response::builder()
                                            .status(302)
                                            .header("location", location)
                                            .body(Full::new(Bytes::new()))
                                            .unwrap());
                                    }
                                    if version == http::Version::HTTP_2 {
                                        // Hyper converts a service error to RST_STREAM(INTERNAL_ERROR).
                                        return Err(std::io::Error::other("reset after consuming POST"));
                                    }
                                    Ok(http::Response::new(Full::new(Bytes::from_static(b"ok"))))
                                }
                            });
                            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                                .serve_connection(TokioIo::new(tls), service)
                                .await;
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        }
    });
    RecoveryServer { url, counts, task }
}

async fn post_after_h2_reset(streaming: bool, idempotency: Idempotency) -> (bool, usize, usize) {
    let server = recovery_server(None).await;
    let session = local_client().session().build();
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        let request = session
            .post(&server.url)
            .idempotency(idempotency)
            .body("one-mutation");
        if streaming {
            request.send_streaming().await?.bytes().await.map(|_| ())
        } else {
            request.send().await.map(|response| {
                assert_eq!(response.version(), HttpVersion::Http11);
                assert_eq!(response.bytes(), b"ok");
            })
        }
    })
    .await
    .expect("H2 reset recovery must finish");
    (
        result.is_ok(),
        server.counts.h2.load(Ordering::SeqCst),
        server.counts.h1.load(Ordering::SeqCst),
    )
}

#[tokio::test]
async fn non_idempotent_buffered_post_is_not_replayed_after_h2_reset() {
    assert_eq!(
        post_after_h2_reset(false, Idempotency::NotIdempotent).await,
        (false, 1, 0)
    );
}

#[tokio::test]
async fn non_idempotent_streaming_post_is_not_replayed_after_h2_reset() {
    assert_eq!(
        post_after_h2_reset(true, Idempotency::NotIdempotent).await,
        (false, 1, 0)
    );
}

#[tokio::test]
async fn explicitly_idempotent_post_can_fall_back_after_h2_reset() {
    for streaming in [false, true] {
        assert_eq!(
            post_after_h2_reset(streaming, Idempotency::Idempotent).await,
            (true, 1, 1)
        );
    }
}

async fn redirect_retry_count(method: http::Method, idempotency: Idempotency) -> (bool, usize) {
    let unused = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = format!("http://{}/", unused.local_addr().unwrap());
    drop(unused);
    let source = recovery_server(Some(target)).await;
    let session = local_client()
        .session()
        .retry_policy(lkrequest::retry::FixedInterval::new(
            2,
            Duration::from_millis(1),
        ))
        .build();
    let mut request = session
        .request(method.clone(), &source.url)
        .idempotency(idempotency);
    if method == http::Method::POST {
        request = request.body("one-mutation");
    }
    let result = tokio::time::timeout(Duration::from_secs(10), request.send())
        .await
        .expect("redirect retries must finish");
    let count = if method == http::Method::POST {
        source.counts.post.load(Ordering::SeqCst)
    } else {
        source.counts.get.load(Ordering::SeqCst)
    };
    (result.is_err(), count)
}

#[tokio::test]
async fn redirected_get_connection_failure_does_not_replay_initial_post() {
    assert_eq!(
        redirect_retry_count(http::Method::POST, Idempotency::NotIdempotent).await,
        (true, 1)
    );
}

#[tokio::test]
async fn safe_get_redirect_can_retry_connection_failure() {
    assert_eq!(
        redirect_retry_count(http::Method::GET, Idempotency::Default).await,
        (true, 3)
    );
}

#[tokio::test]
async fn explicitly_idempotent_post_redirect_can_retry_connection_failure() {
    assert_eq!(
        redirect_retry_count(http::Method::POST, Idempotency::Idempotent).await,
        (true, 3)
    );
}

#[cfg(feature = "quic-h3")]
async fn raced_post_count(streaming: bool) -> usize {
    use bytes::Buf;
    use quinn::crypto::rustls::QuicServerConfig;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    let _ = rustls::crypto::ring::default_provider().install_default();
    let https = support::local_https::start_local_https_server().await;
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
    let quic = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let quic_port = quic.local_addr().unwrap().port();
    let quic_posts = Arc::new(AtomicUsize::new(0));
    let server_task = tokio::spawn({
        let quic = quic.clone();
        let quic_posts = quic_posts.clone();
        async move {
            let connection = quic.accept().await.unwrap().await.unwrap();
            let mut h3 =
                h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                    .await
                    .unwrap();
            let Some(resolver) = h3.accept().await.unwrap() else {
                return;
            };
            let (request, mut stream) = resolver.resolve_request().await.unwrap();
            assert_eq!(request.method(), http::Method::POST);
            let mut body = Vec::new();
            while let Some(mut data) = stream.recv_data().await.unwrap() {
                let size = data.remaining();
                body.extend_from_slice(&data.copy_to_bytes(size));
            }
            assert_eq!(body, b"one-mutation");
            quic_posts.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(500)).await;
            if stream
                .send_response(http::Response::builder().status(200).body(()).unwrap())
                .await
                .is_ok()
            {
                let _ = stream.send_data(Bytes::from_static(b"ok")).await;
                let _ = stream.finish().await;
            }
            let _ = h3.accept().await;
        }
    });
    let policy = lkrequest::ProtocolPolicy::chrome_standard().with_acquisition(
        lkrequest::AcquisitionPolicy::Race(
            lkrequest::RacePolicy::chrome_like().with_tcp_delay(Duration::from_millis(100)),
        ),
    );
    let session = local_client().session().protocol_policy(policy).build();
    let warmup = session
        .get(&format!("{}/alt-svc?port={quic_port}", https.base_url))
        .preferred_http_version(lkrequest::PreferredHttpVersion::Http2Only)
        .send()
        .await
        .unwrap();
    assert_eq!(warmup.version(), HttpVersion::H2);
    https.request_counter.store(0, Ordering::SeqCst);
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        let request = session
            .post(&format!("{}/post", https.base_url))
            .idempotency(Idempotency::NotIdempotent)
            .body("one-mutation");
        if streaming {
            request
                .send_streaming()
                .await?
                .bytes()
                .await
                .map(|body| !body.is_empty())
        } else {
            request
                .send()
                .await
                .map(|response| !response.bytes().is_empty())
        }
    })
    .await;
    let count =
        https.request_counter.load(Ordering::SeqCst) as usize + quic_posts.load(Ordering::SeqCst);
    quic.close(0u32.into(), b"done");
    server_task.abort();
    let _ = server_task.await;
    assert!(result
        .expect("raced POST must finish")
        .expect("raced POST succeeds"));
    count
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn protocol_race_sends_non_idempotent_buffered_post_once() {
    assert_eq!(
        raced_post_count(false).await,
        1,
        "connection racing must not duplicate a POST"
    );
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn protocol_race_sends_non_idempotent_streaming_post_once() {
    assert_eq!(
        raced_post_count(true).await,
        1,
        "connection racing must not duplicate a POST"
    );
}

#[cfg(feature = "quic-h3")]
struct AdvertisedH3Dns {
    port: u16,
}

#[cfg(feature = "quic-h3")]
#[async_trait::async_trait]
impl lkrequest::DnsResolver for AdvertisedH3Dns {
    async fn resolve(&self, _host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
    }

    async fn lookup_https(&self, _host: &str) -> std::io::Result<Option<lkrequest::HttpsRecord>> {
        Ok(Some(lkrequest::HttpsRecord {
            alpn: vec!["h3".into()],
            port: Some(self.port),
            ..Default::default()
        }))
    }
}

#[cfg(feature = "quic-h3")]
async fn raced_post_error_after_tcp_failure(
    streaming: bool,
    connection_limit: usize,
) -> (usize, bool, bool) {
    use bytes::Buf;
    use quinn::crypto::rustls::QuicServerConfig;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    let _ = rustls::crypto::ring::default_provider().install_default();
    let unused_tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = unused_tcp.local_addr().unwrap().port();
    drop(unused_tcp);
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
    let quic = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let quic_posts = Arc::new(AtomicUsize::new(0));
    let server_task = tokio::spawn({
        let quic = quic.clone();
        let quic_posts = quic_posts.clone();
        async move {
            let incoming = quic.accept().await.unwrap();
            // Let the competing TCP reservation or connection attempt fail first.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let connection = incoming.await.unwrap();
            let mut h3 =
                h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                    .await
                    .unwrap();
            while let Ok(Some(resolver)) = h3.accept().await {
                let (request, mut stream) = resolver.resolve_request().await.unwrap();
                assert_eq!(request.method(), http::Method::POST);
                let mut body = Vec::new();
                while let Some(mut data) = stream.recv_data().await.unwrap() {
                    let size = data.remaining();
                    body.extend_from_slice(&data.copy_to_bytes(size));
                }
                assert_eq!(body, b"one-mutation");
                quic_posts.fetch_add(1, Ordering::SeqCst);
                stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
            }
        }
    });
    let client = Client::builder()
        .preset(lkrequest::preset::chrome_150())
        .dns_resolver(Arc::new(AdvertisedH3Dns {
            port: quic.local_addr().unwrap().port(),
        }))
        .verify(false)
        .timeout_config(
            lkrequest::TimeoutConfig::default().with_tcp_connect_timeout(Duration::from_millis(50)),
        )
        .build();
    let policy = lkrequest::ProtocolPolicy::chrome_standard().with_acquisition(
        lkrequest::AcquisitionPolicy::Race(
            lkrequest::RacePolicy::chrome_like().with_tcp_delay(Duration::ZERO),
        ),
    );
    let session = client
        .session()
        .protocol_policy(policy)
        .max_connections(connection_limit)
        .retry_policy(lkrequest::retry::FixedInterval::new(
            2,
            Duration::from_millis(1),
        ))
        .build();
    let result = tokio::time::timeout(Duration::from_secs(8), async {
        let request = session
            .post(&format!("https://localhost:{origin_port}/post"))
            .idempotency(Idempotency::NotIdempotent)
            .body("one-mutation");
        if streaming {
            request.send_streaming().await.map(|_| ())
        } else {
            request.send().await.map(|_| ())
        }
    })
    .await;
    let count = quic_posts.load(Ordering::SeqCst);
    quic.close(0u32.into(), b"done");
    server_task.abort();
    let _ = server_task.await;
    let error = result
        .expect("race failure must finish within eight seconds")
        .expect_err("server resets the submitted POST");
    (
        count,
        error.is_safe_to_replay(),
        error.phase() == Some(lkrequest::error::ConnectionPhase::QuicFallback),
    )
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn raced_post_error_after_tcp_connect_failure_is_not_replayable() {
    assert_eq!(
        raced_post_error_after_tcp_failure(false, 8).await,
        (1, false, false),
        "a sent POST's H3 stream error must survive the failed TCP branch"
    );
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn raced_post_error_after_tcp_budget_failure_is_not_replayable() {
    assert_eq!(
        raced_post_error_after_tcp_failure(false, 1).await,
        (1, false, false),
        "TCP budget failure must not replay or replace a sent POST's H3 error"
    );
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn raced_post_error_after_tcp_connect_failure_preserves_streaming_error() {
    assert_eq!(
        raced_post_error_after_tcp_failure(true, 8).await,
        (1, false, false),
        "streaming must retain the submitted POST's H3 failure classification"
    );
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn raced_post_error_after_tcp_budget_failure_preserves_streaming_error() {
    assert_eq!(
        raced_post_error_after_tcp_failure(true, 1).await,
        (1, false, false),
        "TCP budget failure must not replace a submitted streaming POST's H3 error"
    );
}
