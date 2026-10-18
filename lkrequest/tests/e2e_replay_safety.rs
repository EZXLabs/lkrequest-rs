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
    recovery_server_with_mode(redirect, None).await
}

async fn recovery_server_with_mode(
    redirect: Option<String>,
    pooled_failures: Option<usize>,
) -> RecoveryServer {
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
                            let close = Arc::new(tokio::sync::Notify::new());
                            let close_service = close.clone();
                            let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                                let counts = counts.clone();
                                let redirect = redirect.clone();
                                let close = close_service.clone();
                                async move {
                                    let method = req.method().clone();
                                    let version = req.version();
                                    let body = req.into_body().collect().await.unwrap().to_bytes();
                                    let mut post_number = 0;
                                    if method == http::Method::POST {
                                        assert_eq!(body, "one-mutation");
                                        post_number = counts.post.fetch_add(1, Ordering::SeqCst) + 1;
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
                                    if let Some(failures) = pooled_failures {
                                        if post_number > 0 && post_number <= failures {
                                            close.notify_one();
                                            return std::future::pending::<Result<_, std::io::Error>>().await;
                                        }
                                        return Ok(http::Response::new(Full::new(Bytes::from_static(b"ok"))));
                                    }
                                    if version == http::Version::HTTP_2 {
                                        // Hyper converts a service error to RST_STREAM(INTERNAL_ERROR).
                                        return Err(std::io::Error::other("reset after consuming POST"));
                                    }
                                    Ok(http::Response::new(Full::new(Bytes::from_static(b"ok"))))
                                }
                            });
                            let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                            tokio::select! {
                                _ = builder.serve_connection(TokioIo::new(tls), service) => {},
                                _ = close.notified() => {},
                            }
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        }
    });
    RecoveryServer { url, counts, task }
}

#[tokio::test]
async fn pooled_connection_recovery_respects_post_replay_safety() {
    for (http2, streaming) in [(false, false), (true, false), (true, true)] {
        for idempotency in [
            Idempotency::Default,
            Idempotency::NotIdempotent,
            Idempotency::Idempotent,
        ] {
            let server = recovery_server_with_mode(None, Some(1)).await;
            let client = local_client();
            let builder = client.session();
            let session = if http2 {
                builder.http2_only().build()
            } else {
                builder.http1_only().build()
            };
            let warmup = session.get(&server.url).send().await.unwrap();
            assert_eq!(
                warmup.version(),
                if http2 {
                    HttpVersion::H2
                } else {
                    HttpVersion::Http11
                }
            );
            assert_eq!(warmup.bytes(), b"ok");
            let request = session
                .post(&server.url)
                .idempotency(idempotency)
                .body("one-mutation");
            let result = tokio::time::timeout(Duration::from_secs(3), async {
                if streaming {
                    request.send_streaming().await?.bytes().await.map(|_| ())
                } else {
                    request.send().await.map(|_| ())
                }
            })
            .await
            .unwrap();
            let allowed = idempotency == Idempotency::Idempotent;
            assert_eq!(
                server.counts.post.load(Ordering::SeqCst),
                if allowed { 2 } else { 1 },
                "HTTP/2={http2}, streaming={streaming}, idempotency={idempotency:?}"
            );
            assert_eq!(
                result.is_ok(),
                allowed,
                "HTTP/2={http2}, idempotency={idempotency:?}"
            );
        }
    }
}

#[tokio::test]
async fn pooled_recovery_stops_after_one_additional_send() {
    for streaming in [false, true] {
        let server = recovery_server_with_mode(None, Some(usize::MAX)).await;
        let session = local_client().session().http2_only().build();
        assert_eq!(
            session.get(&server.url).send().await.unwrap().bytes(),
            b"ok"
        );
        let request = session
            .post(&server.url)
            .idempotency(Idempotency::Idempotent)
            .body("one-mutation");
        let result = tokio::time::timeout(Duration::from_secs(3), async {
            if streaming {
                request.send_streaming().await.map(|_| ())
            } else {
                request.send().await.map(|_| ())
            }
        })
        .await
        .expect("pooled recovery repeatedly retried a failed replacement");
        assert!(result.is_err());
        assert_eq!(
            server.counts.h1.load(Ordering::SeqCst),
            0,
            "HTTP/2-only recovery downgraded to H1"
        );
        assert_eq!(server.counts.post.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn pooled_refused_h2_stream_can_replay_a_post_before_processing() {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(
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
    config.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}/", listener.local_addr().unwrap());
    let attempts = Arc::new(AtomicUsize::new(0));
    let processed = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn({
        let attempts = attempts.clone();
        let processed = processed.clone();
        async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (socket, _) = accepted.unwrap();
                        let acceptor = acceptor.clone();
                        let attempts = attempts.clone();
                        let processed = processed.clone();
                        connections.spawn(async move {
                            let mut connection = h2::server::handshake(acceptor.accept(socket).await.unwrap()).await.unwrap();
                            let mut requests = tokio::task::JoinSet::new();
                            while let Some(Ok((request, mut respond))) = connection.accept().await {
                                let attempts = attempts.clone();
                                let processed = processed.clone();
                                requests.spawn(async move {
                                    if request.method() == http::Method::POST {
                                        if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                                            respond.send_reset(h2::Reason::REFUSED_STREAM);
                                            return;
                                        }
                                        let mut body = request.into_body();
                                        let mut received = Vec::new();
                                        while let Some(data) = body.data().await { received.extend_from_slice(&data.unwrap()); }
                                        assert_eq!(received, b"one-mutation");
                                        processed.fetch_add(1, Ordering::SeqCst);
                                    }
                                    let mut stream = respond.send_response(http::Response::new(()), false).unwrap();
                                    stream.send_data(Bytes::from_static(b"ok"), true).unwrap();
                                });
                            }
                        });
                    }
                    _ = connections.join_next(), if !connections.is_empty() => {},
                }
            }
        }
    });
    let session = local_client().session().http2_only().build();
    assert_eq!(session.get(&url).send().await.unwrap().bytes(), b"ok");
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        session.post(&url).body("one-mutation").send(),
    )
    .await;
    server.abort();
    let _ = server.await;
    assert_eq!(result.unwrap().unwrap().bytes(), b"ok");
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(processed.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn pooled_h3_recovery_respects_post_replay_safety() {
    use bytes::Buf;
    use quinn::crypto::rustls::QuicServerConfig;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    for streaming in [false, true] {
        for reject_before_processing in [false, true] {
            for idempotency in [
                Idempotency::Default,
                Idempotency::NotIdempotent,
                Idempotency::Idempotent,
            ] {
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                let mut tls = rustls::ServerConfig::builder_with_provider(
                    rustls::crypto::ring::default_provider().into(),
                )
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.cert.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        cert.signing_key.serialize_der(),
                    )),
                )
                .unwrap();
                tls.alpn_protocols = vec![b"h3".to_vec()];
                let config = quinn::ServerConfig::with_crypto(Arc::new(
                    QuicServerConfig::try_from(tls).unwrap(),
                ));
                let endpoint =
                    quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
                let url = format!(
                    "https://localhost:{}/",
                    endpoint.local_addr().unwrap().port()
                );
                let posts = Arc::new(AtomicUsize::new(0));
                let attempts = Arc::new(AtomicUsize::new(0));
                let connection_count = Arc::new(AtomicUsize::new(0));
                let server = tokio::spawn({
                    let endpoint = endpoint.clone();
                    let posts = posts.clone();
                    let attempts = attempts.clone();
                    let connection_count = connection_count.clone();
                    async move {
                        let mut connections = tokio::task::JoinSet::new();
                        loop {
                            tokio::select! {
                                incoming = endpoint.accept() => {
                                    let Some(incoming) = incoming else { break };
                                    let posts = posts.clone();
                                    let attempts = attempts.clone();
                                    let connection_count = connection_count.clone();
                                    connections.spawn(async move {
                                        let connection = incoming.await.unwrap();
                                        connection_count.fetch_add(1, Ordering::SeqCst);
                                        let mut h3 = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection.clone())).await.unwrap();
                                        while let Ok(Some(resolver)) = h3.accept().await {
                                            let (request, mut stream) = resolver.resolve_request().await.unwrap();
                                            let mut body = Vec::new();
                                            while let Some(mut data) = stream.recv_data().await.unwrap() {
                                                let length = data.remaining();
                                                body.extend_from_slice(&data.copy_to_bytes(length));
                                            }
                                            if request.method() == http::Method::POST {
                                                assert_eq!(body, b"one-mutation");
                                                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                                                if reject_before_processing && attempt == 0 {
                                                    stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
                                                    continue;
                                                }
                                                if posts.fetch_add(1, Ordering::SeqCst) == 0 && !reject_before_processing {
                                                    connection.close(0x102u32.into(), b"closed after processing POST");
                                                    break;
                                                }
                                            } else { assert_eq!(request.method(), http::Method::GET); }
                                            stream.send_response(http::Response::new(())).await.unwrap();
                                            stream.send_data(Bytes::from_static(b"ok")).await.unwrap();
                                            stream.finish().await.unwrap();
                                        }
                                    });
                                }
                                _ = connections.join_next(), if !connections.is_empty() => {},
                            }
                        }
                    }
                });
                let session = local_client().session().http3_only().build();
                let warmup = session.get(&url).send().await.unwrap();
                assert_eq!(warmup.version(), HttpVersion::H3);
                let request = session
                    .post(&url)
                    .idempotency(idempotency)
                    .body("one-mutation");
                let result = tokio::time::timeout(Duration::from_secs(5), async {
                    if streaming {
                        request.send_streaming().await?.bytes().await.map(|_| ())
                    } else {
                        request.send().await.map(|_| ())
                    }
                })
                .await;
                endpoint.close(0u32.into(), b"done");
                server.abort();
                let _ = server.await;
                let allowed = reject_before_processing || idempotency == Idempotency::Idempotent;
                let outcome = result.unwrap();
                assert_eq!(
                posts.load(Ordering::SeqCst),
                if reject_before_processing || !allowed {
                    1
                } else {
                    2
                },
                "{idempotency:?}, streaming={streaming}, reject={reject_before_processing}, connections={}, outcome={:?}",
                connection_count.load(Ordering::SeqCst),
                outcome.as_ref().map_err(|e| (
                    e.to_string(),
                    e.phase(),
                    e.is_safe_to_replay()
                ))
            );
                assert_eq!(attempts.load(Ordering::SeqCst), if allowed { 2 } else { 1 });
                assert_eq!(outcome.is_ok(), allowed);
            }
        }
    }
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
