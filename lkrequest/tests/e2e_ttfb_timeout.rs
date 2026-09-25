//! TTFB deadlines bound response headers, independently of response body reads.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use lkrequest::error::{ConnectionPhase, Error, Result};
use lkrequest::{Client, Session};

// Leave scheduling headroom on shared CI runners while keeping the deliberate
// header/body delay well beyond the deadline under test.
const TTFB: Duration = Duration::from_millis(200);
const RESPONSE_DELAY: Duration = Duration::from_secs(1);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);

struct DelayedBody {
    delay: Pin<Box<tokio::time::Sleep>>,
    sent: bool,
}

impl Body for DelayedBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        if this.sent {
            return Poll::Ready(None);
        }
        std::task::ready!(this.delay.as_mut().poll(cx));
        this.sent = true;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"ok")))))
    }

    fn is_end_stream(&self) -> bool {
        self.sent
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(if self.sent { 0 } else { 2 })
    }
}

struct LocalServer {
    url: String,
    accepts: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn server_tls(alpn: &[u8]) -> rustls::ServerConfig {
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
    config.alpn_protocols = vec![alpn.to_vec()];
    config
}

async fn tcp_server(h2: bool) -> LocalServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let alpn = if h2 { b"h2".as_slice() } else { b"http/1.1" };
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls(alpn)));
    let accepts = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn({
        let accepts = Arc::clone(&accepts);
        async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                // TLS tickets and H2 control frames must not hold response
                // headers behind Nagle/delayed ACK on Linux.
                socket.set_nodelay(true).unwrap();
                accepts.fetch_add(1, Ordering::Relaxed);
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let tls = acceptor.accept(socket).await.unwrap();
                    let service = service_fn(|request: http::Request<Incoming>| async move {
                        if request.uri().path() == "/slow-headers" {
                            tokio::time::sleep(RESPONSE_DELAY).await;
                        }
                        let body_delay = if request.uri().path() == "/slow-body" {
                            RESPONSE_DELAY
                        } else {
                            Duration::ZERO
                        };
                        Ok::<_, Infallible>(http::Response::new(DelayedBody {
                            delay: Box::pin(tokio::time::sleep(body_delay)),
                            sent: false,
                        }))
                    });
                    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        }
    });
    LocalServer { url, accepts, task }
}

fn client() -> Client {
    Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .h2_profile(lkrequest::h2::profile::chrome_144_h2())
        .verify(false)
        .ttfb_timeout(TTFB)
        .total_timeout(TOTAL_TIMEOUT)
        .build()
}

async fn fetch(session: &Session, url: &str, streaming: bool) -> Result<Bytes> {
    if streaming {
        session.get(url).send_streaming().await?.bytes().await
    } else {
        Ok(session.get(url).send().await?.into_bytes())
    }
}

#[tokio::test]
async fn h1_response_headers_have_ttfb_deadline() {
    let server = tcp_server(false).await;
    for streaming in [false, true] {
        let session = client().session().http1_only().build();
        let error = fetch(&session, &format!("{}/slow-headers", server.url), streaming)
            .await
            .expect_err("H1 response headers must obey the TTFB deadline");
        assert!(matches!(
            error,
            Error::Timeout { phase: Some(ConnectionPhase::HttpRequest), duration: Some(value), .. }
                if value == TTFB
        ));
    }
}

#[tokio::test]
async fn h2_first_and_pooled_response_headers_have_ttfb_deadline() {
    for streaming in [false, true] {
        for pooled in [false, true] {
            let server = tcp_server(true).await;
            let session = client().session().http2_only().build();
            if pooled {
                assert_eq!(
                    fetch(&session, &format!("{}/fast", server.url), streaming)
                        .await
                        .unwrap_or_else(|error| {
                            panic!("H2 warmup failed (streaming={streaming}): {error:?}")
                        }),
                    "ok"
                );
            }
            let error = fetch(&session, &format!("{}/slow-headers", server.url), streaming)
                .await
                .expect_err("H2 response headers must obey the TTFB deadline");
            assert!(matches!(
                error,
                Error::Timeout { phase: Some(ConnectionPhase::HttpRequest), duration: Some(value), .. }
                    if value == TTFB
            ));
            assert_eq!(server.accepts.load(Ordering::Relaxed), 1);
        }
    }
}

#[tokio::test]
async fn timely_tcp_headers_allow_body_slower_than_ttfb() {
    for h2 in [false, true] {
        let server = tcp_server(h2).await;
        for streaming in [false, true] {
            let builder = client().session();
            let session = if h2 {
                builder.http2_only()
            } else {
                builder.http1_only()
            }
            .build();
            let started = std::time::Instant::now();
            let body = fetch(&session, &format!("{}/slow-body", server.url), streaming)
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "TTFB must not impose a response body deadline \
                         (h2={h2}, streaming={streaming}): {error:?}"
                    )
                });
            assert_eq!(body, "ok");
            assert!(started.elapsed() >= RESPONSE_DELAY);
        }
    }
}

#[cfg(feature = "quic-h3")]
async fn quic_server() -> (quinn::Endpoint, tokio::task::JoinHandle<()>) {
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_tls(b"h3")).unwrap(),
    ));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let task = tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let connection = incoming.await.unwrap();
                    let mut h3 = h3::server::Connection::<_, Bytes>::new(
                        h3_quinn::Connection::new(connection),
                    )
                    .await
                    .unwrap();
                    while let Ok(Some(resolver)) = h3.accept().await {
                        tokio::spawn(async move {
                            let (request, mut stream) = resolver.resolve_request().await.unwrap();
                            if request.uri().path() == "/slow-headers" {
                                tokio::time::sleep(RESPONSE_DELAY).await;
                            }
                            if stream.send_response(http::Response::new(())).await.is_err() {
                                return;
                            }
                            if request.uri().path() == "/slow-body" {
                                tokio::time::sleep(RESPONSE_DELAY).await;
                            }
                            if stream.send_data(Bytes::from_static(b"ok")).await.is_ok() {
                                let _ = stream.finish().await;
                            }
                        });
                    }
                });
            }
        }
    });
    (endpoint, task)
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn h3_first_and_pooled_response_headers_have_ttfb_deadline() {
    let (endpoint, task) = quic_server().await;
    let url = format!("https://{}", endpoint.local_addr().unwrap());
    for streaming in [false, true] {
        for pooled in [false, true] {
            let session = Client::builder()
                .fingerprint(lktls::profile::presets::chrome_144())
                .quic_profile(lkh3::chrome_quic())
                .verify(false)
                .ttfb_timeout(TTFB)
                .total_timeout(TOTAL_TIMEOUT)
                .build()
                .session()
                .http3_only()
                .build();
            if pooled {
                assert_eq!(
                    fetch(&session, &format!("{url}/fast"), streaming)
                        .await
                        .unwrap_or_else(|error| {
                            panic!("H3 warmup failed (streaming={streaming}): {error:?}")
                        }),
                    "ok"
                );
            }
            let error = fetch(&session, &format!("{url}/slow-headers"), streaming)
                .await
                .expect_err("H3 response headers must obey the TTFB deadline");
            assert!(matches!(
                error,
                Error::Timeout { phase: Some(ConnectionPhase::HttpRequest), duration: Some(value), .. }
                    if value == TTFB
            ));
            let started = std::time::Instant::now();
            assert_eq!(
                fetch(&session, &format!("{url}/slow-body"), streaming)
                    .await
                    .unwrap_or_else(|error| {
                        panic!("H3 body failed (streaming={streaming}, pooled={pooled}): {error:?}")
                    }),
                "ok"
            );
            assert!(started.elapsed() >= RESPONSE_DELAY);
        }
    }
    endpoint.close(0u32.into(), b"done");
    task.abort();
}
