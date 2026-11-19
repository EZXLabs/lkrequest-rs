use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use lkrequest::{AttemptDenialReason, AttemptLimits, AttemptOutcome, Client};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

struct Peer {
    url: String,
    h2_requests: Arc<AtomicUsize>,
    h1_requests: Arc<AtomicUsize>,
    accepts: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Peer {
    async fn new() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )
        .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("https://{}/", listener.local_addr().unwrap());
        let h2_requests = Arc::new(AtomicUsize::new(0));
        let h1_requests = Arc::new(AtomicUsize::new(0));
        let accepts = Arc::new(AtomicUsize::new(0));
        let h2_count = h2_requests.clone();
        let h1_count = h1_requests.clone();
        let accepted = accepts.clone();
        let task = tokio::spawn(async move {
            let mut handlers = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let (socket, _) = result.unwrap();
                        accepted.fetch_add(1, Ordering::SeqCst);
                        let acceptor = acceptor.clone();
                        let h2_count = h2_count.clone();
                        let h1_count = h1_count.clone();
                        handlers.spawn(async move {
                            let tls = acceptor.accept(socket).await.unwrap();
                            if tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()) {
                                let mut connection = h2::server::handshake(tls).await.unwrap();
                                while let Some(request) = connection.accept().await {
                                    let (_, mut response) = request.unwrap();
                                    h2_count.fetch_add(1, Ordering::SeqCst);
                                    response.send_reset(h2::Reason::PROTOCOL_ERROR);
                                }
                            } else {
                                assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"http/1.1".as_slice()));
                                let service = service_fn(move |_| {
                                    h1_count.fetch_add(1, Ordering::SeqCst);
                                    async { Ok::<_, std::convert::Infallible>(http::Response::new(
                                        Full::new(Bytes::from_static(b"h1 fallback")),
                                    )) }
                                });
                                let _ = hyper::server::conn::http1::Builder::new()
                                    .serve_connection(TokioIo::new(tls), service).await;
                            }
                        });
                    }
                    result = handlers.join_next(), if !handlers.is_empty() => {
                        result.unwrap().expect("local protocol peer must not panic");
                    }
                }
            }
        });
        Self {
            url,
            h2_requests,
            h1_requests,
            accepts,
            task,
        }
    }
}

async fn check(streaming: bool) -> Vec<AttemptOutcome> {
    tokio::time::timeout(Duration::from_secs(8), async {
        let mut outcomes = Vec::new();
        for cap in [2, 1] {
            let peer = Peer::new().await;
            let session = Client::builder()
                .fingerprint(lktls::profile::presets::chrome_144())
                .h2_profile(lkrequest::h2::profile::chrome_144_h2())
                .h2_fallback_h1(true)
                .retry_on_connection_close(false)
                .verify(false)
                .build()
                .session()
                .build();
            let request = session
                .get(&peer.url)
                .attempt_limits(AttemptLimits::default().with_connect_attempts(cap));
            let (result, summary) = if streaming {
                let (result, summary) = request.send_streaming_with_attempt_summary().await;
                let body = match result {
                    Ok(response) => response.bytes().await,
                    Err(error) => Err(error),
                };
                (body, summary)
            } else {
                let (result, summary) = request.send_with_attempt_summary().await;
                (
                    result.map(|response| Bytes::copy_from_slice(response.bytes())),
                    summary,
                )
            };
            assert_eq!(peer.h2_requests.load(Ordering::SeqCst), 1);
            assert_eq!(peer.accepts.load(Ordering::SeqCst) as u64, cap);
            assert_eq!(summary.connect_initiations(), cap);
            if cap == 2 {
                assert_eq!(result.unwrap(), "h1 fallback");
                assert_eq!(peer.h1_requests.load(Ordering::SeqCst), 1);
                assert_eq!(summary.denial_reason(), None);
            } else {
                let error = result.unwrap_err();
                assert!(
                    matches!(
                        error,
                        lkrequest::error::Error::H2(_)
                            | lkrequest::error::Error::ConnectionClosed {
                                kind: lkrequest::error::ConnectionClosedKind::Reset,
                                ..
                            }
                    ),
                    "original H2 error: {error:?}"
                );
                assert!(error.to_string().contains("error_code=1"), "{error}");
                assert_eq!(peer.h1_requests.load(Ordering::SeqCst), 0);
                assert_eq!(
                    summary.denial_reason(),
                    Some(AttemptDenialReason::ConnectLimit)
                );
            }
            outcomes.push(summary.outcome());
        }
        outcomes
    })
    .await
    .expect("bounded local H2 fallback fixture")
}

#[tokio::test]
async fn buffered_h2_fallback_denial_preserves_original_protocol_error() {
    assert_eq!(
        check(false).await,
        [AttemptOutcome::Succeeded, AttemptOutcome::Failed]
    );
}

#[tokio::test]
async fn streaming_h2_fallback_denial_preserves_original_protocol_error() {
    assert_eq!(
        check(true).await,
        [AttemptOutcome::Succeeded, AttemptOutcome::Failed]
    );
}
