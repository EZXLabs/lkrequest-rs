use super::{chrome_preset_client, start_local_https_server, url_join};
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use lkrequest::{AttemptLimits, AttemptSummary, Session};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::convert::Infallible;
use std::future::{poll_fn, Future};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use tokio::sync::oneshot;

const LIMIT: Duration = Duration::from_secs(5);

async fn get(session: &Session, url: &str, cap: u64, streaming: bool) -> (Vec<u8>, AttemptSummary) {
    let (request, observer) = session
        .get(url)
        .timeout(LIMIT)
        .attempt_limits(AttemptLimits::default().with_connect_attempts(cap))
        .observe_attempts();
    let body = if streaming {
        request
            .send_streaming()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
            .to_vec()
    } else {
        let response = request.send().await.unwrap();
        assert_eq!(response.version(), lkrequest::HttpVersion::H2);
        response.bytes().to_vec()
    };
    (body, observer.snapshot())
}

#[tokio::test]
async fn warm_h2_with_zero_connect_allowance_uses_the_existing_wire_connection() {
    for streaming in [false, true] {
        let peer = start_local_https_server().await;
        let session = chrome_preset_client().session().http2_only().build();
        let url = url_join(&peer.base_url, "/get");
        let (_, warm) = get(&session, &url, 1, streaming).await;
        assert_eq!(warm.connect_initiations(), 1);
        let (body, reused) = get(&session, &url, 0, streaming).await;
        assert!(!body.is_empty());
        assert_eq!(reused.connect_initiations(), 0);
        assert_eq!(reused.http_submissions(), 1);
        assert_eq!(reused.denial_reason(), None);
        assert_eq!(peer.tcp_accept_counter.load(Ordering::SeqCst), 1);
        assert_eq!(session.pool_stats().h2_connections, 1);
    }
}

struct GatedH2Peer {
    url: String,
    connections: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    arrived: Option<oneshot::Receiver<()>>,
    release: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for GatedH2Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl GatedH2Peer {
    async fn start() -> Self {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut tls = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )
        .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "https://localhost:{}/",
            listener.local_addr().unwrap().port()
        );
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let (arrived_tx, arrived) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let task = tokio::spawn({
            let connections = connections.clone();
            let requests = requests.clone();
            async move {
                let mut gate = Some((arrived_tx, released));
                let mut handlers = tokio::task::JoinSet::new();
                while let Ok((socket, _)) = listener.accept().await {
                    connections.fetch_add(1, Ordering::SeqCst);
                    let gate = gate.take();
                    let acceptor = acceptor.clone();
                    let requests = requests.clone();
                    handlers.spawn(async move {
                        if let Some((arrived, released)) = gate {
                            let _ = arrived.send(());
                            if released.await.is_err() {
                                return;
                            }
                        }
                        let tls = acceptor.accept(socket).await.unwrap();
                        let service =
                            service_fn(move |request: http::Request<hyper::body::Incoming>| {
                                assert_eq!(request.version(), http::Version::HTTP_2);
                                requests.fetch_add(1, Ordering::SeqCst);
                                async {
                                    Ok::<_, Infallible>(http::Response::new(Full::new(
                                        Bytes::from_static(b"shared-h2"),
                                    )))
                                }
                            });
                        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(tls), service)
                            .await;
                    });
                }
            }
        });
        Self {
            url,
            connections,
            requests,
            arrived: Some(arrived),
            release: Some(release),
            task,
        }
    }
}

#[tokio::test]
async fn zero_budget_h2_waiters_share_the_leaders_delayed_handshake() {
    for streaming in [false, true] {
        tokio::time::timeout(LIMIT, async {
            let mut peer = GatedH2Peer::start().await;
            let session = chrome_preset_client().session().http2_only().build();
            let leader = tokio::spawn({
                let session = session.clone();
                let url = peer.url.clone();
                async move { get(&session, &url, 1, streaming).await }
            });
            peer.arrived.take().unwrap().await.unwrap();
            let mut follower = Box::pin(get(&session, &peer.url, 0, streaming));
            poll_fn(|cx| {
                assert!(
                    follower.as_mut().poll(cx).is_pending(),
                    "waiter must join the in-flight handshake"
                );
                Poll::Ready(())
            })
            .await;
            assert_eq!(peer.connections.load(Ordering::SeqCst), 1);
            peer.release.take().unwrap().send(()).unwrap();
            let ((leader_body, leader_summary), (follower_body, follower_summary)) =
                tokio::join!(async { leader.await.unwrap() }, follower);
            assert_eq!(leader_body, b"shared-h2");
            assert_eq!(follower_body, b"shared-h2");
            assert_eq!(leader_summary.connect_initiations(), 1);
            assert_eq!(follower_summary.connect_initiations(), 0);
            assert_eq!(follower_summary.http_submissions(), 1);
            assert_eq!(follower_summary.denial_reason(), None);
            assert_eq!(peer.connections.load(Ordering::SeqCst), 1);
            assert_eq!(peer.requests.load(Ordering::SeqCst), 2);
        })
        .await
        .expect("shared H2 handshake must finish within the test deadline");
    }
}
