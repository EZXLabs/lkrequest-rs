use super::*;
use bytes::Bytes;
use std::future::{poll_fn, Future};
use std::sync::atomic::AtomicUsize;
use std::task::Poll;
use tokio::sync::{oneshot, watch};

struct Peers {
    quic: quinn::Endpoint,
    quic_task: tokio::task::JoinHandle<()>,
    tcp_task: tokio::task::JoinHandle<()>,
}

impl Drop for Peers {
    fn drop(&mut self) {
        self.quic.close(0u32.into(), b"test complete");
        self.quic_task.abort();
        self.tcp_task.abort();
    }
}

async fn fallback_waiters(
    hold_headers: bool,
    streaming_upload: bool,
    race: bool,
) -> (usize, usize) {
    tokio::time::timeout(Duration::from_secs(10), async {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()),
                ),
            )
            .unwrap();
        tls.alpn_protocols = vec![b"not-h3".to_vec()];
        let quic_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls.clone()).unwrap(),
        ));
        let quic = quinn::Endpoint::server(quic_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let quic_port = quic.local_addr().unwrap().port();
        let quic_attempts = Arc::new(AtomicUsize::new(0));
        let (arrived_tx, arrived) = oneshot::channel();
        let (reject_tx, reject) = oneshot::channel();
        let quic_task = tokio::spawn({
            let quic = quic.clone();
            let attempts = quic_attempts.clone();
            async move {
                let mut arrived_tx = Some(arrived_tx);
                let mut reject = Some(reject);
                while let Some(incoming) = quic.accept().await {
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        arrived_tx.take().unwrap().send(()).unwrap();
                        reject.take().unwrap().await.unwrap();
                    }
                    assert!(incoming.await.is_err());
                }
            }
        });
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let tcp_connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let (release, release_rx) = watch::channel(false);
        let (tcp_started_tx, tcp_started) = oneshot::channel();
        let (tcp_release, tcp_released) = oneshot::channel();
        let (tcp_outcome_tx, tcp_outcome) = oneshot::channel();
        let (fast_seen_tx, mut fast_seen) = tokio::sync::mpsc::unbounded_channel();
        let tcp_task = tokio::spawn({
            let connections = tcp_connections.clone();
            let requests = requests.clone();
            async move {
                let mut handlers = tokio::task::JoinSet::new();
                let mut tcp_started_tx = Some(tcp_started_tx);
                let mut tcp_released = Some(tcp_released);
                let mut tcp_outcome_tx = Some(tcp_outcome_tx);
                while let Ok((socket, _)) = listener.accept().await {
                    let index = connections.fetch_add(1, Ordering::SeqCst);
                    let acceptor = acceptor.clone();
                    let requests = requests.clone();
                    let release_rx = release_rx.clone();
                    let fast_seen_tx = fast_seen_tx.clone();
                    let pending_racer = if race && index == 1 {
                        tcp_started_tx.take().unwrap().send(()).unwrap();
                        Some((tcp_released.take().unwrap(), tcp_outcome_tx.take().unwrap()))
                    } else {
                        None
                    };
                    handlers.spawn(async move {
                        let mut tcp_outcome_tx = if let Some((release, outcome)) = pending_racer {
                            release.await.unwrap();
                            Some(outcome)
                        } else {
                            None
                        };
                        let socket = match acceptor.accept(socket).await {
                            Ok(socket) => socket,
                            Err(error) => {
                                if let Some(outcome) = tcp_outcome_tx.take() {
                                    outcome.send(false).unwrap();
                                    return;
                                }
                                panic!("unexpected TLS error: {error}");
                            }
                        };
                        if index == 0 {
                            let service = hyper::service::service_fn(move |_| async move {
                                Ok::<_, std::convert::Infallible>(
                                    http::Response::builder()
                                        .header("alt-svc", format!("h3=\":{quic_port}\"; ma=3600"))
                                        .body(http_body_util::Full::new(Bytes::from_static(
                                            b"warm",
                                        )))
                                        .unwrap(),
                                )
                            });
                            let _ = hyper::server::conn::http1::Builder::new()
                                .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                                .await;
                            return;
                        }
                        let mut connection = h2::server::handshake(socket).await.unwrap();
                        let mut streams = tokio::task::JoinSet::new();
                        while let Some(request) = connection.accept().await {
                            let (mut request, mut respond) = request.unwrap();
                            if let Some(outcome) = tcp_outcome_tx.take() {
                                outcome.send(true).unwrap();
                            }
                            let mut release_rx = release_rx.clone();
                            let fast_seen_tx = fast_seen_tx.clone();
                            requests.fetch_add(1, Ordering::SeqCst);
                            streams.spawn(async move {
                                let mut body = Vec::new();
                                while let Some(data) = request.body_mut().data().await {
                                    let data = data.unwrap();
                                    body.extend_from_slice(&data);
                                    request
                                        .body_mut()
                                        .flow_control()
                                        .release_capacity(data.len())
                                        .unwrap();
                                }
                                assert_eq!(body, b"payload");
                                let slow = request.uri().path() == "/slow";
                                if !slow {
                                    fast_seen_tx.send(()).unwrap();
                                }
                                if slow && hold_headers {
                                    while !*release_rx.borrow_and_update() {
                                        release_rx.changed().await.unwrap();
                                    }
                                }
                                let mut stream = respond
                                    .send_response(http::Response::new(()), false)
                                    .unwrap();
                                if (slow && !hold_headers) || (race && !slow) {
                                    while !*release_rx.borrow_and_update() {
                                        release_rx.changed().await.unwrap();
                                    }
                                }
                                stream.send_data(Bytes::from_static(b"ok"), true).unwrap();
                            });
                        }
                        if let Some(outcome) = tcp_outcome_tx.take() {
                            outcome.send(false).unwrap();
                        }
                    });
                }
            }
        });
        let _peers = Peers {
            quic,
            quic_task,
            tcp_task,
        };
        let session = Client::builder()
            .preset(lkrequest::preset::chrome_155())
            .dns_resolver(Arc::new(LocalDns))
            .verify(false)
            .build()
            .session()
            .protocol_policy(
                ProtocolPolicy::chrome_standard()
                    .with_acquisition(AcquisitionPolicy::EstablishBestAvailable)
                    .with_fallback(FallbackPolicy::AllowFallback),
            )
            .max_connections(if race { 3 } else { 1 })
            .build();
        assert_eq!(
            session
                .get(&format!("{base}/warm"))
                .preferred_http_version(PreferredHttpVersion::Http1Only)
                .send()
                .await
                .unwrap()
                .bytes(),
            b"warm"
        );
        session.pool_clear();
        let post = |path: &str| {
            let session = session.clone();
            let url = format!("{base}/{path}");
            let raced = race && path == "fast";
            Box::pin(async move {
                let request = session
                    .post(&url)
                    .idempotency(lkrequest::Idempotency::NotIdempotent);
                let request = if raced {
                    request.protocol_policy(ProtocolPolicy::chrome_standard().with_acquisition(
                        AcquisitionPolicy::Race(
                            lkrequest::RacePolicy::chrome_like().with_tcp_delay(Duration::ZERO),
                        ),
                    ))
                } else {
                    request
                };
                let request = if streaming_upload {
                    request.body_reader(std::io::Cursor::new(b"payload".to_vec()), Some(7))
                } else {
                    request.body("payload")
                };
                request.send().await
            })
        };
        let leader = tokio::spawn(post("slow"));
        arrived.await.unwrap();
        let mut followers = Vec::new();
        for _ in 0..if race { 1 } else { 2 } {
            let mut follower = post("fast");
            poll_fn(|cx| {
                assert!(follower.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            followers.push(tokio::spawn(follower));
        }
        if race {
            tcp_started.await.unwrap();
        }
        reject_tx.send(()).unwrap();
        if race {
            fast_seen.recv().await.unwrap();
            tcp_release.send(()).unwrap();
            assert!(
                !tcp_outcome.await.unwrap(),
                "the losing TCP job must not send another POST"
            );
            assert_eq!(requests.load(Ordering::SeqCst), 2);
            assert!(!leader.is_finished());
            release.send(true).unwrap();
        }
        for follower in followers {
            let response = tokio::time::timeout(Duration::from_secs(2), follower)
                .await
                .expect("waiting requests must reuse H2 before the first fallback response ends")
                .unwrap()
                .expect("a ready H2 fallback fits the one-connection budget");
            assert_eq!(response.version(), HttpVersion::H2);
            assert_eq!(response.bytes(), b"ok");
        }
        if !race {
            assert!(!leader.is_finished());
        }
        assert_eq!(requests.load(Ordering::SeqCst), if race { 2 } else { 3 });
        assert_eq!(session.pool_stats().total, 1);
        release.send(true).unwrap();
        assert_eq!(leader.await.unwrap().unwrap().bytes(), b"ok");
        (
            quic_attempts.load(Ordering::SeqCst),
            tcp_connections.load(Ordering::SeqCst),
        )
    })
    .await
    .expect("bounded fallback concurrency fixture")
}

#[tokio::test]
async fn coalesced_fallback_reuses_h2_before_response_headers() {
    for streaming_upload in [false, true] {
        assert_eq!(
            fallback_waiters(true, streaming_upload, false).await,
            (1, 2)
        );
    }
}

#[tokio::test]
async fn coalesced_fallback_reuses_h2_before_response_body() {
    for streaming_upload in [false, true] {
        assert_eq!(
            fallback_waiters(false, streaming_upload, false).await,
            (1, 2)
        );
    }
}

#[tokio::test]
async fn coalesced_fallback_preserves_protocol_race_single_send() {
    assert_eq!(fallback_waiters(false, false, true).await, (1, 3));
}
