use super::*;
use bytes::{Buf, Bytes};
use std::sync::atomic::AtomicUsize;
use tokio::sync::{mpsc, watch};

#[derive(Clone, Copy, PartialEq, Eq)]
enum BodyEnd {
    Complete,
    Cancel,
    Reject,
}

struct Peer {
    endpoint: quinn::Endpoint,
    task: tokio::task::JoinHandle<()>,
    requests: Arc<AtomicUsize>,
    headers: mpsc::UnboundedReceiver<()>,
    release: watch::Sender<bool>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"test complete");
        self.task.abort();
    }
}

async fn peer(reject_body: bool) -> Peer {
    let _ = rustls::crypto::ring::default_provider().install_default();
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
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let (headers_tx, headers) = mpsc::unbounded_channel();
    let (release, release_rx) = watch::channel(false);
    let task = tokio::spawn({
        let endpoint = endpoint.clone();
        let requests = requests.clone();
        async move {
            // Hold both handshakes until both callers have missed the empty pool.
            let first = endpoint.accept().await.unwrap();
            let second = endpoint.accept().await.unwrap();
            let mut connections = tokio::task::JoinSet::new();
            for incoming in [first, second] {
                let requests = requests.clone();
                let headers_tx = headers_tx.clone();
                let release_rx = release_rx.clone();
                connections.spawn(async move {
                    let connection = incoming.await.unwrap();
                    let mut h3 = h3::server::Connection::<_, Bytes>::new(
                        h3_quinn::Connection::new(connection),
                    )
                    .await
                    .unwrap();
                    let mut streams = tokio::task::JoinSet::new();
                    while let Ok(Some(resolver)) = h3.accept().await {
                        let requests = requests.clone();
                        let headers_tx = headers_tx.clone();
                        let mut release_rx = release_rx.clone();
                        streams.spawn(async move {
                            let (request, mut stream) = resolver.resolve_request().await.unwrap();
                            let mut body = Vec::new();
                            while let Some(mut chunk) = stream.recv_data().await.unwrap() {
                                body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                            }
                            if request.method() == http::Method::POST {
                                assert_eq!(body, b"one-mutation");
                            }
                            requests.fetch_add(1, Ordering::SeqCst);
                            stream
                                .send_response(
                                    http::Response::builder().status(200).body(()).unwrap(),
                                )
                                .await
                                .unwrap();
                            let _ = headers_tx.send(());
                            while !*release_rx.borrow_and_update() {
                                if release_rx.changed().await.is_err() {
                                    return;
                                }
                            }
                            if reject_body && request.method() == http::Method::POST {
                                stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
                                return;
                            }
                            // Dropping a response is part of the cancellation case.
                            if stream
                                .send_data(Bytes::from_static(b"complete-body"))
                                .await
                                .is_ok()
                            {
                                let _ = stream.finish().await;
                            }
                        });
                    }
                    while let Some(result) = streams.join_next().await {
                        result.unwrap();
                    }
                });
            }
            while let Some(result) = connections.join_next().await {
                result.unwrap();
            }
        }
    });
    Peer {
        endpoint,
        task,
        requests,
        headers,
        release,
    }
}

async fn wait_for_one_connection(session: &Session) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while session.pool_stats().total != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("unpooled H3 driver must release its physical connection permit");
}

async fn race(streaming: bool, body_end: BodyEnd) -> usize {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut peer = peer(body_end == BodyEnd::Reject).await;
        let url = format!(
            "https://localhost:{}/post",
            peer.endpoint.local_addr().unwrap().port()
        );
        let session = chrome_preset_client()
            .session()
            .http3_only()
            .max_connections(2)
            .build();
        let mut requests = Vec::new();
        for index in 0..2 {
            let session = session.clone();
            let url = url.clone();
            // Two buffered callers coalesce handshakes; streaming can establish
            // independently and race either a buffered or another streaming call.
            let request_streaming = streaming || index == 1;
            requests.push(tokio::spawn(async move {
                let request = session
                    .post(&url)
                    .body("one-mutation")
                    .idempotency(lkrequest::Idempotency::NotIdempotent);
                if request_streaming {
                    Ok(Some(request.send_streaming().await?))
                } else {
                    let response = request.send().await?;
                    assert_eq!(response.version(), HttpVersion::H3);
                    assert_eq!(response.bytes(), &Bytes::from_static(b"complete-body"));
                    Ok::<_, lkrequest::error::Error>(None)
                }
            }));
        }
        for _ in 0..2 {
            peer.headers
                .recv()
                .await
                .expect("both requests reach the server");
        }
        let mut responses = Vec::new();
        if streaming {
            for request in requests.drain(..) {
                responses.push(
                    request
                        .await
                        .unwrap()
                        .expect("H3 response headers")
                        .unwrap(),
                );
            }
        }
        // Pending response bodies must retain both drivers and reservations.
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(session.pool_stats().h3_connections, 1);
        assert_eq!(session.pool_stats().total, 2);
        assert_eq!(peer.requests.load(Ordering::SeqCst), 2);
        if body_end == BodyEnd::Cancel {
            drop(responses);
        } else {
            peer.release.send(true).unwrap();
            for response in &mut responses {
                if body_end == BodyEnd::Reject {
                    let error = response
                        .chunk()
                        .await
                        .expect_err("reset after response headers");
                    assert!(!error.is_safe_to_replay());
                    assert!(matches!(
                        error,
                        lkrequest::error::Error::ConnectionClosed {
                            kind: lkrequest::error::ConnectionClosedKind::Reset,
                            ..
                        }
                    ));
                    continue;
                }
                let mut body = Vec::new();
                while let Some(chunk) = response.chunk().await.expect("delayed H3 body") {
                    body.extend_from_slice(&chunk);
                }
                assert_eq!(body, b"complete-body");
            }
            for request in requests {
                if let Some(response) = request.await.unwrap().expect("H3 response") {
                    assert_eq!(response.bytes().await.unwrap(), b"complete-body"[..]);
                }
            }
            // Completed responses remain owned while the unpooled driver exits.
            wait_for_one_connection(&session).await;
            for response in &mut responses {
                assert!(response.chunk().await.unwrap().is_none());
            }
        }
        wait_for_one_connection(&session).await;
        peer.release.send(true).unwrap();
        let response = session
            .get(&url)
            .send()
            .await
            .expect("reuse winning H3 connection");
        assert_eq!(response.bytes(), &Bytes::from_static(b"complete-body"));
        assert_eq!(session.pool_stats().total, 1);
        peer.requests.load(Ordering::SeqCst)
    })
    .await
    .expect("H3 establishment race must finish without extra connections")
}

#[tokio::test]
async fn concurrent_h3_establishment_preserves_buffered_requests() {
    assert_eq!(race(false, BodyEnd::Complete).await, 3);
}

#[tokio::test]
async fn concurrent_h3_establishment_preserves_streaming_bodies() {
    assert_eq!(race(true, BodyEnd::Complete).await, 3);
}

#[tokio::test]
async fn concurrent_h3_establishment_releases_cancelled_bodies() {
    assert_eq!(race(true, BodyEnd::Cancel).await, 3);
}

#[tokio::test]
async fn concurrent_h3_establishment_releases_failed_bodies_without_replay() {
    assert_eq!(race(true, BodyEnd::Reject).await, 3);
}
