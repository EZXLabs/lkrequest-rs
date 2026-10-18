use super::*;
use bytes::Bytes;
use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::task::Poll;
use tokio::sync::{oneshot, watch};

struct EarlyAcceptance(Arc<AtomicUsize>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for EarlyAcceptance {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        if event.metadata().target() != "lkrequest::session::transport" {
            return;
        }
        struct Accepted(bool);
        impl tracing::field::Visit for Accepted {
            fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
                if field.name() == "accepted" {
                    self.0 = value;
                }
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
        }
        let mut accepted = Accepted(false);
        event.record(&mut accepted);
        if accepted.0 {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum First {
    SlowBody,
    Refused,
    Cancelled,
}

struct Peer {
    endpoint: quinn::Endpoint,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"test complete");
        self.task.abort();
    }
}

async fn poll_pending<T: Future>(mut future: Pin<&mut T>) {
    poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

async fn coalesced(first: First) -> usize {
    tokio::time::timeout(Duration::from_secs(10), async {
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
        let url = format!(
            "https://localhost:{}",
            endpoint.local_addr().unwrap().port()
        );
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let (arrived_tx, arrived) = oneshot::channel();
        let (start_tx, start) = oneshot::channel();
        let (body_tx, body_rx) = watch::channel(false);
        let task = tokio::spawn({
            let endpoint = endpoint.clone();
            let connections = connections.clone();
            let requests = requests.clone();
            async move {
                let mut arrived_tx = Some(arrived_tx);
                let mut start = Some(start);
                let mut handlers = tokio::task::JoinSet::new();
                while let Some(incoming) = endpoint.accept().await {
                    let index = connections.fetch_add(1, Ordering::SeqCst);
                    if index == 0 {
                        arrived_tx.take().unwrap().send(()).unwrap();
                        start.take().unwrap().await.unwrap();
                        if first != First::SlowBody {
                            incoming.refuse();
                            continue;
                        }
                    }
                    let requests = requests.clone();
                    let body_rx = body_rx.clone();
                    handlers.spawn(async move {
                        let connection = incoming.await.unwrap();
                        let mut h3 = h3::server::Connection::<_, Bytes>::new(
                            h3_quinn::Connection::new(connection),
                        )
                        .await
                        .unwrap();
                        let mut streams = tokio::task::JoinSet::new();
                        while let Ok(Some(resolver)) = h3.accept().await {
                            let requests = requests.clone();
                            let mut body_rx = body_rx.clone();
                            streams.spawn(async move {
                                let (request, mut stream) =
                                    resolver.resolve_request().await.unwrap();
                                while stream.recv_data().await.unwrap().is_some() {}
                                requests.fetch_add(1, Ordering::SeqCst);
                                stream.send_response(http::Response::new(())).await.unwrap();
                                if request.uri().path() == "/slow" {
                                    while !*body_rx.borrow_and_update() {
                                        body_rx.changed().await.unwrap();
                                    }
                                }
                                stream.send_data(Bytes::from_static(b"ok")).await.unwrap();
                                stream.finish().await.unwrap();
                            });
                        }
                    });
                }
            }
        });
        let _peer = Peer { endpoint, task };
        let session = chrome_preset_client()
            .session()
            .http3_only()
            .max_connections(1)
            .build();
        let request = |path: &str| {
            let session = session.clone();
            let url = format!("{url}/{path}");
            Box::pin(async move {
                session
                    .post(&url)
                    .idempotency(lkrequest::Idempotency::NotIdempotent)
                    .send()
                    .await
            })
        };
        let leader = tokio::spawn(request("slow"));
        arrived.await.unwrap();
        // LocalDns resolves synchronously, so each first poll reaches the
        // in-flight handshake wait while the server still withholds its flight.
        let mut abandoned = request("abandoned");
        poll_pending(abandoned.as_mut()).await;
        drop(abandoned);
        let mut followers = Vec::new();
        for _ in 0..3 {
            let mut follower = request("fast");
            poll_pending(follower.as_mut()).await;
            followers.push(tokio::spawn(follower));
        }
        let leader = if first == First::Cancelled {
            leader.abort();
            assert!(leader.await.unwrap_err().is_cancelled());
            None
        } else {
            Some(leader)
        };
        start_tx.send(()).unwrap();
        for follower in followers {
            let response = tokio::time::timeout(Duration::from_secs(2), follower)
                .await
                .expect("waiter must not wait for the leader response body")
                .unwrap()
                .expect("waiters must elect one replacement handshake after failure");
            assert_eq!(response.version(), HttpVersion::H3);
            assert_eq!(response.bytes(), b"ok");
        }
        assert_eq!(session.pool_stats().total, 1);
        assert_eq!(session.pool_stats().h3_connections, 1);
        if first == First::SlowBody {
            let leader = leader.unwrap();
            assert!(!leader.is_finished(), "the first body is still held");
            body_tx.send(true).unwrap();
            assert_eq!(leader.await.unwrap().unwrap().bytes(), b"ok");
            assert_eq!(requests.load(Ordering::SeqCst), 4);
        } else {
            if let Some(leader) = leader {
                assert!(leader.await.unwrap().is_err());
            }
            assert_eq!(requests.load(Ordering::SeqCst), 3);
        }
        connections.load(Ordering::SeqCst)
    })
    .await
    .expect("coalesced H3 requests complete")
}

#[tokio::test]
async fn h3_coalesced_waiters_do_not_wait_for_response_body() {
    assert_eq!(coalesced(First::SlowBody).await, 1);
}

#[tokio::test]
async fn h3_coalesced_waiters_replace_failed_handshake_once() {
    assert_eq!(coalesced(First::Refused).await, 2);
}

#[tokio::test]
async fn h3_coalesced_waiters_replace_cancelled_handshake_once() {
    assert_eq!(coalesced(First::Cancelled).await, 2);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EarlyEnd {
    Headers,
    Body,
    Cancel,
    ResetOnce,
    ResetAlways,
    CloseOnce,
    CloseAlways,
}

async fn accepted_zero_rtt(end: EarlyEnd) -> usize {
    use tracing_subscriber::prelude::*;
    let accepted = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(EarlyAcceptance(accepted.clone()));
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let hold_headers = matches!(end, EarlyEnd::Headers | EarlyEnd::Cancel);
    tokio::time::timeout(Duration::from_secs(10), async {
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
        tls.max_early_data_size = u32::MAX;
        let config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let url = format!(
            "https://localhost:{}",
            endpoint.local_addr().unwrap().port()
        );
        let connections = Arc::new(AtomicUsize::new(0));
        let slow_requests = Arc::new(AtomicUsize::new(0));
        let (seen_tx, mut seen) = tokio::sync::mpsc::unbounded_channel();
        let (release, release_rx) = watch::channel(false);
        let task = tokio::spawn({
            let endpoint = endpoint.clone();
            let connections = connections.clone();
            let slow_requests = slow_requests.clone();
            async move {
                let mut handlers = tokio::task::JoinSet::new();
                while let Some(incoming) = endpoint.accept().await {
                    let index = connections.fetch_add(1, Ordering::SeqCst);
                    let seen_tx = seen_tx.clone();
                    let release_rx = release_rx.clone();
                    let slow_requests = slow_requests.clone();
                    handlers.spawn(async move {
                        let connection = incoming.await.unwrap();
                        let mut h3 = h3::server::Connection::<_, Bytes>::new(
                            h3_quinn::Connection::new(connection.clone()),
                        )
                        .await
                        .unwrap();
                        let mut streams = tokio::task::JoinSet::new();
                        while let Ok(Some(resolver)) = h3.accept().await {
                            let seen_tx = seen_tx.clone();
                            let mut release_rx = release_rx.clone();
                            let connection = connection.clone();
                            let slow_requests = slow_requests.clone();
                            streams.spawn(async move {
                                let (request, mut stream) =
                                    resolver.resolve_request().await.unwrap();
                                while stream.recv_data().await.unwrap().is_some() {}
                                let slow = request.uri().path() == "/slow";
                                let slow_attempt = if slow {
                                    slow_requests.fetch_add(1, Ordering::SeqCst) + 1
                                } else {
                                    0
                                };
                                seen_tx
                                    .send((request.uri().path().to_owned(), index))
                                    .unwrap();
                                if slow && hold_headers {
                                    while !*release_rx.borrow_and_update() {
                                        release_rx.changed().await.unwrap();
                                    }
                                }
                                if stream.send_response(http::Response::new(())).await.is_err() {
                                    return;
                                }
                                if slow && !hold_headers {
                                    while !*release_rx.borrow_and_update() {
                                        release_rx.changed().await.unwrap();
                                    }
                                }
                                if slow
                                    && (end == EarlyEnd::ResetAlways
                                        || (end == EarlyEnd::ResetOnce && slow_attempt == 1))
                                {
                                    stream.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
                                    return;
                                }
                                if slow
                                    && (end == EarlyEnd::CloseAlways
                                        || (end == EarlyEnd::CloseOnce && slow_attempt == 1))
                                {
                                    connection.close(0x102u32.into(), b"fixture response failure");
                                    return;
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
        let _peer = Peer { endpoint, task };
        // Share the test ticket across fresh Sessions to require a new transport
        // without waiting for a pooled connection's idle timeout.
        let client = Client::builder()
            .preset(lkrequest::preset::chrome_155())
            .tls_session_cache_partition_policy(
                lkrequest::TlsSessionCachePartitionPolicy::Unpartitioned,
            )
            .dns_resolver(Arc::new(LocalDns))
            .verify(false)
            .build();
        let warm = client.session().http3_only().build();
        assert_eq!(
            warm.get(&format!("{url}/warm"))
                .send()
                .await
                .unwrap()
                .bytes(),
            b"ok"
        );
        assert_eq!(seen.recv().await.unwrap(), ("/warm".to_owned(), 0));
        drop(warm);
        let session = client.session().http3_only().max_connections(1).build();
        let leader = tokio::spawn({
            let session = session.clone();
            let url = format!("{url}/slow");
            async move { session.get(&url).send().await }
        });
        assert_eq!(seen.recv().await.unwrap(), ("/slow".to_owned(), 1));
        tokio::time::timeout(Duration::from_secs(1), async {
            while accepted.load(Ordering::SeqCst) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the client must confirm acceptance of the early request");
        let fast = tokio::time::timeout(
            Duration::from_secs(2),
            session
                .post(&format!("{url}/fast"))
                .idempotency(lkrequest::Idempotency::NotIdempotent)
                .send(),
        )
        .await
        .expect("confirmed 0-RTT connection must be reusable before its response completes")
        .unwrap();
        assert_eq!(fast.bytes(), b"ok");
        assert_eq!(seen.recv().await.unwrap(), ("/fast".to_owned(), 1));
        assert!(!leader.is_finished());
        assert_eq!(session.pool_stats().total, 1);
        if end == EarlyEnd::Cancel {
            leader.abort();
            assert!(leader.await.unwrap_err().is_cancelled());
            release.send(true).unwrap();
            assert_eq!(
                session
                    .get(&format!("{url}/after"))
                    .send()
                    .await
                    .unwrap()
                    .bytes(),
                b"ok"
            );
            assert_eq!(seen.recv().await.unwrap(), ("/after".to_owned(), 1));
            assert_eq!(slow_requests.load(Ordering::SeqCst), 1);
            return connections.load(Ordering::SeqCst);
        }
        release.send(true).unwrap();
        let result = leader.await.unwrap();
        if matches!(end, EarlyEnd::ResetAlways | EarlyEnd::CloseAlways) {
            let error = result.expect_err("recovery is bounded to one additional request");
            if end == EarlyEnd::CloseAlways {
                assert!(!error.is_safe_to_replay());
            }
        } else {
            assert_eq!(result.unwrap().bytes(), b"ok");
        }
        let replayed = matches!(
            end,
            EarlyEnd::ResetOnce
                | EarlyEnd::ResetAlways
                | EarlyEnd::CloseOnce
                | EarlyEnd::CloseAlways
        );
        assert_eq!(
            slow_requests.load(Ordering::SeqCst),
            if replayed { 2 } else { 1 }
        );
        if replayed {
            let index = if matches!(end, EarlyEnd::CloseOnce | EarlyEnd::CloseAlways) {
                2
            } else {
                1
            };
            assert_eq!(seen.recv().await.unwrap(), ("/slow".to_owned(), index));
        }
        assert!(seen.try_recv().is_err());
        connections.load(Ordering::SeqCst)
    })
    .await
    .expect("accepted 0-RTT concurrency fixture completes")
}

#[tokio::test]
async fn h3_accepted_zero_rtt_is_reusable_before_response_headers() {
    assert_eq!(accepted_zero_rtt(EarlyEnd::Headers).await, 2);
}

#[tokio::test]
async fn h3_accepted_zero_rtt_is_reusable_before_response_body() {
    assert_eq!(accepted_zero_rtt(EarlyEnd::Body).await, 2);
}

#[tokio::test]
async fn h3_accepted_zero_rtt_cancellation_preserves_shared_connection() {
    assert_eq!(accepted_zero_rtt(EarlyEnd::Cancel).await, 2);
}

#[tokio::test]
async fn h3_accepted_zero_rtt_stream_failure_reuses_shared_connection_once() {
    for end in [EarlyEnd::ResetOnce, EarlyEnd::ResetAlways] {
        assert_eq!(accepted_zero_rtt(end).await, 2);
    }
}

#[tokio::test]
async fn h3_accepted_zero_rtt_connection_failure_reacquires_once() {
    for end in [EarlyEnd::CloseOnce, EarlyEnd::CloseAlways] {
        assert_eq!(accepted_zero_rtt(end).await, 3);
    }
}
