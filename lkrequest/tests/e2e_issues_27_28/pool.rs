use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use lkrequest::{HttpVersion, Session};
use tokio::sync::Barrier;

use super::support::{bounded, client, HttpsServer};

async fn burst(session: &Session, url: &str, n: usize, streaming: bool, h1: bool) -> Vec<String> {
    bounded(async {
        let barrier = Arc::new(Barrier::new(n));
        let mut tasks = Vec::new();
        for _ in 0..n {
            let session = session.clone();
            let url = url.to_string();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                if streaming {
                    let response = session
                        .get(&url)
                        .send_streaming()
                        .await
                        .map_err(|e| e.to_string())?;
                    assert_eq!(response.status().as_u16(), 200);
                    let body = response.bytes().await.map_err(|e| e.to_string())?;
                    assert_eq!(body.as_ref(), b"ok");
                } else {
                    let response = session.get(&url).send().await.map_err(|e| e.to_string())?;
                    assert_eq!(response.status().as_u16(), 200);
                    assert_eq!(
                        response.version(),
                        if h1 {
                            HttpVersion::Http11
                        } else {
                            HttpVersion::H2
                        }
                    );
                    assert_eq!(response.bytes(), b"ok");
                }
                Ok::<_, String>(())
            }));
        }
        let mut errors = Vec::new();
        for task in tasks {
            if let Err(error) = task.await.expect("request task panicked") {
                errors.push(error);
            }
        }
        errors
    })
    .await
}

async fn h2_burst(warm: bool, limited: bool, streaming: bool, reconnect: bool) -> usize {
    let server = HttpsServer::start(false, Duration::from_millis(60), false).await;
    let session = client()
        .session()
        .max_connections(if limited { 6 } else { 1000 })
        .build();
    if warm || reconnect {
        let response = bounded(session.get(&server.url()).send()).await.unwrap();
        assert_eq!(response.version(), HttpVersion::H2);
    }
    if reconnect {
        server.disconnect_all().await;
    }
    let before = server.accepts.load(Ordering::SeqCst);
    let n = if limited { 100 } else { 50 };
    let errors = burst(&session, &server.url(), n, streaming, false).await;
    let accepts = server.accepts.load(Ordering::SeqCst);
    eprintln!("warm={warm} limited={limited} streaming={streaming} reconnect={reconnect} successes={} errors={} TCP_accepts={accepts} new_accepts={} first_error={:?}", n-errors.len(), errors.len(), accepts-before, errors.first());
    assert!(
        errors.is_empty(),
        "{} of {n} requests failed: {:?}",
        errors.len(),
        errors.first()
    );
    if reconnect {
        accepts - before
    } else {
        accepts
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_warm_h2_burst() {
    assert_eq!(h2_burst(true, false, false, false).await, 1);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_warm_h2_burst_limit_6() {
    assert_eq!(h2_burst(true, true, false, false).await, 1);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue28_cold_h2_burst() {
    assert_eq!(h2_burst(false, false, false, false).await, 1);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue28_cold_h2_burst_limit_6() {
    assert_eq!(h2_burst(false, true, false, false).await, 1);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue28_cold_streaming_h2_burst() {
    assert_eq!(h2_burst(false, false, true, false).await, 1);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue28_cold_streaming_h2_burst_limit_6() {
    assert_eq!(h2_burst(false, true, true, false).await, 1);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue28_h2_burst_after_disconnect() {
    assert_eq!(h2_burst(false, false, false, true).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_acquisition_waits_for_h2_readiness_not_the_first_response() {
    bounded(async {
        let server = HttpsServer::start(false, Duration::from_millis(60), true).await;
        let session = client().session().max_connections(1).build();
        let mut tasks = Vec::new();
        for index in 0..20 {
            let session = session.clone();
            let url = server.url();
            tasks.push(tokio::spawn(async move {
                if index % 2 == 0 {
                    assert_eq!(
                        session
                            .post(&url)
                            .body("non-idempotent body")
                            .send()
                            .await
                            .unwrap()
                            .bytes(),
                        b"ok"
                    );
                } else {
                    assert_eq!(
                        session
                            .get(&url)
                            .send_streaming()
                            .await
                            .unwrap()
                            .bytes()
                            .await
                            .unwrap()
                            .as_ref(),
                        b"ok"
                    );
                }
            }));
        }
        let preconnect = tokio::spawn({
            let session = session.clone();
            let url = server.url();
            async move { session.preconnect(&url).await.unwrap() }
        });
        server.wait_for(&server.requests, 20).await;
        preconnect.await.unwrap();
        assert_eq!(server.accepts.load(Ordering::SeqCst), 1);
        server.response_gate.as_ref().unwrap().add_permits(20);
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(
            server.requests.load(Ordering::SeqCst),
            20,
            "POST requests must not be replayed"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independent_sessions_do_not_share_handshakes_or_connections() {
    let server = HttpsServer::start(false, Duration::from_millis(60), false).await;
    let client = client();
    let a = client.session().max_connections(1).build();
    let b = client.session().max_connections(1).build();
    let url = server.url();
    let (a, b) = tokio::join!(
        burst(&a, &url, 10, false, false),
        burst(&b, &url, 10, true, false)
    );
    assert!(a.is_empty() && b.is_empty());
    assert_eq!(server.accepts.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_h1_cold_burst_still_dials_in_parallel() {
    let server = HttpsServer::start(true, Duration::from_millis(80), false).await;
    let session = client().session().build();
    let errors = burst(&session, &server.url(), 8, false, true).await;
    let parallel = server.max_handshakes.load(Ordering::SeqCst);
    eprintln!("H1 max_concurrent_handshakes={parallel} errors={errors:?}");
    assert!(errors.is_empty());
    assert!(parallel >= 2, "H1 cold handshakes were serialized");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_h1_busy_connection_limit_is_still_an_error() {
    let server = HttpsServer::start(true, Duration::ZERO, true).await;
    let session = client().session().max_connections(1).build();
    let first = tokio::spawn({
        let session = session.clone();
        let url = server.url();
        async move { session.get(&url).send().await }
    });
    server.wait_for(&server.requests, 1).await;
    let error = bounded(session.get(&server.url()).send())
        .await
        .unwrap_err();
    eprintln!("busy H1 error={error}");
    assert!(error
        .to_string()
        .contains("session connection limit reached"));
    server.response_gate.as_ref().unwrap().add_permits(1);
    bounded(first).await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_cold_waiter_obeys_own_total_timeout() {
    let server = HttpsServer::start(false, Duration::from_millis(300), false).await;
    let session = client().session().build();
    let first = tokio::spawn({
        let session = session.clone();
        let url = server.url();
        async move { session.get(&url).send().await }
    });
    server.wait_for(&server.accepts, 1).await;
    let error = bounded(
        session
            .get(&server.url())
            .timeout(Duration::from_millis(30))
            .send(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, lkrequest::error::Error::Timeout { .. }),
        "{error}"
    );
    assert_eq!(
        bounded(first).await.unwrap().unwrap().version(),
        HttpVersion::H2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_cancelled_cold_leader_allows_next_request() {
    let server = HttpsServer::start(false, Duration::from_millis(100), false).await;
    let session = client().session().max_connections(1).build();
    let first = tokio::spawn({
        let session = session.clone();
        let url = server.url();
        async move { session.get(&url).send().await }
    });
    server.wait_for(&server.accepts, 1).await;
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    assert_eq!(
        bounded(session.get(&server.url()).send())
            .await
            .unwrap()
            .version(),
        HttpVersion::H2
    );
}
