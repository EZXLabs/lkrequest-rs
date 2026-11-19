use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lkrequest::{Client, FixedInterval, TimeoutConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn read_headers(socket: &mut tokio::net::TcpStream) -> bool {
    let mut bytes = Vec::new();
    let mut byte = [0];
    while !bytes.ends_with(b"\r\n\r\n") {
        if socket.read_exact(&mut byte).await.is_err() {
            return false;
        }
        bytes.push(byte[0]);
    }
    true
}

async fn delayed_server(
    body_delay: Duration,
    status: u16,
) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let requests = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn({
        let requests = Arc::clone(&requests);
        async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let requests = Arc::clone(&requests);
                tokio::spawn(async move {
                    if !read_headers(&mut socket).await {
                        return;
                    }
                    requests.fetch_add(1, Ordering::SeqCst);
                    let headers = format!(
                        "HTTP/1.1 {status} Test\r\nContent-Length: 2\r\nConnection: close\r\n\r\n"
                    );
                    if socket.write_all(headers.as_bytes()).await.is_err() {
                        return;
                    }
                    tokio::time::sleep(body_delay).await;
                    let _ = socket.write_all(b"ok").await;
                });
            }
        }
    });
    (url, requests, task)
}

#[tokio::test]
async fn total_timeout_includes_retry_backoff() {
    let (url, requests, task) = delayed_server(Duration::ZERO, 503).await;
    let session = Client::builder()
        .total_timeout(Duration::from_millis(200))
        .build()
        .session()
        .http1_only()
        .retry_policy(FixedInterval::new(2, Duration::from_millis(500)))
        .build();
    let started = Instant::now();
    let result = session.get(&url).send().await;
    task.abort();
    assert!(result.is_err_and(|error| error.is_timeout()));
    assert!(started.elapsed() < Duration::from_millis(800));
    assert_eq!(requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn total_timeout_survives_streaming_response_headers() {
    let (url, _, task) = delayed_server(Duration::from_millis(700), 200).await;
    let session = Client::builder()
        .total_timeout(Duration::from_millis(200))
        .build()
        .session()
        .http1_only()
        .build();
    let response = session.get(&url).send_streaming().await.unwrap();
    let result = response.bytes().await;
    task.abort();
    assert!(result.is_err_and(|error| error.is_timeout()));
}

#[tokio::test]
async fn expired_streaming_deadline_rejects_already_buffered_data() {
    for decoded in [false, true] {
        let (url, _, task) = delayed_server(Duration::ZERO, 200).await;
        let session = Client::builder()
            .total_timeout(Duration::from_millis(200))
            .build()
            .session()
            .http1_only()
            .build();
        let mut response = session.get(&url).send_streaming().await.unwrap();
        tokio::time::sleep(Duration::from_millis(350)).await;
        let result = if decoded {
            response.chunk_decoded().await
        } else {
            response.chunk().await
        };
        task.abort();
        assert!(result.is_err_and(|error| error.is_timeout()));
    }
}

#[test]
fn replay_and_protocol_fallback_require_opt_in() {
    let client = Client::builder().build();
    assert!(!client.fallback().retry_on_connection_close);
    assert!(!client.fallback().h2_to_h1);
    assert_eq!(
        client.timeouts().total_timeout,
        Some(Duration::from_secs(120))
    );
}

#[tokio::test]
async fn body_read_idle_timeout_covers_buffered_and_streaming_reads() {
    for streaming in [false, true] {
        let (url, _, task) = delayed_server(Duration::from_millis(700), 200).await;
        let config = TimeoutConfig {
            total_timeout: None,
            read_idle_timeout: Some(Duration::from_millis(200)),
            ..TimeoutConfig::default()
        };
        let session = Client::builder()
            .timeout_config(config)
            .build()
            .session()
            .http1_only()
            .build();
        let result = if streaming {
            session
                .get(&url)
                .send_streaming()
                .await
                .unwrap()
                .bytes()
                .await
        } else {
            session
                .get(&url)
                .send()
                .await
                .map(|response| response.into_bytes())
        };
        task.abort();
        let error = result.unwrap_err();
        assert!(error.is_timeout());
        assert_eq!(
            error.phase(),
            Some(lkrequest::error::ConnectionPhase::HttpRequest)
        );
    }
}

#[tokio::test]
async fn cancelling_chunk_does_not_reset_idle_budget() {
    let (url, _, task) = delayed_server(Duration::from_secs(2), 200).await;
    let config = TimeoutConfig {
        total_timeout: None,
        read_idle_timeout: Some(Duration::from_millis(400)),
        ..TimeoutConfig::default()
    };
    let session = Client::builder()
        .timeout_config(config)
        .build()
        .session()
        .http1_only()
        .build();
    let mut response = session.get(&url).send_streaming().await.unwrap();
    let started = Instant::now();
    assert!(
        tokio::time::timeout(Duration::from_millis(250), response.chunk())
            .await
            .is_err()
    );
    let error = response.chunk().await.unwrap_err();
    task.abort();
    assert!(error.is_timeout());
    assert!(started.elapsed() < Duration::from_millis(600));
    assert!(response.chunk().await.unwrap_err().is_timeout());
}

#[tokio::test]
async fn disabling_total_does_not_add_an_implicit_body_deadline() {
    let (url, _, task) = delayed_server(Duration::from_millis(400), 200).await;
    let config = TimeoutConfig {
        total_timeout: None,
        ttfb_timeout: Some(Duration::from_millis(200)),
        ..TimeoutConfig::default()
    };
    let session = Client::builder()
        .timeout_config(config)
        .build()
        .session()
        .http1_only()
        .build();
    let response = session.get(&url).send_streaming().await.unwrap();
    assert_eq!(response.bytes().await.unwrap(), "ok");
    task.abort();
}

#[tokio::test]
async fn disabling_total_preserves_explicit_proxy_fallback() {
    for scheme in ["http", "socks5"] {
        let (url, requests, task) = delayed_server(Duration::ZERO, 200).await;
        let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        drop(proxy);
        let session = Client::builder()
            .timeout_config(TimeoutConfig {
                total_timeout: None,
                ..TimeoutConfig::default()
            })
            .proxy_fallback_direct(true)
            .build()
            .session()
            .http1_only()
            .proxy(&format!("{scheme}://{proxy_address}"))
            .build();
        let response = session.get(&url).send().await.unwrap();
        task.abort();
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn stale_connection_replay_requires_explicit_configuration() {
    for enabled in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn({
            let requests = Arc::clone(&requests);
            async move {
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    while read_headers(&mut socket).await {
                        let index = requests.fetch_add(1, Ordering::SeqCst);
                        if index == 1 {
                            break;
                        }
                        if socket
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        });
        let builder = Client::builder().total_timeout(Duration::from_secs(3));
        let client = if enabled {
            builder.retry_on_connection_close(true).build()
        } else {
            builder.build()
        };
        let session = client.session().http1_only().build();
        session.get(&url).send().await.unwrap();
        let result = session.get(&url).send().await;
        task.abort();
        assert_eq!(result.is_ok(), enabled, "replay opt-in={enabled}");
        assert_eq!(requests.load(Ordering::SeqCst), if enabled { 3 } else { 2 });
    }
}
