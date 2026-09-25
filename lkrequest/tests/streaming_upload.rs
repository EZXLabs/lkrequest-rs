use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use std::convert::Infallible;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn session() -> lkrequest::Session {
    lkrequest::Client::default().session().http1_only().build()
}

async fn echo_server(status: u16) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/upload", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let service = hyper::service::service_fn(
            move |request: hyper::Request<hyper::body::Incoming>| async move {
                let headers = request.headers().clone();
                let body = request.into_body().collect().await;
                let mut response = http::Response::builder().status(status);
                if let Some(value) = headers.get("transfer-encoding") {
                    response = response.header("x-upload-framing", value);
                }
                response = response.header("connection", "close");
                if status == 307 {
                    response = response.header("location", "/again");
                }
                Ok::<_, Infallible>(
                    response
                        .body(Full::new(
                            body.map(|body| body.to_bytes()).unwrap_or_default(),
                        ))
                        .unwrap(),
                )
            },
        );
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
            .await;
    });
    (url, server)
}

struct Chunks(std::collections::VecDeque<std::io::Result<Bytes>>);

impl futures_core::Stream for Chunks {
    type Item = std::io::Result<Bytes>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::task::Poll::Ready(self.0.pop_front())
    }
}

#[tokio::test]
async fn reader_upload_sends_before_source_eof() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (received_tx, received_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        while !request.windows(5).any(|window| window == b"hello") {
            let count = socket.read(&mut buffer).await.unwrap();
            assert_ne!(count, 0);
            request.extend_from_slice(&buffer[..count]);
        }
        received_tx.send(()).unwrap();
        while !request.windows(10).any(|window| window == b"helloworld") {
            let count = socket.read(&mut buffer).await.unwrap();
            assert_ne!(count, 0);
            request.extend_from_slice(&buffer[..count]);
        }
        assert!(String::from_utf8_lossy(&request)
            .to_ascii_lowercase()
            .contains("content-length: 10\r\n"));
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let (mut producer, reader) = tokio::io::duplex(32);
    let writer = tokio::spawn(async move {
        producer.write_all(b"hello").await.unwrap();
        received_rx.await.unwrap();
        producer.write_all(b"world").await.unwrap();
        producer.shutdown().await.unwrap();
    });
    let session = lkrequest::Client::builder()
        .fingerprint(lkrequest::lktls::profile::presets::chrome_144())
        .build()
        .session()
        .build();
    let response = session
        .post(&format!("http://{address}/upload"))
        .body_reader(reader, Some(10))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    assert_eq!(response.bytes(), b"ok");
    writer.await.unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn unknown_length_stream_upload_and_streaming_download() {
    let (url, server) = echo_server(200).await;
    let chunks = Chunks(
        [
            Ok(Bytes::new()),
            Ok(Bytes::from_static(b"hello")),
            Ok(Bytes::from_static(b"world")),
        ]
        .into(),
    );
    let mut response = session()
        .post(&url)
        .body_stream(chunks, None)
        .timeout(Duration::from_secs(5))
        .send_streaming()
        .await
        .unwrap();
    assert_eq!(response.headers()["x-upload-framing"], "chunked");
    let mut received = Vec::new();
    while let Some(chunk) = response.chunk().await.unwrap() {
        received.extend_from_slice(&chunk);
    }
    assert_eq!(received, b"helloworld");
    server.await.unwrap();
}

#[tokio::test]
async fn known_length_mismatch_aborts_upload() {
    for length in [0, 3, 8] {
        let (url, server) = echo_server(200).await;
        let result = session()
            .post(&url)
            .body_reader(std::io::Cursor::new(b"hello"), Some(length))
            .timeout(Duration::from_secs(5))
            .send()
            .await;
        assert!(result.is_err(), "length {length} must fail");
        server.abort();
    }
}

#[tokio::test]
async fn source_error_aborts_upload() {
    let (url, server) = echo_server(200).await;
    let chunks = Chunks(
        [
            Ok(Bytes::from_static(b"hello")),
            Err(std::io::Error::other("source failure")),
        ]
        .into(),
    );
    let result = session()
        .post(&url)
        .body_stream(chunks, None)
        .timeout(Duration::from_secs(5))
        .send()
        .await;
    assert!(result.is_err());
    server.abort();
}

#[tokio::test]
async fn streamed_put_is_not_retried_on_status() {
    let (url, server) = echo_server(503).await;
    let session = lkrequest::Client::default()
        .session()
        .http1_only()
        .retry_policy(lkrequest::FixedInterval::new(2, Duration::ZERO))
        .build();
    let response = session
        .put(&url)
        .body_reader(std::io::Cursor::new(b"hello"), Some(5))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(response.bytes(), b"hello");
    server.await.unwrap();
}

#[tokio::test]
async fn body_preserving_redirect_does_not_replay_stream() {
    let (url, server) = echo_server(307).await;
    let error = session()
        .post(&url)
        .body_reader(std::io::Cursor::new(b"hello"), Some(5))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap_err();
    assert!(error.to_string().contains("replay"), "{error}");
    server.await.unwrap();
}

#[tokio::test]
async fn post_redirect_discards_stream_for_get() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/upload", listener.local_addr().unwrap());
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let service =
            hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                let seen = seen.clone();
                async move {
                    let index = seen.fetch_add(1, Ordering::SeqCst);
                    if index == 0 {
                        assert_eq!(request.method(), "POST");
                        assert_eq!(
                            request.into_body().collect().await.unwrap().to_bytes(),
                            "hello"
                        );
                        Ok::<_, Infallible>(
                            http::Response::builder()
                                .status(303)
                                .header("location", "/done")
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                    } else {
                        assert_eq!(request.method(), "GET");
                        assert!(!request.headers().contains_key("transfer-encoding"));
                        assert!(!request.headers().contains_key("content-length"));
                        assert!(request
                            .into_body()
                            .collect()
                            .await
                            .unwrap()
                            .to_bytes()
                            .is_empty());
                        Ok(http::Response::builder()
                            .header("connection", "close")
                            .body(Full::new(Bytes::from_static(b"done")))
                            .unwrap())
                    }
                }
            });
        hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
            .await
            .unwrap();
    });
    let response = session()
        .post(&url)
        .body_reader(std::io::Cursor::new(b"hello"), None)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .unwrap();
    assert_eq!(response.bytes(), b"done");
    assert_eq!(count.load(Ordering::SeqCst), 2);
    server.await.unwrap();
}

#[test]
fn blocking_reader_upload() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/upload", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut received = Vec::new();
        let mut buffer = [0; 1024];
        while !received.windows(5).any(|window| window == b"hello") {
            let count = socket.read(&mut buffer).unwrap();
            assert_ne!(count, 0);
            received.extend_from_slice(&buffer[..count]);
        }
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
    });
    let client = lkrequest::blocking::Client::new(lkrequest::Client::default());
    let response = client
        .session()
        .build()
        .post(&url)
        .body_reader(std::io::Cursor::new(b"hello"), Some(5))
        .timeout(Duration::from_secs(5))
        .send()
        .unwrap();
    assert_eq!(response.status(), 200);
    server.join().unwrap();
}

struct PendingUpload {
    dropped: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for PendingUpload {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(());
        }
    }
}

impl futures_core::Stream for PendingUpload {
    type Item = std::io::Result<Bytes>;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::task::Poll::Pending
    }
}

#[tokio::test]
async fn timeout_drops_pending_upload_source() {
    let (url, server) = echo_server(200).await;
    let (dropped, observed) = tokio::sync::oneshot::channel();
    let result = session()
        .post(&url)
        .body_stream(
            PendingUpload {
                dropped: Some(dropped),
            },
            None,
        )
        .timeout(Duration::from_millis(100))
        .send()
        .await;
    assert!(result.unwrap_err().is_timeout());
    tokio::time::timeout(Duration::from_secs(2), observed)
        .await
        .expect("upload retained after timeout")
        .unwrap();
    server.abort();
}

#[tokio::test]
async fn conflicting_framing_is_rejected() {
    for (name, value) in [
        ("content-length", "6"),
        ("content-length", "bad"),
        ("transfer-encoding", "chunked"),
    ] {
        let (url, server) = echo_server(200).await;
        let result = session()
            .post(&url)
            .header(name, value)
            .body_reader(std::io::Cursor::new(b"hello"), Some(5))
            .timeout(Duration::from_secs(2))
            .send()
            .await;
        assert!(result.is_err(), "accepted {name}: {value}");
        server.abort();
    }
}

#[tokio::test]
async fn explicit_length_applies_to_unknown_length_source() {
    let (url, server) = echo_server(200).await;
    let response = session()
        .post(&url)
        .header("content-length", "5")
        .body_reader(std::io::Cursor::new(b"hello"), None)
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .unwrap();
    assert_eq!(response.bytes(), b"hello");
    server.await.unwrap();
}

#[tokio::test]
async fn zero_length_reader_completes() {
    let (url, server) = echo_server(200).await;
    let response = session()
        .post(&url)
        .body_reader(std::io::Cursor::new(b""), Some(0))
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .unwrap();
    assert!(response.bytes().is_empty());
    server.await.unwrap();
}

#[tokio::test]
async fn early_response_releases_pending_source() {
    for streaming in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/upload", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 4096];
            assert_ne!(socket.read(&mut buffer).await.unwrap(), 0);
            socket.write_all(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n").await.unwrap();
            let (next_socket, _) = listener.accept().await.unwrap();
            let service = hyper::service::service_fn(
                |request: hyper::Request<hyper::body::Incoming>| async move {
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    assert_eq!(body, "healthy");
                    Ok::<_, Infallible>(
                        http::Response::builder()
                            .header("connection", "close")
                            .body(Full::new(body))
                            .unwrap(),
                    )
                },
            );
            hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(next_socket), service)
                .await
                .unwrap();
            drop(socket);
        });
        let (dropped, observed) = tokio::sync::oneshot::channel();
        let session = session();
        let request = session
            .post(&url)
            .body_stream(
                PendingUpload {
                    dropped: Some(dropped),
                },
                None,
            )
            .timeout(Duration::from_secs(2));
        let status = if streaming {
            let response = request.send_streaming().await.unwrap();
            let status = response.status();
            assert!(response.bytes().await.unwrap().is_empty());
            status
        } else {
            request.send().await.unwrap().status()
        };
        assert_eq!(status, 413);
        tokio::time::timeout(Duration::from_secs(2), observed)
            .await
            .unwrap()
            .unwrap();
        let response = session
            .post(&url)
            .body_reader(std::io::Cursor::new(b"healthy"), Some(7))
            .timeout(Duration::from_secs(2))
            .send()
            .await
            .unwrap();
        assert_eq!(response.bytes(), b"healthy");
        server.await.unwrap();
    }
}

struct ReplaceUpload;

impl lkrequest::Middleware for ReplaceUpload {
    fn on_request(
        &self,
        mut request: lkrequest::middleware::MiddlewareRequest,
    ) -> lkrequest::error::Result<lkrequest::middleware::MiddlewareRequest> {
        assert!(request.body.is_none());
        request.body = Some(Bytes::from_static(b"replacement"));
        Ok(request)
    }
}

#[tokio::test]
async fn middleware_can_replace_stream_without_polling_it() {
    let (url, server) = echo_server(200).await;
    let session = lkrequest::Client::default()
        .session()
        .http1_only()
        .middleware(ReplaceUpload)
        .build();
    let (dropped, observed) = tokio::sync::oneshot::channel();
    let response = session
        .post(&url)
        .body_stream(
            PendingUpload {
                dropped: Some(dropped),
            },
            None,
        )
        .timeout(Duration::from_secs(2))
        .send()
        .await
        .unwrap();
    assert_eq!(response.bytes(), b"replacement");
    observed.await.unwrap();
    server.await.unwrap();
}

struct RemoveBody;

impl lkrequest::Middleware for RemoveBody {
    fn on_request(
        &self,
        mut request: lkrequest::middleware::MiddlewareRequest,
    ) -> lkrequest::error::Result<lkrequest::middleware::MiddlewareRequest> {
        request.body = None;
        Ok(request)
    }
}

#[tokio::test]
async fn middleware_removing_replacement_does_not_restore_original_stream() {
    for streaming in [false, true] {
        let (url, server) = echo_server(200).await;
        let session = lkrequest::Client::default()
            .session()
            .http1_only()
            .middleware(ReplaceUpload)
            .middleware(RemoveBody)
            .build();
        let request = session
            .post(&url)
            .body_reader(std::io::Cursor::new(b"original"), None)
            .timeout(Duration::from_secs(2));
        let body = if streaming {
            request
                .send_streaming()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
        } else {
            request.send().await.unwrap().into_bytes()
        };
        assert!(body.is_empty(), "original stream was restored: {body:?}");
        server.await.unwrap();
    }
}

#[tokio::test]
async fn completed_h1_upload_reuses_buffered_connection() {
    for known_length in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/upload", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let count = Arc::new(AtomicUsize::new(0));
            let service = hyper::service::service_fn(
                move |request: hyper::Request<hyper::body::Incoming>| {
                    let index = count.fetch_add(1, Ordering::SeqCst);
                    async move {
                        let body = request.into_body().collect().await.unwrap().to_bytes();
                        let mut response = http::Response::builder();
                        if index == 2 {
                            response = response.header("connection", "close");
                        }
                        Ok::<_, Infallible>(response.body(Full::new(body)).unwrap())
                    }
                },
            );
            hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                .await
                .unwrap();
        });
        let session = session();
        let first = session
            .post(&url)
            .body("before")
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .unwrap();
        assert_eq!(first.bytes(), b"before");
        let payload = vec![b'x'; 2 * 1024 * 1024];
        let second = session
            .post(&url)
            .body_reader(
                std::io::Cursor::new(payload.clone()),
                known_length.then_some(payload.len() as u64),
            )
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .unwrap();
        assert_eq!(second.bytes(), payload);
        let third = session
            .post(&url)
            .body("after")
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .unwrap();
        assert_eq!(third.bytes(), b"after");
        server.await.unwrap();
    }
}
