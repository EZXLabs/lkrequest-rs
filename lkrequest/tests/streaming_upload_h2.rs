use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Notify};
use tokio::task::{JoinHandle, JoinSet};

const FIRST: &[u8] = b"first-upload-chunk";
const SECOND: &[u8] = b"second-upload-chunk";

struct Observation {
    connection: usize,
    length: Option<String>,
    transfer_encoding: bool,
    body: Vec<u8>,
}

struct Fixture {
    url: String,
    session: lkrequest::Session,
    received: mpsc::UnboundedReceiver<Observation>,
    first_received: Arc<Notify>,
    task: JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(15), future)
        .await
        .expect("local upload timed out")
}

struct ChannelStream(mpsc::Receiver<io::Result<Bytes>>);

impl futures_core::Stream for ChannelStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(context)
    }
}

struct FailingReader;

impl AsyncRead for FailingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("intentional upload reader failure")))
    }
}

async fn response_bytes(request: lkrequest::session::RequestBuilder, streaming: bool) -> Bytes {
    if streaming {
        let response = request.send_streaming().await.unwrap();
        assert_eq!(response.status(), 200);
        response.bytes().await.unwrap()
    } else {
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), 200);
        Bytes::copy_from_slice(response.bytes())
    }
}

async fn incremental(reader: bool, streaming: bool, known_length: bool) -> Vec<u8> {
    bounded(async {
        let mut fixture = fixture().await;
        let expected = [FIRST, SECOND].concat();
        let length = known_length.then_some(expected.len() as u64);
        let request = fixture.session.post(&format!("{}/gated", fixture.url));
        let notify = fixture.first_received.clone();
        let (request, producer) = if reader {
            let (mut writer, reader) = tokio::io::duplex(128);
            let producer = tokio::spawn(async move {
                writer.write_all(FIRST).await.unwrap();
                notify.notified().await;
                writer.write_all(SECOND).await.unwrap();
                writer.shutdown().await.unwrap();
            });
            (request.body_reader(reader, length), producer)
        } else {
            let (sender, receiver) = mpsc::channel(1);
            let producer = tokio::spawn(async move {
                sender.send(Ok(Bytes::from_static(FIRST))).await.unwrap();
                notify.notified().await;
                sender.send(Ok(Bytes::from_static(SECOND))).await.unwrap();
            });
            (
                request.body_stream(ChannelStream(receiver), length),
                producer,
            )
        };
        assert_eq!(response_bytes(request, streaming).await.as_ref(), expected);
        producer.await.unwrap();
        let observed = fixture.received.recv().await.unwrap();
        assert_eq!(observed.body, expected);
        assert_eq!(observed.length, length.map(|value| value.to_string()));
        assert!(!observed.transfer_encoding);
        observed.body
    })
    .await
}

#[tokio::test]
async fn reader_delivers_incrementally_for_both_response_modes_and_lengths() {
    for streaming in [false, true] {
        for known_length in [false, true] {
            assert_eq!(
                incremental(true, streaming, known_length).await,
                [FIRST, SECOND].concat()
            );
        }
    }
}

#[tokio::test]
async fn stream_delivers_incrementally_for_both_response_modes_and_lengths() {
    for streaming in [false, true] {
        for known_length in [false, true] {
            assert_eq!(
                incremental(false, streaming, known_length).await,
                [FIRST, SECOND].concat()
            );
        }
    }
}

#[tokio::test]
async fn large_upload_exceeds_flow_control_windows_and_reuses_buffered_connection() {
    bounded(async {
        let mut fixture = fixture().await;
        let warmup = response_bytes(fixture.session.post(&fixture.url).body("before"), false).await;
        assert_eq!(warmup.as_ref(), b"before");
        let first = fixture.received.recv().await.unwrap();
        let payload = Bytes::from(vec![0x5a; 2 * 1024 * 1024]);
        for streaming in [false, true] {
            let response = response_bytes(
                fixture.session.post(&fixture.url).body_reader(
                    std::io::Cursor::new(payload.clone()),
                    Some(payload.len() as u64),
                ),
                streaming,
            )
            .await;
            assert_eq!(response, payload);
            let observed = fixture.received.recv().await.unwrap();
            assert_eq!(observed.connection, first.connection);
            assert_eq!(observed.body.as_slice(), payload.as_ref());
        }
        let response =
            response_bytes(fixture.session.post(&fixture.url).body("after"), false).await;
        assert_eq!(response.as_ref(), b"after");
        assert_eq!(
            fixture.received.recv().await.unwrap().connection,
            first.connection
        );
    })
    .await;
}

#[tokio::test]
async fn reader_error_is_reported_for_both_response_modes() {
    bounded(async {
        let fixture = fixture().await;
        for streaming in [false, true] {
            let request = fixture
                .session
                .post(&fixture.url)
                .body_reader(FailingReader, None);
            let error = if streaming {
                request
                    .send_streaming()
                    .await
                    .expect_err("reader error must fail upload")
            } else {
                request
                    .send()
                    .await
                    .expect_err("reader error must fail upload")
            };
            assert!(
                error
                    .to_string()
                    .contains("intentional upload reader failure"),
                "{error}"
            );
            assert_eq!(
                response_bytes(fixture.session.post(&fixture.url).body("healthy"), false)
                    .await
                    .as_ref(),
                b"healthy",
            );
        }
    })
    .await;
}

#[tokio::test]
async fn cancelling_pending_reader_releases_source_and_session_remains_usable() {
    bounded(async {
        for streaming in [false, true] {
            let fixture = fixture().await;
            let (mut writer, reader) = tokio::io::duplex(128);
            let session = fixture.session.clone();
            let url = format!("{}/gated", fixture.url);
            let upload = tokio::spawn(async move {
                let request = session.post(&url).body_reader(reader, None);
                if streaming {
                    let _ = request.send_streaming().await;
                } else {
                    let _ = request.send().await;
                }
            });
            writer.write_all(FIRST).await.unwrap();
            fixture.first_received.notified().await;
            upload.abort();
            assert!(upload.await.unwrap_err().is_cancelled());
            assert!(
                writer.write_all(&[0x5a; 1024]).await.is_err(),
                "reader must be dropped"
            );
            assert_eq!(
                response_bytes(
                    fixture.session.post(&fixture.url).body("after-cancel"),
                    false
                )
                .await
                .as_ref(),
                b"after-cancel",
            );
        }
    })
    .await;
}

use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;

async fn fixture() -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (observations, received) = mpsc::unbounded_channel();
    let first_received = Arc::new(Notify::new());
    let notify = first_received.clone();
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        let mut connection = 0;
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            connection += 1;
            let observations = observations.clone();
            let notify = notify.clone();
            connections.spawn(async move {
                let service =
                    service_fn(move |mut request: hyper::Request<hyper::body::Incoming>| {
                        let observations = observations.clone();
                        let notify = notify.clone();
                        async move {
                            assert_eq!(request.version(), http::Version::HTTP_2);
                            let length = request
                                .headers()
                                .get("content-length")
                                .map(|value| value.to_str().unwrap().to_owned());
                            let transfer_encoding =
                                request.headers().contains_key("transfer-encoding");
                            let gated = request.uri().path() == "/gated";
                            let mut body = Vec::new();
                            let mut acknowledged = false;
                            while let Some(frame) = request.body_mut().frame().await {
                                let frame = frame?;
                                if let Ok(data) = frame.into_data() {
                                    body.extend_from_slice(&data);
                                    if gated && !acknowledged && body.len() >= FIRST.len() {
                                        assert_eq!(&body[..FIRST.len()], FIRST);
                                        acknowledged = true;
                                        notify.notify_one();
                                    }
                                }
                            }
                            let response = Bytes::copy_from_slice(&body);
                            let _ = observations.send(Observation {
                                connection,
                                length,
                                transfer_encoding,
                                body,
                            });
                            Ok::<_, hyper::Error>(http::Response::new(Full::new(response)))
                        }
                    });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .initial_stream_window_size(16 * 1024)
                    .initial_connection_window_size(65_535)
                    .adaptive_window(false)
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    let session = lkrequest::Client::builder()
        .fingerprint(lktls::profile::presets::chrome_131())
        .h2_profile(lkrequest::h2::profile::chrome_144_h2())
        .build()
        .session()
        .http2_only()
        .build();
    Fixture {
        url,
        session,
        received,
        first_received,
        task,
    }
}
