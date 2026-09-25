use bytes::Bytes;
use futures_core::Stream;
use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::mpsc,
};

struct Source {
    receiver: mpsc::UnboundedReceiver<io::Result<Bytes>>,
    reads: Arc<AtomicUsize>,
}

impl Stream for Source {
    type Item = io::Result<Bytes>;
    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let result = self.receiver.poll_recv(context);
        if matches!(result, Poll::Ready(Some(_))) {
            self.reads.fetch_add(1, Ordering::SeqCst);
        }
        result
    }
}

async fn frame(peer: &mut DuplexStream) -> (u8, u8, u32, Vec<u8>) {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut header = [0; 9];
        peer.read_exact(&mut header).await.unwrap();
        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let mut payload = vec![0; length];
        peer.read_exact(&mut payload).await.unwrap();
        (
            header[3],
            header[4],
            u32::from_be_bytes(header[5..9].try_into().unwrap()),
            payload,
        )
    })
    .await
    .expect("wire frame timed out")
}

async fn next_kind(peer: &mut DuplexStream, kind: u8) -> (u8, u8, u32, Vec<u8>) {
    loop {
        let received = frame(peer).await;
        if received.0 == kind {
            return received;
        }
    }
}

async fn setup() -> (lkh2::UnifiedH2Connection, DuplexStream) {
    let (client, mut peer) = tokio::io::duplex(256 * 1024);
    let connection = lkh2::connect_h2_native(client, &lkh2::profile::chrome_146_h2(), None)
        .await
        .unwrap();
    let mut preface = [0; 24];
    peer.read_exact(&mut preface).await.unwrap();
    assert_eq!(&preface, lkh2::CONNECTION_PREFACE);
    (connection, peer)
}

async fn blocked_upload() -> (
    lkh2::UnifiedH2Connection,
    DuplexStream,
    mpsc::UnboundedSender<io::Result<Bytes>>,
    UploadTask,
    u32,
) {
    let (client, mut peer) = tokio::io::duplex(128);
    let connection = lkh2::connect_h2_native(client, &lkh2::profile::chrome_146_h2(), None)
        .await
        .unwrap();
    peer.read_exact(&mut [0; 24]).await.unwrap();
    let (sender, reads, task) = upload(&connection);
    let stream_id = next_kind(&mut peer, 1).await.2;
    sender.send(Ok(Bytes::from(vec![1; 16384]))).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while reads.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    (connection, peer, sender, task, stream_id)
}

#[tokio::test]
async fn blocked_data_write_does_not_block_cancellation() {
    let (_connection, mut peer, sender, task, stream_id) = blocked_upload().await;
    task.abort();
    let _ = task.await;
    tokio::time::timeout(Duration::from_millis(500), sender.closed())
        .await
        .expect("blocked write retained cancelled source");
    let mut received = 0;
    loop {
        let (kind, _, target, payload) = frame(&mut peer).await;
        assert_eq!(target, stream_id);
        if kind == 3 {
            assert_eq!(payload, 8u32.to_be_bytes());
            break;
        }
        assert_eq!(kind, 0);
        received += payload.len();
    }
    assert_eq!(received, 16384);
}

#[tokio::test]
async fn blocked_data_write_does_not_block_peer_reset() {
    let (_connection, mut peer, sender, task, stream_id) = blocked_upload().await;
    let mut reset = vec![0, 0, 4, 3, 0];
    reset.extend_from_slice(&stream_id.to_be_bytes());
    reset.extend_from_slice(&8u32.to_be_bytes());
    peer.write_all(&reset).await.unwrap();
    let result = tokio::time::timeout(Duration::from_millis(500), task)
        .await
        .expect("blocked write prevented peer reset")
        .unwrap();
    assert!(result.is_err());
    assert!(sender.is_closed());
}

#[tokio::test]
async fn blocked_data_write_does_not_block_early_response() {
    let (_connection, mut peer, sender, task, stream_id) = blocked_upload().await;
    let mut headers = vec![0, 0, 1, 1, 5];
    headers.extend_from_slice(&stream_id.to_be_bytes());
    headers.push(0x88);
    peer.write_all(&headers).await.unwrap();
    let response = tokio::time::timeout(Duration::from_millis(500), task)
        .await
        .expect("blocked write prevented early response")
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(sender.is_closed());
}

type UploadTask =
    tokio::task::JoinHandle<Result<http::Response<lkh2::H2RecvStream>, lkh2::H2SendError>>;

#[tokio::test]
async fn buffered_two_mib_upload_with_wide_peer_windows_has_no_new_body_cap() {
    let received = buffered_two_mib_upload(true).await;
    assert_eq!(received, 2 * 1024 * 1024);
}

#[tokio::test]
async fn buffered_two_mib_upload_resumes_after_wide_window_update() {
    let received = buffered_two_mib_upload(false).await;
    assert_eq!(received, 2 * 1024 * 1024);
}

async fn buffered_two_mib_upload(initial_credit: bool) -> usize {
    let (connection, mut peer) = setup().await;
    let window = 4 * 1024 * 1024u32;
    let mut settings = vec![0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 4];
    settings.extend_from_slice(&window.to_be_bytes());
    peer.write_all(&settings).await.unwrap();
    let mut update = vec![0, 0, 4, 8, 0, 0, 0, 0, 0];
    update.extend_from_slice(&(window - 65535).to_be_bytes());
    if initial_credit {
        peer.write_all(&update).await.unwrap();
    }
    peer.write_all(&[0, 0, 8, 6, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8])
        .await
        .unwrap();
    assert_eq!(next_kind(&mut peer, 6).await.1, 1);
    let client = connection.clone_sender();
    let task = tokio::spawn(async move {
        let (response, mut body) = client
            .ready()
            .await
            .unwrap()
            .send_request(
                http::Request::builder()
                    .method("POST")
                    .uri("https://example.test/buffered")
                    .body(())
                    .unwrap(),
                false,
            )
            .unwrap();
        body.send_data(Bytes::from(vec![0x5a; 2 * 1024 * 1024]), true)
            .unwrap();
        response.await_response().await
    });
    let headers = next_kind(&mut peer, 1).await;
    assert_eq!(headers.1 & 1, 0);
    let mut received = 0;
    loop {
        let data = next_kind(&mut peer, 0).await;
        assert_eq!(data.2, headers.2);
        assert!(data.3.iter().all(|byte| *byte == 0x5a));
        received += data.3.len();
        if !initial_credit && received == 65535 {
            peer.write_all(&update).await.unwrap();
        }
        if data.1 & 1 != 0 {
            break;
        }
    }
    let mut response = vec![0, 0, 1, 1, 5];
    response.extend_from_slice(&headers.2.to_be_bytes());
    response.push(0x88);
    peer.write_all(&response).await.unwrap();
    assert_eq!(task.await.unwrap().unwrap().status(), 200);
    received
}

fn upload(
    connection: &lkh2::UnifiedH2Connection,
) -> (
    mpsc::UnboundedSender<io::Result<Bytes>>,
    Arc<AtomicUsize>,
    UploadTask,
) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let reads = Arc::new(AtomicUsize::new(0));
    let source = Source {
        receiver,
        reads: reads.clone(),
    };
    let client = connection.clone_sender();
    let task = tokio::spawn(async move {
        client
            .ready()
            .await
            .unwrap()
            .send_streaming_request(
                http::Request::builder()
                    .method("POST")
                    .uri("https://example.test/upload")
                    .body(())
                    .unwrap(),
                Box::pin(source),
            )
            .await_response()
            .await
    });
    (sender, reads, task)
}

#[tokio::test]
async fn incremental_delivery_and_pending_source_does_not_block_connection() {
    let (connection, mut peer) = setup().await;
    let (sender, _, task) = upload(&connection);
    let headers = next_kind(&mut peer, 1).await;
    assert_eq!(headers.1 & 1, 0);
    sender.send(Ok(Bytes::from_static(b"first"))).unwrap();
    let data = next_kind(&mut peer, 0).await;
    assert_eq!(data.3, b"first");
    assert_eq!(data.1 & 1, 0);
    peer.write_all(&[0, 0, 8, 6, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8])
        .await
        .unwrap();
    assert_eq!(next_kind(&mut peer, 6).await.1, 1);
    sender.send(Ok(Bytes::from_static(b"second"))).unwrap();
    assert_eq!(next_kind(&mut peer, 0).await.3, b"second");
    drop(sender);
    assert_eq!(next_kind(&mut peer, 0).await.1 & 1, 1);
    task.abort();
}

#[tokio::test]
async fn exhausted_window_stops_source_reads_and_resumes() {
    let (connection, mut peer) = setup().await;
    let (sender, reads, task) = upload(&connection);
    let stream_id = next_kind(&mut peer, 1).await.2;
    sender.send(Ok(Bytes::from(vec![7; 65536]))).unwrap();
    sender.send(Ok(Bytes::from_static(b"next"))).unwrap();
    let mut received = 0;
    while received < 65535 {
        received += next_kind(&mut peer, 0).await.3.len();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    for target in [0u32, stream_id] {
        let mut update = vec![0, 0, 4, 8, 0];
        update.extend_from_slice(&target.to_be_bytes());
        update.extend_from_slice(&100u32.to_be_bytes());
        peer.write_all(&update).await.unwrap();
    }
    assert_eq!(next_kind(&mut peer, 0).await.3, [7]);
    assert_eq!(next_kind(&mut peer, 0).await.3, b"next");
    drop(sender);
    assert_eq!(next_kind(&mut peer, 0).await.1 & 1, 1);
    task.abort();
}

#[tokio::test]
async fn reader_error_resets_stream_and_reaches_caller() {
    let (connection, mut peer) = setup().await;
    let (sender, _, task) = upload(&connection);
    next_kind(&mut peer, 1).await;
    sender.send(Err(io::Error::other("upload failed"))).unwrap();
    let reset = next_kind(&mut peer, 3).await;
    assert_eq!(reset.3, 2u32.to_be_bytes());
    let error = task.await.unwrap().err().expect("upload must fail");
    assert!(error.to_string().contains("upload failed"));
}

#[tokio::test]
async fn cancelling_pending_reader_resets_stream() {
    let (connection, mut peer) = setup().await;
    let (sender, _, task) = upload(&connection);
    next_kind(&mut peer, 1).await;
    task.abort();
    let _ = task.await;
    assert_eq!(next_kind(&mut peer, 3).await.3, 8u32.to_be_bytes());
    assert!(sender.is_closed());
}

#[tokio::test]
async fn eof_at_exact_window_boundary_sends_end_stream() {
    let (connection, mut peer) = setup().await;
    let (sender, _, task) = upload(&connection);
    next_kind(&mut peer, 1).await;
    sender.send(Ok(Bytes::from(vec![7; 65535]))).unwrap();
    drop(sender);
    let mut received = 0;
    loop {
        let data = next_kind(&mut peer, 0).await;
        received += data.3.len();
        if data.1 & 1 != 0 {
            break;
        }
    }
    assert_eq!(received, 65535);
    task.abort();
}

#[tokio::test]
async fn early_completed_response_cancels_upload_without_losing_response() {
    let (connection, mut peer) = setup().await;
    let (sender, _, task) = upload(&connection);
    let stream_id = next_kind(&mut peer, 1).await.2;
    let mut headers = vec![0, 0, 1, 1, 5];
    headers.extend_from_slice(&stream_id.to_be_bytes());
    headers.push(0x88);
    peer.write_all(&headers).await.unwrap();
    let response = task.await.unwrap().unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(next_kind(&mut peer, 3).await.3, 0u32.to_be_bytes());
    assert!(sender.is_closed());
}

#[tokio::test]
async fn stream_window_blocks_upload_independently_of_connection_window() {
    let (connection, mut peer) = setup().await;
    peer.write_all(&[0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 5])
        .await
        .unwrap();
    loop {
        if next_kind(&mut peer, 4).await.1 == 1 {
            break;
        }
    }
    let (sender, reads, task) = upload(&connection);
    let stream_id = next_kind(&mut peer, 1).await.2;
    sender.send(Ok(Bytes::from(vec![9; 20]))).unwrap();
    sender.send(Ok(Bytes::from_static(b"tail"))).unwrap();
    assert_eq!(next_kind(&mut peer, 0).await.3, vec![9; 5]);
    assert!(
        tokio::time::timeout(Duration::from_millis(50), frame(&mut peer))
            .await
            .is_err()
    );
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    let mut update = vec![0, 0, 4, 8, 0];
    update.extend_from_slice(&stream_id.to_be_bytes());
    update.extend_from_slice(&100u32.to_be_bytes());
    peer.write_all(&update).await.unwrap();
    assert_eq!(next_kind(&mut peer, 0).await.3, vec![9; 15]);
    assert_eq!(next_kind(&mut peer, 0).await.3, b"tail");
    drop(sender);
    assert_eq!(next_kind(&mut peer, 0).await.1 & 1, 1);
    task.abort();
}

#[tokio::test]
async fn dropping_response_body_cancels_pending_upload() {
    let (connection, mut peer) = setup().await;
    let (sender, _, task) = upload(&connection);
    let stream_id = next_kind(&mut peer, 1).await.2;
    let mut headers = vec![0, 0, 1, 1, 4];
    headers.extend_from_slice(&stream_id.to_be_bytes());
    headers.push(0x88);
    peer.write_all(&headers).await.unwrap();
    let response = task.await.unwrap().unwrap();
    drop(response);
    assert_eq!(next_kind(&mut peer, 3).await.3, 8u32.to_be_bytes());
    assert!(sender.is_closed());
}

#[tokio::test]
async fn peer_reset_drops_pending_upload() {
    let (connection, mut peer) = setup().await;
    let (sender, _, task) = upload(&connection);
    let stream_id = next_kind(&mut peer, 1).await.2;
    let mut reset = vec![0, 0, 4, 3, 0];
    reset.extend_from_slice(&stream_id.to_be_bytes());
    reset.extend_from_slice(&8u32.to_be_bytes());
    peer.write_all(&reset).await.unwrap();
    let error = task
        .await
        .unwrap()
        .err()
        .expect("peer reset must fail the request");
    assert!(error.to_string().contains("stream reset"));
    assert!(sender.is_closed());
}

#[tokio::test]
async fn cancelling_after_upload_eof_releases_peer_stream_slot() {
    let (connection, mut peer) = setup().await;
    peer.write_all(&[0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1])
        .await
        .unwrap();
    loop {
        if next_kind(&mut peer, 4).await.1 == 1 {
            break;
        }
    }
    let (sender, _, task) = upload(&connection);
    let first = next_kind(&mut peer, 1).await.2;
    drop(sender);
    assert_eq!(next_kind(&mut peer, 0).await.1 & 1, 1);
    let (next_sender, _, next_task) = upload(&connection);
    task.abort();
    let _ = task.await;
    let reset = next_kind(&mut peer, 3).await;
    assert_eq!(reset.2, first);
    assert_eq!(reset.3, 8u32.to_be_bytes());
    assert_eq!(next_kind(&mut peer, 1).await.2, first + 2);
    drop(next_sender);
    next_task.abort();
}

#[tokio::test]
async fn dropping_response_after_upload_eof_sends_cancel() {
    let (connection, mut peer) = setup().await;
    let (sender, _, task) = upload(&connection);
    let stream_id = next_kind(&mut peer, 1).await.2;
    drop(sender);
    assert_eq!(next_kind(&mut peer, 0).await.1 & 1, 1);
    let mut headers = vec![0, 0, 1, 1, 4];
    headers.extend_from_slice(&stream_id.to_be_bytes());
    headers.push(0x88);
    peer.write_all(&headers).await.unwrap();
    drop(task.await.unwrap().unwrap());
    assert_eq!(next_kind(&mut peer, 3).await.3, 8u32.to_be_bytes());
}

struct AlwaysReadable {
    inner: DuplexStream,
    enabled: Arc<AtomicUsize>,
    reads: Arc<AtomicUsize>,
    first_write: Arc<AtomicUsize>,
}

impl tokio::io::AsyncRead for AlwaysReadable {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.enabled.load(Ordering::SeqCst) != 0 && self.reads.load(Ordering::SeqCst) < 256 {
            self.reads.fetch_add(1, Ordering::SeqCst);
            buffer.put_slice(&[0, 0, 8, 6, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl tokio::io::AsyncWrite for AlwaysReadable {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.enabled.load(Ordering::SeqCst) != 0 {
            let _ = self.first_write.compare_exchange(
                0,
                self.reads.load(Ordering::SeqCst),
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
        }
        Pin::new(&mut self.inner).poll_write(context, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[tokio::test]
async fn always_readable_peer_does_not_starve_pending_writes() {
    let (inner, mut peer) = tokio::io::duplex(65536);
    let enabled = Arc::new(AtomicUsize::new(0));
    let reads = Arc::new(AtomicUsize::new(0));
    let first_write = Arc::new(AtomicUsize::new(0));
    let connection = lkh2::connect_h2_native(
        AlwaysReadable {
            inner,
            enabled: enabled.clone(),
            reads: reads.clone(),
            first_write: first_write.clone(),
        },
        &lkh2::profile::chrome_146_h2(),
        None,
    )
    .await
    .unwrap();
    peer.read_exact(&mut [0; 24]).await.unwrap();
    enabled.store(1, Ordering::SeqCst);
    peer.write_all(&[0, 0, 8, 6, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8])
        .await
        .unwrap();
    assert_eq!(next_kind(&mut peer, 6).await.1, 1);
    assert!(
        first_write.load(Ordering::SeqCst) < 256,
        "all ready reads ran before the first write"
    );
    drop(connection);
}
