//! Tier 0: abandoned requests release H2 stream capacity and connection ownership.

use std::future::Future;
use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

struct PeerTask(JoinHandle<Vec<u32>>);

impl Drop for PeerTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("local H2 cancellation did not complete within five seconds")
}

fn frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(9 + payload.len());
    encoded.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    encoded.extend_from_slice(&[kind, flags]);
    encoded.extend_from_slice(&stream_id.to_be_bytes());
    encoded.extend_from_slice(payload);
    encoded
}

async fn read_frame(stream: &mut TcpStream) -> io::Result<Option<(u8, u8, u32, Vec<u8>)>> {
    let mut header = [0; 9];
    if stream.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut header[1..]).await?;
    let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    let stream_id = u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff;
    let mut payload = vec![0; len];
    stream.read_exact(&mut payload).await?;
    Ok(Some((header[3], header[4], stream_id, payload)))
}

async fn cancellation_session(streaming: bool, use_timeout: bool) -> usize {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let (sent_tx, sent_rx) = oneshot::channel();
    let (cancelled_tx, cancelled_rx) = oneshot::channel();
    let mut peer = PeerTask(tokio::spawn(async move {
        // Only this accepted socket can answer: a replacement connection cannot
        // make the post-cancellation request succeed.
        let (mut stream, _) = listener.accept().await.unwrap();
        drop(listener);
        let mut preface = [0; 24];
        stream.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        stream
            .write_all(&frame(4, 0, 0, &[0, 3, 0, 0, 0, 1]))
            .await
            .unwrap();
        let mut sent_tx = Some(sent_tx);
        let mut cancelled_tx = Some(cancelled_tx);
        let mut request_ids = Vec::new();
        let mut settings_acked = false;
        let mut cancelled = false;
        while let Some((kind, flags, stream_id, payload)) = read_frame(&mut stream).await.unwrap() {
            match kind {
                4 if flags & 1 == 0 => {
                    stream.write_all(&frame(4, 1, 0, &[])).await.unwrap();
                }
                4 => settings_acked = true,
                1 => {
                    request_ids.push(stream_id);
                    assert!(request_ids.len() <= 3, "unexpected replay or extra request");
                    if request_ids.len() == 2 {
                        assert!(
                            settings_acked,
                            "peer concurrency limit was not acknowledged"
                        );
                        sent_tx.take().unwrap().send(stream_id).unwrap();
                        continue;
                    }
                    if request_ids.len() == 3 {
                        assert!(cancelled, "new HEADERS preceded the old stream's CANCEL");
                    }
                    stream
                        .write_all(&frame(1, 4, stream_id, &[0x88]))
                        .await
                        .unwrap();
                    stream
                        .write_all(&frame(0, 1, stream_id, b"ok"))
                        .await
                        .unwrap();
                }
                3 => {
                    assert_eq!(request_ids.len(), 2);
                    assert_eq!(stream_id, request_ids[1]);
                    assert_eq!(payload, 8u32.to_be_bytes());
                    assert!(!cancelled, "duplicate cancellation");
                    cancelled = true;
                    cancelled_tx.take().unwrap().send(()).unwrap();
                }
                _ => {}
            }
        }
        assert!(cancelled);
        assert_eq!(request_ids.len(), 3);
        request_ids
    }));

    let session = lkrequest::Client::builder()
        .preset(lkrequest::preset::chrome_155())
        .build()
        .session()
        .http2_only()
        .max_connections(1)
        .build();
    let warm = bounded(session.get(&url).send()).await.unwrap();
    assert_eq!(warm.status().as_u16(), 200);
    assert_eq!(warm.bytes(), b"ok");
    drop(warm);
    assert_eq!(session.pool_stats().h2_connections, 1);

    let mut response = Box::pin(async {
        if streaming {
            session
                .get(&url)
                .send_streaming()
                .await
                .map(|response| response.status())
        } else {
            session
                .get(&url)
                .send()
                .await
                .map(|response| response.status())
        }
    });
    let abandoned_id = tokio::select! {
        sent = bounded(sent_rx) => sent.unwrap(),
        result = &mut response => panic!("request completed without a server response: {result:?}"),
    };
    assert_eq!(session.pool_stats().h2_connections, 1);
    if use_timeout {
        assert!(tokio::time::timeout(Duration::from_millis(1), response)
            .await
            .is_err());
    } else {
        drop(response);
    }
    bounded(cancelled_rx).await.unwrap();
    assert_eq!(session.pool_stats().h2_connections, 1);

    let next = bounded(session.get(&url).send()).await.unwrap();
    assert_eq!(next.status().as_u16(), 200);
    assert_eq!(next.bytes(), b"ok");
    drop(next);
    let reused_connections = session.pool_stats().h2_connections;
    drop(session);

    let ids = bounded(&mut peer.0).await.unwrap();
    assert_eq!(ids[1], abandoned_id);
    assert_eq!(ids[1], ids[0] + 2);
    assert_eq!(ids[2], ids[1] + 2);
    reused_connections
}

#[tokio::test]
async fn buffered_request_timeout_releases_h2_slot_and_session_socket() {
    assert_eq!(cancellation_session(false, true).await, 1);
}

#[tokio::test]
async fn streaming_request_future_drop_releases_h2_slot_and_session_socket() {
    assert_eq!(cancellation_session(true, false).await, 1);
}
