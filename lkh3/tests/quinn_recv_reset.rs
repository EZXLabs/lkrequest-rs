use std::{
    future::{poll_fn, Future},
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use bytes::Bytes;
use h3::quic::{
    BidiStream, ConnectionErrorIncoming, OpenStreams, RecvStream, RecvStreamReset, SendStream,
    SendStreamUnframed, StreamErrorIncoming,
};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

struct PeerPair {
    client_endpoint: quinn::Endpoint,
    server_endpoint: quinn::Endpoint,
    client: quinn::Connection,
    server: quinn::Connection,
}

impl PeerPair {
    async fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
        let private_key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
            certificate.signing_key.serialize_der(),
        ));
        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate_der.clone()], private_key)
            .unwrap();
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_tls).unwrap(),
        ));
        let server_endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate_der).unwrap();
        let mut client_tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls).unwrap()));
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);

        let connecting = client_endpoint
            .connect(server_endpoint.local_addr().unwrap(), "localhost")
            .unwrap();
        let (client, server) = tokio::join!(connecting, async {
            server_endpoint.accept().await.unwrap().await
        });
        Self {
            client_endpoint,
            server_endpoint,
            client: client.unwrap(),
            server: server.unwrap(),
        }
    }

    async fn adapter_bidi(&self) -> (h3_quinn::BidiStream<Bytes>, quinn::SendStream) {
        let mut connection = h3_quinn::Connection::new(self.client.clone());
        let mut stream = poll_fn(|cx| {
            <h3_quinn::Connection as OpenStreams<Bytes>>::poll_open_bidi(&mut connection, cx)
        })
        .await
        .unwrap();
        let mut request = Bytes::from_static(b"request");
        while !request.is_empty() {
            poll_fn(|cx| stream.poll_send(cx, &mut request))
                .await
                .unwrap();
        }
        poll_fn(|cx| stream.poll_finish(cx)).await.unwrap();
        let (server_send, mut server_recv) = self.server.accept_bi().await.unwrap();
        assert_eq!(server_recv.read_to_end(64).await.unwrap(), b"request");
        (stream, server_send)
    }
}

impl Drop for PeerPair {
    fn drop(&mut self) {
        self.client_endpoint.close(0u32.into(), b"test complete");
        self.server_endpoint.close(0u32.into(), b"test complete");
    }
}

#[derive(Default)]
struct TaskWake {
    count: AtomicUsize,
    notified: tokio::sync::Notify,
}

impl Wake for TaskWake {
    fn wake(self: Arc<Self>) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.notified.notify_one();
    }
}

impl TaskWake {
    async fn wait(&self) {
        while self.count.load(Ordering::SeqCst) == 0 {
            self.notified.notified().await;
        }
    }
}

#[tokio::test]
async fn quinn_reset_observer_cancel_after_fin_then_read_eof_releases_waker() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let pair = PeerPair::new().await;
        let (mut request, mut response) = pair.client.open_bi().await.unwrap();
        request.write_all(b"request").await.unwrap();
        request.finish().unwrap();
        let (mut server_send, mut server_recv) = pair.server.accept_bi().await.unwrap();
        assert_eq!(server_recv.read_to_end(64).await.unwrap(), b"request");
        server_send.write_all(b"response payload").await.unwrap();
        server_send.finish().unwrap();
        assert_eq!(server_send.stopped().await.unwrap(), None);

        // FIN has been acknowledged, but the application has not consumed it.
        let task = Arc::new(TaskWake::default());
        let waker = Waker::from(task.clone());
        {
            let mut observer = std::pin::pin!(response.received_reset());
            assert!(observer
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending());
        }
        drop(waker);
        let references_after_cancel = Arc::strong_count(&task);
        let mut payload = Vec::new();
        while let Some(chunk) = response.read_chunk(usize::MAX, true).await.unwrap() {
            payload.extend_from_slice(&chunk.bytes);
        }
        let references_after_eof = Arc::strong_count(&task);
        // Capture a destructor assertion without causing a second unwind.
        let dropped = catch_unwind(AssertUnwindSafe(|| drop(response)));
        eprintln!(
            "ACKed FIN reset observer: refs_after_cancel={references_after_cancel}, \
             refs_after_eof={references_after_eof}, recv_drop_ok={}",
            dropped.is_ok()
        );
        assert_eq!(payload, b"response payload");
        assert!(
            dropped.is_ok(),
            "reading EOF after a cancelled reset observer must permit normal stream destruction"
        );
        assert_eq!(
            references_after_eof, 1,
            "EOF must release the cancelled reset observer's task reference"
        );
    })
    .await
    .expect("local Quinn reset observer regression timed out");
}

#[tokio::test]
async fn quinn_reset_adapter_preserves_payload_and_fin_across_observer_cancellation() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let pair = PeerPair::new().await;
        let (mut response, mut server_send) = pair.adapter_bidi().await;
        let task = Arc::new(TaskWake::default());
        let waker = Waker::from(task.clone());
        assert!(response
            .poll_received_reset(&mut Context::from_waker(&waker))
            .is_pending());
        server_send
            .write_all(b"complete normal body")
            .await
            .unwrap();
        server_send.finish().unwrap();
        assert_eq!(server_send.stopped().await.unwrap(), None);
        task.wait().await;
        assert!(response
            .poll_received_reset(&mut Context::from_waker(&waker))
            .is_pending());
        drop(waker);

        let (_send, mut receive) = response.split();
        let mut payload = Vec::new();
        while let Some(chunk) = poll_fn(|cx| receive.poll_data(cx)).await.unwrap() {
            payload.extend_from_slice(&chunk);
        }
        assert_eq!(payload, b"complete normal body");
        assert_eq!(Arc::strong_count(&task), 1);
        assert_eq!(
            poll_fn(|cx| receive.poll_received_reset(cx)).await.unwrap(),
            None
        );
        pair.server.close(0x155u32.into(), b"close after EOF");
        pair.client.closed().await;
        assert_eq!(
            poll_fn(|cx| receive.poll_received_reset(cx)).await.unwrap(),
            None,
            "an EOF-complete observer cannot replace connection-close notification"
        );
    })
    .await
    .expect("adapter payload/FIN control timed out");
}

#[tokio::test]
async fn quinn_reset_adapter_repeats_real_reset_after_split_and_normal_read() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let pair = PeerPair::new().await;
        let (mut response, mut server_send) = pair.adapter_bidi().await;
        let task = Arc::new(TaskWake::default());
        let waker = Waker::from(task.clone());
        assert!(response
            .poll_received_reset(&mut Context::from_waker(&waker))
            .is_pending());
        server_send.reset(0x10eu32.into()).unwrap();
        task.wait().await;
        assert_eq!(
            poll_fn(|cx| response.poll_received_reset(cx))
                .await
                .unwrap(),
            Some(0x10e)
        );
        let (_send, mut receive) = response.split();
        for _ in 0..2 {
            assert_eq!(
                poll_fn(|cx| receive.poll_received_reset(cx)).await.unwrap(),
                Some(0x10e)
            );
            assert!(matches!(
                poll_fn(|cx| receive.poll_data(cx)).await,
                Err(StreamErrorIncoming::StreamTerminated { error_code: 0x10e })
            ));
        }
    })
    .await
    .expect("adapter reset control timed out");
}

#[tokio::test]
async fn quinn_reset_adapter_connection_close_wakes_without_reading_payload() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let pair = PeerPair::new().await;
        let (response, _server_send) = pair.adapter_bidi().await;
        let (_send, mut receive) = response.split();
        let task = Arc::new(TaskWake::default());
        let waker = Waker::from(task.clone());
        assert!(receive
            .poll_received_reset(&mut Context::from_waker(&waker))
            .is_pending());
        pair.server
            .close(0x155u32.into(), b"terminal observer control");
        task.wait().await;
        assert!(matches!(
            poll_fn(|cx| receive.poll_received_reset(cx)).await,
            Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: ConnectionErrorIncoming::ApplicationClose { error_code: 0x155 }
            })
        ));
    })
    .await
    .expect("adapter connection-close control timed out");
}

#[tokio::test]
async fn quinn_reset_adapter_pending_waker_is_replaced_and_stop_releases_it() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let pair = PeerPair::new().await;
        let (mut response, _server_send) = pair.adapter_bidi().await;
        let first = Arc::new(TaskWake::default());
        let first_waker = Waker::from(first.clone());
        assert!(response
            .poll_received_reset(&mut Context::from_waker(&first_waker))
            .is_pending());
        drop(first_waker);
        assert_eq!(Arc::strong_count(&first), 2);
        let second = Arc::new(TaskWake::default());
        let second_waker = Waker::from(second.clone());
        assert!(response
            .poll_received_reset(&mut Context::from_waker(&second_waker))
            .is_pending());
        drop(second_waker);
        assert_eq!(Arc::strong_count(&first), 1);
        assert_eq!(Arc::strong_count(&second), 2);
        response.stop_sending(0x10c);
        assert_eq!(Arc::strong_count(&second), 1);
        assert!(matches!(
            response.poll_received_reset(&mut Context::from_waker(&Waker::from(first))),
            Poll::Ready(Ok(None))
        ));
    })
    .await
    .expect("adapter cancelled-waker control timed out");
}
