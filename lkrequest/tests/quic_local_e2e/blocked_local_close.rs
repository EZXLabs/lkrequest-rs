//! Native H3-triggered close control, not installed-browser wire evidence.

use std::{
    future::Future,
    io::{self, IoSliceMut},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::{Buf, Bytes};
use quinn::{AsyncUdpSocket, Runtime, UdpPoller};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Default)]
struct GateState {
    armed: bool,
    blocked: bool,
    held: Option<Vec<u8>>,
    successful: Vec<Vec<u8>>,
    waiters: Vec<Waker>,
}

#[derive(Debug)]
struct GateSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    state: Mutex<GateState>,
}

impl GateSocket {
    fn bind() -> Arc<Self> {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        Arc::new(Self {
            inner: quinn::TokioRuntime.wrap_udp_socket(socket).unwrap(),
            state: Mutex::new(GateState::default()),
        })
    }

    fn release(&self) {
        let waiters = {
            let mut state = self.state.lock().unwrap();
            state.armed = false;
            state.blocked = false;
            std::mem::take(&mut state.waiters)
        };
        for waker in waiters {
            waker.wake();
        }
    }
}

#[derive(Debug)]
struct GatePoller {
    socket: Arc<GateSocket>,
    inner: Pin<Box<dyn UdpPoller>>,
}

impl UdpPoller for GatePoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut state = this.socket.state.lock().unwrap();
        if state.blocked {
            if !state
                .waiters
                .iter()
                .any(|waker| waker.will_wake(cx.waker()))
            {
                state.waiters.push(cx.waker().clone());
            }
            return Poll::Pending;
        }
        drop(state);
        this.inner.as_mut().poll_writable(cx)
    }
}

impl AsyncUdpSocket for GateSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(GatePoller {
            inner: self.inner.clone().create_io_poller(),
            socket: self,
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        // Select application-sized short packets, not a delayed warmup ACK.
        if state.armed
            && (state.blocked
                || (transmit.contents.len() >= 1000
                    && transmit
                        .contents
                        .first()
                        .is_some_and(|byte| byte & 0x80 == 0)))
        {
            state.blocked = true;
            state.held.get_or_insert_with(|| transmit.contents.to_vec());
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.inner.try_send(transmit)?;
        state.successful.push(transmit.contents.to_vec());
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

struct Upload(mpsc::Receiver<io::Result<Bytes>>);

impl futures_core::Stream for Upload {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(3), future)
        .await
        .expect("native blocked-close prerequisite did not complete")
}

fn endpoints(
    chrome: bool,
    disable_policy: bool,
) -> (quinn::Endpoint, quinn::Endpoint, Arc<GateSocket>) {
    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    super::ensure_rustls_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.send_tls13_tickets = 0;
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap())),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()));
    let mut transport = quinn::TransportConfig::default();
    transport
        .mtu_discovery_config(None)
        .enable_segmentation_offload(false);
    if chrome {
        let packetization = lkh3::chrome_155_quic().packetization;
        transport
            .stop_before_matching_reset(packetization.stop_before_matching_reset)
            .ack_obligation_only(packetization.ack_obligation_only)
            .reset_finished_on_stop(packetization.reset_finished_on_stop)
            .pto_single_probe_with_gap(packetization.pto_single_probe_with_gap)
            .chrome_pto_timing(packetization.chrome_pto_timing)
            .chrome_loss_timing(packetization.chrome_loss_timing)
            .chrome_rtt_quantization(packetization.chrome_rtt_quantization)
            .queue_pto_while_blocked(packetization.queue_pto_while_blocked)
            .discard_blocked_close(packetization.discard_blocked_close && !disable_policy);
    }
    config.transport_config(Arc::new(transport));
    let socket = GateSocket::bind();
    let mut client = lkquic::QuinnBackend::tokio()
        .create_endpoint_with_socket(socket.clone(), if chrome { 0 } else { 8 }, None, true, None)
        .unwrap();
    client.set_default_client_config(config);
    (client, server, socket)
}

#[derive(Debug)]
struct Observation {
    peer_application_close: Option<u64>,
    successful_sends_after_release: usize,
    old_ciphertext_resent: bool,
}

async fn duplicate_control_while_blocked(chrome: bool, disable_policy: bool) -> Observation {
    let (client_endpoint, server_endpoint, socket) = endpoints(chrome, disable_policy);
    let (connecting, accepting) = tokio::join!(
        client_endpoint
            .connect(server_endpoint.local_addr().unwrap(), "localhost")
            .unwrap(),
        async { server_endpoint.accept().await.unwrap().await }
    );
    let client = connecting.unwrap();
    let server = accepting.unwrap();
    bounded(async {
        while client.stats().frame_rx.handshake_done == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let (prefix_tx, prefix_rx) = oneshot::channel();
    let (duplicate_tx, duplicate_rx) = oneshot::channel();
    let (duplicate_written_tx, duplicate_written_rx) = oneshot::channel();
    let (peer_finish_tx, peer_finish_rx) = oneshot::channel();
    let peer_conn = server.clone();
    let peer = tokio::spawn(async move {
        let mut h3 =
            h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(peer_conn.clone()))
                .await
                .unwrap();
        let (_, mut warm) = h3
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        warm.send_response(http::Response::new(())).await.unwrap();
        warm.send_data(Bytes::from_static(b"ready")).await.unwrap();
        warm.finish().await.unwrap();
        let (_, mut request) = h3
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        let mut prefix = request.recv_data().await.unwrap().unwrap();
        assert_eq!(
            prefix.copy_to_bytes(prefix.remaining()),
            Bytes::from_static(b"positive-prefix")
        );
        prefix_tx.send(()).unwrap();
        duplicate_rx.await.unwrap();
        let mut duplicate = peer_conn.open_uni().await.unwrap();
        duplicate.write_all(b"\x00\x04\x00").await.unwrap();
        duplicate_written_tx.send(()).unwrap();
        let reason = peer_conn.closed().await;
        // Keep H3's Drop from replacing the peer error during the observation.
        let _ = peer_finish_rx.await;
        reason
    });
    let h3 = lkh3::connect_h3(client.clone(), &lkh3::chrome_155_h3())
        .await
        .unwrap();
    let (mut sender, driver) = h3.into_parts();
    let mut warm = bounded(
        sender.send_request(
            http::Request::builder()
                .uri("https://localhost/warm")
                .body(None)
                .unwrap(),
        ),
    )
    .await
    .unwrap();
    assert_eq!(warm.status(), http::StatusCode::OK);
    let mut body = Vec::new();
    while let Some(chunk) = bounded(warm.body_mut().data()).await {
        body.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(body, b"ready");
    drop(warm);
    let (upload_tx, upload_rx) = mpsc::channel(2);
    let upload = tokio::spawn(async move {
        sender
            .send_streaming_request(
                http::Request::builder()
                    .method("POST")
                    .uri("https://localhost/case")
                    .body(())
                    .unwrap(),
                Box::pin(Upload(upload_rx)),
            )
            .await
    });
    upload_tx
        .send(Ok(Bytes::from_static(b"positive-prefix")))
        .await
        .unwrap();
    bounded(prefix_rx).await.unwrap();
    socket.state.lock().unwrap().armed = true;
    upload_tx
        .send(Ok(Bytes::from(vec![7; 4096])))
        .await
        .unwrap();
    bounded(async {
        while !socket.state.lock().unwrap().blocked {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let held = socket.state.lock().unwrap().held.clone().unwrap();
    assert!(held.len() >= 1000 && held[0] & 0x80 == 0);
    duplicate_tx.send(()).unwrap();
    bounded(duplicate_written_rx).await.unwrap();
    let error = bounded(driver).await.unwrap().unwrap_err();
    assert!(
        matches!(
            error,
            lkh3::H3Error::Connection(h3::error::ConnectionError::Local {
                error: h3::error::LocalError::Application {
                    code: h3::error::Code::H3_STREAM_CREATION_ERROR,
                    ..
                },
                ..
            })
        ),
        "duplicate control must drive real local H3 close: {error}"
    );
    assert!(matches!(
        client.close_reason(),
        Some(quinn::ConnectionError::LocallyClosed)
    ));
    assert!(
        server.close_reason().is_none(),
        "peer cannot see a close while writer is held"
    );
    let successful_before_release = socket.state.lock().unwrap().successful.len();
    socket.release();
    let peer_reason = tokio::time::timeout(Duration::from_millis(200), server.closed()).await;
    let peer_application_close = match peer_reason {
        Ok(quinn::ConnectionError::ApplicationClosed(close)) => Some(close.error_code.into_inner()),
        Ok(other) => panic!("unexpected peer transport outcome: {other:?}"),
        Err(_) => None,
    };
    let result = {
        let state = socket.state.lock().unwrap();
        Observation {
            peer_application_close,
            successful_sends_after_release: state.successful.len() - successful_before_release,
            old_ciphertext_resent: state.successful.iter().any(|sent| sent == &held),
        }
    };
    drop(upload_tx);
    assert!(bounded(upload).await.unwrap().is_err());
    let _ = peer_finish_tx.send(());
    client_endpoint.close(0u32.into(), b"test cleanup");
    server_endpoint.close(0u32.into(), b"test cleanup");
    bounded(peer).await.unwrap();
    eprintln!(
        "native duplicate control chrome={chrome} disable_policy={disable_policy}: {result:?}"
    );
    result
}

#[tokio::test]
async fn blocked_local_close_legacy_retains_fresh_close_delivery() {
    let result = duplicate_control_while_blocked(false, false).await;
    assert_eq!(result.peer_application_close, Some(259));
    assert!(result.successful_sends_after_release > 0);
    assert!(!result.old_ciphertext_resent);
}

#[tokio::test]
async fn blocked_local_close_chrome_discards_fresh_close_after_h3_error() {
    let result = duplicate_control_while_blocked(true, false).await;
    assert_eq!(
        result.peer_application_close, None,
        "Chrome's closed socket must not resume a fresh CONNECTION_CLOSE"
    );
    assert_eq!(result.successful_sends_after_release, 0);
    assert!(!result.old_ciphertext_resent);
}

#[tokio::test]
async fn blocked_local_close_same_chrome_options_policy_off_retain_close_delivery() {
    let result = duplicate_control_while_blocked(true, true).await;
    assert_eq!(result.peer_application_close, Some(259));
    assert!(result.successful_sends_after_release > 0);
    assert!(!result.old_ciphertext_resent);
}
