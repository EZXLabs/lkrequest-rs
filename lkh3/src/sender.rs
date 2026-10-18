use bytes::Bytes;
use http::{Request, Response};

use crate::connection::{H3Error, H3RecvStream, LiveSendRequest};
use crate::profile::H3Profile;

/// Cloneable HTTP/3 sender backed by `h3` + `h3-quinn`.
#[derive(Clone)]
pub struct H3Sender {
    profile: H3Profile,
    inner: LiveSendRequest,
}

/// Resolved control-stream priority, independent of automatic HTTP header
/// generation. Higher-level clients carry this in the request extensions.
#[derive(Debug, Clone)]
pub struct RequestPriorityUpdate(pub String);

struct UploadGuard {
    send: Option<h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>>,
    recv: Option<h3::client::RequestStream<h3_quinn::RecvStream, Bytes>>,
    cancel_response_before_upload: bool,
}

enum BufferedRequestState {
    Ready(Response<()>),
    Stopped { code: u64, final_received: bool },
}

impl Drop for UploadGuard {
    fn drop(&mut self) {
        if self.cancel_response_before_upload {
            if let Some(stream) = &mut self.recv {
                stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            }
        }
        if let Some(stream) = &mut self.send {
            stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        }
        if !self.cancel_response_before_upload {
            if let Some(stream) = &mut self.recv {
                stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
            }
        }
    }
}

async fn recv_final_response(
    recv: &mut h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
) -> Result<Response<()>, H3Error> {
    loop {
        let response = recv.recv_response().await?;
        if response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
            recv.stop_sending(h3::error::Code::H3_MESSAGE_ERROR);
            return Err(H3Error::InvalidResponse(
                "HTTP/3 does not support 101 Switching Protocols".into(),
            ));
        }
        if !response.status().is_informational() {
            return Ok(response);
        }
    }
}

async fn stopped_upload_error(
    recv: &mut h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    stop_code: u64,
    mut final_received: bool,
) -> H3Error {
    let source = loop {
        if final_received {
            break H3Error::from(recv.recv_terminal_error().await);
        }
        match recv.recv_response_or_terminal().await {
            Ok(response) if response.status() == http::StatusCode::SWITCHING_PROTOCOLS => {
                recv.stop_sending(h3::error::Code::H3_MESSAGE_ERROR);
                break H3Error::InvalidResponse(
                    "HTTP/3 does not support 101 Switching Protocols".into(),
                );
            }
            Ok(response) => final_received = !response.status().is_informational(),
            Err(error) => break H3Error::from(error),
        }
    };
    let error = H3Error::StoppedUpload {
        stop_code,
        source: Box::new(source),
    };
    if final_received {
        H3Error::AfterFinalResponse(Box::new(error))
    } else {
        error
    }
}

impl H3Sender {
    fn request_priority<T>(&self, request: &Request<T>) -> Option<Vec<u8>> {
        if !self.profile.request_priority_updates {
            return None;
        }
        request
            .extensions()
            .get::<RequestPriorityUpdate>()
            .map(|value| value.0.as_bytes().to_vec())
            .or_else(|| {
                request
                    .headers()
                    .get("priority")
                    .map(|value| value.as_bytes().to_vec())
            })
            .or_else(|| {
                self.profile
                    .priority_updates
                    .first()
                    .map(|(_, value)| value.as_bytes().to_vec())
            })
            .or_else(|| Some(b"u=3".to_vec()))
    }

    /// Send incremental DATA while concurrently receiving the response headers.
    ///
    /// The caller supplies consistent framing headers and validates source length.
    /// A final response can arrive before upload EOF; in that case the remaining
    /// source is dropped and the send direction is cancelled. The returned receive
    /// stream remains usable. Dropping this future cancels both stream directions.
    pub async fn send_streaming_request(
        &mut self,
        request: Request<()>,
        mut body: std::pin::Pin<
            Box<dyn futures_core::Stream<Item = std::io::Result<Bytes>> + Send>,
        >,
    ) -> Result<Response<H3RecvStream>, H3Error> {
        let priority = self.request_priority(&request);
        let stream = match priority {
            Some(value) => {
                self.inner
                    .send_request_with_priority(request, value)
                    .await?
            }
            None => self.inner.send_request(request).await?,
        };
        let cancel_response_before_upload =
            self.profile.cancel_response_before_upload && !stream.is_0rtt();
        let (send, recv) = stream.split();
        let mut guard = UploadGuard {
            send: Some(send),
            recv: Some(recv),
            cancel_response_before_upload,
        };
        let (response, uploaded) = {
            let send = guard.send.as_mut().unwrap();
            let recv = guard.recv.as_mut().unwrap();
            let upload = async {
                while let Some(chunk) = std::future::poll_fn(|cx| body.as_mut().poll_next(cx)).await
                {
                    let chunk = chunk.map_err(H3Error::Upload)?;
                    if !chunk.is_empty() {
                        send.send_data(chunk).await?;
                    }
                }
                send.finish().await.map_err(H3Error::from)
            };
            tokio::pin!(upload);
            // Preserve a partially decoded response when upload finishes first.
            let response = recv_final_response(recv);
            tokio::pin!(response);
            tokio::select! {
                biased;
                response = &mut response => (response?, false),
                result = &mut upload => {
                    result?;
                    (response.await?, true)
                }
            }
        };
        if uploaded {
            guard.send.take();
        }
        let (parts, _) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            H3RecvStream {
                inner: guard.recv.take().unwrap(),
            },
        ))
    }

    pub(crate) fn new(profile: H3Profile, inner: LiveSendRequest) -> Self {
        Self { profile, inner }
    }

    /// Returns the immutable fingerprint profile attached to this sender.
    pub fn profile(&self) -> &H3Profile {
        &self.profile
    }

    /// Indicates whether a concrete HTTP/3 backend is wired behind this sender.
    pub fn is_backend_wired(&self) -> bool {
        true
    }

    pub async fn send_request(
        &mut self,
        request: Request<Option<Bytes>>,
    ) -> Result<Response<H3RecvStream>, H3Error> {
        let method = request.method().clone();
        let uri = request.uri().clone();
        let body_len = request.body().as_ref().map_or(0, Bytes::len);
        tracing::debug!(
            method = %method,
            uri = %uri,
            body_len,
            pseudo_order = %self.profile.pseudo_header_order_token(),
            "h3.send_request_start"
        );
        let priority = self.request_priority(&request);
        let (parts, body) = request.into_parts();
        let request = Request::from_parts(parts, ());
        let stream = match priority {
            Some(value) => {
                self.inner
                    .send_request_with_priority(request, value)
                    .await?
            }
            None => self.inner.send_request(request).await?,
        };
        let cancel_response_before_upload =
            self.profile.cancel_response_before_upload && !stream.is_0rtt();
        let (send, recv) = stream.split();
        let mut guard = UploadGuard {
            send: Some(send),
            recv: Some(recv),
            cancel_response_before_upload,
        };

        let wait_after_stop = self.profile.wait_for_response_after_upload_stop && body_len != 0;
        let state = {
            let send_slot = &mut guard.send;
            let upload = async {
                let (result, was_pending) = {
                    let operation = async {
                        let send = send_slot.as_mut().unwrap();
                        if let Some(body) = body {
                            if !body.is_empty() {
                                tracing::trace!(method = %method, uri = %uri, bytes = body.len(), "h3.send_request_body");
                                send.send_data(body).await?;
                            }
                        }
                        send.finish().await.map_err(H3Error::from)
                    };
                    tokio::pin!(operation);
                    let mut was_pending = false;
                    let result = std::future::poll_fn(|cx| {
                        let result = std::future::Future::poll(operation.as_mut(), cx);
                        was_pending |= result.is_pending();
                        result
                    })
                    .await;
                    (result, was_pending)
                };
                let stopped = match &result {
                    Err(H3Error::Stream(h3::error::StreamError::RemoteTerminate {
                        code, ..
                    })) if wait_after_stop && was_pending => Some(code.value()),
                    _ => None,
                };
                if result.is_ok()
                    || matches!(
                        &result,
                        Err(H3Error::Stream(
                            h3::error::StreamError::RemoteTerminate { .. }
                        ))
                    )
                {
                    // Quinn's Drop echoes a peer STOP code; the cancellation guard must not replace it.
                    send_slot.take();
                }
                (result, stopped)
            };
            tokio::pin!(upload);
            let response = recv_final_response(guard.recv.as_mut().unwrap());
            tokio::pin!(response);
            tokio::select! {
                biased;
                response = &mut response => {
                    let response = response?;
                    let (result, stopped) = upload.await;
                    if let Some(code) = stopped {
                        BufferedRequestState::Stopped { code, final_received: true }
                    } else {
                        result.map_err(|error| H3Error::AfterFinalResponse(Box::new(error)))?;
                        BufferedRequestState::Ready(response)
                    }
                },
                (result, stopped) = &mut upload => {
                    if let Some(code) = stopped {
                        BufferedRequestState::Stopped { code, final_received: false }
                    } else {
                        result?;
                        BufferedRequestState::Ready(response.await?)
                    }
                }
            }
        };
        let response = match state {
            BufferedRequestState::Ready(response) => response,
            BufferedRequestState::Stopped {
                code,
                final_received,
            } => {
                return Err(stopped_upload_error(
                    guard.recv.as_mut().unwrap(),
                    code,
                    final_received,
                )
                .await);
            }
        };
        let (parts, _) = response.into_parts();
        tracing::debug!(
            method = %method,
            uri = %uri,
            status = parts.status.as_u16(),
            "h3.send_request_complete"
        );
        Ok(Response::from_parts(
            parts,
            H3RecvStream {
                inner: guard.recv.take().unwrap(),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Buf;
    use std::{
        io,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::sync::mpsc;

    struct ChannelUpload(mpsc::Receiver<io::Result<Bytes>>);

    impl futures_core::Stream for ChannelUpload {
        type Item = io::Result<Bytes>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.0.poll_recv(cx)
        }
    }

    struct Peer {
        client: quinn::Endpoint,
        server: quinn::Endpoint,
        driver: tokio::task::JoinHandle<Result<(), H3Error>>,
        server_task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Peer {
        fn drop(&mut self) {
            self.client.close(0u32.into(), b"test complete");
            self.server.close(0u32.into(), b"test complete");
            self.driver.abort();
            self.server_task.abort();
        }
    }

    async fn peer_with_response(
        early_response: bool,
    ) -> (H3Sender, Peer, mpsc::Receiver<Result<Bytes, String>>) {
        let (observed_tx, observed_rx) = mpsc::channel(8);
        let (sender, peer) = peer_with_handler(move |connection| async move {
            let mut h3 =
                h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                    .await
                    .unwrap();
            let resolver = h3.accept().await.unwrap().unwrap();
            let (_, mut stream) = resolver.resolve_request().await.unwrap();
            if early_response {
                stream
                    .send_response(Response::builder().status(413).body(()).unwrap())
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
                std::future::pending::<()>().await;
            }
            loop {
                match stream.recv_data().await {
                    Ok(Some(mut chunk)) => {
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        if observed_tx.send(Ok(bytes)).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        let _ = observed_tx.send(Err(error.to_string())).await;
                        return;
                    }
                }
            }
            stream
                .send_response(Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            stream.finish().await.unwrap();
            std::future::pending::<()>().await;
        })
        .await;
        (sender, peer, observed_rx)
    }

    async fn peer_with_handler<F, Fut>(handler: F) -> (H3Sender, Peer)
    where
        F: FnOnce(quinn::Connection) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        peer_with_profile_and_handler(crate::chrome_h3(), handler).await
    }

    async fn peer_with_profile_and_handler<F, Fut>(
        profile: H3Profile,
        handler: F,
    ) -> (H3Sender, Peer)
    where
        F: FnOnce(quinn::Connection) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key)
            .unwrap();
        server_tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_tls).unwrap(),
        ));
        let mut server_transport = quinn::TransportConfig::default();
        server_transport.stream_receive_window((64 * 1024u32).into());
        server_config.transport_config(Arc::new(server_transport));
        let server =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let mut client_tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let mut client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_tls).unwrap()));
        let mut client_transport = quinn::TransportConfig::default();
        client_transport.send_window(64 * 1024);
        client_config.transport_config(Arc::new(client_transport));
        client.set_default_client_config(client_config);
        let endpoint = server.clone();
        let server_task = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            handler(connection).await;
        });
        let connection = client
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap()
            .await
            .unwrap();
        let connection = crate::connection::connect_h3(connection, &profile)
            .await
            .unwrap();
        let (sender, driver) = connection.into_parts();
        (
            sender,
            Peer {
                client,
                server,
                driver,
                server_task,
            },
        )
    }

    async fn observed(
        receiver: &mut mpsc::Receiver<Result<Bytes, String>>,
    ) -> Result<Bytes, String> {
        tokio::time::timeout(Duration::from_secs(5), receiver.recv())
            .await
            .unwrap()
            .unwrap()
    }

    async fn peer() -> (H3Sender, Peer, mpsc::Receiver<Result<Bytes, String>>) {
        peer_with_response(false).await
    }

    #[tokio::test]
    async fn early_response_drops_pending_upload() {
        let (mut sender, _peer, _received) = peer_with_response(true).await;
        let (upload_tx, upload_rx) = mpsc::channel(1);
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            sender.send_streaming_request(request(), Box::pin(ChannelUpload(upload_rx))),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), 413);
        assert!(upload_tx.is_closed());
    }

    #[tokio::test]
    async fn early_response_interrupts_flow_control_blocked_upload() {
        let (mut sender, _peer, _received) = peer_with_response(true).await;
        let (upload_tx, upload_rx) = mpsc::channel(1);
        upload_tx
            .send(Ok(Bytes::from(vec![7; 8 * 1024 * 1024])))
            .await
            .unwrap();
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            sender.send_streaming_request(request(), Box::pin(ChannelUpload(upload_rx))),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), 413);
        assert!(upload_tx.is_closed());
    }

    fn request() -> Request<()> {
        Request::builder()
            .method("POST")
            .uri("https://localhost/upload")
            .body(())
            .unwrap()
    }

    #[tokio::test]
    async fn upload_delivers_chunks_before_source_finishes() {
        let (mut sender, _peer, mut received) = peer().await;
        let (upload_tx, upload_rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            sender
                .send_streaming_request(request(), Box::pin(ChannelUpload(upload_rx)))
                .await
        });
        upload_tx
            .send(Ok(Bytes::from_static(b"first")))
            .await
            .unwrap();
        assert_eq!(observed(&mut received).await.unwrap(), "first");
        upload_tx.send(Ok(Bytes::new())).await.unwrap();
        upload_tx
            .send(Ok(Bytes::from_static(b"second")))
            .await
            .unwrap();
        assert_eq!(observed(&mut received).await.unwrap(), "second");
        drop(upload_tx);
        let response = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn upload_source_error_cancels_request() {
        let (mut sender, _peer, mut received) = peer().await;
        let (upload_tx, upload_rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            sender
                .send_streaming_request(request(), Box::pin(ChannelUpload(upload_rx)))
                .await
        });
        upload_tx
            .send(Ok(Bytes::from_static(b"first")))
            .await
            .unwrap();
        assert_eq!(observed(&mut received).await.unwrap(), "first");
        upload_tx
            .send(Err(io::Error::other("source failed")))
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(result, Err(H3Error::Upload(error)) if error.to_string() == "source failed")
        );
        assert!(observed(&mut received).await.is_err());
    }

    #[tokio::test]
    async fn cancel_order_preserves_both_upload_cancellation_paths() {
        for response_first in [false, true] {
            for streamed in [false, true] {
                let mut profile = crate::profile::chrome_155_h3();
                profile.cancel_response_before_upload = response_first;
                let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
                let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
                let (mut sender, _peer) =
                    peer_with_profile_and_handler(profile, move |connection| async move {
                        let (send, mut recv) = connection.accept_bi().await.unwrap();
                        let mut prefix = vec![0u8; 32 * 1024];
                        recv.read_exact(&mut prefix).await.unwrap();
                        ready_tx.send(()).unwrap();
                        let (stop, reset) = tokio::join!(send.stopped(), recv.received_reset());
                        observed_tx.send((stop.unwrap(), reset.unwrap())).unwrap();
                        std::future::pending::<()>().await;
                    })
                    .await;
                let mut task = tokio::spawn(async move {
                    let body = Bytes::from(vec![7; 1024 * 1024]);
                    if streamed {
                        let (upload_tx, upload_rx) = mpsc::channel(1);
                        upload_tx.send(Ok(body)).await.unwrap();
                        sender
                            .send_streaming_request(request(), Box::pin(ChannelUpload(upload_rx)))
                            .await
                    } else {
                        sender
                            .send_request(
                                Request::builder()
                                    .method("POST")
                                    .uri("https://localhost/cancel-order")
                                    .body(Some(body))
                                    .unwrap(),
                            )
                            .await
                    }
                });
                tokio::time::timeout(Duration::from_secs(5), ready_rx)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(50), &mut task)
                        .await
                        .is_err(),
                    "upload must still be pending before cancellation"
                );
                task.abort();
                assert!(matches!(task.await, Err(error) if error.is_cancelled()));
                let (stop, reset) = tokio::time::timeout(Duration::from_secs(5), observed_rx)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    stop.map(u64::from),
                    Some(268),
                    "response direction: streamed={streamed}, response_first={response_first}"
                );
                assert_eq!(
                    reset.map(u64::from),
                    Some(268),
                    "upload direction: streamed={streamed}, response_first={response_first}"
                );
            }
        }
    }

    #[tokio::test]
    async fn dropping_upload_future_cancels_request() {
        let (mut sender, _peer, mut received) = peer().await;
        let (upload_tx, upload_rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            sender
                .send_streaming_request(request(), Box::pin(ChannelUpload(upload_rx)))
                .await
        });
        upload_tx
            .send(Ok(Bytes::from_static(b"first")))
            .await
            .unwrap();
        assert_eq!(observed(&mut received).await.unwrap(), "first");
        task.abort();
        assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        assert!(observed(&mut received).await.is_err());
    }

    #[tokio::test]
    async fn cancelling_buffered_upload_preserves_concurrent_response() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
        let (error_tx, error_rx) = tokio::sync::oneshot::channel();
        let (mut sender, _peer) = peer_with_handler(move |connection| async move {
            let mut h3 =
                h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                    .await
                    .unwrap();
            let resolver = h3.accept().await.unwrap().unwrap();
            let (_, mut upload) = resolver.resolve_request().await.unwrap();
            let mut received = upload.recv_data().await.unwrap().unwrap().remaining();
            started_tx.send(()).unwrap();

            let resolver = h3.accept().await.unwrap().unwrap();
            let (_, mut response) = resolver.resolve_request().await.unwrap();
            response
                .send_response(Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            response
                .send_data(Bytes::from_static(b"before"))
                .await
                .unwrap();
            resume_rx.await.unwrap();

            let error = loop {
                match upload.recv_data().await {
                    Ok(Some(chunk)) => received += chunk.remaining(),
                    Ok(None) => break None,
                    Err(error) => break Some(error),
                }
            };
            error_tx.send((received, error)).unwrap();
            if response
                .send_data(Bytes::from_static(b"after"))
                .await
                .is_ok()
            {
                let _ = response.finish().await;
            }
            std::future::pending::<()>().await;
        })
        .await;

        let mut upload_sender = sender.clone();
        let upload_task = tokio::spawn(async move {
            let request = Request::builder()
                .method("POST")
                .uri("https://localhost/upload")
                .body(Some(Bytes::from(vec![7; 8 * 1024 * 1024])))
                .unwrap();
            upload_sender.send_request(request).await
        });
        tokio::time::timeout(Duration::from_secs(5), started_rx)
            .await
            .unwrap()
            .unwrap();
        let mut response = tokio::time::timeout(
            Duration::from_secs(5),
            sender.send_request(
                Request::builder()
                    .uri("https://localhost/concurrent")
                    .body(None)
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.body_mut().data().await.unwrap().unwrap(), "before");
        assert!(
            !upload_task.is_finished(),
            "large upload must still be blocked"
        );
        upload_task.abort();
        assert!(matches!(upload_task.await, Err(error) if error.is_cancelled()));
        resume_tx.send(()).unwrap();

        let (received, error) = tokio::time::timeout(Duration::from_secs(5), error_rx)
            .await
            .unwrap()
            .unwrap();
        eprintln!("cancelled upload: received={received}, result={error:?}");
        assert!(received < 8 * 1024 * 1024, "upload must remain incomplete");
        assert!(
            matches!(
                error,
                Some(h3::error::StreamError::RemoteTerminate {
                    code: h3::error::Code::H3_REQUEST_CANCELLED,
                    ..
                })
            ),
            "buffered upload cancellation must reset only its stream: {error:?}"
        );
        let after = tokio::time::timeout(Duration::from_secs(5), response.body_mut().data())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(after, "after");
        assert!(response.body_mut().data().await.is_none());
    }

    #[tokio::test]
    async fn buffered_early_final_waits_for_upload_and_preserves_concurrent_response() {
        const UPLOAD_SIZE: usize = 8 * 1024 * 1024;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (respond_tx, respond_rx) = tokio::sync::oneshot::channel();
        let (final_tx, final_rx) = tokio::sync::oneshot::channel();
        let (drain_tx, drain_rx) = tokio::sync::oneshot::channel();
        let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
        let (mut sender, _peer) = peer_with_handler(move |connection| async move {
            let mut h3 =
                h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                    .await
                    .unwrap();
            let resolver = h3.accept().await.unwrap().unwrap();
            let (_, mut upload) = resolver.resolve_request().await.unwrap();
            let mut first = upload.recv_data().await.unwrap().unwrap();
            let first = first.copy_to_bytes(first.remaining());
            let mut received = first.len();
            let mut body_matches = first.iter().all(|byte| *byte == 7);
            started_tx.send(()).unwrap();

            let resolver = h3.accept().await.unwrap().unwrap();
            let (_, mut concurrent) = resolver.resolve_request().await.unwrap();
            concurrent
                .send_response(Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            concurrent
                .send_data(Bytes::from_static(b"before"))
                .await
                .unwrap();
            respond_rx.await.unwrap();
            upload
                .send_response(Response::builder().status(413).body(()).unwrap())
                .await
                .unwrap();
            upload
                .send_data(Bytes::from_static(b"rejected"))
                .await
                .unwrap();
            upload.finish().await.unwrap();
            final_tx.send(received).unwrap();

            // Model the captured peer: send a final response, pause, then resume draining.
            drain_rx.await.unwrap();
            let error = loop {
                match upload.recv_data().await {
                    Ok(Some(mut chunk)) => {
                        let bytes = chunk.copy_to_bytes(chunk.remaining());
                        received += bytes.len();
                        body_matches &= bytes.iter().all(|byte| *byte == 7);
                    }
                    Ok(None) => break None,
                    Err(error) => break Some(error),
                }
            };
            observed_tx.send((received, body_matches, error)).unwrap();
            concurrent
                .send_data(Bytes::from_static(b"after"))
                .await
                .unwrap();
            concurrent.finish().await.unwrap();
            std::future::pending::<()>().await;
        })
        .await;
        let mut upload_sender = sender.clone();
        let mut upload_task = tokio::spawn(async move {
            upload_sender
                .send_request(
                    Request::builder()
                        .method("POST")
                        .uri("https://localhost/upload")
                        .header("content-length", UPLOAD_SIZE)
                        .body(Some(Bytes::from(vec![7; UPLOAD_SIZE])))
                        .unwrap(),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), started_rx)
            .await
            .unwrap()
            .unwrap();
        let mut concurrent = tokio::time::timeout(
            Duration::from_secs(5),
            sender.send_request(
                Request::builder()
                    .uri("https://localhost/concurrent")
                    .body(None)
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            concurrent.body_mut().data().await.unwrap().unwrap(),
            "before"
        );
        respond_tx.send(()).unwrap();
        let before_final = tokio::time::timeout(Duration::from_secs(5), final_rx)
            .await
            .unwrap()
            .unwrap();
        let final_seen = std::time::Instant::now();
        let premature = tokio::time::timeout(Duration::from_millis(400), &mut upload_task).await;
        eprintln!(
            "buffered early final full upload: status=413, requested={UPLOAD_SIZE}, peer_read_before_final={before_final}, premature_delivery={}, wait_ms={}",
            premature.is_ok(),
            final_seen.elapsed().as_millis()
        );
        assert!(
            premature.is_err(),
            "a final response alone must not stop the buffered upload while peer reads are paused"
        );
        drain_tx.send(()).unwrap();
        let mut response =
            match tokio::time::timeout(Duration::from_secs(5), &mut upload_task).await {
                Ok(result) => result.unwrap().unwrap(),
                Err(_) => {
                    upload_task.abort();
                    let _ = upload_task.await;
                    panic!("buffered upload did not finish after peer reads resumed");
                }
            };
        assert_eq!(response.status(), 413);
        assert_eq!(
            response.body_mut().data().await.unwrap().unwrap(),
            "rejected"
        );
        assert!(response.body_mut().data().await.is_none());
        let (received, body_matches, error) =
            tokio::time::timeout(Duration::from_secs(5), observed_rx)
                .await
                .unwrap()
                .unwrap();
        eprintln!(
            "buffered early final full upload: status=413, peer_read_total={received}, result={error:?}, delivery_ms={}",
            final_seen.elapsed().as_millis()
        );
        assert_eq!(received, UPLOAD_SIZE);
        assert!(body_matches);
        assert!(
            error.is_none(),
            "the complete upload must end with FIN: {error:?}"
        );
        let after = tokio::time::timeout(Duration::from_secs(5), concurrent.body_mut().data())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(after, "after");
        assert!(concurrent.body_mut().data().await.is_none());
    }

    #[tokio::test]
    async fn buffered_complete_upload_preserves_request_wire() {
        let body = Bytes::from(
            (0..256 * 1024 + 31)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>(),
        );
        let (wire_tx, wire_rx) = tokio::sync::oneshot::channel();
        let (mut sender, _peer) = peer_with_handler(move |connection| async move {
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let wire = recv.read_to_end(512 * 1024).await.unwrap();
            wire_tx.send(wire).unwrap();
            // Stateless QPACK :status=200, then a four-byte DATA frame.
            send.write_all(b"\x01\x03\x00\x00\xd9\x00\x04done")
                .await
                .unwrap();
            send.finish().unwrap();
            std::future::pending::<()>().await;
        })
        .await;
        let mut response = tokio::time::timeout(
            Duration::from_secs(5),
            sender.send_request(
                Request::builder()
                    .method("POST")
                    .uri("https://localhost/upload")
                    .header("content-length", body.len())
                    .body(Some(body.clone()))
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.body_mut().data().await.unwrap().unwrap(), "done");
        assert!(response.body_mut().data().await.is_none());

        let wire = wire_rx.await.unwrap();
        let mut frames = wire.as_slice();
        assert_eq!(read_frame_varint(&mut frames), 1, "HEADERS must lead");
        let headers_len = read_frame_varint(&mut frames) as usize;
        let headers = frames.copy_to_bytes(headers_len);
        assert_eq!(&headers[..2], &[0, 0], "request QPACK remains stateless");
        assert_eq!(read_frame_varint(&mut frames), 0, "one DATA frame follows");
        assert_eq!(read_frame_varint(&mut frames), body.len() as u64);
        assert_eq!(
            frames,
            body.as_ref(),
            "complete DATA content and no extra frames"
        );
        eprintln!(
            "buffered complete upload wire: total={}, headers={headers:02x?}, data={}, trailing=0",
            wire.len(),
            body.len()
        );
    }

    #[tokio::test]
    async fn buffered_stop_wait_preserves_final_response_and_reset_provenance() {
        for final_before_stop in [true, false] {
            for stop_code in [0u64, 256, 268] {
                let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
                let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
                let (stopped_tx, stopped_rx) = tokio::sync::oneshot::channel();
                let (final_tx, final_rx) = tokio::sync::oneshot::channel();
                let (final_ready_tx, final_ready_rx) = tokio::sync::oneshot::channel();
                let (reset_tx, reset_rx) = tokio::sync::oneshot::channel();
                let (mut sender, _peer) = peer_with_profile_and_handler(
                    crate::profile::chrome_155_h3(),
                    move |connection| async move {
                        let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                        recv.read_exact(&mut vec![0u8; 32 * 1024]).await.unwrap();
                        let response = b"\x01\x03\x00\x00\xd9\x00\x04body";
                        if final_before_stop {
                            send.write_all(response).await.unwrap();
                        }
                        ready_tx.send(()).unwrap();
                        stop_rx.await.unwrap();
                        recv.stop(stop_code.try_into().unwrap()).unwrap();
                        stopped_tx.send(()).unwrap();
                        final_rx.await.unwrap();
                        if !final_before_stop {
                            send.write_all(response).await.unwrap();
                        }
                        final_ready_tx.send(()).unwrap();
                        tokio::select! {
                            reset = reset_rx => reset.unwrap(),
                            stopped = send.stopped() => panic!("response cancelled before peer reset: {stopped:?}"),
                        }
                        // A refusal code on the response must not erase the earlier upload STOP.
                        send.reset(267u32.into()).unwrap();
                        std::future::pending::<()>().await;
                    },
                ).await;
                let mut task = tokio::spawn(async move {
                    sender
                        .send_request(
                            Request::builder()
                                .method("POST")
                                .uri("https://localhost/stopped-upload")
                                .body(Some(Bytes::from(vec![7; 1024 * 1024])))
                                .unwrap(),
                        )
                        .await
                });
                tokio::time::timeout(Duration::from_secs(5), ready_rx)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(tokio::time::timeout(Duration::from_millis(50), &mut task)
                    .await
                    .is_err());
                stop_tx.send(()).unwrap();
                tokio::time::timeout(Duration::from_secs(5), stopped_rx)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(50), &mut task)
                        .await
                        .is_err(),
                    "STOP must retain the response direction"
                );
                final_tx.send(()).unwrap();
                tokio::time::timeout(Duration::from_secs(5), final_ready_rx)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_millis(50), &mut task)
                        .await
                        .is_err(),
                    "final headers and body alone must not complete the stopped upload"
                );
                reset_tx.send(()).unwrap();
                let error = tokio::time::timeout(Duration::from_secs(5), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .err()
                    .expect("peer reset");
                let H3Error::AfterFinalResponse(source) = error else {
                    panic!("final headers lost after STOP {stop_code}: {error:?}");
                };
                let H3Error::StoppedUpload {
                    stop_code: actual,
                    source,
                } = *source
                else {
                    panic!("upload STOP provenance lost");
                };
                assert_eq!(actual, stop_code);
                assert!(matches!(
                    *source,
                    H3Error::Stream(h3::error::StreamError::RemoteTerminate {
                        code: h3::error::Code::H3_REQUEST_REJECTED,
                        ..
                    })
                ));
            }
        }
    }

    #[tokio::test]
    async fn buffered_stop_wait_without_headers_preserves_upload_provenance() {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (reset_tx, reset_rx) = tokio::sync::oneshot::channel();
        let (mut sender, _peer) = peer_with_profile_and_handler(
            crate::profile::chrome_155_h3(),
            move |connection| async move {
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                recv.read_exact(&mut vec![0u8; 32 * 1024]).await.unwrap();
                recv.stop(256u32.into()).unwrap();
                ready_tx.send(()).unwrap();
                tokio::select! {
                    reset = reset_rx => reset.unwrap(),
                    stopped = send.stopped() => panic!("response cancelled before peer reset: {stopped:?}"),
                }
                send.reset(267u32.into()).unwrap();
                std::future::pending::<()>().await;
            },
        ).await;
        let mut task = tokio::spawn(async move {
            sender
                .send_request(
                    Request::builder()
                        .method("POST")
                        .uri("https://localhost/stopped-without-headers")
                        .body(Some(Bytes::from(vec![7; 1024 * 1024])))
                        .unwrap(),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), ready_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(100), &mut task)
            .await
            .is_err());
        reset_tx.send(()).unwrap();
        let error = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .err()
            .expect("peer reset");
        let H3Error::StoppedUpload { stop_code, source } = error else {
            panic!("missing STOP provenance or fabricated final response: {error:?}");
        };
        assert_eq!(stop_code, 256);
        assert!(matches!(
            *source,
            H3Error::Stream(h3::error::StreamError::RemoteTerminate {
                code: h3::error::Code::H3_REQUEST_REJECTED,
                ..
            })
        ));
    }

    #[tokio::test]
    async fn buffered_stop_wait_policy_keeps_streamed_upload_contract() {
        let (mut sender, _peer) = peer_with_profile_and_handler(
            crate::profile::chrome_155_h3(),
            move |connection| async move {
                let (mut send, _recv) = connection.accept_bi().await.unwrap();
                send.write_all(b"\x01\x03\x00\x00\xd9").await.unwrap();
                send.finish().unwrap();
                std::future::pending::<()>().await;
            },
        )
        .await;
        let (upload_tx, upload_rx) = mpsc::channel(1);
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            sender.send_streaming_request(request(), Box::pin(ChannelUpload(upload_rx))),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), 200);
        assert!(upload_tx.is_closed());
    }

    #[tokio::test]
    async fn buffered_peer_stop_preserves_upload_error_and_connection() {
        for stop_code in [0_u64, 256, 268] {
            let (mut sender, _peer) = peer_with_handler(move |connection| async move {
                let mut h3 =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                        .await
                        .unwrap();
                let resolver = h3.accept().await.unwrap().unwrap();
                let (_, mut upload) = resolver.resolve_request().await.unwrap();
                assert!(upload.recv_data().await.unwrap().is_some());
                upload.stop_sending(h3::error::Code::from(stop_code));
                upload
                    .send_response(Response::builder().status(413).body(()).unwrap())
                    .await
                    .unwrap();
                upload
                    .send_data(Bytes::from_static(b"rejected"))
                    .await
                    .unwrap();
                upload.finish().await.unwrap();

                // Do not read the stopped receive direction; keep the connection available.
                let resolver = h3.accept().await.unwrap().unwrap();
                let (_, mut next) = resolver.resolve_request().await.unwrap();
                next.send_response(Response::builder().status(200).body(()).unwrap())
                    .await
                    .unwrap();
                next.send_data(Bytes::from_static(b"healthy"))
                    .await
                    .unwrap();
                next.finish().await.unwrap();
                std::future::pending::<()>().await;
            })
            .await;
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                sender.send_request(
                    Request::builder()
                        .method("POST")
                        .uri("https://localhost/stopped-upload")
                        .body(Some(Bytes::from(vec![7; 8 * 1024 * 1024])))
                        .unwrap(),
                ),
            )
            .await
            .unwrap();
            let error = match result {
                Err(error) => error,
                Ok(response) => panic!(
                    "STOP {stop_code} was hidden by status {}",
                    response.status()
                ),
            };
            eprintln!("buffered peer STOP {stop_code}: {error:?}");
            let source = match &error {
                H3Error::AfterFinalResponse(source) => source.as_ref(),
                error => error,
            };
            assert!(
                matches!(
                    source,
                    H3Error::Stream(h3::error::StreamError::RemoteTerminate { code, .. })
                        if code.value() == stop_code
                ),
                "{error}"
            );
            let mut response = tokio::time::timeout(
                Duration::from_secs(5),
                sender.send_request(
                    Request::builder()
                        .uri("https://localhost/after-stop")
                        .body(None)
                        .unwrap(),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(
                response.body_mut().data().await.unwrap().unwrap(),
                "healthy"
            );
            assert!(response.body_mut().data().await.is_none());
        }
    }

    #[tokio::test]
    async fn buffered_rejection_preserves_final_response_provenance() {
        for after_final in [true, false] {
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
            let (sender, _peer) = peer_with_handler(move |connection| async move {
                let mut h3 =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                        .await
                        .unwrap();
                let resolver = h3.accept().await.unwrap().unwrap();
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                assert!(stream.recv_data().await.unwrap().is_some());
                if after_final {
                    stream
                        .send_response(Response::builder().status(413).body(()).unwrap())
                        .await
                        .unwrap();
                    stream.finish().await.unwrap();
                }
                ready_tx.send(()).unwrap();
                stop_rx.await.unwrap();
                stream.stop_sending(h3::error::Code::H3_REQUEST_REJECTED);
                std::future::pending::<()>().await;
            })
            .await;
            let mut request_sender = sender.clone();
            let mut task = tokio::spawn(async move {
                request_sender
                    .send_request(
                        Request::builder()
                            .method("POST")
                            .uri("https://localhost/rejected-upload")
                            .body(Some(Bytes::from(vec![7; 8 * 1024 * 1024])))
                            .unwrap(),
                    )
                    .await
            });
            tokio::time::timeout(Duration::from_secs(5), ready_rx)
                .await
                .unwrap()
                .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut task)
                    .await
                    .is_err(),
                "upload must remain pending before the delayed STOP"
            );
            stop_tx.send(()).unwrap();
            let error = match tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .unwrap()
                .unwrap()
            {
                Err(error) => error,
                Ok(response) => panic!("STOP 267 was hidden by status {}", response.status()),
            };
            eprintln!("buffered STOP 267: after_final={after_final}, error={error:?}");
            let source = if after_final {
                match &error {
                    H3Error::AfterFinalResponse(source) => source.as_ref(),
                    _ => panic!("cached final-response provenance was lost: {error:?}"),
                }
            } else {
                assert!(matches!(&error, H3Error::Stream(_)));
                &error
            };
            assert!(matches!(
                source,
                H3Error::Stream(h3::error::StreamError::RemoteTerminate {
                    code: h3::error::Code::H3_REQUEST_REJECTED,
                    ..
                })
            ));
        }
    }

    fn read_frame_varint(bytes: &mut &[u8]) -> u64 {
        let first = bytes.get_u8();
        let width = 1 << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for _ in 1..width {
            value = (value << 8) | u64::from(bytes.get_u8());
        }
        value
    }

    #[tokio::test]
    async fn informational_response_does_not_finish_buffered_request() {
        let (mut sender, _peer) = peer_with_handler(|connection| async move {
            let mut h3 =
                h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                    .await
                    .unwrap();
            let resolver = h3.accept().await.unwrap().unwrap();
            let (_, mut stream) = resolver.resolve_request().await.unwrap();
            stream
                .send_response(Response::builder().status(103).body(()).unwrap())
                .await
                .unwrap();
            stream
                .send_response(Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            stream
                .send_data(Bytes::from_static(b"final"))
                .await
                .unwrap();
            stream.finish().await.unwrap();
            std::future::pending::<()>().await;
        })
        .await;
        let mut response = tokio::time::timeout(
            Duration::from_secs(5),
            sender.send_request(
                Request::builder()
                    .uri("https://localhost/hints")
                    .body(None)
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.body_mut().data().await.unwrap().unwrap(), "final");
        assert!(response.body_mut().data().await.is_none());
    }

    #[tokio::test]
    async fn informational_response_does_not_cancel_streaming_upload() {
        let (informational_tx, informational_rx) = tokio::sync::oneshot::channel();
        let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
        let (sender, _peer) = peer_with_handler(move |connection| async move {
            let mut h3 =
                h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                    .await
                    .unwrap();
            let resolver = h3.accept().await.unwrap().unwrap();
            let (_, mut stream) = resolver.resolve_request().await.unwrap();
            for status in [100, 103] {
                stream
                    .send_response(Response::builder().status(status).body(()).unwrap())
                    .await
                    .unwrap();
            }
            informational_tx.send(()).unwrap();
            let mut body = Vec::new();
            loop {
                match stream.recv_data().await {
                    Ok(Some(mut chunk)) => {
                        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                    }
                    Ok(None) => break,
                    Err(_) => return,
                }
            }
            observed_tx.send(body).unwrap();
            stream
                .send_response(Response::builder().status(200).body(()).unwrap())
                .await
                .unwrap();
            stream
                .send_data(Bytes::from_static(b"final"))
                .await
                .unwrap();
            stream.finish().await.unwrap();
            std::future::pending::<()>().await;
        })
        .await;
        let (upload_tx, upload_rx) = mpsc::channel(1);
        let mut upload_sender = sender.clone();
        let task = tokio::spawn(async move {
            upload_sender
                .send_streaming_request(request(), Box::pin(ChannelUpload(upload_rx)))
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), informational_rx)
            .await
            .unwrap()
            .unwrap();
        let sent = upload_tx
            .send(Ok(Bytes::from_static(b"after-continue")))
            .await;
        drop(upload_tx);
        let mut response = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), 200);
        assert!(
            sent.is_ok(),
            "informational headers must keep the upload source alive"
        );
        assert_eq!(observed_rx.await.unwrap(), b"after-continue");
        assert_eq!(response.body_mut().data().await.unwrap().unwrap(), "final");
        assert!(response.body_mut().data().await.is_none());
    }

    async fn switching_protocols_response(streaming: bool) -> Result<http::StatusCode, H3Error> {
        let (mut sender, _peer) = peer_with_handler(|connection| async move {
            let mut h3 =
                h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                    .await
                    .unwrap();
            let resolver = h3.accept().await.unwrap().unwrap();
            let (_, mut stream) = resolver.resolve_request().await.unwrap();
            stream
                .send_response(Response::builder().status(101).body(()).unwrap())
                .await
                .unwrap();
            std::future::pending::<()>().await;
        })
        .await;
        let (upload_tx, upload_rx) = mpsc::channel(1);
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            if streaming {
                sender
                    .send_streaming_request(request(), Box::pin(ChannelUpload(upload_rx)))
                    .await
            } else {
                sender
                    .send_request(
                        Request::builder()
                            .uri("https://localhost/upgrade")
                            .body(None)
                            .unwrap(),
                    )
                    .await
            }
        })
        .await
        .expect("unsupported status 101 must not wait for another response");
        assert!(upload_tx.is_closed());
        result.map(|response| response.status())
    }

    #[tokio::test]
    async fn buffered_request_rejects_switching_protocols() {
        let error = switching_protocols_response(false)
            .await
            .expect_err("HTTP/3 must reject status 101");
        assert!(
            matches!(error, H3Error::InvalidResponse(ref message) if message.contains("101")),
            "{error}"
        );
    }

    #[tokio::test]
    async fn streaming_request_rejects_switching_protocols() {
        let error = switching_protocols_response(true)
            .await
            .expect_err("HTTP/3 must reject status 101");
        assert!(
            matches!(error, H3Error::InvalidResponse(ref message) if message.contains("101")),
            "{error}"
        );
    }

    #[tokio::test]
    async fn trailer_completion_waits_for_fin_or_reset_after_data_eof() {
        for reset in [false, true] {
            let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
            let (mut sender, _peer) = peer_with_handler(move |connection| async move {
                let mut h3 =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                        .await
                        .unwrap();
                let resolver = h3.accept().await.unwrap().unwrap();
                let (_, mut stream) = resolver.resolve_request().await.unwrap();
                stream
                    .send_response(Response::builder().status(200).body(()).unwrap())
                    .await
                    .unwrap();
                stream.send_data(Bytes::from_static(b"body")).await.unwrap();
                let mut trailers = http::HeaderMap::new();
                trailers.insert("x-trailer", "valid".parse().unwrap());
                stream.send_trailers(trailers).await.unwrap();
                finish_rx.await.unwrap();
                if reset {
                    stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                } else {
                    stream.finish().await.unwrap();
                }
                std::future::pending::<()>().await;
            })
            .await;
            let mut response = tokio::time::timeout(
                Duration::from_secs(5),
                sender.send_request(
                    Request::builder()
                        .uri("https://localhost/trailers")
                        .body(None)
                        .unwrap(),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(response.body_mut().data().await.unwrap().unwrap(), "body");
            assert!(
                tokio::time::timeout(Duration::from_secs(5), response.body_mut().data())
                    .await
                    .unwrap()
                    .is_none(),
                "the data API ends at trailers HEADERS before QUIC FIN"
            );
            let completion = response.body_mut().trailers();
            tokio::pin!(completion);
            let pending = std::future::poll_fn(|cx| {
                Poll::Ready(std::future::Future::poll(completion.as_mut(), cx).is_pending())
            })
            .await;
            assert!(pending, "trailers must wait while peer FIN remains gated");
            eprintln!("trailer completion: data=None, completion=Pending, reset={reset}");
            finish_tx.send(()).unwrap();
            let result = tokio::time::timeout(Duration::from_secs(5), completion)
                .await
                .unwrap();
            eprintln!("trailer completion after peer release: {result:?}");
            if reset {
                assert!(matches!(
                    result,
                    Err(H3Error::Stream(h3::error::StreamError::RemoteTerminate {
                        code: h3::error::Code::H3_INTERNAL_ERROR,
                        ..
                    }))
                ));
            } else {
                assert_eq!(result.unwrap().unwrap()["x-trailer"], "valid");
            }
        }
    }

    async fn response_with_trailer_bytes(
        trailer_bytes: &'static [u8],
    ) -> (H3Sender, Peer, Response<H3RecvStream>) {
        let (mut sender, peer) = peer_with_handler(move |connection| async move {
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            recv.read_to_end(64 * 1024).await.unwrap();
            // Stateless QPACK :status=200 and DATA("body"), followed by the test suffix.
            send.write_all(b"\x01\x03\x00\x00\xd9\x00\x04body")
                .await
                .unwrap();
            send.write_all(trailer_bytes).await.unwrap();
            send.finish().unwrap();
            std::future::pending::<()>().await;
        })
        .await;
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            sender.send_request(
                Request::builder()
                    .uri("https://localhost/trailers")
                    .body(None)
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        (sender, peer, response)
    }

    #[tokio::test]
    async fn trailer_completion_invalid_qpack_is_checked_after_data_eof() {
        let (_sender, _peer, mut response) =
            response_with_trailer_bytes(b"\x01\x03\x00\x00\xff").await;
        assert_eq!(response.body_mut().data().await.unwrap().unwrap(), "body");
        assert!(response.body_mut().data().await.is_none());
        let error = response.body_mut().trailers().await.unwrap_err();
        eprintln!("trailer completion invalid QPACK: data=None, trailers={error:?}");
        assert!(
            error.to_string().contains("QPACK_DECOMPRESSION_FAILED"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn trailer_completion_truncated_headers_fail_during_data() {
        let (_sender, _peer, mut response) = response_with_trailer_bytes(b"\x01\x03\x00").await;
        assert_eq!(response.body_mut().data().await.unwrap().unwrap(), "body");
        let error = response
            .body_mut()
            .data()
            .await
            .expect("incomplete trailer HEADERS must not be data EOF")
            .expect_err("incomplete trailer HEADERS must fail");
        eprintln!("trailer completion truncated HEADERS: data={error:?}");
        assert!(error.to_string().contains("H3_FRAME_ERROR"), "{error}");
    }

    #[tokio::test]
    async fn trailer_completion_truncated_frame_after_trailers_is_rejected() {
        // Empty stateless trailers, then an unknown frame whose five-byte payload is truncated.
        let (_sender, _peer, mut response) =
            response_with_trailer_bytes(b"\x01\x02\x00\x00\x21\x05x").await;
        assert_eq!(response.body_mut().data().await.unwrap().unwrap(), "body");
        assert!(response.body_mut().data().await.is_none());
        let error = response.body_mut().trailers().await.unwrap_err();
        eprintln!("trailer completion truncated trailing frame: data=None, trailers={error:?}");
        assert!(error.to_string().contains("H3_FRAME_ERROR"), "{error}");
    }

    #[tokio::test]
    async fn trailer_completion_delayed_data_fin_completes_without_panic() {
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let (mut sender, _peer) = peer_with_handler(move |connection| async move {
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            recv.read_to_end(64 * 1024).await.unwrap();
            // Declare five DATA bytes, deliver three, and wait until those bytes are consumed.
            send.write_all(b"\x01\x03\x00\x00\xd9\x00\x05abc")
                .await
                .unwrap();
            finish_rx.await.unwrap();
            send.finish().unwrap();
            std::future::pending::<()>().await;
        })
        .await;
        let mut response = tokio::time::timeout(
            Duration::from_secs(5),
            sender.send_request(
                Request::builder()
                    .uri("https://localhost/truncated-data")
                    .body(None)
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.body_mut().data().await.unwrap().unwrap(), "abc");
        finish_tx.send(()).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(5), response.body_mut().data())
                .await
                .unwrap()
                .is_none(),
            "preserve the delayed-FIN data EOF behavior"
        );
        eprintln!("trailer completion delayed DATA FIN: received=3, declared=5, data=None; requesting completion");
        let completion =
            tokio::time::timeout(Duration::from_secs(5), response.body_mut().trailers())
                .await
                .unwrap();
        eprintln!("trailer completion delayed DATA FIN result: {completion:?}");
        assert!(completion.unwrap().is_none());
    }

    fn response_payload_profiles() -> [(&'static str, H3Profile); 3] {
        let mut chrome_155 = crate::profile::chrome_155_h3();
        // This matrix isolates payload EOF compatibility; incomplete frame headers
        // retain immediate errors here, with their wait policy tested separately.
        chrome_155.wait_for_incomplete_response_frame_headers = false;
        let mut disabled = chrome_155.clone();
        disabled.accept_truncated_response_payloads = false;
        [
            ("chrome_154", crate::profile::chrome_154_h3()),
            ("chrome_155", chrome_155),
            ("chrome_155_disabled", disabled),
        ]
    }

    async fn read_profiled_raw_response(
        profile: H3Profile,
        wire: &'static [u8],
        fin_after_body: Option<usize>,
    ) -> Result<Bytes, H3Error> {
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let (sender, _peer) =
            peer_with_profile_and_handler(profile, move |connection| async move {
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                recv.read_to_end(64 * 1024).await.unwrap();
                send.write_all(wire).await.unwrap();
                if fin_after_body.is_some() {
                    finish_rx.await.unwrap();
                }
                send.finish().unwrap();
                std::future::pending::<()>().await;
            })
            .await;
        let mut request_sender = sender.clone();
        let mut finish_tx = Some(finish_tx);
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut response = request_sender
                .send_request(
                    Request::builder()
                        .uri("https://localhost/framing")
                        .body(None)
                        .unwrap(),
                )
                .await?;
            assert_eq!(response.status(), 200);
            let mut body = Vec::new();
            while let Some(chunk) = response.body_mut().data().await {
                body.extend_from_slice(&chunk?);
                if fin_after_body.is_some_and(|size| body.len() >= size) {
                    if let Some(finish_tx) = finish_tx.take() {
                        finish_tx.send(()).unwrap();
                    }
                }
            }
            response.body_mut().trailers().await?;
            Ok(Bytes::from(body))
        })
        .await
        .expect("bounded response framing fixture")
    }

    #[tokio::test]
    async fn response_payload_policy_accepts_only_opted_in_payload_eof() {
        // Name, raw response, body, legacy acceptance, and optional delayed-FIN gate.
        type PayloadEofCase = (
            &'static str,
            &'static [u8],
            &'static [u8],
            bool,
            Option<usize>,
        );
        const CASES: &[PayloadEofCase] = &[
            (
                "complete_data",
                b"\x01\x03\x00\x00\xd9\x00\x03abc",
                b"abc",
                true,
                None,
            ),
            (
                "inline_data",
                b"\x01\x03\x00\x00\xd9\x00\x05abc",
                b"abc",
                false,
                None,
            ),
            (
                "delayed_data",
                b"\x01\x03\x00\x00\xd9\x00\x05abc",
                b"abc",
                true,
                Some(3),
            ),
            (
                "empty_data_payload",
                b"\x01\x03\x00\x00\xd9\x00\x05",
                b"",
                true,
                None,
            ),
            (
                "partial_trailer",
                b"\x01\x03\x00\x00\xd9\x00\x03abc\x01\x05\x00",
                b"abc",
                false,
                None,
            ),
            (
                "empty_trailer_payload",
                b"\x01\x03\x00\x00\xd9\x00\x03abc\x01\x05",
                b"abc",
                false,
                None,
            ),
            (
                "partial_unknown",
                b"\x01\x03\x00\x00\xd9\x00\x03abc\x21\x05x",
                b"abc",
                false,
                None,
            ),
            (
                "empty_unknown_payload",
                b"\x01\x03\x00\x00\xd9\x00\x03abc\x21\x05",
                b"abc",
                false,
                None,
            ),
            (
                "multibyte_unknown_header",
                b"\x01\x03\x00\x00\xd9\x00\x03abc\x40\x21\x40\x05x",
                b"abc",
                false,
                None,
            ),
        ];
        for (profile_name, profile) in response_payload_profiles() {
            for &(name, wire, body, legacy_accepts, fin_after_body) in CASES {
                let result =
                    read_profiled_raw_response(profile.clone(), wire, fin_after_body).await;
                eprintln!("response payload policy: profile={profile_name}, case={name}, result={result:?}");
                if profile.accept_truncated_response_payloads || legacy_accepts {
                    assert_eq!(result.unwrap(), body, "{profile_name}: {name}");
                } else {
                    let error = result.unwrap_err();
                    assert!(
                        error.to_string().contains("H3_FRAME_ERROR"),
                        "{profile_name}: {name}: {error}"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn response_payload_policy_preserves_header_and_sequence_errors() {
        // Name, raw response, legacy code, and opted-in code.
        const CASES: &[(&str, &[u8], &str, &str)] = &[
            (
                "partial_length",
                b"\x01\x03\x00\x00\xd9\x00\x40",
                "H3_FRAME_ERROR",
                "H3_FRAME_ERROR",
            ),
            (
                "partial_type",
                b"\x01\x03\x00\x00\xd9\x40",
                "H3_FRAME_ERROR",
                "H3_FRAME_ERROR",
            ),
            (
                "initial_partial_headers",
                b"\x01\x05\x00",
                "H3_FRAME_ERROR",
                "H3_FRAME_UNEXPECTED",
            ),
            (
                "partial_settings",
                b"\x01\x03\x00\x00\xd9\x00\x03abc\x04\x05x",
                "H3_FRAME_ERROR",
                "H3_FRAME_UNEXPECTED",
            ),
            (
                "partial_h2_ping",
                b"\x01\x03\x00\x00\xd9\x00\x03abc\x06\x05x",
                "H3_FRAME_ERROR",
                "H3_FRAME_UNEXPECTED",
            ),
            (
                "complete_bad_qpack",
                b"\x01\x03\x00\x00\xd9\x00\x03abc\x01\x03\x00\x00\xff",
                "QPACK_DECOMPRESSION_FAILED",
                "QPACK_DECOMPRESSION_FAILED",
            ),
            (
                "data_after_trailers",
                b"\x01\x03\x00\x00\xd9\x00\x03abc\x01\x02\x00\x00\x00\x01x",
                "H3_FRAME_UNEXPECTED",
                "H3_FRAME_UNEXPECTED",
            ),
            (
                "partial_data_after_trailers",
                b"\x01\x03\x00\x00\xd9\x00\x03abc\x01\x02\x00\x00\x00\x05x",
                "H3_FRAME_UNEXPECTED",
                "H3_FRAME_UNEXPECTED",
            ),
            (
                "second_partial_headers",
                b"\x01\x03\x00\x00\xd9\x00\x03abc\x01\x02\x00\x00\x01\x05\x00",
                "H3_FRAME_ERROR",
                "H3_FRAME_UNEXPECTED",
            ),
        ];
        for (profile_name, profile) in response_payload_profiles() {
            for &(name, wire, legacy_code, opted_in_code) in CASES {
                let error = read_profiled_raw_response(profile.clone(), wire, None)
                    .await
                    .unwrap_err();
                let expected = if profile.accept_truncated_response_payloads {
                    opted_in_code
                } else {
                    legacy_code
                };
                eprintln!("response payload policy error: profile={profile_name}, case={name}, error={error:?}");
                assert!(
                    error.to_string().contains(expected),
                    "{profile_name}: {name}: {error}"
                );
            }
        }
    }
}
