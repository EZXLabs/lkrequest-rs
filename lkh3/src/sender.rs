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

struct UploadGuard {
    send: Option<h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>>,
    recv: Option<h3::client::RequestStream<h3_quinn::RecvStream, Bytes>>,
}

impl Drop for UploadGuard {
    fn drop(&mut self) {
        if let Some(stream) = &mut self.send {
            stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        }
        if let Some(stream) = &mut self.recv {
            stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        }
    }
}

impl H3Sender {
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
        let (send, recv) = self.inner.send_request(request).await?.split();
        let mut guard = UploadGuard {
            send: Some(send),
            recv: Some(recv),
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
            tokio::select! {
                biased;
                response = recv.recv_response() => (response?, false),
                result = &mut upload => {
                    result?;
                    (recv.recv_response().await?, true)
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
        let (parts, body) = request.into_parts();
        let request = Request::from_parts(parts, ());
        let mut stream = self.inner.send_request(request).await?;

        if let Some(body) = body {
            if !body.is_empty() {
                tracing::trace!(method = %method, uri = %uri, bytes = body.len(), "h3.send_request_body");
                stream.send_data(body).await?;
            }
        }
        stream.finish().await?;

        let response = stream.recv_response().await?;
        let (parts, _) = response.into_parts();
        tracing::debug!(
            method = %method,
            uri = %uri,
            status = parts.status.as_u16(),
            "h3.send_request_complete"
        );
        let (_, stream) = stream.split();
        Ok(Response::from_parts(parts, H3RecvStream { inner: stream }))
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
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_tls).unwrap(),
        ));
        let server =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let mut client_tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_tls).unwrap(),
        )));
        let endpoint = server.clone();
        let (observed_tx, observed_rx) = mpsc::channel(8);
        let server_task = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
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
        });
        let connection = client
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap()
            .await
            .unwrap();
        let connection = crate::connection::connect_h3(connection, &crate::chrome_h3())
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
            observed_rx,
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
}
