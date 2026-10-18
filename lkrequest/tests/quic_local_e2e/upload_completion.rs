use super::*;
use bytes::Buf;
use std::time::Duration;

const UPLOAD_SIZE: usize = 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Action {
    Complete,
    Cancel,
    Deadline,
    RejectedAfterFinal,
}

struct Peer {
    endpoint: Endpoint,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"test complete");
        self.task.abort();
    }
}

async fn check_early_final(streaming: bool, action: Action) -> usize {
    ensure_rustls_provider();
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate = cert.cert.der().to_vec();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
    let mut transport = quinn::TransportConfig::default();
    transport
        .stream_receive_window(65_536u32.into())
        .receive_window(262_144u32.into());
    config.transport_config(Arc::new(transport));
    let endpoint = Endpoint::server(config, localhost_addr(0)).unwrap();
    let port = endpoint.local_addr().unwrap().port();
    let (ready_tx, ready_rx) = oneshot::channel();
    let (drain_tx, drain_rx) = oneshot::channel();
    let (observed_tx, observed_rx) = oneshot::channel();
    let task = tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let mut h3 = server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(
                connection.clone(),
            ))
            .await
            .unwrap();
            let resolver = h3.accept().await.unwrap().unwrap();
            let (mut request, mut stream) = resolver.resolve_request().await.unwrap();
            if action == Action::RejectedAfterFinal {
                assert_eq!(request.method(), "GET");
                stream.send_response(http::Response::new(())).await.unwrap();
                stream
                    .send_data(bytes::Bytes::from_static(b"warm"))
                    .await
                    .unwrap();
                stream.finish().await.unwrap();
                (request, stream) = h3
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
            }
            assert_eq!(request.method(), "POST");
            let mut received = stream.recv_data().await.unwrap().unwrap().remaining();
            stream
                .send_response(http::Response::builder().status(413).body(()).unwrap())
                .await
                .unwrap();
            stream
                .send_data(bytes::Bytes::from_static(b"rejected"))
                .await
                .unwrap();
            stream.finish().await.unwrap();
            ready_tx.send(()).unwrap();
            if drain_rx.await.is_err() {
                return;
            }
            if action == Action::RejectedAfterFinal {
                let resets_before = connection.stats().frame_rx.reset_stream;
                stream.stop_sending(h3::error::Code::H3_REQUEST_REJECTED);
                tokio::time::timeout(Duration::from_secs(2), async {
                    while connection.stats().frame_rx.reset_stream == resets_before {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .expect("peer STOP must reach the upload before connection close");
                connection.close(258u32.into(), b"stopped upload terminal control");
                let mut replacement = None;
                let duplicate = tokio::time::timeout(Duration::from_millis(500), async {
                    let connection = endpoint.accept().await.unwrap().await.unwrap();
                    replacement = Some(
                        server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(
                            connection,
                        ))
                        .await
                        .unwrap(),
                    );
                    replacement.as_mut().unwrap().accept().await.unwrap()
                })
                .await
                .ok()
                .flatten();
                let repeated = duplicate.is_some();
                if let Some(resolver) = duplicate {
                    let (request, mut duplicate) = resolver.resolve_request().await.unwrap();
                    eprintln!(
                        "unsafe duplicate after final response: {} {}",
                        request.method(),
                        request.uri().path()
                    );
                    while duplicate.recv_data().await.unwrap().is_some() {}
                    duplicate
                        .send_response(http::Response::new(()))
                        .await
                        .unwrap();
                    duplicate
                        .send_data(bytes::Bytes::from_static(b"duplicate"))
                        .await
                        .unwrap();
                    duplicate.finish().await.unwrap();
                }
                observed_tx
                    .send((
                        received,
                        Some(h3::error::Code::H3_REQUEST_REJECTED),
                        repeated,
                    ))
                    .unwrap();
                std::future::pending::<()>().await;
                drop(replacement);
                return;
            }
            let reset = loop {
                match stream.recv_data().await {
                    Ok(Some(chunk)) => received += chunk.remaining(),
                    Ok(None) => break None,
                    Err(h3::error::StreamError::RemoteTerminate { code, .. }) => break Some(code),
                    Err(error) => panic!("unexpected upload error: {error}"),
                }
            };
            observed_tx.send((received, reset, false)).unwrap();
            std::future::pending::<()>().await;
        }
    });
    let _peer = Peer { endpoint, task };
    let session = lkrequest::Client::builder()
        .preset(lkrequest::preset::chrome_155())
        .add_ca_cert_der(&certificate)
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .build()
        .session()
        .http3_only()
        .build();
    if action == Action::RejectedAfterFinal {
        let warm = session
            .get(&format!("https://localhost:{port}/warm"))
            .send()
            .await
            .unwrap();
        assert_eq!(warm.bytes(), b"warm");
    }
    let request = session
        .post(&format!("https://localhost:{port}/upload"))
        .body(vec![b'x'; UPLOAD_SIZE])
        .timeout(if action == Action::Deadline {
            Duration::from_millis(350)
        } else {
            Duration::from_secs(5)
        });
    let mut result = tokio::spawn(async move {
        let (status, body) = if streaming {
            let response = request.send_streaming().await?;
            (response.status(), response.bytes().await?.to_vec())
        } else {
            let response = request.send().await?;
            (response.status(), response.bytes().to_vec())
        };
        Ok::<_, lkrequest::error::Error>((status, body))
    });
    tokio::select! {
        ready = ready_rx => ready.unwrap(),
        response = &mut result => panic!("request finished before gated upload: {response:?}"),
    }
    match action {
        Action::Complete => {
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut result)
                    .await
                    .is_err(),
                "413 must not finish a buffered upload before peer drain, streaming={streaming}"
            );
            drain_tx.send(()).unwrap();
            let (status, body) = tokio::time::timeout(Duration::from_secs(5), result)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(status, 413);
            assert_eq!(body, b"rejected".as_slice());
        }
        Action::Cancel => {
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut result)
                    .await
                    .is_err(),
                "the upload must remain cancellable after early response headers"
            );
            result.abort();
            assert!(result.await.unwrap_err().is_cancelled());
            drain_tx.send(()).unwrap();
        }
        Action::Deadline => {
            let error = tokio::time::timeout(Duration::from_secs(2), result)
                .await
                .unwrap()
                .unwrap()
                .expect_err("upload deadline");
            assert!(error.is_timeout(), "{error}");
            drain_tx.send(()).unwrap();
        }
        Action::RejectedAfterFinal => {
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut result)
                    .await
                    .is_err()
            );
            drain_tx.send(()).unwrap();
            let error = tokio::time::timeout(Duration::from_secs(5), result)
                .await
                .unwrap()
                .unwrap()
                .expect_err("POST cannot be replayed after final response headers");
            assert!(!error.is_safe_to_replay(), "{error}");
        }
    }
    let (received, reset, repeated) = tokio::time::timeout(Duration::from_secs(5), observed_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(!repeated, "unsafe POST must be observed only once");
    if action == Action::Complete {
        assert_eq!(received, UPLOAD_SIZE);
        assert!(reset.is_none());
    } else if action == Action::RejectedAfterFinal {
        assert_eq!(reset, Some(h3::error::Code::H3_REQUEST_REJECTED));
    } else {
        assert!((1..UPLOAD_SIZE).contains(&received));
        assert_eq!(reset, Some(h3::error::Code::H3_REQUEST_CANCELLED));
    }
    received
}

#[tokio::test]
async fn buffered_h3_early_final_waits_for_complete_upload() {
    for streaming in [false, true] {
        assert_eq!(
            check_early_final(streaming, Action::Complete).await,
            UPLOAD_SIZE
        );
    }
}

#[tokio::test]
async fn buffered_h3_early_final_remains_cancellable() {
    for streaming in [false, true] {
        assert!(check_early_final(streaming, Action::Cancel).await < UPLOAD_SIZE);
    }
}

#[tokio::test]
async fn buffered_h3_early_final_preserves_request_deadline() {
    for streaming in [false, true] {
        assert!(check_early_final(streaming, Action::Deadline).await < UPLOAD_SIZE);
    }
}

#[tokio::test]
async fn buffered_h3_early_final_prevents_rejected_upload_replay() {
    for streaming in [false, true] {
        assert!(check_early_final(streaming, Action::RejectedAfterFinal).await < UPLOAD_SIZE);
    }
}
