use super::*;
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
enum Completion {
    PeerClose,
    PeerReset,
    Cancel,
    Deadline,
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

async fn stopped_upload(
    streaming: bool,
    completion: Completion,
) -> Option<lkrequest::error::Error> {
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
    let (finish_tx, finish_rx) = oneshot::channel();
    let (observed_tx, mut observed_rx) = oneshot::channel();
    let task = tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let mut critical = Vec::new();
            for bytes in [&b"\x00\x04\x00"[..], &b"\x02"[..], &b"\x03"[..]] {
                let mut stream = connection.open_uni().await.unwrap();
                stream.write_all(bytes).await.unwrap();
                critical.push(stream);
            }
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            // More than request headers arrive, while the 1 MiB upload exceeds the receive window.
            let mut prefix = vec![0; 32 * 1024];
            recv.read_exact(&mut prefix).await.unwrap();
            if !matches!(completion, Completion::PeerReset) {
                send.write_all(b"\x01\x03\x00\x00\xd9\x00\x04body")
                    .await
                    .unwrap();
            }
            if matches!(completion, Completion::PeerClose) {
                send.finish().unwrap();
                assert!(
                    send.stopped().await.unwrap().is_none(),
                    "response FIN acknowledged"
                );
            }
            recv.stop(256u32.into()).unwrap();
            ready_tx.send(()).unwrap();
            match completion {
                Completion::PeerClose => {
                    finish_rx.await.unwrap();
                    connection.close(258u32.into(), b"stopped upload peer close");
                    observed_tx.send(None).unwrap();
                }
                Completion::PeerReset => {
                    finish_rx.await.unwrap();
                    send.reset(267u32.into()).unwrap();
                    observed_tx.send(None).unwrap();
                }
                Completion::Cancel | Completion::Deadline => {
                    let stopped = send.stopped().await.unwrap();
                    observed_tx.send(stopped.map(u64::from)).unwrap();
                }
            }
            std::future::pending::<()>().await;
            drop(critical);
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
    let request = session
        .post(&format!("https://localhost:{port}/stopped"))
        .body(vec![b'x'; 1024 * 1024])
        .timeout(if matches!(completion, Completion::Deadline) {
            Duration::from_secs(1)
        } else {
            Duration::from_secs(5)
        });
    let mut result = tokio::spawn(async move {
        if streaming {
            request.send_streaming().await.map(|_| ())
        } else {
            request.send().await.map(|_| ())
        }
    });
    tokio::select! {
        ready = ready_rx => ready.unwrap(),
        result = &mut result => panic!("completed before STOP readiness: {result:?}"),
    }
    assert!(tokio::time::timeout(Duration::from_millis(100), &mut result).await.is_err(),
        "STOP must retain the response until peer termination or caller cancellation: {completion:?}, streaming={streaming}");
    assert!(
        matches!(
            observed_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ),
        "response must not be cancelled before the caller or peer ends the wait"
    );
    let error = match completion {
        Completion::PeerClose | Completion::PeerReset => {
            finish_tx.send(()).unwrap();
            Some(
                result
                    .await
                    .unwrap()
                    .expect_err("real peer connection close"),
            )
        }
        Completion::Cancel => {
            result.abort();
            assert!(result.await.unwrap_err().is_cancelled());
            None
        }
        Completion::Deadline => Some(result.await.unwrap().expect_err("request deadline")),
    };
    let observed = observed_rx.await.unwrap();
    assert_eq!(
        observed,
        if matches!(completion, Completion::PeerClose | Completion::PeerReset) {
            None
        } else {
            Some(268)
        }
    );
    error
}

#[tokio::test]
async fn h3_stopped_upload_terminal_refusal_without_headers_is_not_replay_safe() {
    for streaming in [false, true] {
        let error = tokio::time::timeout(
            Duration::from_secs(6),
            stopped_upload(streaming, Completion::PeerReset),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!error.is_safe_to_replay(), "{error}");
        assert!(matches!(
            error,
            lkrequest::error::Error::ConnectionClosed {
                kind: lkrequest::error::ConnectionClosedKind::Reset,
                ..
            }
        ));
        let message = error.to_string();
        assert!(
            message.contains("upload stopped by peer (code 256)"),
            "{message}"
        );
        assert!(message.contains("H3_REQUEST_REJECTED"), "{message}");
        assert!(
            !message.contains("after response headers"),
            "no final response was sent: {message}"
        );
    }
}

#[tokio::test]
async fn h3_stopped_upload_with_response_fin_waits_for_real_peer_close() {
    for streaming in [false, true] {
        let error = tokio::time::timeout(
            Duration::from_secs(6),
            stopped_upload(streaming, Completion::PeerClose),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!error.is_timeout(), "{error}");
        assert!(!error.is_safe_to_replay(), "{error}");
        assert!(
            error
                .to_string()
                .contains("upload stopped by peer (code 256)"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("Remote error: ApplicationClose: H3_INTERNAL_ERROR"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn h3_stopped_upload_cancellation_closes_response_direction() {
    for streaming in [false, true] {
        assert!(tokio::time::timeout(
            Duration::from_secs(6),
            stopped_upload(streaming, Completion::Cancel)
        )
        .await
        .unwrap()
        .is_none());
    }
}

#[tokio::test]
async fn h3_stopped_upload_preserves_request_deadline() {
    for streaming in [false, true] {
        let error = tokio::time::timeout(
            Duration::from_secs(6),
            stopped_upload(streaming, Completion::Deadline),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(error.is_timeout(), "{error}");
    }
}
