use super::*;
use bytes::Bytes;
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
enum Phase {
    Initial,
    Body,
    Trailers,
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

struct Fixture {
    _peer: Peer,
    session: lkrequest::Session,
    url: String,
    ready: oneshot::Receiver<()>,
    close: oneshot::Sender<()>,
}

async fn fixture(phase: Phase, partial_length: bool) -> Fixture {
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
    let endpoint = Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap())),
        localhost_addr(0),
    )
    .unwrap();
    let port = endpoint.local_addr().unwrap().port();
    let (ready_tx, ready) = oneshot::channel();
    let (close, close_rx) = oneshot::channel();
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
            recv.read_to_end(64 * 1024).await.unwrap();
            let mut response = match phase {
                Phase::Initial => Vec::new(),
                Phase::Body => b"\x01\x03\x00\x00\xd9\x00\x04body".to_vec(),
                Phase::Trailers => b"\x01\x03\x00\x00\xd9\x00\x04body\x01\x02\x00\x00".to_vec(),
            };
            response.extend_from_slice(if partial_length { b"\x01\x40" } else { b"\x40" });
            send.write_all(&response).await.unwrap();
            send.finish().unwrap();
            // ACK confirms the peer received FIN before the pending assertion.
            assert!(send
                .stopped()
                .await
                .expect("response FIN acknowledgement")
                .is_none());
            let _ = ready_tx.send(());
            if close_rx.await.is_ok() {
                connection.close(0x102u32.into(), b"partial header peer close");
                connection.closed().await;
            }
            drop(critical);
        }
    });
    let session = lkrequest::Client::builder()
        .preset(lkrequest::preset::chrome_155())
        .add_ca_cert_der(&certificate)
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .build()
        .session()
        .http3_only()
        .build();
    Fixture {
        _peer: Peer { endpoint, task },
        session,
        url: format!("https://localhost:{port}/incomplete-header"),
        ready,
        close,
    }
}

async fn wait_for_peer_close(
    streaming: bool,
    phase: Phase,
    partial_length: bool,
) -> lkrequest::error::Error {
    let Fixture {
        _peer,
        session,
        url,
        ready,
        close,
    } = fixture(phase, partial_length).await;
    let request = session.post(&url).body(Bytes::from_static(b"request"));
    let mut response = Box::pin(async move {
        if streaming {
            let mut response = request.send_streaming().await?;
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                bytes.extend_from_slice(&chunk);
            }
            Ok::<_, lkrequest::error::Error>(bytes)
        } else {
            Ok(request.send().await?.bytes().to_vec())
        }
    });
    tokio::select! {
        ready = ready => ready.unwrap(),
        result = &mut response => panic!("completed before FIN acknowledgement: {phase:?}, length={partial_length}, streaming={streaming}: {result:?}"),
        _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("peer readiness timed out"),
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut response).await.is_err(),
        "incomplete frame header must wait while the connection is open: {phase:?}, length={partial_length}, streaming={streaming}"
    );
    close.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .expect("connection close must wake response")
        .expect_err("peer connection close")
}

#[tokio::test]
async fn h3_incomplete_header_waits_for_peer_close_in_all_receive_phases() {
    for streaming in [false, true] {
        for phase in [Phase::Initial, Phase::Body, Phase::Trailers] {
            for partial_length in [false, true] {
                let error = wait_for_peer_close(streaming, phase, partial_length).await;
                assert!(
                    error
                        .to_string()
                        .contains("Remote error: ApplicationClose: H3_INTERNAL_ERROR"),
                    "{error}"
                );
            }
        }
    }
}

#[tokio::test]
async fn h3_incomplete_header_resumes_after_cancelled_chunk() {
    for phase in [Phase::Body, Phase::Trailers] {
        let Fixture {
            _peer,
            session,
            url,
            ready,
            close,
        } = fixture(phase, false).await;
        let request = session.post(&url).body(Bytes::from_static(b"request"));
        let mut response = tokio::time::timeout(Duration::from_secs(5), request.send_streaming())
            .await
            .expect("response headers")
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), response.chunk())
                .await
                .expect("initial DATA")
                .unwrap()
                .unwrap(),
            b"body"[..]
        );
        tokio::time::timeout(Duration::from_secs(5), ready)
            .await
            .expect("FIN acknowledgement")
            .unwrap();
        for _ in 0..2 {
            assert!(
                tokio::time::timeout(Duration::from_millis(100), response.chunk())
                    .await
                    .is_err()
            );
        }
        close.send(()).unwrap();
        let error = tokio::time::timeout(Duration::from_secs(5), response.chunk())
            .await
            .expect("connection close must wake resumed chunk")
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Remote error: ApplicationClose: H3_INTERNAL_ERROR"),
            "{error}"
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(5), response.chunk())
                .await
                .expect("terminal chunk")
                .unwrap()
                .is_none(),
            "terminal error reported once"
        );
    }
}

#[tokio::test]
async fn h3_incomplete_header_preserves_request_deadline() {
    for streaming in [false, true] {
        let Fixture {
            _peer,
            session,
            url,
            ready,
            close: _close,
        } = fixture(Phase::Initial, true).await;
        let request = session
            .post(&url)
            .body(Bytes::from_static(b"request"))
            .timeout(Duration::from_secs(1));
        let mut result = Box::pin(async move {
            if streaming {
                request.send_streaming().await.map(|_| ())
            } else {
                request.send().await.map(|_| ())
            }
        });
        tokio::select! {
            ready = ready => ready.expect("FIN acknowledged before deadline"),
            result = &mut result => panic!("request ended before FIN acknowledgement: {result:?}"),
            _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("peer readiness timed out"),
        }
        let result = tokio::time::timeout(Duration::from_secs(5), result)
            .await
            .expect("request deadline must remain effective");
        let error = result.expect_err("incomplete initial frame header cannot complete");
        assert!(error.is_timeout(), "expected request timeout, got {error}");
    }
}
