use super::*;
use bytes::Bytes;
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
enum Ending {
    Fin,
    Reset,
    BadQpack,
    ExtraData,
    TruncatedFrame,
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

async fn completion_case(
    streaming: bool,
    ending: Ending,
    payload_compatibility: bool,
) -> lkrequest::error::Result<Vec<u8>> {
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
    let (ready_tx, ready_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel();
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
            send.write_all(b"\x01\x03\x00\x00\xd9\x00\x04body")
                .await
                .unwrap();
            let trailers = if matches!(ending, Ending::BadQpack) {
                b"\x01\x03\x00\x00\xff".as_slice()
            } else {
                b"\x01\x02\x00\x00".as_slice()
            };
            send.write_all(trailers).await.unwrap();
            ready_tx.send(()).unwrap();
            if finish_rx.await.is_err() {
                return;
            }
            match ending {
                Ending::Reset => {
                    send.reset(
                        quinn::VarInt::from_u64(h3::error::Code::H3_INTERNAL_ERROR.value())
                            .unwrap(),
                    )
                    .unwrap();
                }
                Ending::ExtraData => {
                    send.write_all(b"\x00\x01x").await.unwrap();
                    send.finish().unwrap();
                }
                Ending::TruncatedFrame => {
                    send.write_all(b"\x21\x05x").await.unwrap();
                    send.finish().unwrap();
                }
                _ => {
                    send.finish().unwrap();
                }
            }
            std::future::pending::<()>().await;
            drop(critical);
        }
    });
    let _peer = Peer { endpoint, task };
    let mut preset = lkrequest::preset::chrome_155();
    preset
        .quic_profile
        .as_mut()
        .unwrap()
        .h3
        .accept_truncated_response_payloads = payload_compatibility;
    let session = lkrequest::Client::builder()
        .preset(preset)
        .add_ca_cert_der(&certificate)
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .build()
        .session()
        .http3_only()
        .build();
    let request = session
        .post(&format!("https://localhost:{port}/completion"))
        .body(Bytes::from_static(b"request"));
    if streaming {
        let mut response = tokio::time::timeout(Duration::from_secs(5), request.send_streaming())
            .await
            .unwrap()?;
        let mut bytes = Vec::new();
        while bytes.len() < 4 {
            bytes.extend_from_slice(&response.chunk().await?.expect("initial response DATA"));
        }
        assert_eq!(bytes, b"body");
        ready_rx.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), response.chunk())
                .await
                .is_err(),
            "trailers before FIN cannot complete a streaming response: {ending:?}"
        );
        // The timed-out chunk future is dropped; the next call must resume trailer validation.
        finish_tx.send(()).unwrap();
        let completion = tokio::time::timeout(Duration::from_secs(5), response.chunk())
            .await
            .unwrap();
        let terminal = response.chunk().await;
        assert!(
            matches!(terminal, Ok(None)),
            "a terminal completion is observed only once: {terminal:?}"
        );
        assert!(completion?.is_none());
        Ok(bytes)
    } else {
        let mut response = Box::pin(request.send());
        tokio::select! {
            ready = ready_rx => ready.unwrap(),
            result = &mut response => panic!("response completed before peer trailers: {result:?}"),
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut response)
                .await
                .is_err(),
            "trailers before FIN cannot complete a buffered response: {ending:?}"
        );
        finish_tx.send(()).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(5), response)
            .await
            .unwrap()?;
        Ok(response.bytes().to_vec())
    }
}

#[tokio::test]
async fn h3_completion_waits_for_fin_with_valid_trailers() {
    for streaming in [false, true] {
        assert_eq!(
            completion_case(streaming, Ending::Fin, true).await.unwrap(),
            b"body"
        );
    }
}

#[tokio::test]
async fn h3_completion_rejects_reset_after_trailers() {
    for streaming in [false, true] {
        let error = completion_case(streaming, Ending::Reset, true)
            .await
            .expect_err("RESET after trailers");
        assert!(error.to_string().contains("H3_INTERNAL_ERROR"), "{error}");
    }
}

#[tokio::test]
async fn h3_completion_validates_trailer_qpack() {
    for streaming in [false, true] {
        let error = completion_case(streaming, Ending::BadQpack, true)
            .await
            .expect_err("invalid trailer QPACK");
        assert!(
            error.to_string().contains("QPACK_DECOMPRESSION_FAILED"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn h3_completion_resumes_validation_after_cancelled_chunk() {
    for streaming in [false, true] {
        let error = completion_case(streaming, Ending::ExtraData, true)
            .await
            .expect_err("DATA after trailers");
        assert!(error.to_string().contains("H3_FRAME_UNEXPECTED"), "{error}");
    }
}

#[tokio::test]
async fn h3_completion_legacy_rejects_truncated_unknown_frame_after_trailers() {
    for streaming in [false, true] {
        let error = completion_case(streaming, Ending::TruncatedFrame, false)
            .await
            .expect_err("truncated trailing frame");
        assert!(error.to_string().contains("H3_FRAME_ERROR"), "{error}");
    }
}

#[tokio::test]
async fn h3_completion_chrome155_accepts_truncated_unknown_frame_after_trailers() {
    for streaming in [false, true] {
        assert_eq!(
            completion_case(streaming, Ending::TruncatedFrame, true)
                .await
                .unwrap(),
            b"body"
        );
    }
}
