use super::*;
use std::time::Duration;

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

async fn delayed_trailers(streaming: bool) -> Vec<u8> {
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
    let (insert_tx, insert_rx) = oneshot::channel();
    let (decoder_tx, decoder_rx) = oneshot::channel();
    let task = tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let mut critical = Vec::new();
            for bytes in [&b"\x00\x04\x00"[..], &b"\x03"[..]] {
                let mut stream = connection.open_uni().await.unwrap();
                stream.write_all(bytes).await.unwrap();
                critical.push(stream);
            }
            let mut encoder = connection.open_uni().await.unwrap();
            encoder.write_all(b"\x02").await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            assert_eq!(u64::from(send.id()), 0);
            recv.read_to_end(64 * 1024).await.unwrap();
            // RFC 9204 sections 4.5.1/4.5.2: RIC=1, Base=1, dynamic index 0.
            send.write_all(b"\x01\x03\x00\x00\xd9\x00\x04body\x01\x03\x02\x00\x80")
                .await
                .unwrap();
            send.finish().unwrap();
            assert!(
                send.stopped().await.unwrap().is_none(),
                "response FIN acknowledged"
            );
            ready_tx.send(()).unwrap();
            insert_rx.await.unwrap();
            // Capacity 256, then literal insertion x-test=ready (sections 4.3.1/4.3.3).
            encoder
                .write_all(b"\x3f\xe1\x01\x46x-test\x05ready")
                .await
                .unwrap();

            let mut incoming_critical = Vec::new();
            let mut reading_types = tokio::task::JoinSet::new();
            let mut decoder = loop {
                // Lower stream IDs can be allocated without transmitting their type.
                tokio::select! {
                    received = connection.accept_uni() => {
                        let mut stream = received.unwrap();
                        reading_types.spawn(async move {
                            let mut kind = [0];
                            stream.read_exact(&mut kind).await.unwrap();
                            (kind, stream)
                        });
                    }
                    Some(result) = reading_types.join_next(), if !reading_types.is_empty() => {
                        let (kind, stream) = result.unwrap();
                        if kind == [3] {
                            break stream;
                        }
                        incoming_critical.push(stream);
                    }
                }
            };
            let mut instructions = vec![0; 2];
            decoder.read_exact(&mut instructions).await.unwrap();
            let mut extra = [0; 16];
            if let Ok(result) =
                tokio::time::timeout(Duration::from_millis(150), decoder.read(&mut extra)).await
            {
                if let Some(length) = result.unwrap() {
                    instructions.extend_from_slice(&extra[..length]);
                }
            }
            decoder_tx.send(instructions).unwrap();
            std::future::pending::<()>().await;
            drop((critical, incoming_critical, reading_types, encoder, decoder));
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
    let request = session.post(&format!("https://localhost:{port}/qpack"));
    if streaming {
        let mut response = request.send_streaming().await.unwrap();
        assert_eq!(response.chunk().await.unwrap().unwrap(), b"body"[..]);
        ready_rx.await.unwrap();
        for _ in 0..2 {
            assert!(
                tokio::time::timeout(Duration::from_millis(75), response.chunk())
                    .await
                    .is_err()
            );
        }
        insert_tx.send(()).unwrap();
        assert!(response.chunk().await.unwrap().is_none());
        assert!(response.chunk().await.unwrap().is_none());
    } else {
        let mut response = Box::pin(request.send());
        tokio::select! {
            ready = ready_rx => ready.unwrap(),
            result = &mut response => panic!("QPACK trailers completed before insertion: {result:?}"),
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut response)
                .await
                .is_err()
        );
        insert_tx.send(()).unwrap();
        assert_eq!(response.await.unwrap().bytes(), b"body");
    }
    decoder_rx.await.unwrap()
}

#[tokio::test]
async fn h3_qpack_delayed_trailers_complete_once_across_response_apis() {
    for streaming in [false, true] {
        let instructions =
            tokio::time::timeout(Duration::from_secs(5), delayed_trailers(streaming))
                .await
                .expect("QPACK integration fixture must finish");
        // InsertCountIncrement(1), then exactly one SectionAcknowledgment(stream 0).
        assert_eq!(instructions, [0x01, 0x80]);
    }
}
