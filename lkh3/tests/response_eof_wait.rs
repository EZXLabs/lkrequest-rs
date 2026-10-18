use std::{sync::Arc, time::Duration};

use http::Request;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

fn endpoints() -> (quinn::Endpoint, quinn::Endpoint) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert_der.clone()], key)
    .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap())),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).unwrap(),
    )));
    (client, server)
}

fn request() -> Request<Option<bytes::Bytes>> {
    Request::builder()
        .uri("https://localhost/eof-wait")
        .body(None)
        .unwrap()
}

#[tokio::test]
async fn response_eof_wait_driver_abort_releases_all_readers_without_closing_transport() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, server) = endpoints();
        let server_endpoint = server.clone();
        let (acknowledged, fin_acknowledged) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            let responses: [&[u8]; 4] = [
                b"\x01\x03\x00\x00\xd9\x00\x01x",
                b"\x01\x03\x00\x00\xd9\x00\x01x\x40",
                b"\x01\x03\x00\x00\xd9\x00\x01x\x01\x02\x00\x00\x01\x40",
                b"\x40",
            ];
            for wire in responses {
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                recv.read_to_end(64 * 1024).await.unwrap();
                send.write_all(wire).await.unwrap();
                send.finish().unwrap();
                assert_eq!(
                    send.stopped().await.unwrap(),
                    None,
                    "response FIN must be ACKed"
                );
            }
            acknowledged.send(()).unwrap();
            connection.closed().await
        });
        let quic = client
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap()
            .await
            .unwrap();
        let connection = lkh3::connect_h3(quic.clone(), &lkh3::chrome_155_h3())
            .await
            .unwrap();
        let (mut sender, driver) = connection.into_parts();
        let mut completed = sender.send_request(request()).await.unwrap();
        assert_eq!(completed.body_mut().data().await.unwrap().unwrap(), "x");
        assert!(completed.body_mut().data().await.is_none());
        assert!(completed.body_mut().trailers().await.unwrap().is_none());

        let mut body = sender.clone().send_request(request()).await.unwrap();
        assert_eq!(body.body_mut().data().await.unwrap().unwrap(), "x");
        let body_wait =
            tokio::spawn(async move { body.body_mut().data().await.unwrap().unwrap_err() });
        let mut trailer = sender.clone().send_request(request()).await.unwrap();
        assert_eq!(trailer.body_mut().data().await.unwrap().unwrap(), "x");
        assert!(trailer.body_mut().data().await.is_none());
        let trailer_wait =
            tokio::spawn(async move { trailer.body_mut().trailers().await.unwrap_err() });
        let mut initial_sender = sender.clone();
        let initial_wait = tokio::spawn(async move {
            match initial_sender.send_request(request()).await {
                Err(error) => error,
                Ok(_) => panic!("partial initial frame must not complete"),
            }
        });
        fin_acknowledged.await.unwrap();
        let mut readers = [initial_wait, body_wait, trailer_wait];
        for reader in &mut readers {
            assert!(tokio::time::timeout(Duration::from_millis(20), reader)
                .await
                .is_err());
        }
        driver.abort();
        assert!(driver.await.unwrap_err().is_cancelled());
        for reader in readers {
            let error = reader.await.unwrap();
            assert!(
                error.to_string().contains("connection driver dropped"),
                "{error}"
            );
        }
        assert!(quic.close_reason().is_none());
        assert!(!peer.is_finished());
        assert!(completed.body_mut().data().await.is_none());
        assert!(completed.body_mut().trailers().await.unwrap().is_none());
        client.close(0u32.into(), b"test complete");
        peer.await.unwrap();
        server.close(0u32.into(), b"test complete");
    })
    .await
    .expect("driver-abort fixture must finish");
}
