use std::{sync::Arc, time::Duration};

use http::Request;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

fn endpoints() -> (quinn::Endpoint, quinn::Endpoint) {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        certificate.signing_key.serialize_der(),
    ));
    let mut server_tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certificate_der.clone()], key)
    .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls).unwrap())),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate_der).unwrap();
    let mut client_tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_tls).unwrap(),
    )));
    (client, server)
}

async fn read_varint(stream: &mut quinn::RecvStream) -> u64 {
    let mut first = [0];
    stream.read_exact(&mut first).await.unwrap();
    let length = 1usize << (first[0] >> 6);
    let mut rest = [0; 7];
    stream.read_exact(&mut rest[..length - 1]).await.unwrap();
    rest[..length - 1]
        .iter()
        .fold(u64::from(first[0] & 0x3f), |value, byte| {
            (value << 8) | u64::from(*byte)
        })
}

async fn fresh_idle_qpack_types(profile: lkh3::H3Profile) -> Vec<u64> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, server) = endpoints();
        let connecting = client
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap();
        let (quic, peer) = tokio::join!(connecting, async {
            server.accept().await.unwrap().await
        });
        let quic = quic.unwrap();
        let peer = peer.unwrap();
        let h3 = lkh3::connect_h3(quic.clone(), &profile).await.unwrap();
        let (mut sender, driver) = h3.into_parts();

        let mut peer_control = peer.open_uni().await.unwrap();
        peer_control.write_all(b"\x00\x04\x00").await.unwrap();
        // A response to this reserved stream proves the H3 driver was polled.
        let mut driver_probe = peer.open_uni().await.unwrap();
        driver_probe.write_all(b"\x21").await.unwrap();
        assert_eq!(
            driver_probe.stopped().await.unwrap(),
            Some(quinn::VarInt::from_u32(0x103)),
            "the active H3 driver must reject the unknown peer stream"
        );

        let request = Request::builder()
            .uri("https://localhost/lazy-qpack")
            .body(None)
            .unwrap();
        let serve = async {
            let (mut send, mut receive) = peer.accept_bi().await.unwrap();
            let bytes = receive.read_to_end(64 * 1024).await.unwrap();
            assert_eq!(bytes.first(), Some(&0x01), "request starts with HEADERS");
            // Static QPACK :status 200, followed by one DATA byte; no instructions.
            send.write_all(b"\x01\x03\x00\x00\xd9\x00\x01x")
                .await
                .unwrap();
            send.finish().unwrap();
        };
        let (response, ()) = tokio::join!(sender.send_request(request), serve);
        let mut response = response.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(response.body_mut().data().await.unwrap().unwrap(), "x");
        assert!(response.body_mut().data().await.is_none());
        assert!(response.body_mut().trailers().await.unwrap().is_none());

        let mut streams = Vec::new();
        let mut control_settings = 0;
        let mut qpack_types = Vec::new();
        while let Ok(received) =
            tokio::time::timeout(Duration::from_millis(150), peer.accept_uni()).await
        {
            let mut stream = received.unwrap();
            let kind = read_varint(&mut stream).await;
            match kind {
                0 => {
                    assert_eq!(read_varint(&mut stream).await, 4, "SETTINGS is first");
                    let length = usize::try_from(read_varint(&mut stream).await).unwrap();
                    assert!((1..=4096).contains(&length));
                    let mut settings = vec![0; length];
                    stream.read_exact(&mut settings).await.unwrap();
                    control_settings += 1;
                }
                2 | 3 => {
                    let mut extra = [0];
                    assert!(
                        tokio::time::timeout(Duration::from_millis(20), stream.read(&mut extra))
                            .await
                            .is_err(),
                        "idle QPACK stream must carry only its type byte, without FIN or instructions"
                    );
                    qpack_types.push(kind);
                }
                _ => panic!("unexpected client unidirectional stream type {kind}"),
            }
            streams.push(stream);
        }
        assert_eq!(control_settings, 1, "exactly one complete control SETTINGS");
        assert!(!driver.is_finished(), "H3 driver must remain active");
        assert!(quic.close_reason().is_none());
        assert!(peer.close_reason().is_none());
        qpack_types.sort_unstable();
        eprintln!("fresh idle QPACK types after driver/request/SETTINGS: {qpack_types:?}");

        driver.abort();
        assert!(driver.await.unwrap_err().is_cancelled());
        client.close(0u32.into(), b"test complete");
        server.close(0u32.into(), b"test complete");
        drop(streams);
        drop(peer_control);
        qpack_types
    })
    .await
    .expect("fresh local QUIC QPACK-prefix fixture must finish")
}

#[tokio::test]
async fn chrome155_fresh_connection_defers_idle_qpack_prefixes() {
    let observed = fresh_idle_qpack_types(lkh3::chrome_155_h3()).await;
    assert_eq!(observed, Vec::<u64>::new());
}

#[tokio::test]
async fn default_fresh_connection_preserves_eager_qpack_prefixes() {
    let observed = fresh_idle_qpack_types(lkh3::chrome_h3()).await;
    assert_eq!(observed, [2, 3]);
}

#[tokio::test]
async fn chrome154_fresh_connection_preserves_eager_qpack_prefixes() {
    let observed = fresh_idle_qpack_types(lkh3::chrome_154_h3()).await;
    assert_eq!(observed, [2, 3]);
}

#[tokio::test]
async fn chrome155_explicit_disable_preserves_eager_qpack_prefixes() {
    let mut profile = lkh3::chrome_155_h3();
    profile.defer_qpack_stream_prefixes = false;
    let observed = fresh_idle_qpack_types(profile).await;
    assert_eq!(observed, [2, 3]);
}

#[tokio::test]
async fn custom_profile_can_defer_idle_qpack_prefixes() {
    let mut profile = lkh3::chrome_h3();
    profile.defer_qpack_stream_prefixes = true;
    let observed = fresh_idle_qpack_types(profile).await;
    assert_eq!(observed, Vec::<u64>::new());
}
