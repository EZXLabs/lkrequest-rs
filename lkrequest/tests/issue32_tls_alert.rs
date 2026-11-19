use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn tls13_client_certificate_required_reaches_h1_caller_promptly() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = Arc::new(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..8 {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.set_nodelay(true).unwrap();
            let mut tls = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut bytes = [0; 16384];
            loop {
                let n = socket.read(&mut bytes).await.unwrap();
                assert_ne!(n, 0);
                tls.read_tls(&mut std::io::Cursor::new(&bytes[..n]))
                    .unwrap();
                let result = tls.process_new_packets();
                while tls.wants_write() {
                    let mut output = Vec::new();
                    tls.write_tls(&mut output).unwrap();
                    socket.write_all(&output).await.unwrap();
                }
                if let Err(error) = result {
                    assert!(
                        error.to_string().contains("peer sent no certificates"),
                        "{error}"
                    );
                    // Keep TCP alive until the client has consumed the alert.
                    // Dropping with unread HTTP bytes can replace it with RST.
                    let _ = tokio::time::timeout(Duration::from_millis(200), async {
                        while socket.read(&mut bytes).await.unwrap_or(0) != 0 {}
                    })
                    .await;
                    break;
                }
            }
        }
    });
    let client = lkrequest::Client::builder()
        .fingerprint(lktls::profile::presets::chrome_158())
        .add_ca_cert_der(cert.cert.der())
        .ttfb_timeout(Duration::from_secs(10))
        .build();
    for streaming in [false, true] {
        for _ in 0..4 {
            let session = client.session().http1_only().build();
            let url = format!("https://localhost:{}", addr.port());
            let result = tokio::time::timeout(Duration::from_secs(3), async {
                if streaming {
                    session.get(&url).send_streaming().await.map(|_| ())
                } else {
                    session.get(&url).send().await.map(|_| ())
                }
            })
            .await
            .expect("a received fatal alert must not wait for TTFB");
            let error = result.unwrap_err();
            assert_eq!(
                error.as_tls_alert().map(|a| a.description.as_byte()),
                Some(116),
                "{error:?}"
            );
            assert_eq!(
                error.phase(),
                Some(lkrequest::error::ConnectionPhase::HttpRequest)
            );
            assert!(
                !error.is_safe_to_replay(),
                "post-handshake failure is not proof of replay safety"
            );
            assert!(!error.is_retryable());
        }
    }
    server.await.unwrap();
}
