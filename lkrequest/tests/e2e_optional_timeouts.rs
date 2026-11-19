use std::time::Duration;
use std::{io, net::SocketAddr, sync::Arc};

use lkrequest::{Client, TimeoutConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn read_headers(socket: &mut (impl tokio::io::AsyncRead + Unpin)) {
    let mut request = Vec::new();
    let mut byte = [0];
    while !request.ends_with(b"\r\n\r\n") {
        socket.read_exact(&mut byte).await.unwrap();
        request.push(byte[0]);
    }
}

async fn reply(mut socket: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin) {
    read_headers(&mut socket).await;
    socket
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await
        .unwrap();
}

struct SlowResolver(SocketAddr);

#[async_trait::async_trait]
impl lkrequest::DnsResolver for SlowResolver {
    async fn resolve(&self, _: &str, _: u16) -> io::Result<Vec<SocketAddr>> {
        tokio::time::sleep(Duration::from_secs(11)).await;
        Ok(vec![self.0])
    }
}

#[tokio::test]
async fn none_does_not_restore_tcp_or_dns_deadlines() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        reply(listener.accept().await.unwrap().0).await;
    });
    let session = Client::builder()
        .timeout_config(TimeoutConfig::none())
        .dns_resolver(Arc::new(SlowResolver(address)))
        .build()
        .session()
        .http1_only()
        .build();
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        session.get("http://delayed.test/").send(),
    )
    .await;
    server.abort();
    assert_eq!(result.unwrap().unwrap().text().unwrap(), "ok");
}

#[tokio::test]
async fn none_does_not_restore_a_tls_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.cert.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            cert.signing_key.serialize_der(),
        )),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(11)).await;
        reply(acceptor.accept(socket).await.unwrap()).await;
    });
    let session = Client::builder()
        .timeout_config(TimeoutConfig::none())
        .verify(false)
        .build()
        .session()
        .http1_only()
        .build();
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        session.get(&format!("https://{address}/")).send(),
    )
    .await;
    server.abort();
    assert_eq!(result.unwrap().unwrap().text().unwrap(), "ok");
}

#[tokio::test]
async fn none_does_not_restore_a_proxy_tunnel_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_headers(&mut socket).await;
        tokio::time::sleep(Duration::from_secs(11)).await;
        socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        reply(socket).await;
    });
    let session = Client::builder()
        .timeout_config(TimeoutConfig::none())
        .build()
        .session()
        .http1_only()
        .proxy(&format!("http://{address}"))
        .build();
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        session.get("http://target.invalid/").send(),
    )
    .await;
    server.abort();
    assert_eq!(result.unwrap().unwrap().text().unwrap(), "ok");
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn quic_none_waits_past_the_previous_hidden_deadline() {
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for quic_connect_timeout in [Some(Duration::from_millis(200)), None] {
        let session = Client::builder()
            .timeout_config(TimeoutConfig {
                quic_connect_timeout,
                ..TimeoutConfig::none()
            })
            .quic_profile(lkh3::chrome_quic())
            .verify(false)
            .build()
            .session()
            .http3_only()
            .build();
        let result = tokio::time::timeout(
            Duration::from_secs(6),
            session
                .get(&format!("https://{}/", blackhole.local_addr().unwrap()))
                .send(),
        )
        .await;
        if quic_connect_timeout.is_some() {
            let error = result.unwrap().unwrap_err();
            assert!(error.is_timeout());
            assert_eq!(
                error.phase(),
                Some(lkrequest::error::ConnectionPhase::QuicHandshake)
            );
        } else {
            assert!(
                result.is_err(),
                "None must leave the QUIC handshake pending"
            );
        }
    }
}

#[test]
fn none_reports_disabled_in_legacy_getters() {
    let client = Client::builder()
        .timeout_config(TimeoutConfig::none())
        .build();
    assert_eq!(client.connect_timeout(), Duration::MAX);
    assert_eq!(client.read_timeout(), Duration::MAX);
}

#[tokio::test]
async fn none_does_not_restore_the_default_header_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        tokio::time::sleep(Duration::from_secs(31)).await;
        let _ = socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await;
    });
    let session = Client::builder()
        .timeout_config(TimeoutConfig::none())
        .build()
        .session()
        .http1_only()
        .build();
    let result = tokio::time::timeout(
        Duration::from_secs(40),
        session.get(&format!("http://{address}/")).send(),
    )
    .await;
    server.abort();
    assert_eq!(result.unwrap().unwrap().text().unwrap(), "ok");
}
