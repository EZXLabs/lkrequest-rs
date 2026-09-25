//! Tier-0 address-family and origin-preserving dial override tests.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use lkrequest::{Client, DnsResolver, IpFamily};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Clone)]
struct Addresses {
    ips: Vec<IpAddr>,
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl DnsResolver for Addresses {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        self.calls.lock().unwrap().push(host.to_owned());
        Ok(self
            .ips
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect())
    }
}

fn resolver(ips: Vec<IpAddr>) -> Addresses {
    Addresses {
        ips,
        calls: Arc::new(Mutex::new(Vec::new())),
    }
}

struct HttpsDns;

#[async_trait]
impl DnsResolver for HttpsDns {
    async fn resolve(&self, _host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))])
    }

    async fn lookup_https(&self, _host: &str) -> io::Result<Option<lkrequest::HttpsRecord>> {
        Ok(Some(lkrequest::HttpsRecord {
            alpn: vec!["h3".into()],
            ech_config_list: Some(vec![0, 0]),
            target: Some("alternate.test".into()),
            port: Some(8443),
            ..Default::default()
        }))
    }
}

#[tokio::test]
async fn family_filter_preserves_https_discovery_and_ech_metadata() {
    let client = Client::builder()
        .ip_family(IpFamily::Ipv4)
        .dns_resolver(Arc::new(HttpsDns))
        .build();
    let record = client
        .resolver()
        .lookup_https("origin.test")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.alpn, ["h3"]);
    assert_eq!(record.ech_config_list, Some(vec![0, 0]));
    assert_eq!(record.target.as_deref(), Some("alternate.test"));
    assert_eq!(record.port, Some(8443));
}

#[tokio::test]
async fn family_filters_custom_resolution_without_reordering_candidates() {
    let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    for (family, expected) in [
        (IpFamily::Any, vec![v6, v4]),
        (IpFamily::Ipv4, vec![v4]),
        (IpFamily::Ipv6, vec![v6]),
    ] {
        let client = Client::builder()
            .ip_family(family)
            .dns_resolver(Arc::new(resolver(vec![v6, v4])))
            .build();
        let actual = client.resolver().resolve("origin.test", 443).await.unwrap();
        assert_eq!(
            actual,
            expected
                .into_iter()
                .map(|ip| SocketAddr::new(ip, 443))
                .collect::<Vec<_>>()
        );
    }
}

#[tokio::test]
async fn ipv4_policy_rejects_an_ipv6_only_result_and_literal() {
    let client = Client::builder()
        .dns_resolver(Arc::new(resolver(vec![Ipv6Addr::LOCALHOST.into()])))
        .ip_family(IpFamily::Ipv4)
        .build();
    for host in ["only-v6.test", "[::1]", "::1"] {
        let error = client.resolver().resolve(host, 443).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
        assert!(error.to_string().contains("IPv4"));
    }
}

#[tokio::test]
async fn ip_literals_cannot_be_rewritten_by_a_custom_resolver() {
    let dns = resolver(vec![Ipv4Addr::LOCALHOST.into()]);
    let client = Client::builder()
        .ip_family(IpFamily::Ipv4)
        .dns_resolver(Arc::new(dns.clone()))
        .build();
    assert!(client.resolver().resolve("[::1]", 443).await.is_err());
    assert!(dns.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn family_policy_survives_a_later_dns_setting() {
    let client = Client::builder()
        .ip_family(IpFamily::Ipv4)
        .dns(lkrequest::DnsConfig::System)
        .build();
    assert!(client.resolver().resolve("[::1]", 443).await.is_err());
}

#[tokio::test]
async fn any_family_with_an_override_does_not_reclassify_unrelated_dns_failures() {
    let client = Client::builder()
        .dns_resolver(Arc::new(resolver(Vec::new())))
        .connect_to("pinned.test", 443, "127.0.0.1:443".parse().unwrap())
        .build();
    let error = client
        .session()
        .http1_only()
        .build()
        .get("http://unrelated.test/")
        .send()
        .await
        .unwrap_err();
    assert!(!error.is_address_family_mismatch(), "{error:?}");
    assert!(error.is_retryable());
}

#[tokio::test]
async fn ipv6_policy_does_not_dial_ipv4_mapped_addresses() {
    let client = Client::builder().ip_family(IpFamily::Ipv6).build();
    assert!(client
        .resolver()
        .resolve("[::ffff:127.0.0.1]", 443)
        .await
        .is_err());
}

#[tokio::test]
async fn proxy_address_family_failure_never_falls_back_to_direct() {
    let dns = resolver(vec![Ipv6Addr::LOCALHOST.into()]);
    let client = Client::builder()
        .ip_family(IpFamily::Ipv4)
        .dns_resolver(Arc::new(dns.clone()))
        .proxy_fallback_direct(true)
        .build();
    let session = client
        .session()
        .http1_only()
        .proxy("http://proxy.test:8080")
        .build();
    let error = session.get("http://origin.test/").send().await.unwrap_err();
    assert!(error.is_address_family_mismatch(), "{error:?}");
    assert!(!error.is_retryable());
    assert_eq!(*dns.calls.lock().unwrap(), ["proxy.test"]);
}

#[tokio::test]
async fn socks5_target_family_rejection_does_not_trigger_direct_fallback() {
    let dns = resolver(vec![Ipv6Addr::LOCALHOST.into()]);
    let client = Client::builder()
        .ip_family(IpFamily::Ipv4)
        .dns_resolver(Arc::new(dns.clone()))
        .proxy_fallback_direct(true)
        .build();
    let error = client
        .session()
        .http1_only()
        .proxy("socks5://127.0.0.1:1")
        .build()
        .get("http://origin.test/")
        .send()
        .await
        .unwrap_err();
    assert!(error.is_address_family_mismatch(), "{error:?}");
    assert_eq!(*dns.calls.lock().unwrap(), ["origin.test"]);
}

#[tokio::test]
async fn an_incompatible_override_fails_before_the_proxy_is_contacted() {
    let dns = resolver(Vec::new());
    let client = Client::builder()
        .ip_family(IpFamily::Ipv4)
        .dns_resolver(Arc::new(dns.clone()))
        .connect_to("origin.test", 443, "[::1]:443".parse().unwrap())
        .build();
    let error = client
        .session()
        .proxy("http://proxy.test:8080")
        .build()
        .get("https://origin.test/")
        .send()
        .await
        .unwrap_err();
    assert!(error.is_address_family_mismatch(), "{error:?}");
    assert!(dns.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn remote_dns_keeps_the_domain_when_no_override_is_configured() {
    let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = proxy.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = proxy.accept().await.unwrap();
        let head = read_head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        head
    });
    let dns = resolver(Vec::new());
    let client = Client::builder()
        .ip_family(IpFamily::Ipv4)
        .dns_resolver(Arc::new(dns.clone()))
        .build();
    let result = client
        .session()
        .proxy(&format!("http://{address}"))
        .build()
        .get("https://origin.test/")
        .send()
        .await;
    assert!(result.is_err());
    assert!(task
        .await
        .unwrap()
        .starts_with("CONNECT origin.test:443 HTTP/1.1\r\n"));
    assert!(dns.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn ipv4_direct_dial_uses_filtered_candidates_for_both_response_modes() {
    for streaming in [false, true] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let head = read_head(&mut stream).await;
            assert!(head.starts_with("GET / HTTP/1.1"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });
        let client = Client::builder()
            .ip_family(IpFamily::Ipv4)
            .dns_resolver(Arc::new(resolver(vec![
                Ipv6Addr::LOCALHOST.into(),
                Ipv4Addr::LOCALHOST.into(),
            ])))
            .build();
        let session = client.session().build();
        let request = session.get(&format!("http://origin.test:{}/", addr.port()));
        let status = if streaming {
            request.send_streaming().await.unwrap().status()
        } else {
            request.send().await.unwrap().status()
        };
        assert_eq!(status.as_u16(), 200);
        server.await.unwrap();
    }
}

async fn read_head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.unwrap());
        assert!(bytes.len() < 32_768);
    }
    String::from_utf8(bytes).unwrap()
}

#[tokio::test]
async fn connect_to_preserves_tls_identity_and_host_through_http_proxy() {
    let cert = rcgen::generate_simple_self_signed(vec!["origin.test".into()]).unwrap();
    let root = cert.cert.der().to_vec();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let tls = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.cert.der().clone()], key.into())
    .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(tls))
            .accept(tcp)
            .await
            .unwrap();
        let sni = stream.get_ref().1.server_name().unwrap().to_owned();
        let head = read_head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        (sni, head)
    });
    let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let relay = tokio::spawn(async move {
        let (mut incoming, _) = proxy.accept().await.unwrap();
        let connect = read_head(&mut incoming).await;
        assert!(connect.starts_with(&format!("CONNECT {endpoint} HTTP/1.1\r\n")));
        let mut outgoing = tokio::net::TcpStream::connect(endpoint).await.unwrap();
        incoming
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await;
    });
    let dns = resolver(Vec::new());
    let client = Client::builder()
        .ip_family(IpFamily::Ipv4)
        .dns_resolver(Arc::new(dns.clone()))
        .connect_to("ORIGIN.test", 443, endpoint)
        .add_ca_cert_der(&root)
        .build();
    let session = client
        .session()
        .http1_only()
        .proxy(&format!("http://{proxy_addr}"))
        .build();
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        session.get("https://origin.test/path").send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.url(), "https://origin.test/path");
    let (sni, head) = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sni, "origin.test");
    assert!(
        head.to_ascii_lowercase()
            .contains("\r\nhost: origin.test\r\n"),
        "{head}"
    );
    assert!(dns.calls.lock().unwrap().is_empty());
    relay.abort();
}

#[tokio::test]
async fn connect_to_is_scoped_to_origin_port_and_used_by_preconnect() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_head(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
        request
    });
    let dns = resolver(Vec::new());
    let client = Client::builder()
        .dns_resolver(Arc::new(dns.clone()))
        .ip_family(IpFamily::Ipv4)
        .connect_to("origin.test", 80, address)
        .build();
    let session = client.session().http1_only().max_connections(1).build();
    session.preconnect("http://origin.test/").await.unwrap();
    let response = session.get("http://origin.test/").send().await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert!(server
        .await
        .unwrap()
        .to_ascii_lowercase()
        .contains("\r\nhost: origin.test\r\n"));
    let other = client
        .session()
        .http1_only()
        .build()
        .get("http://origin.test:81/")
        .send()
        .await
        .unwrap_err();
    assert!(other.is_address_family_mismatch(), "{other:?}");
    assert_eq!(*dns.calls.lock().unwrap(), ["origin.test"]);
}

#[tokio::test]
async fn socks5h_override_sends_an_ip_without_resolving_the_origin() {
    let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = proxy.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = proxy.accept().await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), 5);
        let mut methods = vec![0; stream.read_u8().await.unwrap() as usize];
        stream.read_exact(&mut methods).await.unwrap();
        stream.write_all(&[5, 0]).await.unwrap();
        let mut connect = [0; 10];
        stream.read_exact(&mut connect).await.unwrap();
        assert_eq!(connect, [5, 1, 0, 1, 192, 0, 2, 80, 31, 144]);
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        let request = read_head(&mut stream).await;
        assert!(request
            .to_ascii_lowercase()
            .contains("\r\nhost: origin.test\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
    });
    let dns = resolver(Vec::new());
    let client = Client::builder()
        .ip_family(IpFamily::Ipv4)
        .dns_resolver(Arc::new(dns.clone()))
        .connect_to("origin.test", 80, "192.0.2.80:8080".parse().unwrap())
        .build();
    let response = client
        .session()
        .proxy(&format!("socks5h://{address}"))
        .build()
        .get("http://origin.test/")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert!(dns.calls.lock().unwrap().is_empty());
    task.await.unwrap();
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn ipv4_policy_rejects_an_ipv6_socks_udp_relay() {
    let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = proxy.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = proxy.accept().await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), 5);
        let mut methods = vec![0; stream.read_u8().await.unwrap() as usize];
        stream.read_exact(&mut methods).await.unwrap();
        stream.write_all(&[5, 0]).await.unwrap();
        let mut associate = [0; 10];
        stream.read_exact(&mut associate).await.unwrap();
        assert_eq!(&associate[..4], &[5, 3, 0, 1]);
        let mut response = vec![5, 0, 0, 4];
        response.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        response.extend_from_slice(&443u16.to_be_bytes());
        stream.write_all(&response).await.unwrap();
    });
    let client = Client::builder()
        .preset(lkrequest::preset::chrome_154())
        .ip_family(IpFamily::Ipv4)
        .connect_to("origin.test", 443, "127.0.0.1:443".parse().unwrap())
        .build();
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        client
            .session()
            .proxy(&format!("socks5h://{address}"))
            .http3_only()
            .build()
            .get("https://origin.test/")
            .send(),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert!(error.is_address_family_mismatch(), "{error:?}");
    task.await.unwrap();
}

#[cfg(feature = "quic-h3")]
async fn quic_override_preserves_origin(
    family: IpFamily,
    bind: SocketAddr,
) -> Option<lkrequest::Response> {
    let cert = rcgen::generate_simple_self_signed(vec!["origin.test".into()]).unwrap();
    let root = cert.cert.der().to_vec();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.cert.der().clone()], key.into())
    .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let endpoint = match quinn::Endpoint::server(config, bind) {
        Ok(endpoint) => endpoint,
        Err(error)
            if bind.is_ipv6()
                && matches!(
                    error.raw_os_error(),
                    Some(97 | 99 | 47 | 49 | 10047 | 10049)
                ) =>
        {
            eprintln!("IPv6 loopback unavailable: {error}");
            return None;
        }
        Err(error) => panic!("QUIC server bind failed: {error}"),
    };
    let address = endpoint.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let mut h3 =
            h3::server::Connection::<_, bytes::Bytes>::new(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
        let (request, mut stream) = h3
            .accept()
            .await
            .unwrap()
            .unwrap()
            .resolve_request()
            .await
            .unwrap();
        assert_eq!(request.uri().authority().unwrap().as_str(), "origin.test");
        stream
            .send_response(http::Response::builder().status(200).body(()).unwrap())
            .await
            .unwrap();
        stream.finish().await.unwrap();
        let _ = stop_rx.await;
    });
    let dns = resolver(Vec::new());
    let client = Client::builder()
        .preset(lkrequest::preset::chrome_154())
        .ip_family(family)
        .connect_to("origin.test", 443, address)
        .dns_resolver(Arc::new(dns.clone()))
        .add_ca_cert_der(&root)
        .build();
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        client
            .session()
            .http3_only()
            .build()
            .get("https://origin.test/")
            .send(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(dns.calls.lock().unwrap().is_empty());
    let _ = stop_tx.send(());
    server.await.unwrap();
    Some(response)
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn quic_ipv4_override_keeps_the_origin_identity() {
    let response = quic_override_preserves_origin(IpFamily::Ipv4, (Ipv4Addr::LOCALHOST, 0).into())
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.version(), lkrequest::HttpVersion::H3);
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
async fn quic_ipv6_override_uses_an_ipv6_endpoint() {
    if let Some(response) =
        quic_override_preserves_origin(IpFamily::Ipv6, (Ipv6Addr::LOCALHOST, 0).into()).await
    {
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.version(), lkrequest::HttpVersion::H3);
    }
}
