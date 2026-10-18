use std::future::pending;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use lkrequest::dns::{DnsResolver, HttpsRecord};
use lkrequest::error::Error;
use lkrequest::{Client, DnsConfig, ProtocolPolicy, ProtocolSelectionPolicy, TimeoutConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct CountingDns(Arc<AtomicUsize>);

#[async_trait]
impl DnsResolver for CountingDns {
    async fn resolve(&self, _: &str, _: u16) -> io::Result<Vec<SocketAddr>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::new(io::ErrorKind::NotFound, "controlled lookup"))
    }
}

#[tokio::test]
async fn user_issue_6_invalid_request_proxy_stops_before_dns() {
    for streaming in [false, true] {
        let calls = Arc::new(AtomicUsize::new(0));
        let client = Client::builder()
            .dns_resolver(Arc::new(CountingDns(calls.clone())))
            .build();
        let session = client.session().http1_only().build();
        let request = session
            .get("http://fixture.invalid/")
            .proxy("not a proxy URL");
        let error = if streaming {
            request.send_streaming().await.err().unwrap()
        } else {
            request.send().await.err().unwrap()
        };
        assert!(matches!(error, Error::InvalidConfig(_)), "{error:?}");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "invalid proxy must not route a request"
        );
    }
}

#[test]
fn user_issue_8_session_inherits_race_without_legacy_override() {
    let client = Client::builder()
        .protocol_policy(ProtocolPolicy::chrome_standard())
        .build();
    assert_eq!(
        client.session().build().protocol_policy(),
        client.protocol_policy()
    );
    let deterministic = client
        .session()
        .protocol_selection_policy(ProtocolSelectionPolicy::Deterministic)
        .build();
    assert_ne!(
        deterministic.protocol_policy().acquisition,
        client.protocol_policy().acquisition
    );
}

struct PendingDns;

#[async_trait]
impl DnsResolver for PendingDns {
    async fn resolve(&self, _: &str, _: u16) -> io::Result<Vec<SocketAddr>> {
        pending().await
    }
    async fn lookup_https(&self, _: &str) -> io::Result<Option<HttpsRecord>> {
        pending().await
    }
}

#[tokio::test]
async fn user_issue_9_client_dns_timeout_bounds_both_query_types() {
    let client = Client::builder()
        .dns_resolver(Arc::new(PendingDns))
        .dns_timeout(Duration::from_millis(20))
        .build();
    let addresses = tokio::time::timeout(
        Duration::from_millis(300),
        client.resolver().resolve("pending.invalid", 80),
    )
    .await
    .expect("address lookup must obey the configured DNS timeout")
    .unwrap_err();
    assert_eq!(addresses.kind(), io::ErrorKind::TimedOut);
    let https = tokio::time::timeout(
        Duration::from_millis(300),
        client.resolver().lookup_https("pending.invalid"),
    )
    .await
    .expect("HTTPS lookup must obey the configured DNS timeout")
    .unwrap_err();
    assert_eq!(https.kind(), io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn user_issue_9_builtin_dns_timeout_beats_resolver_retries() {
    let server = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let client = Client::builder()
        .dns(DnsConfig::Custom(server.local_addr().unwrap()))
        .dns_timeout(Duration::from_millis(30))
        .build();
    let resolve = client.resolver().resolve("silent.example.com", 80);
    tokio::pin!(resolve);
    let mut datagram = [0u8; 1500];
    tokio::select! {
        result = &mut resolve => panic!("resolver finished before query observation: {result:?}"),
        result = server.recv_from(&mut datagram) => { assert!(result.unwrap().0 > 12); }
        _ = tokio::time::sleep(Duration::from_secs(1)) => panic!("local DNS query missing"),
    }
    let error = tokio::time::timeout(Duration::from_millis(300), resolve)
        .await
        .expect("built-in DNS must honor client timeout before internal retries")
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn user_issue_9_disabled_dns_timeout_remains_unbounded() {
    let client = Client::builder()
        .dns_resolver(Arc::new(PendingDns))
        .timeout_config(TimeoutConfig::none())
        .build();
    assert!(tokio::time::timeout(
        Duration::from_millis(30),
        client.resolver().resolve("pending.invalid", 80)
    )
    .await
    .is_err());
}

#[tokio::test]
async fn user_issue_9_request_reports_dns_timeout_phase() {
    for streaming in [false, true] {
        let client = Client::builder()
            .dns_resolver(Arc::new(PendingDns))
            .dns_timeout(Duration::from_millis(20))
            .build();
        let session = client.session().http1_only().build();
        let request = session.get("http://pending.invalid/");
        let error = if streaming {
            request.send_streaming().await.err().unwrap()
        } else {
            request.send().await.err().unwrap()
        };
        assert!(error.is_timeout(), "{error:?}");
        assert_eq!(
            error.phase(),
            Some(lkrequest::error::ConnectionPhase::DnsResolution)
        );
    }
}

async fn read_head(stream: &mut tokio::net::TcpStream) {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 1);
        bytes.push(byte[0]);
        assert!(bytes.len() < 16384);
    }
}

#[tokio::test]
async fn user_issue_3_reused_h1_reset_reconnects() {
    for streaming in [false, true] {
        for (retry_enabled, post) in [(true, false), (false, false), (true, true)] {
            let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let seen = Arc::new(AtomicUsize::new(0));
            let server_seen = seen.clone();
            let server = tokio::spawn(async move {
                let (mut first, _) = listener.accept().await.unwrap();
                read_head(&mut first).await;
                server_seen.fetch_add(1, Ordering::SeqCst);
                first
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await
                    .unwrap();
                read_head(&mut first).await;
                server_seen.fetch_add(1, Ordering::SeqCst);
                socket2::SockRef::from(&first)
                    .set_linger(Some(Duration::ZERO))
                    .unwrap();
                drop(first);
                let (mut fresh, _) = listener.accept().await.unwrap();
                read_head(&mut fresh).await;
                server_seen.fetch_add(1, Ordering::SeqCst);
                fresh
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
            });
            let session = Client::builder()
                .retry_on_connection_close(retry_enabled)
                .build()
                .session()
                .http1_only()
                .build();
            let url = format!("http://{address}/reused");
            assert_eq!(
                session.get(&url).send().await.unwrap().status().as_u16(),
                200
            );
            let request = if post {
                session.post(&url)
            } else {
                session.get(&url)
            };
            let result = if streaming {
                request.send_streaming().await.map(|r| r.status())
            } else {
                request.send().await.map(|r| r.status())
            };
            server.abort();
            if retry_enabled && !post {
                assert!(
                    result.is_ok(),
                    "reused H1 should retry classified reset: {result:?}"
                );
                assert_eq!(seen.load(Ordering::SeqCst), 3);
            } else {
                assert!(
                    result.is_err(),
                    "disabled recovery and unsafe POST must not retry"
                );
                assert_eq!(seen.load(Ordering::SeqCst), 2);
            }
        }
    }
}
