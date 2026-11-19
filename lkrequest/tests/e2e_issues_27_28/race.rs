use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use lkrequest::dns::{DnsResolver, HttpsRecord};
use lkrequest::{
    AcquisitionPolicy, Client, FallbackPolicy, HttpIntent, HttpVersion, ProtocolPolicy, RacePolicy,
    UpgradePolicy,
};
use tokio::task::{JoinHandle, JoinSet};

use super::support::{bounded, server_tls, HttpsServer};

struct LoopbackDns;

#[async_trait]
impl DnsResolver for LoopbackDns {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        assert_eq!(
            host, "service.test",
            "the probe must not resolve public hosts"
        );
        Ok(vec![(Ipv4Addr::LOCALHOST, port).into()])
    }
    async fn lookup_https(&self, host: &str) -> io::Result<Option<HttpsRecord>> {
        assert_eq!(host, "service.test");
        Ok(Some(HttpsRecord {
            alpn: vec!["h3".into(), "h2".into()],
            ..HttpsRecord::default()
        }))
    }
}

struct H3Peer {
    endpoint: quinn::Endpoint,
    task: JoinHandle<()>,
    requests: Arc<AtomicUsize>,
    accepts: Arc<AtomicUsize>,
}

impl H3Peer {
    fn start(socket: std::net::UdpSocket) -> Self {
        let crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls(&[b"h3"])).unwrap();
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(quinn::ServerConfig::with_crypto(Arc::new(crypto))),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn({
            let endpoint = endpoint.clone();
            let accepts = accepts.clone();
            let requests = requests.clone();
            async move {
                let mut handlers = JoinSet::new();
                loop {
                    tokio::select! {
                        incoming = endpoint.accept() => {
                            let Some(incoming) = incoming else { break };
                            accepts.fetch_add(1, Ordering::SeqCst);
                            let requests = requests.clone();
                            handlers.spawn(async move {
                                let connection = incoming.await.unwrap();
                                let mut server = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection)).await.unwrap();
                                let mut streams = JoinSet::new();
                                while let Ok(Some(resolver)) = server.accept().await {
                                    let requests = requests.clone();
                                    streams.spawn(async move {
                                        let (_, mut stream) = resolver.resolve_request().await.unwrap();
                                        while stream.recv_data().await.unwrap().is_some() {}
                                        requests.fetch_add(1, Ordering::SeqCst);
                                        stream.send_response(http::Response::new(())).await.unwrap();
                                        stream.send_data(Bytes::from_static(b"ok")).await.unwrap();
                                        stream.finish().await.unwrap();
                                    });
                                }
                                while let Some(result) = streams.join_next().await { result.unwrap(); }
                            });
                        }
                        Some(result) = handlers.join_next(), if !handlers.is_empty() => {
                            result.expect("H3 peer panicked");
                        }
                    }
                }
            }
        });
        Self {
            endpoint,
            task,
            requests,
            accepts,
        }
    }
}

impl Drop for H3Peer {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"probe complete");
        self.task.abort();
    }
}

async fn check(intent: HttpIntent, tcp: bool, quic: bool, expected: HttpVersion) -> HttpVersion {
    bounded(async {
        // Keep rejected TCP reservations alive so Windows cannot repeatedly
        // hand out the same port from a UDP exclusion range.
        let mut rejected = Vec::new();
        let (socket, listener) = loop {
            let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            match std::net::UdpSocket::bind(listener.local_addr().unwrap()) {
                Ok(socket) => break (socket, listener),
                Err(error) if matches!(error.kind(), io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied) => {
                    rejected.push(listener);
                    assert!(rejected.len() < 1024, "cannot allocate a TCP/UDP fixture port: {error}");
                }
                Err(error) => panic!("UDP fixture bind failed: {error}"),
            }
        };
        drop(rejected);
        let quic_peer = H3Peer::start(socket);
        let tcp_peer = HttpsServer::from_listener(listener, false, Duration::ZERO, false).await;
        let mut race = RacePolicy::chrome_like();
        race.enable_tcp = tcp;
        race.enable_quic = quic;
        race.tcp_delay = Duration::ZERO;
        let policy = ProtocolPolicy::new(intent, AcquisitionPolicy::Race(race), UpgradePolicy::Off, FallbackPolicy::NoFallback);
        policy.validate().expect("single-sided race is a valid policy");
        let client = Client::builder()
            .preset(lkrequest::preset::chrome_146())
            .dns_resolver(Arc::new(LoopbackDns))
            .verify(false)
            .protocol_policy(policy)
            .total_timeout(Duration::from_secs(10))
            .build();
        let session = client.session().build();
        let response = session.get(&format!("https://service.test:{}/get", tcp_peer.addr.port())).send().await.unwrap();
        let tcp_accepts = tcp_peer.accepts.load(Ordering::SeqCst);
        let quic_accepts = quic_peer.accepts.load(Ordering::SeqCst);
        eprintln!("intent={intent:?} enable_tcp={tcp} enable_quic={quic} response={:?} TCP_accepts={tcp_accepts} QUIC_accepts={quic_accepts}", response.version());
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.bytes(), b"ok");
        if expected == HttpVersion::H2 {
            assert_eq!(quic_accepts, 0);
            assert_eq!(tcp_peer.requests.load(Ordering::SeqCst), 1);
        } else {
            assert_eq!(tcp_accepts, 0);
            assert_eq!(quic_peer.requests.load(Ordering::SeqCst), 1);
        }
        response.version()
    }).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue27_1_acquire_h3_tcp_only_must_use_h2() {
    assert_eq!(
        check(
            HttpIntent::AcquireH3WhenViable,
            true,
            false,
            HttpVersion::H2,
        )
        .await,
        HttpVersion::H2
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn issue27_1_reuse_existing_quic_only_must_use_h3() {
    assert_eq!(
        check(
            HttpIntent::ReuseExistingProtocol,
            false,
            true,
            HttpVersion::H3,
        )
        .await,
        HttpVersion::H3
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_acquire_h3_quic_only_uses_h3() {
    assert_eq!(
        check(
            HttpIntent::AcquireH3WhenViable,
            false,
            true,
            HttpVersion::H3,
        )
        .await,
        HttpVersion::H3
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_reuse_existing_tcp_only_uses_h2() {
    assert_eq!(
        check(
            HttpIntent::ReuseExistingProtocol,
            true,
            false,
            HttpVersion::H2,
        )
        .await,
        HttpVersion::H2
    );
}
