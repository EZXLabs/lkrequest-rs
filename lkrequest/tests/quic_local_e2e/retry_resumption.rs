use super::*;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use lkrequest::protocol::{AcquisitionPolicy, FallbackPolicy, ProtocolPolicy, UpgradePolicy};
use lkrequest::retry::H3RetryMode;
use std::collections::HashSet;
use std::convert::Infallible;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use std::time::Duration;
use tracing_subscriber::prelude::*;

const LIMIT: Duration = Duration::from_secs(5);

#[derive(Default)]
struct EarlyEvents {
    ready: AtomicUsize,
    request_starts: AtomicUsize,
    accepted: AtomicUsize,
    rejected_or_failed: AtomicUsize,
    reused: AtomicUsize,
}

struct ObserveEarly(Arc<EarlyEvents>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for ObserveEarly {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Fields {
            accepted: Option<bool>,
            ready: bool,
            request_start: bool,
            reused: bool,
        }
        impl tracing::field::Visit for Fields {
            fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
                if field.name() == "accepted" {
                    self.accepted = Some(value);
                }
                if field.name() == "reused" {
                    self.reused = value;
                }
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" && format!("{value:?}") == "h3.connect_0rtt_ready" {
                    self.ready = true;
                }
                if field.name() == "message" && format!("{value:?}") == "h3.send_request_start" {
                    self.request_start = true;
                }
            }
        }
        let mut fields = Fields {
            accepted: None,
            ready: false,
            request_start: false,
            reused: false,
        };
        event.record(&mut fields);
        if event.metadata().target() == "lkh3::connection" && fields.ready {
            self.0.ready.fetch_add(1, Ordering::SeqCst);
        }
        if event.metadata().target() == "lkh3::sender" && fields.request_start {
            self.0.request_starts.fetch_add(1, Ordering::SeqCst);
        }
        if event.metadata().target() == "lkrequest::session::transport" {
            if fields.reused {
                self.0.reused.fetch_add(1, Ordering::SeqCst);
            }
            if let Some(accepted) = fields.accepted {
                let counter = if accepted {
                    &self.0.accepted
                } else {
                    &self.0.rejected_or_failed
                };
                counter.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ResumeAction {
    CloseHandshake,
    RejectEarlyData,
    RejectReducedLimits,
    RejectedSlowResponse,
    RejectRequestReset,
    AcceptRequestReset,
    RejectThenClose,
    HoldHandshake,
    AcceptedSlowResponse,
    BlockH3Control,
}

struct Peer {
    endpoint: Endpoint,
    tcp_tls: Arc<rustls::ServerConfig>,
    task: tokio::task::JoinHandle<()>,
    connections: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<(usize, String)>>>,
    request_streams: Arc<Mutex<Vec<(usize, u64)>>>,
    release_resume: Option<oneshot::Sender<()>>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.endpoint
            .close(0u32.into(), b"resumption fixture complete");
        self.task.abort();
    }
}

impl Peer {
    fn new(action: ResumeAction) -> Self {
        Self::with_socket(
            action,
            std::net::UdpSocket::bind(localhost_addr(0)).unwrap(),
        )
    }

    fn with_socket(action: ResumeAction, socket: std::net::UdpSocket) -> Self {
        ensure_rustls_provider();
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
            )
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.max_early_data_size = u32::MAX;
        let mut tcp_tls = tls.clone();
        tcp_tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        tcp_tls.max_early_data_size = 0;
        let mut rejecting_tls = tls.clone();
        rejecting_tls.max_early_data_size = 0;
        let mut config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
        if matches!(action, ResumeAction::BlockH3Control) {
            let mut transport = quinn::TransportConfig::default();
            transport.max_concurrent_uni_streams(0u32.into());
            config.transport_config(Arc::new(transport));
        }
        let mut rejecting = config.clone();
        rejecting.crypto = Arc::new(QuicServerConfig::try_from(rejecting_tls).unwrap());
        if matches!(action, ResumeAction::RejectReducedLimits) {
            let mut transport = quinn::TransportConfig::default();
            transport.stream_receive_window(32_768u32.into());
            rejecting.transport_config(Arc::new(transport));
        }
        socket.set_nonblocking(true).unwrap();
        let endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let request_streams = Arc::new(Mutex::new(Vec::new()));
        let (release_resume, resume_released) = oneshot::channel();
        let task = tokio::spawn({
            let endpoint = endpoint.clone();
            let connections = connections.clone();
            let requests = requests.clone();
            let request_streams = request_streams.clone();
            async move {
                let mut resume_released = Some(resume_released);
                let mut handlers = tokio::task::JoinSet::new();
                let mut initial_ids = HashSet::new();
                loop {
                    tokio::select! {
                        incoming = endpoint.accept() => {
                            let Some(incoming) = incoming else { break; };
                            if !initial_ids.insert(incoming.orig_dst_cid()) {
                                incoming.ignore();
                                continue;
                            }
                            let index = connections.fetch_add(1, Ordering::SeqCst);
                            if index == 0 && matches!(action, ResumeAction::RejectEarlyData | ResumeAction::RejectThenClose | ResumeAction::RejectReducedLimits | ResumeAction::RejectedSlowResponse | ResumeAction::RejectRequestReset) {
                                endpoint.set_server_config(Some(rejecting.clone()));
                            }
                            if index == 1 {
                                if resume_released.take().unwrap().await.is_err() { break; }
                                if matches!(action, ResumeAction::HoldHandshake) {
                                    incoming.ignore();
                                    continue;
                                }
                                if matches!(action, ResumeAction::CloseHandshake) {
                                    let (connection, _accepted) = incoming.accept().unwrap().into_0rtt()
                                        .unwrap_or_else(|_| panic!("server accepts a connection before handshake completion"));
                                    connection.close(258u32.into(), b"original resumed handshake failure");
                                    continue;
                                }
                            }
                            if index == 2 && matches!(action, ResumeAction::RejectThenClose) {
                                let (connection, _accepted) = incoming.accept().unwrap().into_0rtt()
                                    .unwrap_or_else(|_| panic!("replacement server connection is available before completion"));
                                connection.close(258u32.into(), b"replacement handshake failed");
                                continue;
                            }
                            let requests = requests.clone();
                            let request_streams = request_streams.clone();
                            handlers.spawn(async move {
                                let conn = incoming.await.unwrap();
                                let Ok(mut h3) = server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await else { return; };
                                while let Ok(Some(resolver)) = h3.accept().await {
                                    let Ok((request, mut stream)) = resolver.resolve_request().await else { break; };
                                    while stream.recv_data().await.unwrap().is_some() {}
                                    requests.lock().unwrap().push((index, request.uri().path().to_owned()));
                                    request_streams.lock().unwrap().push((index, stream.id().into_inner()));
                                    if request.uri().path() == "/case" && matches!(action, ResumeAction::RejectRequestReset | ResumeAction::AcceptRequestReset) {
                                        stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
                                        continue;
                                    }
                                    if request.uri().path() == "/case" && matches!(action, ResumeAction::AcceptedSlowResponse | ResumeAction::RejectedSlowResponse) {
                                        tokio::time::sleep(Duration::from_millis(450)).await;
                                    }
                                    stream.send_response(http::Response::new(())).await.unwrap();
                                    stream.send_data(Bytes::from_static(b"complete")).await.unwrap();
                                    stream.finish().await.unwrap();
                                }
                            });
                        }
                        result = handlers.join_next(), if !handlers.is_empty() => {
                            result.unwrap().expect("resumption peer handler must not panic");
                        }
                    }
                }
                handlers.shutdown().await;
            }
        });
        Self {
            endpoint,
            tcp_tls: Arc::new(tcp_tls),
            task,
            connections,
            requests,
            request_streams,
            release_resume: Some(release_resume),
        }
    }
}

struct TcpPeer {
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
    stop: Option<oneshot::Sender<()>>,
}

fn paired_peer(action: ResumeAction) -> (Peer, TcpPeer) {
    // Windows may reserve different ephemeral ranges for TCP and UDP.
    for _ in 0..1024 {
        let tcp = std::net::TcpListener::bind(localhost_addr(0)).unwrap();
        let udp = match std::net::UdpSocket::bind(tcp.local_addr().unwrap()) {
            Ok(socket) => socket,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                continue
            }
            Err(error) => panic!("paired fixture UDP bind failed: {error}"),
        };
        tcp.set_nonblocking(true).unwrap();
        let peer = Peer::with_socket(action, udp);
        let tcp = TcpPeer::new(&peer, tokio::net::TcpListener::from_std(tcp).unwrap());
        return (peer, tcp);
    }
    panic!("no shared loopback TCP/UDP port available");
}

impl Drop for TcpPeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TcpPeer {
    fn new(peer: &Peer, listener: tokio::net::TcpListener) -> Self {
        let acceptor = tokio_rustls::TlsAcceptor::from(peer.tcp_tls.clone());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn({
            let requests = requests.clone();
            async move {
                let mut handlers = tokio::task::JoinSet::new();
                tokio::pin!(stopped);
                loop {
                    tokio::select! {
                        _ = &mut stopped => break,
                        incoming = listener.accept() => {
                            let (socket, _) = incoming.unwrap();
                            let acceptor = acceptor.clone();
                            let requests = requests.clone();
                            handlers.spawn(async move {
                                let tls = acceptor.accept(socket).await.unwrap();
                                assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"http/1.1".as_slice()));
                                let service = service_fn(move |request: http::Request<Incoming>| {
                                    assert_eq!(request.version(), http::Version::HTTP_11);
                                    requests.lock().unwrap().push(request.uri().path().to_owned());
                                    async { Ok::<_, Infallible>(http::Response::new(Full::new(Bytes::from_static(b"tcp-complete")))) }
                                });
                                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(tls), service).await;
                            });
                        }
                        result = handlers.join_next(), if !handlers.is_empty() => {
                            result.unwrap().expect("TCP fallback peer must not panic");
                        }
                    }
                }
                handlers.shutdown().await;
            }
        });
        Self {
            requests,
            task,
            stop: Some(stop),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct FallbackCase {
    action: ResumeAction,
    mode: H3RetryMode,
    fallback: FallbackPolicy,
    early: bool,
    request_h3_only: bool,
    streaming: bool,
    race: bool,
}

struct AdvertisedH3Dns {
    port: u16,
}

#[async_trait]
impl lkrequest::DnsResolver for AdvertisedH3Dns {
    async fn resolve(&self, _host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(vec![localhost_addr(port)])
    }
    async fn lookup_https(&self, _host: &str) -> std::io::Result<Option<lkrequest::HttpsRecord>> {
        Ok(Some(lkrequest::HttpsRecord {
            alpn: vec!["h3".into()],
            port: Some(self.port),
            ..Default::default()
        }))
    }
}

impl Default for FallbackCase {
    fn default() -> Self {
        Self {
            action: ResumeAction::CloseHandshake,
            mode: H3RetryMode::Safe,
            fallback: FallbackPolicy::AllowFallback,
            early: true,
            request_h3_only: false,
            streaming: false,
            race: false,
        }
    }
}

async fn late_fallback(case: FallbackCase) -> usize {
    let events = Arc::new(EarlyEvents::default());
    let _subscriber = tracing::subscriber::set_default(
        tracing_subscriber::registry().with(ObserveEarly(events.clone())),
    );
    tokio::time::timeout(LIMIT, async {
        let (mut peer, mut tcp) = paired_peer(case.action);
        let url = format!("https://localhost:{}", peer.endpoint.local_addr().unwrap().port());
        let resolver = Arc::new(AdvertisedH3Dns { port: peer.endpoint.local_addr().unwrap().port() });
        let mut profile = lkh3::chrome_155_quic();
        if matches!(case.action, ResumeAction::RejectThenClose) {
            profile.packetization.reuse_rejected_0rtt_streams = false;
        }
        let client = lkrequest::Client::builder()
            .preset(lkrequest::preset::chrome_155())
            .quic_profile(profile)
            .tls_session_cache_partition_policy(lkrequest::TlsSessionCachePartitionPolicy::Unpartitioned)
            .dns_resolver(resolver)
            .retry_on_connection_close(false)
            .timeout_config(lkrequest::TimeoutConfig::default()
                .with_quic_connect_timeout(Duration::from_millis(200))
                .with_ttfb_timeout(Duration::from_secs(2))
                .with_total_timeout(Duration::from_secs(3)))
            .verify(false).build();
        let warm = client.session().http3_only().build();
        assert_eq!(warm.get(&format!("{url}/warm")).send().await.unwrap().bytes(), b"complete");
        drop(warm);
        let session = client.session().http3_with_fallback()
            .protocol_policy(ProtocolPolicy::chrome_standard()
                .with_acquisition(if case.race { AcquisitionPolicy::Race(lkrequest::protocol::RacePolicy::chrome_like().with_tcp_delay(Duration::from_secs(1))) } else { AcquisitionPolicy::EstablishBestAvailable })
                .with_upgrade(UpgradePolicy::Off)
                .with_fallback(case.fallback))
            .max_connections(1).h3_retry_mode(case.mode).build();
        let request = tokio::spawn({
            let session = session.clone();
            let url = format!("{url}/case");
            async move {
                let mut request = session.get(&url).preferred_http_version(lkrequest::PreferredHttpVersion::Http3WithFallback);
                if !case.early { request = request.idempotency(lkrequest::Idempotency::NotIdempotent); }
                if case.request_h3_only { request = request.preferred_http_version(lkrequest::PreferredHttpVersion::Http3Only); }
                if case.streaming {
                    let response = request.send_streaming().await?;
                    Ok((None, response.bytes().await?))
                } else {
                    let response = request.send().await?;
                    Ok((Some(response.version()), Bytes::copy_from_slice(response.bytes())))
                }
            }
        });
        while peer.connections.load(Ordering::SeqCst) < 2 || (case.early && events.ready.load(Ordering::SeqCst) == 0) {
            assert!(!request.is_finished(), "the controlled handshake must be reached");
            tokio::task::yield_now().await;
        }
        if case.race {
            while events.request_starts.load(Ordering::SeqCst) < 2 {
                assert!(!request.is_finished(), "the resumed request must pass the QUIC race gate");
                tokio::task::yield_now().await;
            }
            assert!(tcp.requests.lock().unwrap().is_empty());
        }
        if !matches!(case.action, ResumeAction::HoldHandshake) {
            peer.release_resume.take().unwrap().send(()).unwrap();
        }
        let result = request.await.unwrap();
        let tcp_requests = tcp.requests.lock().unwrap().clone();
        eprintln!("late fallback {case:?}: early_ready={} connections={} h3_requests={:?} tcp={tcp_requests:?} result={:?}",
            events.ready.load(Ordering::SeqCst), peer.connections.load(Ordering::SeqCst), peer.requests.lock().unwrap(),
            result.as_ref().map(|r| r.0).map_err(|e: &lkrequest::error::Error| e.to_string()));
        assert_eq!(events.ready.load(Ordering::SeqCst), usize::from(case.early));
        assert_eq!(*peer.requests.lock().unwrap(), [(0, "/warm".to_owned())]);
        let expected_connections = if matches!(case.action, ResumeAction::RejectThenClose) { 3 } else { 2 };
        assert_eq!(peer.connections.load(Ordering::SeqCst), expected_connections, "no hidden QUIC replay");
        if case.race { assert_eq!(events.request_starts.load(Ordering::SeqCst), 2); }
        let allowed = case.fallback != FallbackPolicy::NoFallback && !case.request_h3_only;
        if allowed {
            let response = result.expect("permitted handshake failure must use the available TCP route");
            assert_eq!(response.0, if case.streaming { None } else { Some(lkrequest::HttpVersion::Http11) });
            assert_eq!(response.1.as_ref(), b"tcp-complete");
            assert_eq!(tcp_requests, ["/case"]);
        } else {
            let error = result.expect_err("strict request or NoFallback must preserve the QUIC failure");
            assert_eq!(error.phase(), Some(lkrequest::error::ConnectionPhase::QuicHandshake));
            assert!(tcp_requests.is_empty());
        }
        if matches!(case.action, ResumeAction::HoldHandshake) {
            peer.release_resume.take().unwrap().send(()).unwrap();
        }
        session.pool_clear();
        let next = session.get(&format!("{url}/after"));
        let next = next.preferred_http_version(if allowed { lkrequest::PreferredHttpVersion::Http3WithFallback } else { lkrequest::PreferredHttpVersion::Http1Only });
        assert_eq!(next.send().await.unwrap().bytes(), b"tcp-complete");
        assert_eq!(peer.connections.load(Ordering::SeqCst), expected_connections, "cooldown or explicit TCP must avoid another QUIC dial");
        drop(session);
        drop(client);
        peer.endpoint.close(0u32.into(), b"fallback fixture complete");
        peer.endpoint.wait_idle().await;
        (&mut peer.task).await.unwrap();
        tcp.stop.take().unwrap().send(()).unwrap();
        (&mut tcp.task).await.unwrap();
        tcp_requests.len()
    }).await.expect("late handshake fallback fixture finishes")
}

#[tokio::test]
async fn h3_late_handshake_close_falls_back_with_one_connection_slot() {
    assert_eq!(late_fallback(FallbackCase::default()).await, 1);
}

#[tokio::test]
async fn h3_late_handshake_close_falls_back_in_chrome_mode() {
    assert_eq!(
        late_fallback(FallbackCase {
            mode: H3RetryMode::Chrome155ProtocolErrors,
            ..Default::default()
        })
        .await,
        1
    );
}

#[tokio::test]
async fn h3_late_handshake_close_obeys_network_only_fallback() {
    assert_eq!(
        late_fallback(FallbackCase {
            fallback: FallbackPolicy::AllowFallbackOnNetworkErrors,
            ..Default::default()
        })
        .await,
        1
    );
}

#[tokio::test]
async fn h3_late_handshake_close_obeys_no_fallback() {
    assert_eq!(
        late_fallback(FallbackCase {
            fallback: FallbackPolicy::NoFallback,
            ..Default::default()
        })
        .await,
        0
    );
}

#[tokio::test]
async fn h3_late_handshake_close_obeys_request_h3_only() {
    assert_eq!(
        late_fallback(FallbackCase {
            request_h3_only: true,
            ..Default::default()
        })
        .await,
        0
    );
}

#[tokio::test]
async fn h3_confirmed_path_handshake_close_falls_back_control() {
    assert_eq!(
        late_fallback(FallbackCase {
            early: false,
            ..Default::default()
        })
        .await,
        1
    );
}

#[tokio::test]
async fn h3_confirmed_path_handshake_close_obeys_request_h3_only() {
    assert_eq!(
        late_fallback(FallbackCase {
            early: false,
            request_h3_only: true,
            ..Default::default()
        })
        .await,
        0
    );
}

#[tokio::test]
async fn h3_late_handshake_timeout_obeys_network_only_fallback() {
    assert_eq!(
        late_fallback(FallbackCase {
            action: ResumeAction::HoldHandshake,
            fallback: FallbackPolicy::AllowFallbackOnNetworkErrors,
            ..Default::default()
        })
        .await,
        1
    );
}

#[tokio::test]
async fn h3_confirmed_path_handshake_timeout_obeys_network_only_fallback() {
    assert_eq!(
        late_fallback(FallbackCase {
            action: ResumeAction::HoldHandshake,
            early: false,
            fallback: FallbackPolicy::AllowFallbackOnNetworkErrors,
            ..Default::default()
        })
        .await,
        1
    );
}

#[tokio::test]
async fn h3_streaming_handshake_close_falls_back_control() {
    assert_eq!(
        late_fallback(FallbackCase {
            early: false,
            streaming: true,
            ..Default::default()
        })
        .await,
        1
    );
}

#[tokio::test]
async fn h3_streaming_handshake_close_obeys_request_h3_only() {
    assert_eq!(
        late_fallback(FallbackCase {
            early: false,
            streaming: true,
            request_h3_only: true,
            ..Default::default()
        })
        .await,
        0
    );
}

#[tokio::test]
async fn h3_streaming_handshake_timeout_obeys_network_only_fallback() {
    assert_eq!(
        late_fallback(FallbackCase {
            action: ResumeAction::HoldHandshake,
            early: false,
            streaming: true,
            fallback: FallbackPolicy::AllowFallbackOnNetworkErrors,
            ..Default::default()
        })
        .await,
        1
    );
}

#[tokio::test]
async fn h3_selected_early_race_handshake_failure_falls_back_once() {
    assert_eq!(
        late_fallback(FallbackCase {
            race: true,
            ..Default::default()
        })
        .await,
        1
    );
}

#[tokio::test]
async fn h3_selected_early_race_handshake_timeout_falls_back_once() {
    assert_eq!(
        late_fallback(FallbackCase {
            action: ResumeAction::HoldHandshake,
            race: true,
            ..Default::default()
        })
        .await,
        1
    );
}

#[tokio::test]
async fn h3_selected_early_race_handshake_failure_obeys_no_fallback() {
    assert_eq!(
        late_fallback(FallbackCase {
            race: true,
            fallback: FallbackPolicy::NoFallback,
            ..Default::default()
        })
        .await,
        0
    );
}

#[tokio::test]
async fn h3_rejected_early_replacement_handshake_failure_falls_back() {
    assert_eq!(
        late_fallback(FallbackCase {
            action: ResumeAction::RejectThenClose,
            ..Default::default()
        })
        .await,
        1
    );
}

#[tokio::test]
async fn h3_rejected_early_replacement_handshake_failure_obeys_no_fallback() {
    assert_eq!(
        late_fallback(FallbackCase {
            action: ResumeAction::RejectThenClose,
            fallback: FallbackPolicy::NoFallback,
            ..Default::default()
        })
        .await,
        0
    );
}

#[tokio::test]
async fn h3_rejected_early_replacement_preserves_selected_race_owner() {
    assert_eq!(
        late_fallback(FallbackCase {
            action: ResumeAction::RejectThenClose,
            race: true,
            ..Default::default()
        })
        .await,
        1
    );
}

async fn resumed_failure(action: ResumeAction, mode: H3RetryMode) -> usize {
    resumed_failure_with_reuse(action, mode, true).await
}

async fn resumed_failure_with_reuse(action: ResumeAction, mode: H3RetryMode, reuse: bool) -> usize {
    let events = Arc::new(EarlyEvents::default());
    let subscriber = tracing_subscriber::registry().with(ObserveEarly(events.clone()));
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tokio::time::timeout(LIMIT, async {
        let mut peer = Peer::new(action);
        let url = format!("https://localhost:{}", peer.endpoint.local_addr().unwrap().port());
        let mut profile = lkh3::chrome_155_quic();
        profile.packetization.reuse_rejected_0rtt_streams = reuse;
        let client = lkrequest::Client::builder()
            .preset(lkrequest::preset::chrome_155())
            .quic_profile(profile)
            .tls_session_cache_partition_policy(lkrequest::TlsSessionCachePartitionPolicy::Unpartitioned)
            .dns_resolver(Arc::new(LocalIpv4Dns))
            .retry_on_connection_close(false)
            .timeout_config(lkrequest::TimeoutConfig::default()
                .with_quic_connect_timeout(Duration::from_millis(200))
                .with_ttfb_timeout(Duration::from_secs(2))
                .with_total_timeout(Duration::from_secs(3)))
            .verify(false)
            .build();
        let warm = client.session().http3_only().build();
        assert_eq!(warm.get(&format!("{url}/warm")).send().await.unwrap().bytes(), b"complete");
        drop(warm);
        let session = client.session().http3_only().max_connections(1).h3_retry_mode(mode).build();
        let started = std::time::Instant::now();
        let request = tokio::spawn({
            let session = session.clone();
            let url = format!("{url}/case");
            async move { session.get(&url).send().await }
        });
        while events.ready.load(Ordering::SeqCst) == 0 {
            assert!(!request.is_finished(), "a real ticket must enter the early H3 path");
            tokio::task::yield_now().await;
        }
        if !matches!(action, ResumeAction::HoldHandshake) {
            peer.release_resume.take().unwrap().send(()).unwrap();
        }
        let result = request.await.unwrap();
        let elapsed = started.elapsed();
        let connections = peer.connections.load(Ordering::SeqCst);
        let requests = peer.requests.lock().unwrap().clone();
        eprintln!("resumption action={action:?} mode={mode:?} connections={connections} requests={requests:?} elapsed={elapsed:?} accepted={} rejected_or_failed={} result={:?}",
            events.accepted.load(Ordering::SeqCst), events.rejected_or_failed.load(Ordering::SeqCst), result.as_ref().map(|r| r.status()).map_err(ToString::to_string));
        assert_eq!(events.accepted.load(Ordering::SeqCst), usize::from(matches!(action, ResumeAction::AcceptedSlowResponse | ResumeAction::AcceptRequestReset)));
        assert_eq!(events.rejected_or_failed.load(Ordering::SeqCst), usize::from(matches!(action, ResumeAction::CloseHandshake | ResumeAction::RejectEarlyData | ResumeAction::RejectReducedLimits | ResumeAction::RejectedSlowResponse | ResumeAction::RejectRequestReset)));
        let reused = reuse && matches!(action, ResumeAction::RejectEarlyData | ResumeAction::RejectedSlowResponse | ResumeAction::RejectRequestReset);
        assert_eq!(events.reused.load(Ordering::SeqCst), usize::from(reused));
        match action {
            ResumeAction::CloseHandshake => {
                let error = result.expect_err("a failed resumed handshake is not a successful early-data rejection");
                assert!(error.is_quic_handshake_failure(), "retain original handshake failure: {error:?}");
                assert!(error.to_string().contains("aborted by peer"));
                assert!(error.h3_request_context().is_none(), "a failed handshake is not an accepted HTTP request error");
                assert_eq!(connections, 2, "retry_on_connection_close=false must prevent hidden redial");
                assert_eq!(requests, [(0, "/warm".to_owned())]);
                assert_eq!(session.get(&format!("{url}/after")).send().await.unwrap().bytes(), b"complete");
                assert_eq!(peer.connections.load(Ordering::SeqCst), 3, "failed early reservation must release the single permit");
            }
            ResumeAction::RejectEarlyData | ResumeAction::RejectReducedLimits | ResumeAction::RejectedSlowResponse => {
                assert_eq!(result.unwrap().bytes(), b"complete");
                let target = if reused { 1 } else { 2 };
                assert_eq!(connections, target + 1);
                assert_eq!(requests, [(0, "/warm".to_owned()), (target, "/case".to_owned())]);
                assert_eq!(*peer.request_streams.lock().unwrap(), [(0, 0), (target, 0)]);
                if matches!(action, ResumeAction::RejectedSlowResponse) {
                    assert!(elapsed >= Duration::from_millis(450));
                }
                assert_eq!(session.get(&format!("{url}/after")).send().await.unwrap().bytes(), b"complete");
                assert_eq!(peer.connections.load(Ordering::SeqCst), connections, "recovered H3 must be pooled with its original permit");
                assert_eq!(peer.requests.lock().unwrap().last().unwrap(), &(target, "/after".to_owned()));
                assert_eq!(peer.request_streams.lock().unwrap().last(), Some(&(target, 4)));
            }
            ResumeAction::HoldHandshake => {
                let error = result.expect_err("uncompleted resumed handshake must reach its own deadline");
                assert_eq!(error.phase(), Some(lkrequest::error::ConnectionPhase::QuicHandshake));
                assert!(elapsed < Duration::from_millis(1200), "200ms handshake budget must precede 2s TTFB: {elapsed:?}");
                assert_eq!(connections, 2);
                assert_eq!(requests, [(0, "/warm".to_owned())]);
                peer.release_resume.take().unwrap().send(()).unwrap();
                assert_eq!(session.get(&format!("{url}/after")).send().await.unwrap().bytes(), b"complete");
            }
            ResumeAction::AcceptedSlowResponse => {
                assert_eq!(result.unwrap().bytes(), b"complete");
                assert!(elapsed >= Duration::from_millis(450));
                assert_eq!(connections, 2);
                assert_eq!(requests, [(0, "/warm".to_owned()), (1, "/case".to_owned())]);
            }
            ResumeAction::RejectRequestReset | ResumeAction::AcceptRequestReset => {
                let error = result.expect_err("every application attempt receives a response RESET");
                assert_eq!(error.h3_request_context().is_some(), mode == H3RetryMode::Chrome155ProtocolErrors, "retain each mode's request error contract: {error:?}");
                assert!(!error.is_quic_handshake_failure(), "request RESET is not handshake rejection: {error:?}");
                let attempts = if mode == H3RetryMode::Safe { 1 } else { 3 };
                assert_eq!(connections, 2, "request-level retries stay on the usable original H3 connection");
                let expected_requests: Vec<_> = std::iter::once((0, "/warm".to_owned()))
                    .chain((0..attempts).map(|_| (1, "/case".to_owned()))).collect();
                assert_eq!(requests, expected_requests);
                let expected_streams: Vec<_> = std::iter::once((0, 0))
                    .chain((0..attempts).map(|i| (1, i * 4))).collect();
                assert_eq!(*peer.request_streams.lock().unwrap(), expected_streams);
                assert_eq!(session.get(&format!("{url}/after")).send().await.unwrap().bytes(), b"complete");
                assert_eq!(peer.connections.load(Ordering::SeqCst), 2);
            }
            ResumeAction::BlockH3Control | ResumeAction::RejectThenClose => unreachable!("this action has a dedicated fixture"),
        }
        drop(session);
        drop(client);
        peer.endpoint.close(0u32.into(), b"resumption fixture complete");
        peer.endpoint.wait_idle().await;
        (&mut peer.task).await.expect("all peer handlers must finish before the test observer");
        connections
    }).await.expect("resumption controls must finish")
}

async fn control_setup_timeout(streaming: bool) -> usize {
    tokio::time::timeout(LIMIT, async {
        let (mut peer, mut tcp) = paired_peer(ResumeAction::BlockH3Control);
        let port = peer.endpoint.local_addr().unwrap().port();
        let session = lkrequest::Client::builder()
            .preset(lkrequest::preset::chrome_155())
            .dns_resolver(Arc::new(AdvertisedH3Dns { port }))
            .timeout_config(
                lkrequest::TimeoutConfig::default()
                    .with_quic_connect_timeout(Duration::from_millis(200)),
            )
            .retry_on_connection_close(false)
            .verify(false)
            .build()
            .session()
            .protocol_policy(
                ProtocolPolicy::chrome_standard()
                    .with_acquisition(AcquisitionPolicy::EstablishBestAvailable)
                    .with_upgrade(UpgradePolicy::Off)
                    .with_fallback(FallbackPolicy::AllowFallbackOnNetworkErrors),
            )
            .max_connections(1)
            .build();
        let url = format!("https://localhost:{port}/case");
        let error = if streaming {
            session
                .get(&url)
                .send_streaming()
                .await
                .map(|_| ())
                .expect_err("H3 control setup must time out")
        } else {
            session
                .get(&url)
                .send()
                .await
                .expect_err("H3 control setup must time out")
        };
        eprintln!(
            "H3 control setup streaming={streaming} phase={:?} error={error}",
            error.phase()
        );
        assert_eq!(
            error.phase(),
            Some(lkrequest::error::ConnectionPhase::H3Negotiation)
        );
        assert!(!error.is_quic_handshake_failure());
        assert!(peer.requests.lock().unwrap().is_empty());
        assert!(
            tcp.requests.lock().unwrap().is_empty(),
            "post-handshake H3 negotiation is not a network handshake failure"
        );
        let count = peer.connections.load(Ordering::SeqCst);
        drop(session);
        peer.endpoint
            .close(0u32.into(), b"H3 setup fixture complete");
        peer.endpoint.wait_idle().await;
        (&mut peer.task).await.unwrap();
        tcp.stop.take().unwrap().send(()).unwrap();
        (&mut tcp.task).await.unwrap();
        count
    })
    .await
    .expect("H3 setup control finishes")
}

#[tokio::test]
async fn h3_post_handshake_control_timeout_has_negotiation_phase() {
    assert_eq!(control_setup_timeout(false).await, 1);
}

#[tokio::test]
async fn h3_streaming_post_handshake_control_timeout_has_negotiation_phase() {
    assert_eq!(control_setup_timeout(true).await, 1);
}

#[tokio::test]
async fn h3_failed_zero_rtt_handshake_is_not_replayed_as_rejection() {
    assert_eq!(
        resumed_failure(ResumeAction::CloseHandshake, H3RetryMode::Safe).await,
        2
    );
}

#[tokio::test]
async fn h3_failed_zero_rtt_handshake_is_not_a_chrome_protocol_retry() {
    assert_eq!(
        resumed_failure(
            ResumeAction::CloseHandshake,
            H3RetryMode::Chrome155ProtocolErrors,
        )
        .await,
        2
    );
}

#[tokio::test]
async fn h3_real_zero_rtt_rejection_still_recovers_once() {
    assert_eq!(
        resumed_failure(ResumeAction::RejectEarlyData, H3RetryMode::Safe).await,
        2
    );
}

#[tokio::test]
async fn h3_real_zero_rtt_rejection_recovers_in_chrome_mode() {
    assert_eq!(
        resumed_failure(
            ResumeAction::RejectEarlyData,
            H3RetryMode::Chrome155ProtocolErrors,
        )
        .await,
        2
    );
}

#[tokio::test]
async fn h3_zero_rtt_reuse_disabled_keeps_replacement_recovery() {
    assert_eq!(
        resumed_failure_with_reuse(ResumeAction::RejectEarlyData, H3RetryMode::Safe, false).await,
        3
    );
}

#[tokio::test]
async fn h3_zero_rtt_reduced_peer_limits_keep_replacement_recovery() {
    assert_eq!(
        resumed_failure(ResumeAction::RejectReducedLimits, H3RetryMode::Safe).await,
        3
    );
}

#[tokio::test]
async fn h3_rejected_reused_response_outlives_handshake_budget() {
    assert_eq!(
        resumed_failure(ResumeAction::RejectedSlowResponse, H3RetryMode::Safe).await,
        2
    );
}

#[tokio::test]
async fn h3_rejected_reused_reset_keeps_safe_attempt_budget() {
    assert_eq!(
        resumed_failure(ResumeAction::RejectRequestReset, H3RetryMode::Safe).await,
        2
    );
}

#[tokio::test]
async fn h3_rejected_reused_reset_keeps_chrome_attempt_budget() {
    assert_eq!(
        resumed_failure(
            ResumeAction::RejectRequestReset,
            H3RetryMode::Chrome155ProtocolErrors
        )
        .await,
        2
    );
}

#[tokio::test]
async fn h3_accepted_early_reset_keeps_safe_attempt_budget() {
    assert_eq!(
        resumed_failure(ResumeAction::AcceptRequestReset, H3RetryMode::Safe).await,
        2
    );
}

#[tokio::test]
async fn h3_accepted_early_reset_keeps_chrome_attempt_budget() {
    assert_eq!(
        resumed_failure(
            ResumeAction::AcceptRequestReset,
            H3RetryMode::Chrome155ProtocolErrors
        )
        .await,
        2
    );
}

#[tokio::test]
async fn h3_pending_zero_rtt_acceptance_obeys_handshake_timeout() {
    assert_eq!(
        resumed_failure(ResumeAction::HoldHandshake, H3RetryMode::Safe).await,
        2
    );
}

#[tokio::test]
async fn h3_pending_zero_rtt_acceptance_obeys_handshake_timeout_in_chrome_mode() {
    assert_eq!(
        resumed_failure(
            ResumeAction::HoldHandshake,
            H3RetryMode::Chrome155ProtocolErrors,
        )
        .await,
        2
    );
}

#[tokio::test]
async fn h3_accepted_zero_rtt_response_outlives_handshake_budget() {
    assert_eq!(
        resumed_failure(ResumeAction::AcceptedSlowResponse, H3RetryMode::Safe).await,
        2
    );
}

#[tokio::test]
async fn h3_accepted_zero_rtt_response_outlives_handshake_budget_in_chrome_mode() {
    assert_eq!(
        resumed_failure(
            ResumeAction::AcceptedSlowResponse,
            H3RetryMode::Chrome155ProtocolErrors,
        )
        .await,
        2
    );
}
