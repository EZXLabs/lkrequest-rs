use super::*;
use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use lkrequest::{
    protocol::{AcquisitionPolicy, FallbackPolicy, HttpIntent, ProtocolPolicy, UpgradePolicy},
    retry::H3RetryMode,
    PreferredHttpVersion,
};
use std::{
    convert::Infallible,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
    time::Duration,
};
use tokio::{net::TcpListener, task::JoinSet};

const LIMIT: Duration = Duration::from_secs(5);
const POST_BODY: &[u8] = b"finite-post-routing";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Reset,
    H3Redirect,
    TcpRedirect,
}

#[derive(Clone, Debug)]
struct Attempt {
    protocol: &'static str,
    connection: usize,
    stream: Option<u64>,
    path: String,
    method: http::Method,
    body: Vec<u8>,
}

struct Peer {
    endpoint: Endpoint,
    certificate: Vec<u8>,
    attempts: Arc<Mutex<Vec<Attempt>>>,
    tcp_connections: Arc<AtomicUsize>,
    tcp_ready: mpsc::UnboundedReceiver<oneshot::Sender<()>>,
    tasks: JoinSet<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.endpoint
            .close(0u32.into(), b"routing fixture complete");
        self.tasks.abort_all();
    }
}

impl Peer {
    async fn new(scenario: Scenario, gate_tcp: bool) -> Self {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = cert.cert.der().to_vec();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )
        .unwrap();
        tls.send_tls13_tickets = 0;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tcp_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls.clone()));
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
        let mut bound = None;
        // Windows can exclude UDP ports that are available to the TCP allocator.
        for _ in 0..128 {
            let listener = TcpListener::bind(localhost_addr(0)).await.unwrap();
            let address = listener.local_addr().unwrap();
            match Endpoint::server(config.clone(), address) {
                Ok(endpoint) => {
                    bound = Some((listener, endpoint));
                    break;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    eprintln!("routing fixture port {address} unavailable for UDP: {error}");
                }
                Err(error) => panic!("routing fixture UDP bind failed: {error}"),
            }
        }
        let (tcp_listener, endpoint) =
            bound.expect("a shared loopback TCP/UDP port must be available");
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let tcp_connections = Arc::new(AtomicUsize::new(0));
        let (tcp_tx, tcp_ready) = mpsc::unbounded_channel();
        let mut tasks = JoinSet::new();
        tasks.spawn({
            let attempts = attempts.clone();
            let tcp_connections = tcp_connections.clone();
            async move {
                let mut connections = JoinSet::new();
                let mut next_connection = 0;
                loop {
                    tokio::select! {
                        accepted = tcp_listener.accept() => {
                            let (socket, _) = accepted.unwrap();
                            tcp_connections.fetch_add(1, Ordering::SeqCst);
                            let id = next_connection;
                            next_connection += 1;
                            let acceptor = tcp_acceptor.clone();
                            let attempts = attempts.clone();
                            let tcp_tx = tcp_tx.clone();
                            connections.spawn(async move {
                                let tls = acceptor.accept(socket).await.unwrap();
                                assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"http/1.1".as_slice()));
                                let service = service_fn(move |request: http::Request<Incoming>| {
                                    let attempts = attempts.clone();
                                    let tcp_tx = tcp_tx.clone();
                                    async move {
                                        assert_eq!(request.version(), http::Version::HTTP_11);
                                        let path = request.uri().path().to_owned();
                                        let method = request.method().clone();
                                        let body = request.into_body().collect().await.unwrap().to_bytes();
                                        attempts.lock().unwrap().push(Attempt {
                                            protocol: "h1", connection: id, stream: None,
                                            path: path.clone(), method, body: body.to_vec(),
                                        });
                                        if gate_tcp {
                                            let (release, ready) = oneshot::channel();
                                            tcp_tx.send(release).unwrap();
                                            ready.await.unwrap();
                                        }
                                        let response = if scenario == Scenario::TcpRedirect && path == "/hop0" {
                                            http::Response::builder().status(302).header("location", "/hop1")
                                                .body(Full::new(Bytes::new())).unwrap()
                                        } else {
                                            http::Response::new(Full::new(Bytes::from_static(b"tcp-success")))
                                        };
                                        Ok::<_, Infallible>(response)
                                    }
                                });
                                let _ = hyper::server::conn::http1::Builder::new()
                                    .serve_connection(TokioIo::new(tls), service).await;
                            });
                        }
                        result = connections.join_next(), if !connections.is_empty() => {
                            result.unwrap().expect("TCP fixture must not panic");
                        }
                    }
                }
            }
        });
        tasks.spawn({
            let endpoint = endpoint.clone();
            let attempts = attempts.clone();
            async move {
                let mut connections = JoinSet::new();
                let mut next_connection = 0;
                loop {
                    tokio::select! {
                        incoming = endpoint.accept() => {
                            let Some(incoming) = incoming else { break; };
                            let id = next_connection;
                            next_connection += 1;
                            let attempts = attempts.clone();
                            connections.spawn(async move {
                                let connection = incoming.await.unwrap();
                                let mut h3 = server::Connection::<_, Bytes>::new(
                                    h3_quinn::Connection::new(connection),
                                ).await.unwrap();
                                let mut requests = JoinSet::new();
                                loop {
                                    tokio::select! {
                                        request = h3.accept() => {
                                            let Ok(Some(resolver)) = request else { break; };
                                            let attempts = attempts.clone();
                                            requests.spawn(async move {
                                                let (request, stream) = resolver.resolve_request().await.unwrap();
                                                serve_h3(request, stream, id, scenario, attempts).await;
                                            });
                                        }
                                        result = requests.join_next(), if !requests.is_empty() => {
                                            result.unwrap().expect("H3 request fixture must not panic");
                                        }
                                    }
                                }
                            });
                        }
                        result = connections.join_next(), if !connections.is_empty() => {
                            result.unwrap().expect("H3 connection fixture must not panic");
                        }
                    }
                }
            }
        });
        Self {
            endpoint,
            certificate,
            attempts,
            tcp_connections,
            tcp_ready,
            tasks,
        }
    }

    fn url(&self, path: &str) -> String {
        format!(
            "https://localhost:{}{path}",
            self.endpoint.local_addr().unwrap().port()
        )
    }

    fn session(&self, fallback: FallbackPolicy) -> lkrequest::Session {
        lkrequest::Client::builder()
            .preset(lkrequest::preset::chrome_155())
            .add_ca_cert_der(&self.certificate)
            .dns_resolver(Arc::new(LocalIpv4Dns))
            .build()
            .session()
            .protocol_policy(reuse_policy(fallback))
            .h3_retry_mode(H3RetryMode::Chrome155ProtocolErrors)
            .build()
    }

    async fn warm(&self, session: &lkrequest::Session) {
        let response = session
            .get(&self.url("/warm"))
            .preferred_http_version(PreferredHttpVersion::Http3Only)
            .timeout(LIMIT)
            .send()
            .await
            .unwrap();
        assert_eq!(response.bytes(), b"h3-success");
    }

    async fn snapshot(&mut self) -> Vec<Attempt> {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(80)) => {}
            result = self.tasks.join_next() => panic!("routing peer exited unexpectedly: {result:?}"),
        }
        self.attempts.lock().unwrap().clone()
    }
}

fn reuse_policy(fallback: FallbackPolicy) -> ProtocolPolicy {
    ProtocolPolicy::new(
        HttpIntent::ReuseExistingProtocol,
        AcquisitionPolicy::ReuseExistingFirst,
        UpgradePolicy::Off,
        fallback,
    )
}

async fn serve_h3(
    request: http::Request<()>,
    mut stream: server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    connection: usize,
    scenario: Scenario,
    attempts: Arc<Mutex<Vec<Attempt>>>,
) {
    let path = request.uri().path().to_owned();
    let mut body = Vec::new();
    while let Some(mut data) = stream.recv_data().await.unwrap() {
        body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
    }
    let ordinal = {
        let mut attempts = attempts.lock().unwrap();
        let ordinal = attempts
            .iter()
            .filter(|attempt| attempt.protocol == "h3" && attempt.path == path)
            .count()
            + 1;
        attempts.push(Attempt {
            protocol: "h3",
            connection,
            stream: Some(stream.id().into_inner()),
            path: path.clone(),
            method: request.method().clone(),
            body,
        });
        ordinal
    };
    let reset = match path.as_str() {
        "/warm" | "/healthy" => false,
        "/case" => true,
        "/hop0" | "/hop1" if scenario == Scenario::H3Redirect => ordinal <= 2,
        "/hop0" if scenario == Scenario::TcpRedirect => true,
        "/hop1" if scenario == Scenario::TcpRedirect => false,
        _ => panic!("unexpected H3 fixture path: {path}"),
    };
    if reset {
        stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR);
        return;
    }
    let response = if scenario == Scenario::H3Redirect && path == "/hop0" {
        http::Response::builder()
            .status(302)
            .header("location", "/hop1")
            .body(())
            .unwrap()
    } else {
        http::Response::new(())
    };
    stream.send_response(response).await.unwrap();
    stream
        .send_data(Bytes::from_static(b"h3-success"))
        .await
        .unwrap();
    stream.finish().await.unwrap();
}

fn requests<'a>(attempts: &'a [Attempt], path: &str) -> Vec<&'a Attempt> {
    attempts
        .iter()
        .filter(|attempt| attempt.path == path)
        .collect()
}

#[tokio::test]
async fn browser_retry_routing_fallback_uses_h1_and_keeps_healthy_h3() {
    for streaming in [false, true] {
        let mut peer = Peer::new(Scenario::Reset, true).await;
        let session = peer.session(FallbackPolicy::AllowFallback);
        peer.warm(&session).await;
        let request = session
            .post(&peer.url("/case"))
            .body(POST_BODY)
            .timeout(LIMIT);
        let response = tokio::spawn(async move {
            if streaming {
                let response = request.send_streaming().await.unwrap();
                response.bytes().await.unwrap().to_vec()
            } else {
                request.send().await.unwrap().bytes().to_vec()
            }
        });
        let release = tokio::time::timeout(LIMIT, peer.tcp_ready.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            !response.is_finished(),
            "TCP reply is held during the H3 control"
        );
        let healthy = session
            .get(&peer.url("/healthy"))
            .preferred_http_version(PreferredHttpVersion::Http3Only)
            .timeout(LIMIT)
            .send()
            .await
            .unwrap();
        assert_eq!(healthy.bytes(), b"h3-success");
        release.send(()).unwrap();
        assert_eq!(response.await.unwrap(), b"tcp-success");
        let attempts = peer.snapshot().await;
        let case = requests(&attempts, "/case");
        assert_eq!(case.len(), 2, "{attempts:?}");
        assert_eq!((case[0].protocol, case[1].protocol), ("h3", "h1"));
        assert!(case
            .iter()
            .all(|attempt| attempt.method == http::Method::POST && attempt.body == POST_BODY));
        let warm = requests(&attempts, "/warm");
        let healthy = requests(&attempts, "/healthy");
        assert_eq!(healthy.len(), 1);
        assert_eq!(warm[0].connection, case[0].connection);
        assert_eq!(warm[0].connection, healthy[0].connection);
        assert_ne!(case[0].stream, healthy[0].stream);
    }
}

#[tokio::test]
async fn browser_retry_routing_respects_fallback_permissions() {
    for fallback in [
        FallbackPolicy::NoFallback,
        FallbackPolicy::AllowFallbackOnNetworkErrors,
    ] {
        let mut peer = Peer::new(Scenario::Reset, false).await;
        let session = peer.session(fallback);
        peer.warm(&session).await;
        let error = session
            .post(&peer.url("/case"))
            .body(POST_BODY)
            .timeout(LIMIT)
            .send()
            .await
            .unwrap_err();
        assert!(error.h3_request_context().is_some());
        let attempts = peer.snapshot().await;
        let case = requests(&attempts, "/case");
        assert_eq!(case.len(), 1, "{fallback:?}: {attempts:?}");
        assert_eq!(case[0].protocol, "h3");
        assert!(attempts.iter().all(|attempt| attempt.protocol == "h3"));
        assert_eq!(peer.tcp_connections.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn browser_retry_routing_http3_only_never_falls_back() {
    let mut peer = Peer::new(Scenario::Reset, false).await;
    let session = peer.session(FallbackPolicy::AllowFallback);
    peer.warm(&session).await;
    let error = session
        .post(&peer.url("/case"))
        .body(POST_BODY)
        .preferred_http_version(PreferredHttpVersion::Http3Only)
        .timeout(LIMIT)
        .send()
        .await
        .unwrap_err();
    assert!(error.h3_request_context().is_some());
    let attempts = peer.snapshot().await;
    let case = requests(&attempts, "/case");
    assert_eq!(case.len(), 3, "{attempts:?}");
    assert!(attempts.iter().all(|attempt| attempt.protocol == "h3"));
    assert_eq!(peer.tcp_connections.load(Ordering::SeqCst), 0);
    assert!(case
        .iter()
        .all(|attempt| attempt.method == http::Method::POST && attempt.body == POST_BODY));
}

#[tokio::test]
async fn browser_retry_routing_redirect_resets_budget_and_rewrites_post() {
    let mut peer = Peer::new(Scenario::H3Redirect, false).await;
    let session = peer.session(FallbackPolicy::AllowFallback);
    peer.warm(&session).await;
    let response = session
        .post(&peer.url("/hop0"))
        .body(POST_BODY)
        .preferred_http_version(PreferredHttpVersion::Http3Only)
        .timeout(LIMIT)
        .send()
        .await
        .unwrap();
    assert_eq!(response.bytes(), b"h3-success");
    let attempts = peer.snapshot().await;
    let first = requests(&attempts, "/hop0");
    let second = requests(&attempts, "/hop1");
    assert_eq!(first.len(), 3, "{attempts:?}");
    assert_eq!(second.len(), 3, "{attempts:?}");
    assert!(first
        .iter()
        .all(|attempt| attempt.method == http::Method::POST && attempt.body == POST_BODY));
    assert!(second
        .iter()
        .all(|attempt| attempt.method == http::Method::GET && attempt.body.is_empty()));
    assert!(attempts.iter().all(|attempt| attempt.protocol == "h3"));
}

#[tokio::test]
async fn browser_retry_routing_tcp_redirect_restores_original_protocol() {
    for request_override in [false, true] {
        let mut peer = Peer::new(Scenario::TcpRedirect, false).await;
        let session = peer.session(FallbackPolicy::AllowFallback);
        peer.warm(&session).await;
        let mut request = session
            .post(&peer.url("/hop0"))
            .body(POST_BODY)
            .timeout(LIMIT);
        if request_override {
            request = request
                .protocol_policy(reuse_policy(FallbackPolicy::AllowFallback))
                .preferred_http_version(PreferredHttpVersion::Auto);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.bytes(), b"h3-success");
        let attempts = peer.snapshot().await;
        let first = requests(&attempts, "/hop0");
        let second = requests(&attempts, "/hop1");
        assert_eq!(first.len(), 2, "{attempts:?}");
        assert_eq!((first[0].protocol, first[1].protocol), ("h3", "h1"));
        assert!(first
            .iter()
            .all(|attempt| attempt.method == http::Method::POST && attempt.body == POST_BODY));
        assert_eq!(second.len(), 1, "{attempts:?}");
        assert_eq!(second[0].protocol, "h3");
        assert_eq!(second[0].method, http::Method::GET);
        assert!(second[0].body.is_empty());
        assert_eq!(
            second[0].connection,
            requests(&attempts, "/warm")[0].connection
        );
    }
}
