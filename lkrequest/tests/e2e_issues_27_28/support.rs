use std::convert::Infallible;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

pub const DEADLINE: Duration = Duration::from_secs(15);

pub async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("loopback probe exceeded its outer deadline")
}

pub fn client() -> lkrequest::Client {
    lkrequest::Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .h2_profile(lkrequest::h2::profile::chrome_144_h2())
        .verify(false)
        .total_timeout(Duration::from_secs(10))
        .build()
}

pub fn server_tls(alpn: &[&[u8]]) -> rustls::ServerConfig {
    let cert = rcgen::generate_simple_self_signed(vec![
        "localhost".into(),
        "127.0.0.1".into(),
        "service.test".into(),
    ])
    .unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
    )
    .unwrap();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

pub async fn read_headers(stream: &mut (impl AsyncRead + Unpin)) -> String {
    bounded(async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(bytes.len() < 32 * 1024, "unbounded HTTP header");
            bytes.push(stream.read_u8().await.expect("complete HTTP header"));
        }
        String::from_utf8(bytes).unwrap()
    })
    .await
}

pub fn header<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.trim()))
}

pub struct CounterGuard(Arc<AtomicUsize>);

impl CounterGuard {
    pub fn enter(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(counter.clone())
    }
}

impl Drop for CounterGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct HttpsServer {
    pub addr: SocketAddr,
    pub accepts: Arc<AtomicUsize>,
    pub requests: Arc<AtomicUsize>,
    pub max_handshakes: Arc<AtomicUsize>,
    pub response_gate: Option<Arc<Semaphore>>,
    active: Arc<AtomicUsize>,
    disconnect: watch::Sender<u64>,
    task: JoinHandle<()>,
}

impl HttpsServer {
    pub async fn start(h1_only: bool, handshake_delay: Duration, hold_response: bool) -> Self {
        Self::start_on(
            (Ipv4Addr::LOCALHOST, 0).into(),
            h1_only,
            handshake_delay,
            hold_response,
        )
        .await
    }

    pub async fn start_on(
        addr: SocketAddr,
        h1_only: bool,
        handshake_delay: Duration,
        hold_response: bool,
    ) -> Self {
        let listener = TcpListener::bind(addr).await.unwrap();
        Self::from_listener(listener, h1_only, handshake_delay, hold_response).await
    }

    pub async fn from_listener(
        listener: TcpListener,
        h1_only: bool,
        handshake_delay: Duration,
        hold_response: bool,
    ) -> Self {
        let alpn: &[&[u8]] = if h1_only { &[b"http/1.1"] } else { &[b"h2"] };
        let acceptor = TlsAcceptor::from(Arc::new(server_tls(alpn)));
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let handshakes = Arc::new(AtomicUsize::new(0));
        let max_handshakes = Arc::new(AtomicUsize::new(0));
        let response_gate = hold_response.then(|| Arc::new(Semaphore::new(0)));
        let (disconnect, _) = watch::channel(0);
        let task = tokio::spawn({
            let accepts = accepts.clone();
            let requests = requests.clone();
            let active = active.clone();
            let max_handshakes = max_handshakes.clone();
            let response_gate = response_gate.clone();
            let disconnect = disconnect.clone();
            async move {
                let mut handlers = JoinSet::new();
                loop {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let (tcp, _) = accepted.unwrap();
                            accepts.fetch_add(1, Ordering::SeqCst);
                            let active_guard = CounterGuard::enter(&active);
                            let acceptor = acceptor.clone();
                            let requests = requests.clone();
                            let handshakes = handshakes.clone();
                            let max_handshakes = max_handshakes.clone();
                            let response_gate = response_gate.clone();
                            let mut disconnected = disconnect.subscribe();
                            handlers.spawn(async move {
                                let _active = active_guard;
                                let serve = async {
                                    let handshake = CounterGuard::enter(&handshakes);
                                    max_handshakes.fetch_max(handshakes.load(Ordering::SeqCst), Ordering::SeqCst);
                                    // Delaying the peer makes cold-start overlap reproducible.
                                    tokio::time::sleep(handshake_delay).await;
                                    let Ok(tls) = acceptor.accept(tcp).await else { return };
                                    drop(handshake);
                                    let service = service_fn(move |_| {
                                        requests.fetch_add(1, Ordering::SeqCst);
                                        let gate = response_gate.clone();
                                        async move {
                                            if let Some(gate) = gate { gate.acquire().await.unwrap().forget(); }
                                            if h1_only { tokio::time::sleep(Duration::from_millis(80)).await; }
                                            Ok::<_, Infallible>(http::Response::new(Full::new(Bytes::from_static(b"ok"))))
                                        }
                                    });
                                    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                                        .serve_connection(TokioIo::new(tls), service).await;
                                };
                                tokio::select! {
                                    _ = disconnected.changed() => {},
                                    _ = serve => {},
                                }
                            });
                        }
                        Some(result) = handlers.join_next(), if !handlers.is_empty() => {
                            result.expect("HTTPS handler panicked");
                        }
                    }
                }
            }
        });
        Self {
            addr,
            accepts,
            requests,
            max_handshakes,
            response_gate,
            active,
            disconnect,
            task,
        }
    }

    pub fn url(&self) -> String {
        format!("https://{}/get", self.addr)
    }

    pub async fn wait_for(&self, counter: &AtomicUsize, n: usize) {
        bounded(async {
            while counter.load(Ordering::SeqCst) < n {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await;
    }

    pub async fn disconnect_all(&self) {
        self.disconnect.send_modify(|generation| *generation += 1);
        bounded(async {
            while self.active.load(Ordering::SeqCst) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        // Let the client driver observe the close before the next burst.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

impl Drop for HttpsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
