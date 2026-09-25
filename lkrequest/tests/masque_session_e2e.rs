//! Tier-0 end-to-end tests for MASQUE on the **Session** request path.
//!
//! `masque_tunnel_e2e.rs` covers the bridge in isolation: a `MasqueConnection`
//! driven by hand. This file covers the layer above it — a real
//! `Session::get()` that resolves the proxy, reuses (or opens) this session's
//! outer HTTP/3 connection, tunnels an inner QUIC connection through it and
//! comes back with an HTTP/3 response.
//!
//! The proxy and the origin below are this file's own test doubles. Nothing is
//! shared with `masque_tunnel_e2e.rs`: a change made for one file must not be
//! able to quietly invalidate the other, and these doubles have to do things
//! that one does not (count outer connections, refuse tunnels on demand,
//! capture the first inner datagram).
//!
//! The properties under test:
//!
//! | Property | Test |
//! |---|---|
//! | A request completes over a tunnel | [`a_request_completes_over_a_masque_tunnel`] |
//! | One session, one outer connection, many targets | [`one_session_shares_one_outer_connection_across_targets`] |
//! | Two sessions never share one | [`two_sessions_never_share_an_outer_connection`] |
//! | A proxy-side failure quarantines the route | [`a_refused_tunnel_quarantines_the_route`] |
//! | A blocked destination does not | [`a_target_specific_refusal_leaves_the_route_usable`] |
//! | A dead inner handshake reports itself, not the proxy | [`a_dead_inner_handshake_is_not_reported_as_a_tcp_incapable_proxy`] |
//! | The tunnel budget sheds the least recently used | [`the_tunnel_budget_sheds_the_least_recently_active_first`] |
//! | An idle timeout retires tunnels, not the connection | [`an_idle_timeout_retires_every_idle_tunnel`] |
//!
//! plus the one that matters most to this repository: the tunnel must not
//! change what the origin sees on the wire
//! ([`the_tunnel_does_not_change_the_inner_initial_packet`]).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use h3::ext::Protocol;
use http::{Method, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::task::JoinHandle;

use lkrequest::proxy::{MasqueConnection, MasqueOuterConfig, ProxyConfig};
use lkrequest::{Client, HttpVersion};

const TUNNEL_TEMPLATE_PREFIX: &str = "/.well-known/masque/udp/";
const CAPSULE_PROTOCOL: &str = "capsule-protocol";
const CAPSULE_PROTOCOL_ENABLED: &str = "?1";
const UDP_PAYLOAD_CONTEXT_ID: u64 = 0;

const TIMEOUT: Duration = Duration::from_secs(20);

fn ensure_rustls_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn localhost_addr(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

/// Every name resolves to loopback on the requested port.
///
/// Both hops need this: the session resolves the *proxy* itself (the bridge
/// takes an address, never a name), and the direct-connection baseline resolves
/// the origin. The target of a tunnel is never resolved here — it travels in
/// the CONNECT-UDP `:path` and the proxy resolves it, which is exactly what
/// RFC 9298 §3.1 requires.
#[derive(Clone)]
struct LoopbackDns;

#[async_trait]
impl lkrequest::DnsResolver for LoopbackDns {
    async fn resolve(&self, _host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(vec![localhost_addr(port)])
    }
}

/// A self-signed `localhost` certificate, kept as bytes so several servers can
/// share one trust anchor without juggling a non-`Clone` private key.
#[derive(Clone)]
struct TestCert {
    der: CertificateDer<'static>,
    pkcs8: Vec<u8>,
}

fn self_signed_localhost() -> TestCert {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    TestCert {
        der: CertificateDer::from(generated.cert.der().to_vec()),
        pkcs8: generated.signing_key.serialize_der(),
    }
}

impl TestCert {
    fn server_config(&self, alpn: &[&[u8]]) -> quinn::ServerConfig {
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(self.pkcs8.clone()));
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![self.der.clone()], key)
            .unwrap();
        tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()))
    }
}

// ---------------------------------------------------------------------------
// HTTP Datagram codec (proxy side only)
// ---------------------------------------------------------------------------

fn encode_varint(value: u64, out: &mut Vec<u8>) {
    match value {
        0..=0x3f => out.push(value as u8),
        0x40..=0x3fff => out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        0x4000..=0x3fff_ffff => {
            out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes())
        }
        0x4000_0000..=0x3fff_ffff_ffff_ffff => {
            out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes())
        }
        _ => panic!("varint out of range: {value}"),
    }
}

fn decode_varint(input: &mut &[u8]) -> Option<u64> {
    let first = *input.first()?;
    let length = 1usize << (first >> 6);
    if input.len() < length {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &input[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    *input = &input[length..];
    Some(value)
}

fn encode_datagram(quarter_stream_id: u64, context_id: u64, payload: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(payload.len() + 16);
    encode_varint(quarter_stream_id, &mut out);
    encode_varint(context_id, &mut out);
    out.extend_from_slice(payload);
    Bytes::from(out)
}

fn decode_datagram(datagram: &[u8]) -> Option<(u64, u64, Vec<u8>)> {
    let mut cursor = datagram;
    let quarter_stream_id = decode_varint(&mut cursor)?;
    let context_id = decode_varint(&mut cursor)?;
    Some((quarter_stream_id, context_id, cursor.to_vec()))
}

// ---------------------------------------------------------------------------
// Origin: a local HTTP/3 server
// ---------------------------------------------------------------------------

struct Origin {
    port: u16,
    _endpoint: quinn::Endpoint,
    _task: JoinHandle<()>,
}

impl Origin {
    fn url(&self, path: &str) -> String {
        format!("https://localhost:{}{path}", self.port)
    }
}

/// An HTTP/3 origin that answers every request with `body`, for as many
/// connections and requests as arrive.
fn spawn_origin(cert: &TestCert, body: &'static str) -> Origin {
    ensure_rustls_provider();
    let endpoint =
        quinn::Endpoint::server(cert.server_config(&[b"h3"]), localhost_addr(0)).unwrap();
    let port = endpoint.local_addr().unwrap().port();

    let task = tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    let Ok(mut h3) = h3::server::Connection::<_, Bytes>::new(
                        h3_quinn::Connection::new(connection),
                    )
                    .await
                    else {
                        return;
                    };
                    while let Ok(Some(resolver)) = h3.accept().await {
                        tokio::spawn(async move {
                            let Ok((_request, mut stream)) = resolver.resolve_request().await
                            else {
                                return;
                            };
                            let response = http::Response::builder()
                                .status(StatusCode::OK)
                                .body(())
                                .unwrap();
                            if stream.send_response(response).await.is_err() {
                                return;
                            }
                            let _ = stream.send_data(Bytes::from_static(body.as_bytes())).await;
                            let _ = stream.finish().await;
                        });
                    }
                });
            }
        }
    });

    Origin {
        port,
        _endpoint: endpoint,
        _task: task,
    }
}

// ---------------------------------------------------------------------------
// Proxy: a local MASQUE CONNECT-UDP relay
// ---------------------------------------------------------------------------

/// What the proxy does with a CONNECT-UDP request.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ProxyMode {
    /// Open the tunnel and relay UDP to the named target.
    Relay,
    /// Answer with this status and finish the stream.
    Refuse(u16),
    /// Open the tunnel exactly as [`ProxyMode::Relay`] does — `200` plus the
    /// Capsule Protocol header, stream left open — and then silently discard
    /// every datagram in both directions.
    ///
    /// This is a working proxy in front of a path that eats QUIC: the CONNECT-UDP
    /// hop succeeds, so nothing is wrong with the proxy *configuration*, and it
    /// is the **inner** handshake that dies for want of an answer. A middlebox
    /// dropping QUIC, a target that has no UDP listener, a firewall — they all
    /// look like this from the client, and the error the caller gets has to point
    /// at the inner connection rather than at the proxy.
    Blackhole,
}

#[derive(Default)]
struct ProxyCounters {
    /// Outer QUIC connections accepted. The number a session's pooling is
    /// judged by.
    outer_connections: AtomicUsize,
    /// CONNECT-UDP requests seen, refused ones included.
    tunnel_requests: AtomicUsize,
    first_response_sent: Mutex<Option<Instant>>,
}

struct Proxy {
    port: u16,
    cert: CertificateDer<'static>,
    counters: Arc<ProxyCounters>,
    /// The first payload each tunnel carried client→target: the inner QUIC
    /// Initial datagram, before anything else is sent.
    first_inner_datagram: Arc<Mutex<Vec<Vec<u8>>>>,
    _endpoint: quinn::Endpoint,
    _task: JoinHandle<()>,
}

impl Proxy {
    fn config(&self) -> ProxyConfig {
        ProxyConfig::parse(&format!("masque://127.0.0.1:{}", self.port)).unwrap()
    }

    /// Trust this proxy's throwaway certificate and nothing else, so the test
    /// never depends on the host's certificate store.
    fn outer_config(&self) -> MasqueOuterConfig {
        // `MasqueOuterConfig` is `#[non_exhaustive]`: from `Default`, then
        // assign.
        let mut config = MasqueOuterConfig::default();
        config.use_native_certs = false;
        config.extra_roots = vec![self.cert.clone()];
        config.server_name = Some("localhost".to_string());
        config
    }

    fn outer_connections(&self) -> usize {
        self.counters.outer_connections.load(Ordering::SeqCst)
    }

    fn tunnel_requests(&self) -> usize {
        self.counters.tunnel_requests.load(Ordering::SeqCst)
    }
}

type Relays = Arc<Mutex<HashMap<u64, Arc<tokio::net::UdpSocket>>>>;

fn spawn_proxy(mode: ProxyMode) -> Proxy {
    ensure_rustls_provider();
    let cert = self_signed_localhost();
    let endpoint =
        quinn::Endpoint::server(cert.server_config(&[b"h3"]), localhost_addr(0)).unwrap();
    let port = endpoint.local_addr().unwrap().port();

    let counters = Arc::new(ProxyCounters::default());
    let first_inner_datagram = Arc::new(Mutex::new(Vec::new()));

    let task = tokio::spawn({
        let endpoint = endpoint.clone();
        let counters = counters.clone();
        let captured = first_inner_datagram.clone();
        async move {
            while let Some(incoming) = endpoint.accept().await {
                let counters = counters.clone();
                let captured = captured.clone();
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    counters.outer_connections.fetch_add(1, Ordering::SeqCst);
                    serve_proxy_connection(connection, mode, counters, captured).await;
                });
            }
        }
    });

    Proxy {
        port,
        cert: cert.der.clone(),
        counters,
        first_inner_datagram,
        _endpoint: endpoint,
        _task: task,
    }
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = value.get(index + 1..index + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn parse_connect_udp(request: &http::Request<()>) -> Result<(String, u16), StatusCode> {
    if request.method() != Method::CONNECT {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    if request.extensions().get::<Protocol>() != Some(&Protocol::CONNECT_UDP) {
        return Err(StatusCode::BAD_REQUEST);
    }
    // RFC 9297 §3.4: the client must have asked for the Capsule Protocol.
    if request
        .headers()
        .get(CAPSULE_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        != Some(CAPSULE_PROTOCOL_ENABLED)
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    let rest = request
        .uri()
        .path()
        .strip_prefix(TUNNEL_TEMPLATE_PREFIX)
        .ok_or(StatusCode::NOT_FOUND)?;
    let mut segments = rest.split('/');
    let host = segments.next().ok_or(StatusCode::BAD_REQUEST)?;
    let port = segments.next().ok_or(StatusCode::BAD_REQUEST)?;
    if segments.next() != Some("") || segments.next().is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let host = percent_decode(host).ok_or(StatusCode::BAD_REQUEST)?;
    let port: u16 = port.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    if host.is_empty() || port == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok((host, port))
}

async fn serve_proxy_connection(
    connection: quinn::Connection,
    mode: ProxyMode,
    counters: Arc<ProxyCounters>,
    captured: Arc<Mutex<Vec<Vec<u8>>>>,
) {
    let relays: Relays = Arc::new(Mutex::new(HashMap::new()));

    // Datagrams bypass h3 entirely, exactly as the client's bridge does.
    let pump = tokio::spawn({
        let connection = connection.clone();
        let relays = relays.clone();
        let captured = captured.clone();
        async move {
            let mut seen: HashMap<u64, ()> = HashMap::new();
            while let Ok(datagram) = connection.read_datagram().await {
                let Some((quarter, context_id, payload)) = decode_datagram(&datagram) else {
                    continue;
                };
                if context_id != UDP_PAYLOAD_CONTEXT_ID {
                    continue;
                }
                if seen.insert(quarter, ()).is_none() {
                    // The inner QUIC Initial: the packet whose shape the
                    // fingerprint test compares against a direct connection.
                    captured.lock().unwrap().push(payload.clone());
                }
                let relay = relays.lock().unwrap().get(&quarter).cloned();
                if let Some(relay) = relay {
                    let _ = relay.send(&payload).await;
                }
            }
        }
    });

    let relay_connection = connection.clone();
    let mut builder = h3::server::builder();
    builder
        .enable_extended_connect(true)
        .enable_datagram(true)
        .send_grease(false);
    let Ok(mut h3) = builder
        .build::<_, Bytes>(h3_quinn::Connection::new(connection))
        .await
    else {
        pump.abort();
        return;
    };

    while let Ok(Some(resolver)) = h3.accept().await {
        let Ok((request, mut stream)) = resolver.resolve_request().await else {
            continue;
        };
        counters.tunnel_requests.fetch_add(1, Ordering::SeqCst);
        // The vendored `h3-quinn` quarters stream IDs on both sides, so this is
        // already the Quarter Stream ID the client keyed its tunnel with.
        // Full QUIC stream ID here; the quarter stream ID
        // (RFC 9297 §2.1) is a division away. See the note in
        // `masque_tunnel_e2e.rs` for why this changed.
        let quarter = stream.id().into_inner() / 4;

        let outcome = match mode {
            ProxyMode::Refuse(status) => Err(StatusCode::from_u16(status).unwrap()),
            ProxyMode::Relay | ProxyMode::Blackhole => parse_connect_udp(&request),
        };

        match outcome {
            // The tunnel is established and then leads nowhere: no relay socket
            // is registered, so the datagram pump above drops everything the
            // client sends and nothing ever comes back.
            Ok(_) if mode == ProxyMode::Blackhole => {
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .header(CAPSULE_PROTOCOL, CAPSULE_PROTOCOL_ENABLED)
                    .body(())
                    .unwrap();
                if stream.send_response(response).await.is_err() {
                    continue;
                }
                // No `finish()`, exactly as in the relaying arm: the tunnel must
                // look alive, or the client would fail on the tunnel instead of
                // on the connection inside it.
                tokio::spawn(async move {
                    while let Ok(Some(_capsule)) = stream.recv_data().await {}
                    let _ = stream.finish().await;
                });
            }
            Ok((host, port)) => {
                // RFC 9298 §3.1: the proxy resolves the target before it answers.
                let Ok(mut addrs) = tokio::net::lookup_host((host.as_str(), port)).await else {
                    let response = http::Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(())
                        .unwrap();
                    let _ = stream.send_response(response).await;
                    let _ = stream.finish().await;
                    continue;
                };
                let Some(target) = addrs.find(SocketAddr::is_ipv4) else {
                    continue;
                };

                let relay = tokio::net::UdpSocket::bind(localhost_addr(0))
                    .await
                    .unwrap();
                relay.connect(target).await.unwrap();
                let relay = Arc::new(relay);
                tokio::spawn({
                    let relay = relay.clone();
                    let connection = relay_connection.clone();
                    async move {
                        let mut buf = vec![0u8; 65535];
                        while let Ok(n) = relay.recv(&mut buf).await {
                            match connection.send_datagram(encode_datagram(
                                quarter,
                                UDP_PAYLOAD_CONTEXT_ID,
                                &buf[..n],
                            )) {
                                Ok(()) => {}
                                // The origin here knows nothing about the
                                // tunnel and runs its own MTU discovery, so it
                                // will eventually probe with a packet too big
                                // to wrap in an outer datagram. A proxy drops
                                // that payload (RFC 9298 §5) and the loss is
                                // what makes the origin settle on a size that
                                // fits; ending this direction instead would
                                // silently stall the tunnel for good.
                                Err(quinn::SendDatagramError::TooLarge) => continue,
                                Err(_) => break,
                            }
                        }
                    }
                });

                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .header(CAPSULE_PROTOCOL, CAPSULE_PROTOCOL_ENABLED)
                    .body(())
                    .unwrap();
                if stream.send_response(response).await.is_err() {
                    continue;
                }
                counters
                    .first_response_sent
                    .lock()
                    .unwrap()
                    .get_or_insert_with(Instant::now);
                relays.lock().unwrap().insert(quarter, relay);

                // No `finish()`: the tunnel stays open until the client FINs.
                let relays = relays.clone();
                tokio::spawn(async move {
                    while let Ok(Some(_capsule)) = stream.recv_data().await {}
                    let _ = stream.finish().await;
                    relays.lock().unwrap().remove(&quarter);
                });
            }
            Err(status) => {
                let response = http::Response::builder().status(status).body(()).unwrap();
                let _ = stream.send_response(response).await;
                let _ = stream.finish().await;
            }
        }
    }

    pump.abort();
}

// ---------------------------------------------------------------------------
// Tunnel lifecycle policy
// ---------------------------------------------------------------------------

/// Wait for the outer connection to settle at `expected` live tunnels.
///
/// `reap_tunnels` asks; the per-tunnel stream pump acts, because finishing a
/// request stream needs an `await`. Polling is how a caller observes the
/// difference between the two.
async fn wait_for_tunnel_count(connection: &MasqueConnection, expected: usize) {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        let count = connection.tunnel_count();
        if count == expected {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "tunnel count stayed at {count}, expected {expected}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// `tunnel_idle_timeout: None` really does retire nothing, and the budget is
/// then the only thing bounding growth — least recently active first.
///
/// These are the two knobs the design names, and the order matters: if the
/// budget shed the *newest* tunnel, a session opening tunnels faster than it
/// uses them would keep killing the one it was about to use.
#[tokio::test]
async fn the_tunnel_budget_sheds_the_least_recently_active_first() {
    let proxy = spawn_proxy(ProxyMode::Relay);
    let connection = MasqueConnection::connect(
        &proxy.config(),
        localhost_addr(proxy.port),
        &proxy.outer_config(),
    )
    .await
    .expect("outer connection failed");

    // Opened oldest-first, and `open_tunnel` stamps each one, so the activity
    // order is the creation order until something sends.
    let oldest = connection.open_tunnel("127.0.0.1", 9001).await.unwrap();
    let middle = connection.open_tunnel("127.0.0.1", 9002).await.unwrap();
    let newest = connection.open_tunnel("127.0.0.1", 9003).await.unwrap();
    assert_eq!(connection.tunnel_count(), 3);

    // "Never reclaim" with room to spare: nothing is touched.
    assert_eq!(
        connection.reap_tunnels(None, 3),
        0,
        "no idle timeout and a budget of 3 must leave 3 tunnels alone"
    );
    assert_eq!(connection.tunnel_count(), 3);

    assert_eq!(connection.reap_tunnels(None, 2), 1);
    wait_for_tunnel_count(&connection, 2).await;
    assert!(
        oldest.stats().is_none(),
        "the least recently active tunnel is the one that must go"
    );
    assert!(middle.stats().is_some());
    assert!(newest.stats().is_some());
}

/// An idle timeout retires tunnels regardless of the budget.
///
/// Zero is the honest way to test it: every tunnel's idle time is at least
/// zero, so the rule fires for all of them without the test having to sleep.
#[tokio::test]
async fn an_idle_timeout_retires_every_idle_tunnel() {
    let proxy = spawn_proxy(ProxyMode::Relay);
    let connection = MasqueConnection::connect(
        &proxy.config(),
        localhost_addr(proxy.port),
        &proxy.outer_config(),
    )
    .await
    .expect("outer connection failed");

    let _a = connection.open_tunnel("127.0.0.1", 9101).await.unwrap();
    let _b = connection.open_tunnel("127.0.0.1", 9102).await.unwrap();
    assert_eq!(connection.tunnel_count(), 2);

    assert_eq!(connection.reap_tunnels(Some(Duration::ZERO), 0), 2);
    wait_for_tunnel_count(&connection, 0).await;

    // Retiring tunnels does not take the outer connection with them: the next
    // target still gets one without a fresh handshake.
    assert!(connection.is_live());
    let _c = connection
        .open_tunnel("127.0.0.1", 9103)
        .await
        .expect("the outer connection must survive its tunnels");
    assert_eq!(proxy.outer_connections(), 1);
}

// ---------------------------------------------------------------------------
// Client assembly
// ---------------------------------------------------------------------------

fn client_for(origin_cert: &TestCert, proxy: Option<&Proxy>) -> Client {
    let mut builder = Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .quic_profile(lkh3::chrome_quic())
        .add_ca_cert_der(origin_cert.der.as_ref())
        .dns_resolver(Arc::new(LoopbackDns));
    if let Some(proxy) = proxy {
        builder = builder.masque(proxy.outer_config());
    }
    builder.build()
}

async fn get(
    session: &lkrequest::Session,
    url: &str,
) -> lkrequest::error::Result<lkrequest::Response> {
    tokio::time::timeout(TIMEOUT, session.get(url).send())
        .await
        .expect("request timed out")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The whole point: a plain `session.get()` over a `masque://` proxy comes back
/// as HTTP/3.
///
/// Nothing here asks for H3. A MASQUE proxy relays UDP and nothing else, so the
/// protocol decision has to reach that conclusion on its own — Alt-Svc could
/// never advertise it on this route, because advertising needs an H2 response
/// and there is no H2 to carry one.
#[tokio::test]
async fn a_request_completes_over_a_masque_tunnel() {
    let cert = self_signed_localhost();
    let origin = spawn_origin(&cert, "hello-through-masque");
    let proxy = spawn_proxy(ProxyMode::Relay);

    let client = client_for(&cert, Some(&proxy));
    let session = client.session().proxy_config(proxy.config()).build();

    let response = get(&session, &origin.url("/one"))
        .await
        .expect("request through the MASQUE proxy failed");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.version(),
        HttpVersion::H3,
        "a MASQUE route can only carry HTTP/3"
    );
    assert_eq!(response.text().unwrap(), "hello-through-masque");

    assert_eq!(proxy.outer_connections(), 1);
    assert_eq!(proxy.tunnel_requests(), 1);
}

/// One session visiting two origins pays for **one** outer connection.
///
/// This is the reason RFC 9298 multiplexes tunnels at all: a connection per
/// target would multiply the outer handshake by the number of origins, and the
/// proxy learns nothing new from the sharing — one session already means one
/// credential and one source address.
#[tokio::test]
async fn one_session_shares_one_outer_connection_across_targets() {
    let cert = self_signed_localhost();
    let first = spawn_origin(&cert, "first-origin");
    let second = spawn_origin(&cert, "second-origin");
    let proxy = spawn_proxy(ProxyMode::Relay);

    let client = client_for(&cert, Some(&proxy));
    let session = client.session().proxy_config(proxy.config()).build();

    let a = get(&session, &first.url("/a")).await.expect("first failed");
    let b = get(&session, &second.url("/b"))
        .await
        .expect("second failed");

    assert_eq!(a.text().unwrap(), "first-origin");
    assert_eq!(b.text().unwrap(), "second-origin");

    assert_eq!(
        proxy.outer_connections(),
        1,
        "both targets must share one outer HTTP/3 connection"
    );
    assert_eq!(
        proxy.tunnel_requests(),
        2,
        "each target still needs its own CONNECT-UDP tunnel"
    );
}

/// Two sessions never meet on the same outer connection, even from one client
/// and one proxy.
///
/// A `Session` is a virtual browser user. Sharing an outer connection between
/// two of them would hand the proxy a join key across identities the caller
/// deliberately separated — the same reason cookie jars and connection pools
/// are per session.
#[tokio::test]
async fn two_sessions_never_share_an_outer_connection() {
    let cert = self_signed_localhost();
    let origin = spawn_origin(&cert, "shared-origin");
    let proxy = spawn_proxy(ProxyMode::Relay);

    let client = client_for(&cert, Some(&proxy));
    let one = client.session().proxy_config(proxy.config()).build();
    let two = client.session().proxy_config(proxy.config()).build();

    get(&one, &origin.url("/one")).await.expect("first failed");
    get(&two, &origin.url("/two")).await.expect("second failed");

    assert_eq!(
        proxy.outer_connections(),
        2,
        "each session must have opened its own outer connection"
    );
}

/// A proxy that cannot give out tunnels quarantines the **route**, and the next
/// request does not ask again.
///
/// The failure is the proxy's, not the origin's, so a per-origin mark would let
/// every other origin behind the same proxy re-pay the same failure. The proof
/// is the proxy's own counter: the second request must not produce another
/// CONNECT-UDP request at all.
#[tokio::test]
async fn a_refused_tunnel_quarantines_the_route() {
    let cert = self_signed_localhost();
    let origin = spawn_origin(&cert, "unreachable");
    // 502: the proxy failed on its own side, which says nothing about the
    // target and therefore taints the route.
    let proxy = spawn_proxy(ProxyMode::Refuse(502));

    let client = client_for(&cert, Some(&proxy));
    let session = client.session().proxy_config(proxy.config()).build();

    let first = get(&session, &origin.url("/first")).await;
    assert!(
        first.is_err(),
        "a refused tunnel must not produce a response"
    );
    assert_eq!(proxy.tunnel_requests(), 1);

    let second = get(&session, &origin.url("/second")).await;
    assert!(second.is_err());
    assert_eq!(
        proxy.tunnel_requests(),
        1,
        "the quarantined route must skip QUIC instead of opening a second tunnel"
    );

    // And a different origin behind the same proxy is quarantined too, which is
    // what "per route" means.
    let other = spawn_origin(&cert, "also-unreachable");
    assert!(get(&session, &other.url("/third")).await.is_err());
    assert_eq!(proxy.tunnel_requests(), 1);
}

/// A 4xx refusal is about **that target**, so it must not quarantine the route.
///
/// RFC 9298 §3.1 has the proxy resolve and evaluate the target before it
/// answers, so a `403` comes from a proxy that is working perfectly and has
/// simply declined one destination. Treating it as a route failure would cost
/// every other origin its only transport for the whole cooldown.
#[tokio::test]
async fn a_target_specific_refusal_leaves_the_route_usable() {
    let cert = self_signed_localhost();
    let blocked = spawn_origin(&cert, "blocked");
    let proxy = spawn_proxy(ProxyMode::Refuse(403));

    let client = client_for(&cert, Some(&proxy));
    let session = client.session().proxy_config(proxy.config()).build();

    assert!(get(&session, &blocked.url("/a")).await.is_err());
    assert_eq!(proxy.tunnel_requests(), 1);

    // A second origin still gets its own attempt: the route was not tainted.
    let other = spawn_origin(&cert, "other");
    assert!(get(&session, &other.url("/b")).await.is_err());
    assert_eq!(
        proxy.tunnel_requests(),
        2,
        "a blocked destination must not quarantine every other destination"
    );
}

/// The distinctive words of `proxy::connect::masque_cannot_carry_tcp`, the
/// error the TCP path answers a `masque://` route with.
///
/// A fragment rather than the whole sentence, so that editing the surrounding
/// wording does not quietly turn the assertion below into a no-op. Should even
/// the fragment go, the assertion would pass for the wrong reason — which is
/// what [`the_tcp_fallback_error_is_still_the_one_this_test_guards_against`]
/// exists to catch.
const MASQUE_TCP_REFUSAL: &str = "relays UDP only";

/// An inner handshake that fails behind a working tunnel must report **itself**,
/// not the TCP path's "this proxy only relays UDP".
///
/// The failure being modelled is the common one: the proxy is fine (CONNECT-UDP
/// answers `200`), and the QUIC connection inside the tunnel gets no reply — a
/// middlebox eating QUIC, a target with nothing listening on UDP, a wrong ALPN.
/// That is a handshake-class error, and a handshake-class error used to be enough
/// on its own to send the request down the H2/TCP path, where `connect_tcp`
/// immediately refuses a `masque://` route. The caller was then told their proxy
/// cannot carry TCP — true, irrelevant, and pointing at the one thing that was
/// working. Everything about *why* the handshake failed was gone.
///
/// So the assertion is about error *identity*, not merely about failing: the
/// request must fail (the tunnel really does lead nowhere) with the inner
/// connection's own error, and the proxy must see exactly one CONNECT-UDP
/// request — a second one would mean the retry/fallback machinery had another go.
#[tokio::test]
async fn a_dead_inner_handshake_is_not_reported_as_a_tcp_incapable_proxy() {
    let cert = self_signed_localhost();
    // Spawned so the target genuinely exists: the only reason the handshake
    // fails is the proxy swallowing datagrams.
    let origin = spawn_origin(&cert, "never-reached");
    let proxy = spawn_proxy(ProxyMode::Blackhole);

    // The inner connection has to give up on its own, in seconds rather than in
    // the 30s a browser profile asks for. `max_idle_timeout` is the knob quinn
    // uses while a handshake is still in flight, so shortening it is what turns
    // a 30-second hang into a fast, handshake-class error; quinn floors the
    // actual wait at three PTOs, so the value below buys the floor (~3s) and
    // not less. The outer `quic_connect_timeout` stays well above that on
    // purpose: were it the one to fire, the error would be *our* timeout wrapper
    // rather than the connection's, and the branch under test — which only ever
    // looks at handshake-class errors — would never be consulted.
    let mut quic_profile = lkh3::chrome_quic();
    quic_profile.transport_params.max_idle_timeout = 200;
    let client = Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .quic_profile(quic_profile)
        .add_ca_cert_der(cert.der.as_ref())
        .dns_resolver(Arc::new(LoopbackDns))
        .masque(proxy.outer_config())
        .timeout_config(
            lkrequest::TimeoutConfig::default().with_quic_connect_timeout(Duration::from_secs(10)),
        )
        .build();
    let session = client.session().proxy_config(proxy.config()).build();

    let error = get(&session, &origin.url("/blackholed"))
        .await
        .expect_err("a tunnel that discards every datagram cannot produce a response");

    let message = error.to_string();
    assert!(
        !message.contains(MASQUE_TCP_REFUSAL),
        "the inner handshake failed, but the caller was handed the TCP path's \
         complaint about the proxy instead: {message}"
    );
    // The structural half of the same claim, and the durable one: the TCP
    // refusal is a `Error::Proxy(ProtocolError)`, which is neither
    // handshake-class nor a timeout however it is worded.
    assert!(
        error.is_quic_handshake_failure() || error.is_timeout(),
        "the error must name the inner connection's handshake, not something else: \
         {error:?}"
    );
    assert!(
        !matches!(error, lkrequest::error::Error::InvalidConfig(_)),
        "nothing about this route is misconfigured: {error:?}"
    );

    assert_eq!(
        proxy.tunnel_requests(),
        1,
        "the inner handshake failed once; nothing may re-attempt the route"
    );
    assert_eq!(
        proxy.outer_connections(),
        1,
        "and the outer connection must not have been rebuilt either"
    );
    // A direct connection is not asserted against a counter: this file's
    // `Origin` is a QUIC endpoint and owns no TCP socket, so there is no accept
    // to count without binding a second listener on the same port number — a
    // race against the rest of the machine for a weaker signal than the one
    // above. `masque_cannot_carry_tcp` *is* the direct-path detector here: it is
    // produced before any TCP connect, on entry to the TCP path with a
    // `masque://` route, so its absence is the proof that the route was never
    // taken.
}

/// The guard above is only as good as the string it looks for.
///
/// Asserting on a message fragment is a trap: rename the error and the negative
/// assertion passes forever, for nothing. So produce the error the real way —
/// the TCP path, asked to carry a `masque://` route — and check the fragment
/// still appears in it.
#[tokio::test]
async fn the_tcp_fallback_error_is_still_the_one_this_test_guards_against() {
    let proxy = ProxyConfig::parse("masque://127.0.0.1:1").unwrap();
    // Refused on the scheme alone, before any socket is opened, so the
    // unreachable port above is never dialled.
    let error = proxy
        .connect("localhost", 443, None, &LoopbackDns)
        .await
        .expect_err("a MASQUE proxy must refuse to carry a TCP stream");
    assert!(
        error.to_string().contains(MASQUE_TCP_REFUSAL),
        "`{MASQUE_TCP_REFUSAL}` no longer appears in the TCP path's refusal, so the \
         assertion in `a_dead_inner_handshake_is_not_reported_as_a_tcp_incapable_proxy` \
         has stopped testing anything: {error}"
    );
}

// ---------------------------------------------------------------------------
// Fingerprint: the tunnel must be invisible to the origin
// ---------------------------------------------------------------------------

/// The parts of a QUIC Initial packet that are a fingerprint rather than a
/// random value.
#[derive(Debug, PartialEq, Eq)]
struct InitialShape {
    /// Size of the whole UDP datagram. This is what `initial_datagram_size` and
    /// `initial_mtu` control, and the first thing a tunnel would perturb.
    datagram_len: usize,
    first_byte_high_nibble: u8,
    version: u32,
    dcid_len: u8,
    scid_len: u8,
    token_len: u64,
}

fn parse_initial(datagram: &[u8]) -> InitialShape {
    let mut cursor = datagram;
    let first = cursor[0];
    assert_eq!(first & 0x80, 0x80, "not a long-header packet");
    cursor = &cursor[1..];
    let version = u32::from_be_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
    cursor = &cursor[4..];
    let dcid_len = cursor[0];
    cursor = &cursor[1 + dcid_len as usize..];
    let scid_len = cursor[0];
    cursor = &cursor[1 + scid_len as usize..];
    let token_len = decode_varint(&mut cursor).expect("truncated token length");
    InitialShape {
        datagram_len: datagram.len(),
        // Header form, fixed bit and long packet type; the low nibble carries
        // the (encrypted) packet number length and reserved bits.
        first_byte_high_nibble: first >> 4,
        version,
        dcid_len,
        scid_len,
        token_len,
    }
}

/// A plain UDP forwarder, so the no-proxy baseline can be observed the same way
/// the proxy observes the tunnelled one.
struct UdpTap {
    port: u16,
    first_datagram: Arc<Mutex<Option<Vec<u8>>>>,
    _task: JoinHandle<()>,
}

fn spawn_udp_tap(target: SocketAddr) -> UdpTap {
    let socket = std::net::UdpSocket::bind(localhost_addr(0)).unwrap();
    socket.set_nonblocking(true).unwrap();
    let socket = Arc::new(tokio::net::UdpSocket::from_std(socket).unwrap());
    let port = socket.local_addr().unwrap().port();
    let first_datagram = Arc::new(Mutex::new(None));

    let task = tokio::spawn({
        let first_datagram = first_datagram.clone();
        async move {
            let upstream = Arc::new(
                tokio::net::UdpSocket::bind(localhost_addr(0))
                    .await
                    .unwrap(),
            );
            upstream.connect(target).await.unwrap();
            let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

            let back = tokio::spawn({
                let socket = socket.clone();
                let upstream = upstream.clone();
                let client_addr = client_addr.clone();
                async move {
                    let mut buf = vec![0u8; 65535];
                    while let Ok(n) = upstream.recv(&mut buf).await {
                        let Some(addr) = *client_addr.lock().unwrap() else {
                            continue;
                        };
                        let _ = socket.send_to(&buf[..n], addr).await;
                    }
                }
            });

            let mut buf = vec![0u8; 65535];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                *client_addr.lock().unwrap() = Some(from);
                {
                    let mut first = first_datagram.lock().unwrap();
                    if first.is_none() {
                        *first = Some(buf[..n].to_vec());
                    }
                }
                let _ = upstream.send(&buf[..n]).await;
            }
            back.abort();
        }
    });

    UdpTap {
        port,
        first_datagram,
        _task: task,
    }
}

struct ProbeRelay {
    port: u16,
    dropped_probes: Arc<AtomicUsize>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for ProbeRelay {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

// Drop probes until after CONNECT-UDP succeeds, then pass fresh probes normally.
// Delaying every large packet lets later small packets overtake each probe and
// can exhaust Quinn's MTU search even on a path that accepts the larger size.
async fn spawn_probe_gated_relay(proxy: &Proxy, open_after: Option<Duration>) -> ProbeRelay {
    let front = Arc::new(
        tokio::net::UdpSocket::bind(localhost_addr(0))
            .await
            .unwrap(),
    );
    let back = Arc::new(
        tokio::net::UdpSocket::bind(localhost_addr(0))
            .await
            .unwrap(),
    );
    back.connect(localhost_addr(proxy.port)).await.unwrap();
    let port = front.local_addr().unwrap().port();
    let client = Arc::new(Mutex::new(None::<SocketAddr>));
    let dropped_probes = Arc::new(AtomicUsize::new(0));

    let outbound = {
        let front = front.clone();
        let back = back.clone();
        let client = client.clone();
        let counters = proxy.counters.clone();
        let dropped_probes = dropped_probes.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            while let Ok((len, from)) = front.recv_from(&mut buf).await {
                *client.lock().unwrap() = Some(from);
                let gate_open = open_after.is_some_and(|delay| {
                    counters
                        .first_response_sent
                        .lock()
                        .unwrap()
                        .is_some_and(|sent| sent.elapsed() >= delay)
                });
                if len > 1200 && !gate_open {
                    dropped_probes.fetch_add(1, Ordering::SeqCst);
                    continue;
                }
                let _ = back.send(&buf[..len]).await;
            }
        })
    };

    let inbound = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_536];
        while let Ok(len) = back.recv(&mut buf).await {
            let Some(to) = *client.lock().unwrap() else {
                continue;
            };
            let _ = front.send_to(&buf[..len], to).await;
        }
    });

    ProbeRelay {
        port,
        dropped_probes,
        tasks: vec![outbound, inbound],
    }
}

#[tokio::test]
async fn first_tunnel_waits_for_outer_mtu_discovery() {
    let cert = self_signed_localhost();
    let origin = spawn_origin(&cert, "delayed-probe");
    let proxy = spawn_proxy(ProxyMode::Relay);
    let relay = spawn_probe_gated_relay(&proxy, Some(Duration::from_millis(50))).await;
    let client = client_for(&cert, Some(&proxy));
    let session = client
        .session()
        .proxy_config(ProxyConfig::parse(&format!("masque://127.0.0.1:{}", relay.port)).unwrap())
        .build();

    let response = get(&session, &origin.url("/delayed-probe"))
        .await
        .expect("the first tunnel should wait for the outer PMTU probe acknowledgment");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), HttpVersion::H3);
    assert_eq!(response.text().unwrap(), "delayed-probe");
    assert_eq!(proxy.tunnel_requests(), 1);
    assert!(relay.dropped_probes.load(Ordering::SeqCst) > 0);
}

#[derive(Clone, Copy, Debug)]
enum CapacityRequest {
    Buffered,
    Streaming,
    Preconnect,
}

async fn capacity_failure_keeps_route_usable(mode: CapacityRequest) -> (usize, usize) {
    let cert = self_signed_localhost();
    let origin = spawn_origin(&cert, "late-probe");
    let proxy = spawn_proxy(ProxyMode::Relay);
    let relay = spawn_probe_gated_relay(&proxy, None).await;
    let client = client_for(&cert, Some(&proxy));
    let session = client
        .session()
        .proxy_config(ProxyConfig::parse(&format!("masque://127.0.0.1:{}", relay.port)).unwrap())
        .build();

    let url = origin.url("/before-probe");
    let first = tokio::time::timeout(TIMEOUT, async {
        match mode {
            CapacityRequest::Buffered => session.get(&url).send().await.map(|_| ()),
            CapacityRequest::Streaming => session.get(&url).send_streaming().await.map(|_| ()),
            CapacityRequest::Preconnect => session.preconnect(&url).await,
        }
    })
    .await
    .unwrap()
    .expect_err("the relay blocks all MTU probes");
    assert!(
        first.to_string().contains("offers only 1160 bytes"),
        "{mode:?}: {first}"
    );

    let second = get(&session, &origin.url("/retry"))
        .await
        .expect_err("the relay still blocks all MTU probes");
    assert!(
        second.to_string().contains("offers only 1160 bytes"),
        "the route must retry QUIC instead of falling into an impossible TCP fallback: {second}"
    );
    (proxy.tunnel_requests(), proxy.outer_connections())
}

#[tokio::test]
async fn transient_tunnel_capacity_does_not_quarantine_the_masque_route() {
    assert_eq!(
        capacity_failure_keeps_route_usable(CapacityRequest::Buffered).await,
        (2, 1)
    );
}

#[tokio::test]
async fn streaming_capacity_failure_preserves_the_error_and_allows_retry() {
    assert_eq!(
        capacity_failure_keeps_route_usable(CapacityRequest::Streaming).await,
        (2, 1)
    );
}

#[tokio::test]
async fn preconnect_capacity_failure_allows_retry() {
    assert_eq!(
        capacity_failure_keeps_route_usable(CapacityRequest::Preconnect).await,
        (2, 1)
    );
}

/// **The regression that matters**: routing through MASQUE must not change what
/// the origin sees.
///
/// The inner QUIC connection is handed a `quinn::AsyncUdpSocket` and is never
/// told it is inside a tunnel, so its Initial packet has to be the one the
/// browser profile produces — same padded datagram size, same connection ID
/// lengths, same version, same header shape. The only thing the MASQUE arm is
/// allowed to touch is the MTU ceiling, and it may only *lower* it, never raise
/// it above what the profile asked for.
///
/// Both sides are captured the same way, one datagram off the wire: the proxy
/// records the first payload it relays, and a plain UDP tap records the first
/// datagram of an otherwise identical direct connection. If this ever fails,
/// the assembly has leaked into the inner connection and the fix is upstream of
/// this test, not in it.
#[tokio::test]
async fn the_tunnel_does_not_change_the_inner_initial_packet() {
    let cert = self_signed_localhost();
    let origin = spawn_origin(&cert, "fingerprint");

    // Baseline: no proxy, through a tap that only forwards bytes.
    let tap = spawn_udp_tap(localhost_addr(origin.port));
    let direct_client = client_for(&cert, None);
    let direct_session = direct_client.session().http3_only().build();
    let direct = get(
        &direct_session,
        &format!("https://localhost:{}/direct", tap.port),
    )
    .await
    .expect("direct request failed");
    assert_eq!(direct.version(), HttpVersion::H3);

    // Same client fingerprint, now through the tunnel.
    let proxy = spawn_proxy(ProxyMode::Relay);
    let masque_client = client_for(&cert, Some(&proxy));
    let masque_session = masque_client
        .session()
        .proxy_config(proxy.config())
        .http3_only()
        .build();
    let tunnelled = get(&masque_session, &origin.url("/tunnelled"))
        .await
        .expect("tunnelled request failed");
    assert_eq!(tunnelled.version(), HttpVersion::H3);

    let direct_initial = tap
        .first_datagram
        .lock()
        .unwrap()
        .clone()
        .expect("the tap saw no datagram");
    let tunnelled_initial = proxy
        .first_inner_datagram
        .lock()
        .unwrap()
        .first()
        .cloned()
        .expect("the proxy relayed no datagram");

    let direct_shape = parse_initial(&direct_initial);
    let tunnelled_shape = parse_initial(&tunnelled_initial);
    assert_eq!(
        tunnelled_shape, direct_shape,
        "the MASQUE assembly changed the inner QUIC Initial packet; the tunnel must be \
         invisible to the origin, so investigate the inner endpoint's transport config rather \
         than relaxing this assertion"
    );
}
