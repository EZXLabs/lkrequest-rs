//! Tier-0 end-to-end tests for the MASQUE CONNECT-UDP I/O bridge
//! (`lkrequest::proxy::masque`).
//!
//! `masque_local_e2e.rs` proves the vendored `h3` can carry an extended CONNECT
//! at all, using a throwaway client. This file tests the real bridge: a
//! [`MasqueConnection`] driving `lkmasque`'s tunnel state machine, and
//! [`MasqueUdpSocket`] behaving like the `quinn::AsyncUdpSocket` the inner QUIC
//! endpoint will be handed.
//!
//! The proxy below is its own minimal test double — deliberately not shared
//! with the other file, so neither test can be quietly broken by a change made
//! for the other. It tags every echoed payload with the target port it was
//! tunnelled to, which is what makes the demultiplexing assertions meaningful:
//! a reply that reached the wrong tunnel is visible rather than indistinguishable.

use std::collections::HashMap;
use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use bytes::Bytes;
use h3::ext::Protocol;
use http::{Method, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::udp;
use quinn::AsyncUdpSocket;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use lkrequest::error::ProxyErrorKind;
use lkrequest::proxy::masque::{MasqueConnection, MasqueOuterConfig, MasqueUdpSocket};
use lkrequest::proxy::ProxyConfig;

const TUNNEL_TEMPLATE_PREFIX: &str = "/.well-known/masque/udp/";
const CAPSULE_PROTOCOL: &str = "capsule-protocol";
const CAPSULE_PROTOCOL_ENABLED: &str = "?1";
const UDP_PAYLOAD_CONTEXT_ID: u64 = 0;

/// Target host the proxy answers with 403, for the refusal path.
const REFUSED_HOST: &str = "refused.invalid";
/// Target host the proxy answers 200 for, but without `capsule-protocol: ?1`.
const NO_CAPSULE_HOST: &str = "nocapsule.invalid";
/// A target the proxy double answers with `200` **plus** `content-length: 0`,
/// which RFC 9297 §3.2 forbids on a Capsule Protocol message.
const CONTENT_LENGTH_HOST: &str = "contentlength.invalid";
/// Target host the proxy answers with 407, the proxy-authentication spelling
/// (RFC 9110 §15.5.8) a MASQUE proxy uses for a bad `proxy-authorization`.
const AUTH_407_HOST: &str = "needs-proxy-auth.invalid";
/// Target host the proxy answers with 401, the spelling the masque-go /
/// RFC 9484 §11 style deployments use with an `authorization` field.
const AUTH_401_HOST: &str = "needs-auth.invalid";

const TIMEOUT: Duration = Duration::from_secs(10);

fn ensure_rustls_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn localhost_addr(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

// ---------------------------------------------------------------------------
// Throwaway varint + HTTP Datagram codec for the proxy side only
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
// Local MASQUE proxy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProxyEvent {
    TunnelOpened {
        quarter: u64,
        host: String,
        port: u16,
    },
    TunnelClosed {
        quarter: u64,
    },
}

struct LocalMasqueProxy {
    addr: SocketAddr,
    certificate: CertificateDer<'static>,
    /// The same certificate as PEM — the form a private CA is actually handed
    /// out in, and what `MasqueOuterConfig::add_ca_certs_pem` takes.
    certificate_pem: String,
    events: mpsc::UnboundedReceiver<ProxyEvent>,
    endpoint: quinn::Endpoint,
    _task: JoinHandle<()>,
}

impl LocalMasqueProxy {
    /// The `ProxyConfig` a client would be configured with.
    fn proxy_config(&self) -> ProxyConfig {
        ProxyConfig::parse(&format!("masque://127.0.0.1:{}", self.addr.port())).unwrap()
    }

    /// Outer settings that trust this proxy's throwaway certificate and nothing
    /// else, so the test never depends on the host's certificate store.
    fn outer_config(&self) -> MasqueOuterConfig {
        // `MasqueOuterConfig` is `#[non_exhaustive]`: from `Default`, then
        // assign. A struct literal — `..Default::default()` included — does not
        // compile outside the crate.
        let mut config = MasqueOuterConfig::default();
        config.use_native_certs = false;
        config.extra_roots = vec![self.certificate.clone()];
        config.server_name = Some("localhost".to_string());
        config
    }

    /// The same trust decision, reached through the PEM entry point instead of
    /// by handing `extra_roots` a DER certificate directly.
    fn outer_config_from_pem(&self) -> MasqueOuterConfig {
        let mut config = MasqueOuterConfig::default();
        config.use_native_certs = false;
        config.server_name = Some("localhost".to_string());
        let added = config
            .add_ca_certs_pem(self.certificate_pem.as_bytes())
            .expect("the proxy's own PEM must parse");
        assert_eq!(added, 1);
        config
    }

    /// Same, but with a deliberately shallow per-tunnel inbound queue.
    fn outer_config_with_inbox_depth(&self, inbox_depth: usize) -> MasqueOuterConfig {
        let mut config = self.outer_config();
        config.inbox_depth = inbox_depth;
        config
    }

    async fn next_event(&mut self) -> ProxyEvent {
        tokio::time::timeout(TIMEOUT, self.events.recv())
            .await
            .expect("proxy event timed out")
            .expect("proxy event channel closed")
    }

    /// Kill the proxy the way a crashing or restarting one dies: every QUIC
    /// connection on its endpoint is closed at once, with no CONNECT-UDP
    /// stream being finished first.
    fn kill(&self) {
        self.endpoint.close(0u32.into(), b"proxy gone");
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
    if host.is_empty() || host == REFUSED_HOST {
        return Err(StatusCode::FORBIDDEN);
    }
    // The test double does not verify credentials; these two targets stand in
    // for a proxy that did and disliked what it saw. Both statuses must be
    // classified as an authentication failure rather than a plain refusal.
    if host == AUTH_407_HOST {
        return Err(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
    }
    if host == AUTH_401_HOST {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let port: u16 = port.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    if port == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok((host, port))
}

fn spawn_local_masque_proxy() -> LocalMasqueProxy {
    ensure_rustls_provider();

    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        certificate.signing_key.serialize_der(),
    ));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));

    let endpoint = quinn::Endpoint::server(config, localhost_addr(0)).unwrap();
    let addr = endpoint.local_addr().unwrap();

    let (events_tx, events) = mpsc::unbounded_channel();
    let task = tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            while let Some(incoming) = endpoint.accept().await {
                let events_tx = events_tx.clone();
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    serve_masque_connection(connection, events_tx).await;
                });
            }
        }
    });

    LocalMasqueProxy {
        addr,
        certificate: certificate_der,
        certificate_pem: certificate.cert.pem(),
        events,
        endpoint,
        _task: task,
    }
}

/// What the proxy does with one tunnel's payloads.
#[derive(Clone)]
enum Route {
    /// Echo the payload back, tagged with the target port so a misrouted reply
    /// is visible. Used for every target that is not a real address.
    Echo(u16),
    /// Forward to a real UDP target and relay its answers back — what a MASQUE
    /// proxy actually does, and what lets a whole QUIC connection run inside a
    /// tunnel.
    Relay(Arc<tokio::net::UdpSocket>),
}

/// Quarter Stream ID -> what to do with its datagrams.
type Routes = Arc<Mutex<HashMap<u64, Route>>>;

async fn serve_masque_connection(
    connection: quinn::Connection,
    events: mpsc::UnboundedSender<ProxyEvent>,
) {
    let routes: Routes = Arc::new(Mutex::new(HashMap::new()));

    // Datagrams bypass h3 entirely, exactly as the client does.
    let echo = tokio::spawn({
        let connection = connection.clone();
        let routes = routes.clone();
        async move {
            while let Ok(datagram) = connection.read_datagram().await {
                let Some((quarter, context_id, payload)) = decode_datagram(&datagram) else {
                    continue;
                };
                if context_id != UDP_PAYLOAD_CONTEXT_ID {
                    continue;
                }
                let route = routes.lock().unwrap().get(&quarter).cloned();
                match route {
                    Some(Route::Echo(port)) => {
                        let mut tagged = Vec::with_capacity(payload.len() + 2);
                        tagged.extend_from_slice(&port.to_be_bytes());
                        tagged.extend_from_slice(&payload);
                        let _ = connection.send_datagram(encode_datagram(
                            quarter,
                            UDP_PAYLOAD_CONTEXT_ID,
                            &tagged,
                        ));
                    }
                    Some(Route::Relay(socket)) => {
                        let _ = socket.send(&payload).await;
                    }
                    None => continue,
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
    let Ok(mut h3_connection) = builder
        .build::<_, Bytes>(h3_quinn::Connection::new(connection))
        .await
    else {
        echo.abort();
        return;
    };

    while let Ok(Some(resolver)) = h3_connection.accept().await {
        let Ok((request, mut stream)) = resolver.resolve_request().await else {
            continue;
        };
        // `h3::quic::StreamId` is the full QUIC stream ID on both sides, so
        // the quarter stream ID (RFC 9297 §2.1) is a division away. The fork
        // used to patch `h3-quinn` to hand back quinn's `index()`, which is
        // already `id >> 2`, and this line did no arithmetic at all; the
        // rebase onto current upstream dropped that patch.
        let quarter = stream.id().into_inner() / 4;

        match parse_connect_udp(&request) {
            Ok((host, port)) => {
                let mut response = http::Response::builder().status(StatusCode::OK);
                if host != NO_CAPSULE_HOST {
                    response = response.header(CAPSULE_PROTOCOL, CAPSULE_PROTOCOL_ENABLED);
                }
                // A 200 that also declares content: what an HTTP framework
                // does to a bodyless response, and what RFC 9297 §3.2 forbids
                // on a Capsule Protocol message.
                if host == CONTENT_LENGTH_HOST {
                    response = response.header(http::header::CONTENT_LENGTH, "0");
                }
                if stream
                    .send_response(response.body(()).unwrap())
                    .await
                    .is_err()
                {
                    continue;
                }

                // A target that is a literal address gets a real UDP relay; a
                // made-up hostname gets the tagged echo.
                let route = match host.parse::<std::net::IpAddr>() {
                    Ok(ip) => {
                        let relay = tokio::net::UdpSocket::bind(localhost_addr(0))
                            .await
                            .expect("relay bind failed");
                        relay
                            .connect(SocketAddr::new(ip, port))
                            .await
                            .expect("relay connect failed");
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
                                        // A payload too large for an outer
                                        // datagram is dropped, not fatal
                                        // (RFC 9298 §5): the peer behind this
                                        // relay does its own MTU discovery and
                                        // needs that loss to back off. Ending
                                        // the task would stall the tunnel.
                                        Err(quinn::SendDatagramError::TooLarge) => continue,
                                        Err(_) => break,
                                    }
                                }
                            }
                        });
                        Route::Relay(relay)
                    }
                    Err(_) => Route::Echo(port),
                };
                routes.lock().unwrap().insert(quarter, route);
                let _ = events.send(ProxyEvent::TunnelOpened {
                    quarter,
                    host,
                    port,
                });

                // No `finish()`: the tunnel stays open until the client FINs.
                let routes = routes.clone();
                let events = events.clone();
                tokio::spawn(async move {
                    while let Ok(Some(_capsule)) = stream.recv_data().await {}
                    let _ = stream.finish().await;
                    routes.lock().unwrap().remove(&quarter);
                    let _ = events.send(ProxyEvent::TunnelClosed { quarter });
                });
            }
            Err(status) => {
                let response = http::Response::builder().status(status).body(()).unwrap();
                let _ = stream.send_response(response).await;
                let _ = stream.finish().await;
            }
        }
    }

    echo.abort();
}

// ---------------------------------------------------------------------------
// Driving MasqueUdpSocket as the inner QUIC endpoint would
// ---------------------------------------------------------------------------

fn send_through(socket: &MasqueUdpSocket, payload: &[u8]) -> io::Result<()> {
    socket.try_send(&udp::Transmit {
        destination: socket.quinn_addr(),
        ecn: None,
        contents: payload,
        segment_size: None,
        src_ip: None,
    })
}

async fn recv_through(socket: &MasqueUdpSocket) -> io::Result<(Vec<u8>, SocketAddr)> {
    let mut buf = vec![0u8; 4096];
    let mut meta = [udp::RecvMeta::default()];
    {
        let buf = &mut buf;
        std::future::poll_fn(|cx| {
            let mut bufs = [IoSliceMut::new(&mut buf[..])];
            socket.poll_recv(cx, &mut bufs, &mut meta)
        })
        .await?;
    }
    buf.truncate(meta[0].len);
    Ok((buf, meta[0].addr))
}

async fn expect_echo(socket: &MasqueUdpSocket, expected_port: u16, payload: &[u8]) {
    let (received, from) = tokio::time::timeout(TIMEOUT, recv_through(socket))
        .await
        .expect("tunnel echo timed out")
        .expect("tunnel read failed");
    assert_eq!(
        from,
        socket.quinn_addr(),
        "inbound datagrams must look like they came from the tunnel's peer"
    );
    assert!(received.len() >= 2, "echo is missing its tunnel tag");
    let tag = u16::from_be_bytes([received[0], received[1]]);
    assert_eq!(tag, expected_port, "echo arrived on the wrong tunnel");
    assert_eq!(&received[2..], payload);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tunnel_opens_and_reports_a_usable_capacity() {
    let mut proxy = spawn_local_masque_proxy();
    let connection =
        MasqueConnection::connect(&proxy.proxy_config(), proxy.addr, &proxy.outer_config())
            .await
            .expect("outer connection failed");

    let socket = connection
        .open_tunnel("target.invalid", 443)
        .await
        .expect("tunnel failed");

    assert_eq!(connection.tunnel_count(), 1);
    assert_eq!(socket.quinn_addr(), SocketAddr::from(([127, 0, 0, 2], 443)));

    // The inner MTU is the outer datagram budget minus the two varint prefixes
    // (RFC 9298 §5) — strictly smaller, and large enough to be usable.
    let outer = connection.max_datagram_size();
    assert!(outer > 0, "proxy did not advertise a datagram limit");
    assert!(socket.capacity() > 0);
    assert!(socket.capacity() < outer);
    assert!(outer - socket.capacity() <= 16);

    match proxy.next_event().await {
        ProxyEvent::TunnelOpened { host, port, .. } => {
            assert_eq!(host, "target.invalid");
            assert_eq!(port, 443);
        }
        other => panic!("expected a tunnel to open, got {other:?}"),
    }
}

#[tokio::test]
async fn datagrams_round_trip_through_the_async_udp_socket() {
    let mut proxy = spawn_local_masque_proxy();
    let connection =
        MasqueConnection::connect(&proxy.proxy_config(), proxy.addr, &proxy.outer_config())
            .await
            .expect("outer connection failed");

    let socket = connection
        .open_tunnel("target.invalid", 443)
        .await
        .expect("tunnel failed");
    assert!(matches!(
        proxy.next_event().await,
        ProxyEvent::TunnelOpened { port: 443, .. }
    ));

    for round in 0..3u8 {
        let payload = [b"inner-quic-packet-".as_slice(), &[round]].concat();
        send_through(&socket, &payload).expect("try_send failed");
        expect_echo(&socket, 443, &payload).await;
    }

    let stats = socket.stats().expect("tunnel is still registered");
    assert_eq!(stats.datagrams_sent, 3);
    assert_eq!(stats.datagrams_received, 3);
    assert_eq!(stats.dropped_unknown_context, 0);
    assert_eq!(socket.inbound_drops(), 0);
}

#[tokio::test]
async fn two_tunnels_on_one_outer_connection_are_demultiplexed() {
    let mut proxy = spawn_local_masque_proxy();
    let connection =
        MasqueConnection::connect(&proxy.proxy_config(), proxy.addr, &proxy.outer_config())
            .await
            .expect("outer connection failed");

    let first = connection
        .open_tunnel("first.invalid", 4433)
        .await
        .expect("first tunnel failed");
    let second = connection
        .open_tunnel("second.invalid", 8443)
        .await
        .expect("second tunnel failed");

    assert_eq!(connection.tunnel_count(), 2);
    assert_ne!(
        first.quarter_stream_id(),
        second.quarter_stream_id(),
        "each tunnel needs its own Quarter Stream ID to be routable"
    );
    // The vendored `h3-quinn` hands back already-quartered IDs, so the first two
    // request streams are 0 and 1, not 0 and 4. Getting this wrong routes every
    // tunnel after the first to the wrong place.
    assert_eq!(first.quarter_stream_id().value(), 0);
    assert_eq!(second.quarter_stream_id().value(), 1);

    let mut opened = [proxy.next_event().await, proxy.next_event().await];
    opened.sort_by_key(|event| match event {
        ProxyEvent::TunnelOpened { port, .. } => *port,
        ProxyEvent::TunnelClosed { .. } => u16::MAX,
    });
    assert!(matches!(
        &opened[0],
        ProxyEvent::TunnelOpened { port: 4433, host, .. } if host == "first.invalid"
    ));
    assert!(matches!(
        &opened[1],
        ProxyEvent::TunnelOpened { port: 8443, host, .. } if host == "second.invalid"
    ));

    // Interleave both directions: a demultiplexer that ignored the Quarter
    // Stream ID would deliver these to whichever tunnel read first.
    send_through(&first, b"for-first").expect("try_send failed");
    send_through(&second, b"for-second").expect("try_send failed");

    expect_echo(&first, 4433, b"for-first").await;
    expect_echo(&second, 8443, b"for-second").await;

    // And again in the opposite order, so the result cannot be an artefact of
    // the order the two sockets happened to be polled in.
    send_through(&second, b"second-again").expect("try_send failed");
    send_through(&first, b"first-again").expect("try_send failed");

    expect_echo(&second, 8443, b"second-again").await;
    expect_echo(&first, 4433, b"first-again").await;
}

#[tokio::test]
async fn closing_a_tunnel_finishes_its_request_stream_and_frees_the_outer_connection() {
    let mut proxy = spawn_local_masque_proxy();
    let connection =
        MasqueConnection::connect(&proxy.proxy_config(), proxy.addr, &proxy.outer_config())
            .await
            .expect("outer connection failed");

    let keep = connection
        .open_tunnel("keep.invalid", 443)
        .await
        .expect("tunnel failed");
    let doomed = connection
        .open_tunnel("doomed.invalid", 444)
        .await
        .expect("tunnel failed");
    let doomed_quarter = doomed.quarter_stream_id().value();

    let _ = proxy.next_event().await;
    let _ = proxy.next_event().await;
    assert_eq!(connection.tunnel_count(), 2);

    doomed.close();
    doomed.closed().await;

    // A normal FIN, not a reset: the proxy sees the stream end cleanly.
    match proxy.next_event().await {
        ProxyEvent::TunnelClosed { quarter } => assert_eq!(quarter, doomed_quarter),
        other => panic!("expected the tunnel to close, got {other:?}"),
    }

    // The tunnel is unregistered and its socket now reports the peer as gone,
    // which is what tears the inner QUIC endpoint down.
    assert_eq!(connection.tunnel_count(), 1);
    assert!(socket_is_dead(&doomed).await);
    assert!(send_through(&doomed, b"too late").is_err());

    // The sibling tunnel on the same outer connection is untouched.
    send_through(&keep, b"still-alive").expect("try_send failed");
    expect_echo(&keep, 443, b"still-alive").await;
    assert!(connection.is_live());
}

async fn socket_is_dead(socket: &MasqueUdpSocket) -> bool {
    matches!(
        tokio::time::timeout(TIMEOUT, recv_through(socket)).await,
        Ok(Err(_))
    )
}

#[tokio::test]
async fn dropping_the_socket_retires_the_tunnel() {
    let mut proxy = spawn_local_masque_proxy();
    let connection =
        MasqueConnection::connect(&proxy.proxy_config(), proxy.addr, &proxy.outer_config())
            .await
            .expect("outer connection failed");

    let socket = connection
        .open_tunnel("target.invalid", 443)
        .await
        .expect("tunnel failed");
    let quarter = socket.quarter_stream_id().value();
    let _ = proxy.next_event().await;

    drop(socket);

    match proxy.next_event().await {
        ProxyEvent::TunnelClosed { quarter: closed } => assert_eq!(closed, quarter),
        other => panic!("expected the tunnel to close, got {other:?}"),
    }
    assert_eq!(connection.tunnel_count(), 0);
}

#[tokio::test]
async fn a_refused_tunnel_is_reported_as_a_proxy_error_not_a_quic_failure() {
    let proxy = spawn_local_masque_proxy();
    let connection =
        MasqueConnection::connect(&proxy.proxy_config(), proxy.addr, &proxy.outer_config())
            .await
            .expect("outer connection failed");

    let error = connection
        .open_tunnel(REFUSED_HOST, 443)
        .await
        .expect_err("a 403 must not produce a tunnel");

    let details = error.as_proxy_error().expect("expected a proxy error");
    assert_eq!(
        details.kind,
        ProxyErrorKind::TunnelRefused { status_code: 403 }
    );
    assert_eq!(connection.tunnel_count(), 0);

    // The outer connection survives one refused tunnel, so the next target can
    // still be tried on it.
    assert!(connection.is_live());
    let ok = connection
        .open_tunnel("target.invalid", 443)
        .await
        .expect("a later tunnel must still work");
    assert_eq!(ok.quarter_stream_id().value(), 1);
}

/// Drive one credential rejection end to end and hand back how it was
/// classified.
///
/// The interesting part is not that the tunnel fails — the 403 test above
/// already covers refusal — but *how*, which each caller asserts. A wrong
/// password is the most common MASQUE misconfiguration, and the classification
/// decides whether the user is told to fix their credentials or sent looking
/// for a broken proxy.
///
/// The rest of the contract is asserted here, because it does not vary with the
/// status: one rejected tunnel must not cost the outer connection, which is
/// shared by every other target in the session.
async fn classify_rejected_credential(refusing_host: &str) -> (ProxyErrorKind, String) {
    let mut proxy = spawn_local_masque_proxy();
    let connection =
        MasqueConnection::connect(&proxy.proxy_config(), proxy.addr, &proxy.outer_config())
            .await
            .expect("outer connection failed");

    let error = connection
        .open_tunnel(refusing_host, 443)
        .await
        .expect_err("a rejected credential must not produce a tunnel");
    let details = error.as_proxy_error().expect("expected a proxy error");
    let classified = (details.kind, details.message.clone());

    assert_eq!(connection.tunnel_count(), 0);

    // One bad credential must not tear the outer connection down: it is shared
    // by every tunnel in the session, so a single rejection cannot be allowed
    // to take the others with it.
    assert!(
        connection.is_live(),
        "a rejected tunnel must not close the outer connection"
    );
    let ok = connection
        .open_tunnel("target.invalid", 443)
        .await
        .expect("a later tunnel on the same outer connection must still work");
    assert_eq!(
        ok.quarter_stream_id().value(),
        1,
        "the refused request stream still consumed its own ID"
    );
    assert!(matches!(
        proxy.next_event().await,
        ProxyEvent::TunnelOpened { port: 443, .. }
    ));

    // And it carries traffic, so "live" is not just an unclosed handle.
    send_through(&ok, b"after-auth-failure").expect("try_send failed");
    expect_echo(&ok, 443, b"after-auth-failure").await;

    classified
}

#[tokio::test]
async fn a_407_is_reported_as_an_authentication_failure() {
    let (kind, message) = classify_rejected_credential(AUTH_407_HOST).await;
    assert_eq!(
        kind,
        ProxyErrorKind::AuthenticationFailed,
        "407 must classify as AuthenticationFailed, not TunnelRefused \
         {{ status_code: 407 }}; got {kind:?} with message {message:?}"
    );
    // The status still has to reach the message: "authentication failed" alone
    // does not tell a user which of the two spellings the proxy chose.
    assert!(
        message.contains("credentials") && message.contains("407"),
        "unhelpful message: {message}"
    );
}

#[tokio::test]
async fn a_401_is_reported_as_an_authentication_failure() {
    // The same classification has to hold for the `Authorization` spelling, or
    // masque-go-style deployments would report a bad password as a refusal.
    let (kind, message) = classify_rejected_credential(AUTH_401_HOST).await;
    assert_eq!(
        kind,
        ProxyErrorKind::AuthenticationFailed,
        "401 must classify as AuthenticationFailed, not TunnelRefused \
         {{ status_code: 401 }}; got {kind:?} with message {message:?}"
    );
    assert!(
        message.contains("credentials") && message.contains("401"),
        "unhelpful message: {message}"
    );
}

/// A proxy that answers 200 but omits `capsule-protocol` still gets a tunnel.
///
/// This test asserted the opposite until an RFC audit worked the chain through:
/// RFC 9298 §3.5 imports the requirements of **RFC 9297 §3.2**, and that
/// section's list is 2xx/101, not 204/205/206, and no content fields — the
/// header is not in it. The header's own requirement lives in RFC 9297 §3.4 and
/// is a SHOULD, "to simplify intermediary processing", with §3.2 noting an
/// intermediary can instead rely on "understanding the chosen HTTP Upgrade
/// token". For a 2xx answer to `connect-udp` the protocol is therefore already
/// in force.
///
/// So the old behaviour refused a proxy that was within the specification, and
/// through `quarantine_masque_failure` blacklisted the route as well. The point
/// of a MASQUE proxy is to carry the user's request while hiding their address;
/// rejecting a working proxy over an omitted SHOULD defeats that for no gain.
/// The omission is now logged instead —
/// `masque.capsule_protocol_header_absent`.
#[tokio::test]
async fn a_2xx_without_the_capsule_protocol_header_still_opens_the_tunnel() {
    let proxy = spawn_local_masque_proxy();
    let connection =
        MasqueConnection::connect(&proxy.proxy_config(), proxy.addr, &proxy.outer_config())
            .await
            .expect("outer connection failed");

    let socket = connection
        .open_tunnel(NO_CAPSULE_HOST, 443)
        .await
        .expect("a 200 without capsule-protocol is within RFC 9297 §3.4");

    assert_eq!(
        connection.tunnel_count(),
        1,
        "the tunnel must be registered, not merely not-an-error"
    );
    drop(socket);
}

/// The requirement RFC 9298 §3.5 actually imports, which used to go unchecked:
/// RFC 9297 §3.2 forbids `content-length` (with `content-type` and
/// `transfer-encoding`) on a Capsule Protocol message, and says a receiver
/// seeing one "MUST treat the HTTP message as malformed".
///
/// `content-length: 0` on a bodyless 200 is the realistic case, because HTTP
/// frameworks add it. Accepting it meant the data stream of a message that
/// declares HTTP content was parsed as capsules — either failing several bytes
/// later with an error blaming the capsule framing, or swallowing content as if
/// it were capsules. Failing here, with the field named, is what lets the
/// operator act on it.
#[tokio::test]
async fn a_2xx_declaring_content_is_rejected_as_malformed() {
    let proxy = spawn_local_masque_proxy();
    let connection =
        MasqueConnection::connect(&proxy.proxy_config(), proxy.addr, &proxy.outer_config())
            .await
            .expect("outer connection failed");

    let error = connection
        .open_tunnel(CONTENT_LENGTH_HOST, 443)
        .await
        .expect_err("a response declaring content cannot start the Capsule Protocol");

    let details = error.as_proxy_error().expect("expected a proxy error");
    assert_eq!(details.kind, ProxyErrorKind::ProtocolError);
    assert!(
        details.message.contains("content-length"),
        "the error must name the field it saw: {}",
        details.message
    );
    assert_eq!(
        connection.tunnel_count(),
        0,
        "no tunnel may survive a malformed response"
    );
}

#[tokio::test]
async fn a_payload_over_the_tunnel_capacity_is_dropped_rather_than_failing_the_send() {
    let mut proxy = spawn_local_masque_proxy();
    let connection =
        MasqueConnection::connect(&proxy.proxy_config(), proxy.addr, &proxy.outer_config())
            .await
            .expect("outer connection failed");

    let socket = connection
        .open_tunnel("target.invalid", 443)
        .await
        .expect("tunnel failed");
    let _ = proxy.next_event().await;

    // RFC 9298 §5: too big for the tunnel is an ordinary UDP discard, not an
    // error the sender sees.
    let oversized = vec![0xa5u8; socket.capacity() + 1];
    send_through(&socket, &oversized).expect("an over-capacity payload must not error");
    assert_eq!(
        socket.stats().unwrap().dropped_over_capacity,
        1,
        "the discard must be counted"
    );

    // The tunnel stays usable afterwards.
    send_through(&socket, b"still-works").expect("try_send failed");
    expect_echo(&socket, 443, b"still-works").await;
}

// ---------------------------------------------------------------------------
// Losing the outer connection
// ---------------------------------------------------------------------------

/// The error a dead tunnel reports to the inner QUIC endpoint.
///
/// `ConnectionAborted` is the contract: quinn treats it as the socket being
/// gone and closes the inner connection, which is how a tunnel failure reaches
/// the caller as a path failure instead of hanging forever.
async fn recv_error_kind(socket: &MasqueUdpSocket) -> io::ErrorKind {
    tokio::time::timeout(TIMEOUT, recv_through(socket))
        .await
        .expect("a dead tunnel neither delivered nor failed")
        .expect_err("a dead tunnel must fail the read, not deliver")
        .kind()
}

/// Losing the outer connection has to take **every** tunnel on it down.
///
/// The bridge's cascade runs through the connection-level datagram pump: when
/// `read_datagram` fails the pump calls `Registry::shutdown_all`, which closes
/// each tunnel's inbox and signals each stream pump. Nothing else notices the
/// loss, so if that one path regressed, a tunnel would sit forever waiting for
/// datagrams that can never arrive — the failure mode a timeout hides and a
/// test has to catch.
///
/// The failure is injected by killing the proxy's endpoint: the client sees a
/// CONNECTION_CLOSE with no CONNECT-UDP stream having been finished, i.e. the
/// unclean loss, not the orderly teardown the close tests already cover.
#[tokio::test]
async fn losing_the_outer_connection_tears_down_every_tunnel_on_it() {
    let mut proxy = spawn_local_masque_proxy();
    let connection =
        MasqueConnection::connect(&proxy.proxy_config(), proxy.addr, &proxy.outer_config())
            .await
            .expect("outer connection failed");

    let first = connection
        .open_tunnel("first.invalid", 4433)
        .await
        .expect("first tunnel failed");
    let second = connection
        .open_tunnel("second.invalid", 8443)
        .await
        .expect("second tunnel failed");
    let _ = proxy.next_event().await;
    let _ = proxy.next_event().await;
    assert_eq!(connection.tunnel_count(), 2);

    // Both tunnels carry traffic first, so a dead socket below can only be the
    // cascade and not a tunnel that never worked.
    send_through(&first, b"before-the-loss").expect("try_send failed");
    expect_echo(&first, 4433, b"before-the-loss").await;
    send_through(&second, b"before-the-loss").expect("try_send failed");
    expect_echo(&second, 8443, b"before-the-loss").await;

    proxy.kill();

    // Both sockets, not just the one that happened to be polled first.
    assert_eq!(
        recv_error_kind(&first).await,
        io::ErrorKind::ConnectionAborted,
        "the first tunnel must report the peer as gone"
    );
    assert_eq!(
        recv_error_kind(&second).await,
        io::ErrorKind::ConnectionAborted,
        "the second tunnel must report the peer as gone"
    );

    // Every stream pump retired rather than leaking: `closed()` awaits the
    // spawned task, so this hangs (and the test times out) if a pump is still
    // parked on its request stream.
    tokio::time::timeout(TIMEOUT, first.closed())
        .await
        .expect("the first tunnel's stream pump did not retire");
    tokio::time::timeout(TIMEOUT, second.closed())
        .await
        .expect("the second tunnel's stream pump did not retire");

    assert_eq!(connection.tunnel_count(), 0);
    assert!(
        !connection.is_live(),
        "the outer connection must report itself as gone"
    );

    // Writes fail rather than panicking or pretending to succeed.
    assert!(send_through(&first, b"too late").is_err());
    assert!(send_through(&second, b"too late").is_err());

    // Dropping the sockets and the connection after the cascade must not panic
    // either: teardown runs a second time over already-emptied state.
    drop(first);
    drop(second);
    drop(connection);
}

// ---------------------------------------------------------------------------
// Inbound queue overflow
// ---------------------------------------------------------------------------

/// A reader that falls behind loses the **oldest** datagrams and keeps
/// receiving.
///
/// `TunnelHandle::push` evicts the front of the queue on overflow instead of
/// refusing the new datagram, which is the UDP-shaped choice (RFC 9298 §5): a
/// stalled inner endpoint should resume on fresh packets rather than replay a
/// backlog it has already timed out on. The existing round-trip test only ever
/// asserts `inbound_drops() == 0`, so nothing proved the overflow branch works
/// — or that the queue stays usable afterwards rather than wedging.
///
/// Queue depth is 8 here, not the 512 default. `MasqueOuterConfig::inbox_depth`
/// exists precisely so this queue can be sized, and the eviction rule does not
/// depend on the number: `push` drops the front whenever `queue.len() >= depth`.
/// Filling 512 slots would mean pushing more than 512 echoes through the outer
/// connection and waiting for all of them — no extra coverage, but a much
/// slower test and far more in-flight datagrams for congestion control to drop,
/// which is the one thing that could make the exact drop count below flaky.
#[tokio::test]
async fn an_overflowing_inbound_queue_drops_the_oldest_and_keeps_receiving() {
    const DEPTH: usize = 8;
    const BURST: u16 = 40;

    let mut proxy = spawn_local_masque_proxy();
    let connection = MasqueConnection::connect(
        &proxy.proxy_config(),
        proxy.addr,
        &proxy.outer_config_with_inbox_depth(DEPTH),
    )
    .await
    .expect("outer connection failed");

    let socket = connection
        .open_tunnel("target.invalid", 443)
        .await
        .expect("tunnel failed");
    let _ = proxy.next_event().await;

    // Every echo comes back tagged with the sequence number that produced it,
    // so *which* datagrams survived the overflow is observable rather than a
    // matter of counting.
    for seq in 0..BURST {
        send_through(&socket, &seq.to_be_bytes()).expect("try_send failed");
    }

    // Nothing reads the socket while the echoes pile up: the stalled-reader
    // case the queue depth exists for.
    let expected_drops = u64::from(BURST) - DEPTH as u64;
    let drops = wait_for_inbound_drops(&socket, expected_drops).await;
    assert!(drops > 0, "the overflow branch never ran");
    // Pushes minus queue capacity. Exact, because the burst is small enough
    // that every echo really does come back.
    assert_eq!(
        drops, expected_drops,
        "every datagram over the queue depth must be counted exactly once"
    );

    // Draining shows the queue kept the newest datagrams, not the first eight.
    let mut seen = Vec::new();
    while let Ok(received) =
        tokio::time::timeout(Duration::from_millis(250), recv_through(&socket)).await
    {
        let (payload, _) = received.expect("the tunnel must still be alive");
        assert_eq!(payload.len(), 4, "echo lost its tunnel tag or its sequence");
        assert_eq!(
            u16::from_be_bytes([payload[0], payload[1]]),
            443,
            "echo arrived on the wrong tunnel"
        );
        seen.push(u16::from_be_bytes([payload[2], payload[3]]));
    }

    assert_eq!(
        seen.len(),
        DEPTH,
        "the queue must hand back exactly what it held: {seen:?}"
    );
    assert!(
        !seen.contains(&0),
        "the oldest datagram must be the first evicted, not the one kept: {seen:?}"
    );
    assert!(
        seen.iter().copied().max().unwrap() >= BURST - DEPTH as u16,
        "the reader must still see the newest datagrams, not a stale window: {seen:?}"
    );

    // Overflow is not a failure: the tunnel keeps receiving afterwards. This is
    // the half that distinguishes "dropped the oldest" from "stopped reading".
    send_through(&socket, b"after-overflow").expect("try_send failed");
    expect_echo(&socket, 443, b"after-overflow").await;
    assert_eq!(
        socket.inbound_drops(),
        expected_drops,
        "a datagram read into an empty queue must not count as a drop"
    );
}

/// Wait until at least `expected` inbound datagrams have been dropped.
///
/// The counter is bumped by the datagram pump task, so polling is the only way
/// to observe it; every push is already in flight when this is called, so the
/// loop settles in a few milliseconds.
async fn wait_for_inbound_drops(socket: &MasqueUdpSocket, expected: u64) -> u64 {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        let drops = socket.inbound_drops();
        if drops >= expected {
            return drops;
        }
        if tokio::time::Instant::now() >= deadline {
            let stats = socket.stats();
            panic!(
                "only {drops} of {expected} expected drops after {TIMEOUT:?}; tunnel stats: \
                 {stats:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// ---------------------------------------------------------------------------
// A whole inner QUIC connection inside one tunnel
// ---------------------------------------------------------------------------

const INNER_ALPN: &[u8] = b"lkmasque-inner-test";

struct InnerQuicServer {
    addr: SocketAddr,
    certificate: CertificateDer<'static>,
    _endpoint: quinn::Endpoint,
    _task: JoinHandle<()>,
}

/// A plain QUIC server that echoes one bidirectional stream per connection.
fn spawn_inner_quic_echo_server() -> InnerQuicServer {
    ensure_rustls_provider();

    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        certificate.signing_key.serialize_der(),
    ));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], key)
        .unwrap();
    tls.alpn_protocols = vec![INNER_ALPN.to_vec()];
    let config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));

    let endpoint = quinn::Endpoint::server(config, localhost_addr(0)).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let task = tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                        let Ok(body) = recv.read_to_end(64 * 1024).await else {
                            return;
                        };
                        let _ = send.write_all(&body).await;
                        let _ = send.finish();
                    }
                });
            }
        }
    });

    InnerQuicServer {
        addr,
        certificate: certificate_der,
        _endpoint: endpoint,
        _task: task,
    }
}

/// The payload of the whole design: a QUIC connection that never learns it is
/// inside a tunnel.
///
/// This is the only test that drives [`MasqueUdpSocket`] through quinn itself
/// rather than by hand, so it is what covers `create_io_poller`, the recv meta
/// quinn actually consumes, and the MTU accounting being consistent enough for
/// a handshake to complete.
#[tokio::test]
async fn an_inner_quic_connection_runs_over_one_tunnel() {
    let inner_server = spawn_inner_quic_echo_server();
    let proxy = spawn_local_masque_proxy();
    let connection =
        MasqueConnection::connect(&proxy.proxy_config(), proxy.addr, &proxy.outer_config())
            .await
            .expect("outer connection failed");

    let socket = connection
        .open_tunnel("127.0.0.1", inner_server.addr.port())
        .await
        .expect("tunnel failed");

    // The tunnel's capacity is what the inner endpoint may send, and path MTU
    // discovery must stay off: a probe over the capacity is discarded rather
    // than answered, so discovery would settle above what fits.
    let capacity = socket.capacity();
    assert!(capacity >= 1200, "tunnel too small for QUIC: {capacity}");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(inner_server.certificate.clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![INNER_ALPN.to_vec()];
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ));
    let mut transport = quinn::TransportConfig::default();
    transport.mtu_discovery_config(None);
    transport.initial_mtu(capacity as u16);
    client_config.transport_config(Arc::new(transport));

    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        socket.clone() as Arc<dyn AsyncUdpSocket>,
        Arc::new(quinn::TokioRuntime),
    )
    .expect("inner endpoint failed");

    // The address is a placeholder: the target lives in the tunnel's `:path`.
    let inner = tokio::time::timeout(
        TIMEOUT,
        endpoint
            .connect_with(client_config, socket.quinn_addr(), "localhost")
            .expect("inner connect rejected"),
    )
    .await
    .expect("inner handshake timed out")
    .expect("inner handshake failed");

    let (mut send, mut recv) = inner.open_bi().await.expect("open_bi failed");
    let body = vec![b'q'; 4096];
    send.write_all(&body).await.expect("inner write failed");
    send.finish().expect("inner finish failed");
    let echoed = tokio::time::timeout(TIMEOUT, recv.read_to_end(64 * 1024))
        .await
        .expect("inner echo timed out")
        .expect("inner read failed");
    assert_eq!(echoed, body);

    // Everything above moved as HTTP Datagrams on the one outer connection.
    let stats = socket.stats().expect("tunnel is still registered");
    assert!(stats.datagrams_sent > 0 && stats.datagrams_received > 0);
    assert_eq!(
        stats.dropped_over_capacity, 0,
        "the inner MTU was set too high"
    );
    assert_eq!(connection.tunnel_count(), 1);
}

#[tokio::test]
async fn credentials_are_encoded_onto_the_connect_udp_request() {
    // The encoding is `ProxyConfig::http_auth_header`'s, shared with the HTTP
    // CONNECT path; the bridge only lowercases the field name for HTTP/3.
    let proxy = spawn_local_masque_proxy();
    let authenticated = ProxyConfig::parse(&format!(
        "masque://alice:s3cret@127.0.0.1:{}",
        proxy.addr.port()
    ))
    .unwrap();

    let header = lkrequest::proxy::masque::auth_header(&authenticated)
        .unwrap()
        .expect("credentials must produce a header");
    assert_eq!(header.name(), "proxy-authorization");
    assert_eq!(header.value(), "Basic YWxpY2U6czNjcmV0");

    // And the proxy accepts a request carrying it (the test double does not
    // verify credentials, but the header must at least be well-formed enough to
    // reach it).
    let connection = MasqueConnection::connect(&authenticated, proxy.addr, &proxy.outer_config())
        .await
        .expect("outer connection failed");
    let socket = connection
        .open_tunnel("target.invalid", 443)
        .await
        .expect("authenticated tunnel failed");
    assert_eq!(socket.quarter_stream_id().value(), 0);
}

// ---------------------------------------------------------------------------
// Trust anchors and certificate verification on the outer hop
// ---------------------------------------------------------------------------

/// A certificate for the right name from the wrong issuer: the shape of a
/// misconfigured `extra_roots`, and of an interception attempt.
fn unrelated_certificate() -> CertificateDer<'static> {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    CertificateDer::from(generated.cert.der().to_vec())
}

/// The DER entry point, stated as its own test rather than left implicit in
/// every other test's `outer_config()`, so the PEM one below has a peer to be
/// compared against.
#[tokio::test]
async fn a_private_ca_supplied_as_der_verifies_the_outer_connection() {
    let proxy = spawn_local_masque_proxy();
    let config = proxy.outer_config();
    assert!(config.verify, "this must be the verifying path");
    assert_eq!(config.extra_roots.len(), 1);

    let connection = MasqueConnection::connect(&proxy.proxy_config(), proxy.addr, &config)
        .await
        .expect("a DER trust anchor should verify the proxy");
    connection
        .open_tunnel("target.invalid", 443)
        .await
        .expect("tunnel failed");
    assert_eq!(connection.tunnel_count(), 1);
}

/// The entry point that matters in practice, because a CA arrives as a `.pem`
/// file. The outcome must be indistinguishable from the DER route above.
#[tokio::test]
async fn a_private_ca_supplied_as_pem_verifies_the_outer_connection() {
    let proxy = spawn_local_masque_proxy();
    let config = proxy.outer_config_from_pem();
    assert!(config.verify);

    let connection = MasqueConnection::connect(&proxy.proxy_config(), proxy.addr, &config)
        .await
        .expect("a PEM trust anchor should verify the proxy");
    connection
        .open_tunnel("target.invalid", 443)
        .await
        .expect("tunnel failed");
    assert_eq!(connection.tunnel_count(), 1);
}

/// The test that pins the default. If `verify` ever defaults to `false`, or the
/// flag stops being consulted, this is the one that notices: the anchor here
/// vouches for nothing, so the only way the handshake can succeed is by not
/// checking.
#[tokio::test]
async fn a_wrong_trust_anchor_fails_the_outer_connection_by_default() {
    let proxy = spawn_local_masque_proxy();
    let mut config = MasqueOuterConfig::default();
    config.use_native_certs = false;
    config.extra_roots = vec![unrelated_certificate()];
    config.server_name = Some("localhost".to_string());
    assert!(config.verify, "verify must default to true");

    let error = MasqueConnection::connect(&proxy.proxy_config(), proxy.addr, &config)
        .await
        .expect_err("an unrelated trust anchor must not verify the proxy");
    let message = error.to_string();
    assert!(
        message.contains("MASQUE outer connection"),
        "expected an outer-connection failure, got {message}"
    );
}

/// Same proxy, same wrong anchor, verification off: it connects. This is the
/// development escape hatch, and the only thing it is allowed to change.
#[tokio::test]
async fn verify_false_connects_even_with_a_wrong_trust_anchor() {
    let proxy = spawn_local_masque_proxy();
    let mut config = MasqueOuterConfig::default();
    config.use_native_certs = false;
    config.extra_roots = vec![unrelated_certificate()];
    config.server_name = Some("localhost".to_string());
    config.verify = false;

    let connection = MasqueConnection::connect(&proxy.proxy_config(), proxy.addr, &config)
        .await
        .expect("verify: false must accept any certificate");
    let socket = connection
        .open_tunnel("target.invalid", 443)
        .await
        .expect("tunnel failed");
    assert_eq!(connection.tunnel_count(), 1);
    assert!(
        socket.capacity() > 0,
        "the tunnel must be usable, not merely open"
    );
}

/// And with no anchor at all, nor the OS store, nor a name that the proxy's
/// certificate covers: `verify: false` skips the name check too, so the IP the
/// proxy is addressed by is enough.
#[tokio::test]
async fn verify_false_needs_no_trust_anchor_and_no_server_name() {
    let proxy = spawn_local_masque_proxy();
    let mut config = MasqueOuterConfig::default();
    config.use_native_certs = false;
    config.verify = false;

    let connection = MasqueConnection::connect(&proxy.proxy_config(), proxy.addr, &config)
        .await
        .expect("verify: false must not require anchors or a matching name");
    let socket = connection
        .open_tunnel("target.invalid", 443)
        .await
        .expect("tunnel failed");
    assert_eq!(connection.tunnel_count(), 1);
    assert!(
        socket.capacity() > 0,
        "the tunnel must be usable, not merely open"
    );
}

/// A malformed bundle is reported, and the configuration it was handed to is
/// left exactly as it was — the alternative is a proxy quietly verified against
/// whatever else happened to be trusted.
#[test]
fn a_malformed_pem_bundle_is_rejected_rather_than_ignored() {
    let mut config = MasqueOuterConfig::default();
    config.use_native_certs = false;
    config
        .add_ca_certs_pem(b"-----BEGIN CERTIFICATE-----\nnot base64\n")
        .expect_err("a malformed bundle must be an error");
    assert!(config.extra_roots.is_empty());

    config
        .add_ca_certs_pem(b"/etc/ssl/certs/does-not-exist.pem")
        .expect_err("a path is not a PEM bundle");
    assert!(config.extra_roots.is_empty());
}
