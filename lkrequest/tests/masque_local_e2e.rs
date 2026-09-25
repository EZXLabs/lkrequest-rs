//! Tier-0 local MASQUE (RFC 9298 CONNECT-UDP) end-to-end tests.
//!
//! First task of `design/masque-connect-udp-design.md`: prove that the vendored
//! `deps/h3` can *issue* and *accept* an extended CONNECT carrying
//! `:protocol = connect-udp`, and that HTTP Datagrams round-trip over the
//! resulting tunnel — all with the published `h3` API and no fork patch.
//!
//! The proxy below is a deliberately minimal test double: it validates the
//! request, answers `200` + `capsule-protocol: ?1` without finishing the
//! stream, and echoes datagrams back. The real datagram codec and capsule
//! parser live elsewhere; the encode/decode helpers here are local throwaways.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Once};
use std::time::Duration;

use bytes::Bytes;
use h3::ext::Protocol;
use http::{Method, StatusCode};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const TUNNEL_TEMPLATE_PREFIX: &str = "/.well-known/masque/udp/";
const CAPSULE_PROTOCOL: &str = "capsule-protocol";
const CAPSULE_PROTOCOL_ENABLED: &str = "?1";
/// RFC 9298 §4: context ID 0 carries an unmodified UDP payload.
const UDP_PAYLOAD_CONTEXT_ID: u64 = 0;

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
// Throwaway QUIC varint + HTTP Datagram payload codec (RFC 9000 §16, RFC 9297)
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

/// `[quarter stream id varint][context id varint][payload]`.
fn encode_datagram(quarter_stream_id: u64, context_id: u64, payload: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(payload.len() + 16);
    encode_varint(quarter_stream_id, &mut out);
    encode_varint(context_id, &mut out);
    out.extend_from_slice(payload);
    Bytes::from(out)
}

/// Quarter stream ID (RFC 9297 §2.1) of a CONNECT request stream.
///
/// `h3::quic::StreamId` is the **full** QUIC stream ID, so it has to be
/// divided by four here. That is upstream's convention and `h3-datagram`
/// follows it too (`VarInt::from(stream_id) / 4`).
///
/// **This used to be the opposite**, and the history is worth keeping: the
/// fork patched `h3-quinn`'s `send_id` to return quinn's `StreamId::index()`,
/// which is already `id >> 2`, so `RequestStream::id()` handed back a value
/// that must *not* be divided again. Rebasing onto current upstream dropped
/// that patch — deliberately, since it made one type mean two different things
/// depending on which fork you had — and the meaning of `id()` moved with it.
/// `masque_quarter_stream_ids_follow_h3_quinn_numbering` pins the numbering so
/// the next such move is a failing test rather than misrouted tunnels.
fn quarter_stream_id(id: h3::quic::StreamId) -> u64 {
    id.into_inner() / 4
}

fn decode_datagram(datagram: &[u8]) -> Option<(u64, u64, Bytes)> {
    let mut cursor = datagram;
    let quarter_stream_id = decode_varint(&mut cursor)?;
    let context_id = decode_varint(&mut cursor)?;
    Some((
        quarter_stream_id,
        context_id,
        Bytes::copy_from_slice(cursor),
    ))
}

// ---------------------------------------------------------------------------
// Minimal local MASQUE proxy
// ---------------------------------------------------------------------------

/// What the proxy observed on one accepted CONNECT-UDP request stream.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AcceptedTunnel {
    target_host: String,
    target_port: u16,
    capsule_protocol: Option<String>,
}

struct LocalMasqueProxy {
    addr: SocketAddr,
    certificate: CertificateDer<'static>,
    tunnels: mpsc::UnboundedReceiver<AcceptedTunnel>,
    _endpoint: quinn::Endpoint,
    _task: JoinHandle<()>,
}

/// Percent-decoding for the `target_host` template variable — RFC 9298 §3
/// requires IPv6 literals to arrive with their colons percent-encoded.
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

/// Validate an extended CONNECT against RFC 9298 §3 and extract the target.
fn parse_connect_udp(request: &http::Request<()>) -> Result<AcceptedTunnel, StatusCode> {
    if request.method() != Method::CONNECT {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    if request.extensions().get::<Protocol>() != Some(&Protocol::CONNECT_UDP) {
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
    // The template ends in a trailing slash, so exactly one empty segment is left.
    if segments.next() != Some("") || segments.next().is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let target_host = percent_decode(host).ok_or(StatusCode::BAD_REQUEST)?;
    if target_host.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let target_port: u16 = port.parse().map_err(|_| StatusCode::BAD_REQUEST)?;
    if target_port == 0 {
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(AcceptedTunnel {
        target_host,
        target_port,
        capsule_protocol: request
            .headers()
            .get(CAPSULE_PROTOCOL)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
    })
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

    let (observed, tunnels) = mpsc::unbounded_channel();
    let task = tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            while let Some(incoming) = endpoint.accept().await {
                let observed = observed.clone();
                tokio::spawn(async move {
                    let Ok(connection) = incoming.await else {
                        return;
                    };
                    serve_masque_connection(connection, observed).await;
                });
            }
        }
    });

    LocalMasqueProxy {
        addr,
        certificate: certificate_der,
        tunnels,
        _endpoint: endpoint,
        _task: task,
    }
}

async fn serve_masque_connection(
    connection: quinn::Connection,
    observed: mpsc::UnboundedSender<AcceptedTunnel>,
) {
    // The datagram path bypasses h3 entirely: RFC 9298 payloads are read and
    // written straight on the QUIC connection, exactly as the client does.
    let echo = tokio::spawn({
        let connection = connection.clone();
        async move {
            while let Ok(datagram) = connection.read_datagram().await {
                let Some((quarter_stream_id, context_id, payload)) = decode_datagram(&datagram)
                else {
                    continue;
                };
                // RFC 9298 §5: unknown context IDs are dropped, never an error.
                if context_id != UDP_PAYLOAD_CONTEXT_ID {
                    continue;
                }
                let _ = connection.send_datagram(encode_datagram(
                    quarter_stream_id,
                    context_id,
                    &payload,
                ));
            }
        }
    });

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

    // A finished or dropped request stream tears the tunnel down, so every
    // accepted tunnel is parked here for the lifetime of the connection.
    let mut open_tunnels = Vec::new();
    while let Ok(Some(resolver)) = h3_connection.accept().await {
        let Ok((request, mut stream)) = resolver.resolve_request().await else {
            continue;
        };
        match parse_connect_udp(&request) {
            Ok(tunnel) => {
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .header(CAPSULE_PROTOCOL, CAPSULE_PROTOCOL_ENABLED)
                    .body(())
                    .unwrap();
                if stream.send_response(response).await.is_err() {
                    continue;
                }
                let _ = observed.send(tunnel);
                // Deliberately no `stream.finish()`: the tunnel stays open.
                open_tunnels.push(stream);
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
// Minimal MASQUE client
// ---------------------------------------------------------------------------

type ClientRequestStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

struct MasqueClient {
    connection: quinn::Connection,
    send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    authority: String,
    _endpoint: quinn::Endpoint,
    _driver: JoinHandle<()>,
}

impl MasqueClient {
    async fn connect(proxy: &LocalMasqueProxy) -> Self {
        ensure_rustls_provider();

        let mut roots = rustls::RootCertStore::empty();
        roots.add(proxy.certificate.clone()).unwrap();
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];

        let mut endpoint = quinn::Endpoint::client(localhost_addr(0)).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(tls).unwrap(),
        )));

        let connection = endpoint
            .connect(proxy.addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        let mut builder = h3::client::builder();
        builder
            .enable_extended_connect(true)
            .enable_datagram(true)
            .send_grease(false);
        let (mut driver, send_request) = builder
            .build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await
            .unwrap();
        let driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        Self {
            connection,
            send_request,
            authority: format!("localhost:{}", proxy.addr.port()),
            _endpoint: endpoint,
            _driver: driver,
        }
    }

    /// Send one RFC 9298 CONNECT-UDP request and await its response headers.
    async fn open_tunnel(
        &mut self,
        target_host: &str,
        target_port: u16,
    ) -> (http::Response<()>, ClientRequestStream) {
        let uri = format!(
            "https://{}{TUNNEL_TEMPLATE_PREFIX}{target_host}/{target_port}/",
            self.authority
        );
        let mut request = http::Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header(CAPSULE_PROTOCOL, CAPSULE_PROTOCOL_ENABLED)
            .body(())
            .unwrap();
        request.extensions_mut().insert(Protocol::CONNECT_UDP);

        let mut stream = self.send_request.send_request(request).await.unwrap();
        // No `finish()`: a CONNECT-UDP stream stays open for capsules.
        let response = stream.recv_response().await.unwrap();
        (response, stream)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connect_udp_tunnel_is_accepted_with_capsule_protocol() {
    let mut proxy = spawn_local_masque_proxy();
    let mut client = MasqueClient::connect(&proxy).await;

    let (response, _tunnel) = client.open_tunnel("target.invalid", 443).await;
    assert!(
        response.status().is_success(),
        "expected 2xx, got {}",
        response.status()
    );
    assert_eq!(
        response.headers().get(CAPSULE_PROTOCOL).unwrap(),
        CAPSULE_PROTOCOL_ENABLED
    );

    let accepted = proxy.tunnels.recv().await.unwrap();
    assert_eq!(
        accepted,
        AcceptedTunnel {
            target_host: "target.invalid".to_owned(),
            target_port: 443,
            capsule_protocol: Some(CAPSULE_PROTOCOL_ENABLED.to_owned()),
        }
    );
}

#[tokio::test]
async fn multiple_tunnels_share_one_outer_connection() {
    let mut proxy = spawn_local_masque_proxy();
    let mut client = MasqueClient::connect(&proxy).await;

    // Second target is an IPv6 literal with percent-encoded colons (RFC 9298 §3).
    let (first, first_stream) = client.open_tunnel("target.invalid", 443).await;
    let (second, second_stream) = client.open_tunnel("2001%3Adb8%3A%3A1", 53).await;

    assert!(first.status().is_success());
    assert!(second.status().is_success());
    assert_ne!(
        quarter_stream_id(first_stream.id()),
        quarter_stream_id(second_stream.id()),
        "each tunnel needs its own quarter stream ID for demultiplexing"
    );

    let mut accepted = [
        proxy.tunnels.recv().await.unwrap(),
        proxy.tunnels.recv().await.unwrap(),
    ];
    accepted.sort_by_key(|tunnel| tunnel.target_port);
    assert_eq!(accepted[0].target_host, "2001:db8::1");
    assert_eq!(accepted[0].target_port, 53);
    assert_eq!(accepted[1].target_host, "target.invalid");
    assert_eq!(accepted[1].target_port, 443);
}

#[tokio::test]
async fn http_datagram_round_trips_over_connect_udp_tunnel() {
    let mut proxy = spawn_local_masque_proxy();
    let mut client = MasqueClient::connect(&proxy).await;

    let (response, tunnel) = client.open_tunnel("target.invalid", 443).await;
    assert!(response.status().is_success());
    assert!(proxy.tunnels.recv().await.is_some());

    let quarter = quarter_stream_id(tunnel.id());
    let payload = b"inner-quic-initial-placeholder";
    client
        .connection
        .send_datagram(encode_datagram(quarter, UDP_PAYLOAD_CONTEXT_ID, payload))
        .unwrap();

    let echoed = tokio::time::timeout(Duration::from_secs(5), client.connection.read_datagram())
        .await
        .expect("datagram echo timed out")
        .expect("connection closed before echo");
    let (echoed_quarter, echoed_context, echoed_payload) = decode_datagram(&echoed).unwrap();

    assert_eq!(echoed_quarter, quarter);
    assert_eq!(echoed_context, UDP_PAYLOAD_CONTEXT_ID);
    assert_eq!(&echoed_payload[..], payload);
}

/// Regression guard for [`quarter_stream_id`]: the first two client-initiated
/// bidirectional streams are QUIC stream IDs 0 and 4, so their quarter stream
/// IDs must be 0 and 1.
///
/// If a submodule update ever changes what `h3::quic::StreamId` means — which
/// is exactly what the rebase onto current upstream did — these come out as
/// 0 and 4, and the tunnel demultiplexing key silently changes meaning. That is
/// a misrouting bug with no symptom at the point of failure, so it gets a test
/// of its own rather than a comment.
#[tokio::test]
async fn masque_quarter_stream_ids_follow_h3_quinn_numbering() {
    let proxy = spawn_local_masque_proxy();
    let mut client = MasqueClient::connect(&proxy).await;

    let (_, first) = client.open_tunnel("target.invalid", 443).await;
    let (_, second) = client.open_tunnel("target.invalid", 444).await;

    assert_eq!(quarter_stream_id(first.id()), 0);
    assert_eq!(quarter_stream_id(second.id()), 1);
}

#[test]
fn varint_round_trips_across_all_four_widths() {
    for value in [0u64, 0x3f, 0x40, 0x3fff, 0x4000, 0x3fff_ffff, 0x4000_0000] {
        let mut encoded = Vec::new();
        encode_varint(value, &mut encoded);
        let mut cursor = encoded.as_slice();
        assert_eq!(decode_varint(&mut cursor), Some(value), "value {value:#x}");
        assert!(cursor.is_empty(), "value {value:#x} left trailing bytes");
    }
    assert_eq!(decode_varint(&mut [0x40u8].as_slice()), None);
}
