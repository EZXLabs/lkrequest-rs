//! Tier-0 end-to-end tests for the MASQUE configuration surface on the C ABI
//! (`lk_masque_config_*` plus its two consumers).
//!
//! The motivation is one specific false negative, and it is a C-side one. A
//! MASQUE proxy fronted by a private CA — the normal shape of a self-hosted or
//! vendor-issued deployment — is perfectly healthy, but until this surface
//! existed a C caller had no way to say so: requests through it could not
//! verify the outer hop, and the proxy pool's tunnel probe verified against the
//! operating system's store, failed the handshake and fed a **working** proxy
//! to the blacklist. So the two tests that matter here are
//! [`a_request_goes_through_a_private_ca_masque_proxy`] and
//! [`a_private_ca_masque_proxy_is_probed_alive_not_blacklisted`], with
//! [`a_private_ca_masque_proxy_without_its_ca_is_blacklisted`] pinning the bug
//! itself so the fix cannot quietly stop mattering.
//!
//! Everything runs against doubles inside this process: a MASQUE CONNECT-UDP
//! relay and an HTTP/3 origin, both fronted by certificates that exist only in
//! this binary and are installed nowhere the operating system can see. That is
//! what makes "the CA was accepted" a statement about the handle rather than
//! about the host's certificate store.
//!
//! The doubles are deliberately this file's own, not shared with
//! `lkrequest`'s `masque_session_e2e.rs` / `masque_health_check_e2e.rs`: the
//! Rust-side tests are what those doubles answer to, and a change made for one
//! must not be able to silently invalidate the other.
//!
//! ## Two runtimes
//!
//! The C ABI is blocking: every entry point drives `lkrequest-ffi`'s own
//! internal runtime. So these tests are plain `#[test]`s calling the ABI the
//! way C does, while the server doubles live on a separate runtime owned by
//! [`Doubles`]. The two only ever meet over loopback UDP.
//!
//! ## The tunnel is narrower than the path inside it
//!
//! One thing about the relay below is easy to get wrong, and did. The origin is
//! an ordinary QUIC server that has no idea it is behind a tunnel, so it probes
//! for a path MTU using the loopback socket in front of it — and sooner or
//! later it emits a packet that will not fit in an outer HTTP Datagram
//! (measured here: a 1420-byte probe against a 1414-byte allowance). The
//! proxy's job at that moment is to **drop that one datagram and carry on**,
//! which is what RFC 9298 §5 allows and what lets the origin's own MTU
//! discovery converge on a size the tunnel can carry. Treating it as a fatal
//! relay error instead silently ends the server→client half of the tunnel, and
//! because the probe can land either side of the response, that reads as a
//! coin-flip hang rather than as a bug. See the comment on the relay task.
//!
//! Requires the `masque` feature (`required-features` in `Cargo.toml`).
//! Without it there is no CONNECT-UDP client at all; that build's behaviour —
//! every entry point reporting the missing feature — is covered in
//! `v2_capabilities_smoke.rs`.

use std::collections::HashMap;
use std::ffi::{c_char, CString};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use bytes::Bytes;
use h3::ext::Protocol;
use http::{Method, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

use lkrequest_ffi::{
    lk_client_builder_build, lk_client_builder_free, lk_client_builder_new,
    lk_client_builder_set_masque_config, lk_client_builder_set_preset,
    lk_client_builder_set_use_native_certs, lk_client_free, lk_client_t, lk_error_code,
    lk_error_code_t, lk_error_free, lk_error_message, lk_error_t, lk_masque_config_add_ca_cert_der,
    lk_masque_config_add_ca_certs_pem, lk_masque_config_free, lk_masque_config_new,
    lk_masque_config_set_max_idle_tunnels, lk_masque_config_set_server_name,
    lk_masque_config_set_tunnel_idle_timeout, lk_masque_config_set_use_native_certs,
    lk_masque_config_set_verify, lk_masque_config_t, lk_op_cancel, lk_op_free, lk_op_state_t,
    lk_op_t, lk_op_take_proxy_guard, lk_op_wait, lk_proxy_config_free, lk_proxy_config_identity,
    lk_proxy_config_parse, lk_proxy_config_t, lk_proxy_guard_free, lk_proxy_guard_t,
    lk_proxy_guard_url, lk_proxy_pool_acquire_async, lk_proxy_pool_builder_add_proxy_config,
    lk_proxy_pool_builder_build, lk_proxy_pool_builder_free, lk_proxy_pool_builder_new,
    lk_proxy_pool_builder_set_bad_proxy_config, lk_proxy_pool_builder_set_health_check,
    lk_proxy_pool_builder_set_masque_tunnel_probe, lk_proxy_pool_builder_set_rotation,
    lk_proxy_pool_free, lk_proxy_pool_mark_bad, lk_proxy_pool_t, lk_request_free, lk_request_new,
    lk_request_send, lk_response_free, lk_response_status, lk_response_t, lk_response_text,
    lk_rotation_strategy_t, lk_session_builder_build, lk_session_builder_free,
    lk_session_builder_new, lk_session_builder_set_http3_only, lk_session_builder_set_proxy_config,
    lk_session_free, lk_session_t, lk_status_t,
};

// ---------------------------------------------------------------------------
// RFC 9298 / RFC 9297 constants
// ---------------------------------------------------------------------------

const TUNNEL_TEMPLATE_PREFIX: &str = "/.well-known/masque/udp/";
const CAPSULE_PROTOCOL: &str = "capsule-protocol";
const CAPSULE_PROTOCOL_ENABLED: &str = "?1";
const UDP_PAYLOAD_CONTEXT_ID: u64 = 0;

/// The body the origin answers with, and therefore the proof that a request
/// really traversed the tunnel rather than failing somewhere polite.
const ORIGIN_BODY: &str = "hello-through-masque-ffi";

/// Bound on a single health-check probe. Also what an unreachable proxy costs.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// Bound for the witness that follows the pool's first health-check probe.
const SETTLE: Duration = Duration::from_secs(4);
/// Bound on an acquisition; expiry is a test failure, never a health verdict.
const MARK_BAD_SETTLE: Duration = Duration::from_secs(2);

fn localhost_addr(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
}

fn ensure_rustls_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ---------------------------------------------------------------------------
// C string plumbing
// ---------------------------------------------------------------------------

fn cstring(value: &str) -> CString {
    CString::new(value).expect("interior NUL in test string")
}

unsafe fn view_string(ptr: *const c_char, len: usize) -> String {
    assert!(!ptr.is_null(), "borrowed string pointer is null");
    let bytes = std::slice::from_raw_parts(ptr.cast::<u8>(), len);
    String::from_utf8(bytes.to_vec()).expect("borrowed string is not UTF-8")
}

unsafe fn error_message(err: *mut lk_error_t) -> String {
    let mut ptr_out = ptr::null();
    let mut len_out = 0usize;
    assert_eq!(
        lk_error_message(err, &mut ptr_out, &mut len_out),
        lk_status_t::LK_OK
    );
    view_string(ptr_out, len_out)
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

/// A self-signed certificate kept as bytes, so several servers can share one
/// trust anchor without juggling a non-`Clone` private key.
#[derive(Clone)]
struct TestCert {
    der: CertificateDer<'static>,
    pem: String,
    pkcs8: Vec<u8>,
}

fn self_signed(names: &[&str]) -> TestCert {
    let generated =
        rcgen::generate_simple_self_signed(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
            .expect("self-signed certificate");
    TestCert {
        der: CertificateDer::from(generated.cert.der().to_vec()),
        pem: generated.cert.pem(),
        pkcs8: generated.signing_key.serialize_der(),
    }
}

impl TestCert {
    fn server_config(&self, alpn: &[&[u8]]) -> quinn::ServerConfig {
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(self.pkcs8.clone()));
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![self.der.clone()], key)
            .expect("server TLS config");
        tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(tls).expect("QUIC server config"),
        ))
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

/// RFC 9298 §3 / RFC 9297 §3.4 validation of a CONNECT-UDP request.
fn parse_connect_udp(request: &http::Request<()>) -> Result<(String, u16), StatusCode> {
    if request.method() != Method::CONNECT {
        return Err(StatusCode::METHOD_NOT_ALLOWED);
    }
    if request.extensions().get::<Protocol>() != Some(&Protocol::CONNECT_UDP) {
        return Err(StatusCode::BAD_REQUEST);
    }
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

// ---------------------------------------------------------------------------
// Doubles: one runtime, an HTTP/3 origin and a MASQUE relay
// ---------------------------------------------------------------------------

/// What the proxy does with a CONNECT-UDP request.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ProxyMode {
    /// Open the tunnel and relay UDP to the named target. What the request
    /// path needs.
    Relay,
    /// Validate the CONNECT-UDP request and answer `200` plus
    /// `capsule-protocol: ?1`, without resolving the target or relaying
    /// anything.
    ///
    /// What the health-check probe needs: it opens a tunnel and closes it again
    /// without sending a byte through, so nothing past the CONNECT-UDP response
    /// matters — and its target (`target.test`) deliberately resolves nowhere,
    /// since resolving it is the proxy's job in a real deployment and not
    /// something this test wants to depend on.
    Accept,
    /// Reachable, handshakes, speaks HTTP/3 — and refuses the tunnel. The case
    /// a TCP probe cannot tell apart from a working proxy.
    Refuse,
}

/// The server side of every test: its own tokio runtime, kept alive for as long
/// as the test holds this, plus whichever doubles the test asked for.
///
/// The runtime is separate from the one the C ABI drives internally. Tests call
/// the ABI from a plain thread, so nothing here can be reached by accidentally
/// blocking inside a runtime.
struct Doubles {
    /// Held only to keep the doubles running; dropping it stops them.
    _runtime: Runtime,
    proxy_port: u16,
    proxy_cert: TestCert,
    origin_cert: TestCert,
    origin_port: Option<u16>,
    tunnel_requests: Arc<AtomicUsize>,
    endpoints: Vec<quinn::Endpoint>,
}

impl Drop for Doubles {
    fn drop(&mut self) {
        for endpoint in &self.endpoints {
            endpoint.close(0u32.into(), b"test over");
        }
    }
}

impl Doubles {
    /// A proxy on its own private CA. `with_origin` additionally starts an
    /// HTTP/3 origin for the tunnel to reach — the probe tests do not need one,
    /// because the health-check probe closes its tunnel without sending a byte.
    fn start(mode: ProxyMode, with_origin: bool) -> Self {
        ensure_rustls_provider();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            // The proxy's h3 driver, its connection-level datagram pump, one
            // relay task per tunnel and the origin are all live at once, and
            // none of them may be starved by another.
            .worker_threads(4)
            .enable_all()
            .thread_name("masque-ffi-doubles")
            .build()
            .expect("doubles runtime");

        // Two distinct certificates from two distinct throwaway CAs: the outer
        // hop's trust anchor must not accidentally cover the origin, or a
        // misrouted verification could pass for the wrong reason.
        let proxy_cert = self_signed(&["127.0.0.1", "localhost"]);
        let origin_cert = self_signed(&["localhost"]);

        let mut endpoints = Vec::new();
        let tunnel_requests = Arc::new(AtomicUsize::new(0));

        let origin_port = if with_origin {
            let (endpoint, port) = runtime.block_on(async {
                let endpoint =
                    quinn::Endpoint::server(origin_cert.server_config(&[b"h3"]), localhost_addr(0))
                        .expect("origin endpoint");
                let port = endpoint.local_addr().expect("origin addr").port();
                (endpoint, port)
            });
            let serving = endpoint.clone();
            runtime.spawn(async move { serve_origin(serving).await });
            endpoints.push(endpoint);
            Some(port)
        } else {
            None
        };

        let (proxy_endpoint, proxy_port) = runtime.block_on({
            let cert = proxy_cert.clone();
            async move {
                let endpoint =
                    quinn::Endpoint::server(cert.server_config(&[b"h3"]), localhost_addr(0))
                        .expect("proxy endpoint");
                let port = endpoint.local_addr().expect("proxy addr").port();
                (endpoint, port)
            }
        });
        {
            let serving = proxy_endpoint.clone();
            let counter = Arc::clone(&tunnel_requests);
            runtime.spawn(async move { serve_proxy(serving, mode, counter).await });
        }
        endpoints.push(proxy_endpoint);

        Self {
            _runtime: runtime,
            proxy_port,
            proxy_cert,
            origin_cert,
            origin_port,
            tunnel_requests,
            endpoints,
        }
    }

    fn proxy_url(&self) -> String {
        format!("masque://127.0.0.1:{}", self.proxy_port)
    }

    fn origin_url(&self, path: &str) -> String {
        format!(
            "https://localhost:{}{path}",
            self.origin_port.expect("this double has no origin")
        )
    }

    /// The origin's own certificate, as the DER
    /// `lk_client_builder_add_ca_cert_memory` takes. A different CA from the
    /// proxy's, so a misrouted trust decision cannot pass for the wrong reason.
    fn origin_ca_der(&self) -> Vec<u8> {
        self.origin_cert.der.as_ref().to_vec()
    }
}

/// An HTTP/3 origin that answers every request with [`ORIGIN_BODY`].
async fn serve_origin(endpoint: quinn::Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let Ok(connection) = incoming.await else {
                return;
            };
            let Ok(mut h3) =
                h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                    .await
            else {
                return;
            };
            while let Ok(Some(resolver)) = h3.accept().await {
                tokio::spawn(async move {
                    let Ok((_request, mut stream)) = resolver.resolve_request().await else {
                        return;
                    };
                    let response = http::Response::builder()
                        .status(StatusCode::OK)
                        .body(())
                        .expect("origin response");
                    if stream.send_response(response).await.is_err() {
                        return;
                    }
                    let _ = stream
                        .send_data(Bytes::from_static(ORIGIN_BODY.as_bytes()))
                        .await;
                    let _ = stream.finish().await;
                });
            }
        });
    }
}

type Relays = Arc<Mutex<HashMap<u64, Arc<tokio::net::UdpSocket>>>>;

async fn serve_proxy(
    endpoint: quinn::Endpoint,
    mode: ProxyMode,
    tunnel_requests: Arc<AtomicUsize>,
) {
    while let Some(incoming) = endpoint.accept().await {
        let tunnel_requests = Arc::clone(&tunnel_requests);
        tokio::spawn(async move {
            let Ok(connection) = incoming.await else {
                return;
            };
            serve_proxy_connection(connection, mode, tunnel_requests).await;
        });
    }
}

async fn serve_proxy_connection(
    connection: quinn::Connection,
    mode: ProxyMode,
    tunnel_requests: Arc<AtomicUsize>,
) {
    let relays: Relays = Arc::new(Mutex::new(HashMap::new()));

    // Datagrams bypass h3 entirely, exactly as the client's bridge does.
    let pump = tokio::spawn({
        let connection = connection.clone();
        let relays = Arc::clone(&relays);
        async move {
            while let Ok(datagram) = connection.read_datagram().await {
                let Some((quarter, context_id, payload)) = decode_datagram(&datagram) else {
                    continue;
                };
                if context_id != UDP_PAYLOAD_CONTEXT_ID {
                    continue;
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
        tunnel_requests.fetch_add(1, Ordering::SeqCst);
        // The vendored `h3-quinn` quarters stream IDs on both sides, so this is
        // already the Quarter Stream ID the client keyed its tunnel with.
        // Full QUIC stream ID here; the quarter stream ID
        // (RFC 9297 §2.1) is a division away. See the note in
        // `masque_tunnel_e2e.rs` for why this changed.
        let quarter = stream.id().into_inner() / 4;

        let outcome = match mode {
            ProxyMode::Refuse => Err(StatusCode::FORBIDDEN),
            ProxyMode::Relay | ProxyMode::Accept => parse_connect_udp(&request),
        };

        match outcome {
            // The tunnel opens and leads nowhere: no relay socket is
            // registered, so the datagram pump drops anything the client sends.
            // The probe never sends anything, which is the point.
            Ok(_) if mode == ProxyMode::Accept => {
                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .header(CAPSULE_PROTOCOL, CAPSULE_PROTOCOL_ENABLED)
                    .body(())
                    .unwrap();
                if stream.send_response(response).await.is_err() {
                    continue;
                }
                // No `finish()`: the tunnel must look alive until the client
                // closes it, exactly as in the relaying arm.
                tokio::spawn(async move {
                    while let Ok(Some(_capsule)) = stream.recv_data().await {}
                    let _ = stream.finish().await;
                });
            }
            Ok((host, port)) => {
                // RFC 9298 §3.1: the proxy resolves the target, not the client.
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
                    .expect("relay socket");
                relay.connect(target).await.expect("relay connect");
                let relay = Arc::new(relay);
                tokio::spawn({
                    let relay = Arc::clone(&relay);
                    let connection = relay_connection.clone();
                    async move {
                        let mut buf = vec![0u8; 65535];
                        while let Ok(n) = relay.recv(&mut buf).await {
                            let datagram =
                                encode_datagram(quarter, UDP_PAYLOAD_CONTEXT_ID, &buf[..n]);
                            match connection.send_datagram(datagram) {
                                Ok(()) => {}
                                // The target's packet does not fit in an outer
                                // datagram. **Drop it and keep relaying** —
                                // this is not an error, it is the normal and
                                // expected outcome of the inner endpoint
                                // probing for a path MTU the tunnel cannot
                                // carry, and RFC 9298 §5 has a proxy drop a UDP
                                // payload it cannot forward.
                                //
                                // The origin here is an ordinary QUIC server
                                // with no idea it is behind a tunnel, so it
                                // raises its packet size until a probe is lost
                                // — one such probe always exceeds the outer
                                // budget (measured: a 1420-byte probe against a
                                // 1414-byte allowance). Losing it is the signal
                                // that makes the origin settle on a size that
                                // fits; treating it as fatal instead killed
                                // this direction of the tunnel for good, and
                                // whether that happened before or after the
                                // response was a coin flip — which is exactly
                                // the flake this arm used to produce.
                                Err(quinn::SendDatagramError::TooLarge) => continue,
                                // Anything else really is the end of the road:
                                // the connection is gone, or datagrams are not
                                // available on it at all.
                                Err(_) => break,
                            }
                        }
                    }
                });

                // Registered *before* the response, so the client's first inner
                // packet cannot arrive at a pump that has no socket to hand it
                // to. The other order leaves that packet to be recovered by a
                // QUIC probe timeout, which is a second, slower source of
                // nondeterminism in what is supposed to be a Tier-0 test.
                relays.lock().unwrap().insert(quarter, Arc::clone(&relay));

                let response = http::Response::builder()
                    .status(StatusCode::OK)
                    .header(CAPSULE_PROTOCOL, CAPSULE_PROTOCOL_ENABLED)
                    .body(())
                    .unwrap();
                if stream.send_response(response).await.is_err() {
                    relays.lock().unwrap().remove(&quarter);
                    continue;
                }

                // No `finish()`: the tunnel stays open until the client FINs.
                let relays = Arc::clone(&relays);
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
// ABI helpers
// ---------------------------------------------------------------------------

unsafe fn new_masque_config() -> *mut lk_masque_config_t {
    let mut config = ptr::null_mut::<lk_masque_config_t>();
    assert_eq!(lk_masque_config_new(&mut config), lk_status_t::LK_OK);
    assert!(!config.is_null());
    config
}

unsafe fn add_ca_certs_pem(config: *mut lk_masque_config_t, pem: &str) -> (lk_status_t, usize) {
    let owned = cstring(pem);
    let mut added = usize::MAX;
    let status = lk_masque_config_add_ca_certs_pem(config, owned.as_ptr(), pem.len(), &mut added);
    (status, added)
}

unsafe fn set_server_name(config: *mut lk_masque_config_t, name: &str) -> lk_status_t {
    let owned = cstring(name);
    lk_masque_config_set_server_name(config, owned.as_ptr(), name.len())
}

unsafe fn parse_proxy_config(url: &str) -> *mut lk_proxy_config_t {
    let owned = cstring(url);
    let mut config = ptr::null_mut::<lk_proxy_config_t>();
    assert_eq!(
        lk_proxy_config_parse(owned.as_ptr(), url.len(), &mut config),
        lk_status_t::LK_OK
    );
    assert!(!config.is_null());
    config
}

unsafe fn proxy_identity(config: *const lk_proxy_config_t) -> String {
    let mut ptr_out = ptr::null();
    let mut len_out = 0usize;
    assert_eq!(
        lk_proxy_config_identity(config, &mut ptr_out, &mut len_out),
        lk_status_t::LK_OK
    );
    view_string(ptr_out, len_out)
}

/// The outer settings a private-CA deployment needs, reached through the PEM
/// entry point: add the CA, and stop trusting the OS store so a pass really
/// does mean "this certificate was accepted".
unsafe fn private_ca_config(doubles: &Doubles) -> *mut lk_masque_config_t {
    let config = new_masque_config();
    assert_eq!(
        lk_masque_config_set_use_native_certs(config, false),
        lk_status_t::LK_OK
    );
    let (status, added) = add_ca_certs_pem(config, &doubles.proxy_cert.pem);
    assert_eq!(status, lk_status_t::LK_OK);
    assert_eq!(
        added, 1,
        "the proxy's own PEM holds exactly one certificate"
    );
    config
}

// ---------------------------------------------------------------------------
// Handle round-trip
// ---------------------------------------------------------------------------

/// Create, set everything reachable, free. No server involved: this is the
/// handle's own contract.
#[test]
fn the_handle_round_trips_every_setter() {
    unsafe {
        let config = new_masque_config();

        assert_eq!(
            lk_masque_config_set_use_native_certs(config, false),
            lk_status_t::LK_OK
        );
        assert_eq!(
            set_server_name(config, "proxy.example.com"),
            lk_status_t::LK_OK
        );
        // NULL restores the default (derive the name from the proxy URL).
        assert_eq!(
            lk_masque_config_set_server_name(config, ptr::null(), 0),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_masque_config_set_tunnel_idle_timeout(config, 30_000),
            lk_status_t::LK_OK
        );
        // Zero is "never retire on idleness", not "retire immediately".
        assert_eq!(
            lk_masque_config_set_tunnel_idle_timeout(config, 0),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_masque_config_set_max_idle_tunnels(config, 8),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_masque_config_set_max_idle_tunnels(config, 0),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_masque_config_set_verify(config, false),
            lk_status_t::LK_OK
        );
        // And back on, so the setter is not a one-way door.
        assert_eq!(
            lk_masque_config_set_verify(config, true),
            lk_status_t::LK_OK
        );

        lk_masque_config_free(config);
        // Freeing NULL is a no-op, as everywhere else on this ABI.
        lk_masque_config_free(ptr::null_mut());
    }
}

/// Both trust-anchor entry points work, and both append rather than replace —
/// a deployment behind two CAs (rotation, or a vendor plus a private one) has
/// to be expressible.
#[test]
fn both_trust_anchor_entry_points_append() {
    unsafe {
        let first = self_signed(&["proxy-a.example.com"]);
        let second = self_signed(&["proxy-b.example.com"]);

        let config = new_masque_config();

        // PEM, the form a CA is normally handed out in.
        let (status, added) = add_ca_certs_pem(config, &first.pem);
        assert_eq!(status, lk_status_t::LK_OK);
        assert_eq!(added, 1);

        // A bundle of several certificates in one call.
        let bundle = format!("{}{}", first.pem, second.pem);
        let (status, added) = add_ca_certs_pem(config, &bundle);
        assert_eq!(status, lk_status_t::LK_OK);
        assert_eq!(added, 2, "a bundle must load every certificate in it");

        // And the DER entry point, for a caller that already parsed the file.
        assert_eq!(
            lk_masque_config_add_ca_cert_der(
                config,
                second.der.as_ref().as_ptr(),
                second.der.as_ref().len(),
            ),
            lk_status_t::LK_OK
        );

        // `out_added` is optional.
        let pem = cstring(&first.pem);
        assert_eq!(
            lk_masque_config_add_ca_certs_pem(
                config,
                pem.as_ptr(),
                first.pem.len(),
                ptr::null_mut(),
            ),
            lk_status_t::LK_OK
        );

        lk_masque_config_free(config);
    }
}

/// A bundle that holds no certificate is an error, not a silent no-op.
///
/// This is the failure the PEM entry point exists for: a path typo (a caller
/// passing a filename instead of the file), a DER file fed to the PEM door, a
/// truncated copy-paste. Any of them leaving the trust store unchanged is how a
/// proxy ends up verified against a store nobody meant to use — which is the
/// same false negative this whole surface is here to prevent, arriving from the
/// other direction.
#[test]
fn a_malformed_pem_bundle_is_rejected() {
    unsafe {
        let config = new_masque_config();

        for input in [
            "not a PEM file at all",
            "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
            "/etc/ssl/certs/does-not-exist.pem",
            "",
        ] {
            let (status, added) = add_ca_certs_pem(config, input);
            assert_ne!(
                status,
                lk_status_t::LK_OK,
                "a bundle with no certificate must be reported: {input:?}"
            );
            assert_eq!(added, 0, "nothing must be counted as added: {input:?}");
        }

        // An empty DER is rejected too, rather than queued to fail later.
        assert_ne!(
            lk_masque_config_add_ca_cert_der(config, ptr::null(), 0),
            lk_status_t::LK_OK
        );

        // And the handle is still usable: a rejected bundle changed nothing.
        let good = self_signed(&["proxy.example.com"]);
        let (status, added) = add_ca_certs_pem(config, &good.pem);
        assert_eq!(status, lk_status_t::LK_OK);
        assert_eq!(added, 1);

        lk_masque_config_free(config);
    }
}

/// Null handles are rejected rather than dereferenced, like everywhere else on
/// this ABI.
#[test]
fn null_handles_are_rejected() {
    assert_ne!(
        lk_masque_config_new(ptr::null_mut()),
        lk_status_t::LK_OK,
        "a null out-parameter is an invalid argument"
    );
    assert_ne!(
        lk_masque_config_set_use_native_certs(ptr::null_mut(), false),
        lk_status_t::LK_OK
    );
    assert_ne!(
        lk_masque_config_set_max_idle_tunnels(ptr::null_mut(), 4),
        lk_status_t::LK_OK
    );
    assert_ne!(
        lk_masque_config_add_ca_cert_der(ptr::null_mut(), [0u8; 4].as_ptr(), 4),
        lk_status_t::LK_OK
    );
    assert_ne!(
        lk_masque_config_set_verify(ptr::null_mut(), false),
        lk_status_t::LK_OK,
        "a null handle must not be the way verification appears to be disabled"
    );
    assert_ne!(
        lk_client_builder_set_masque_config(ptr::null_mut(), ptr::null()),
        lk_status_t::LK_OK
    );
    assert_ne!(
        lk_proxy_pool_builder_set_masque_tunnel_probe(ptr::null_mut(), ptr::null()),
        lk_status_t::LK_OK
    );
}

// ---------------------------------------------------------------------------
// Consumer 1: the client builder
// ---------------------------------------------------------------------------

/// The request path: a plain `GET` over a `masque://` proxy whose certificate
/// chains to a CA that exists only in this binary.
///
/// Before `lk_masque_config_*` existed a C caller had no way to name that CA,
/// so this request could only fail. Note that nothing here asks for the proxy
/// to be trusted by luck: `use_native_certs` is off on both hops, so the only
/// anchors in play are the two handed over explicitly.
#[test]
fn a_request_goes_through_a_private_ca_masque_proxy() {
    let doubles = Doubles::start(ProxyMode::Relay, true);

    unsafe {
        let masque = private_ca_config(&doubles);
        // The proxy is addressed as an IP; its certificate covers both, but
        // pinning the name is what a real deployment behind a hostname does.
        assert_eq!(set_server_name(masque, "localhost"), lk_status_t::LK_OK);

        let builder = lk_client_builder_new();
        assert!(!builder.is_null());
        let preset = cstring("chrome_144");
        assert_eq!(
            lk_client_builder_set_preset(builder, preset.as_ptr()),
            lk_status_t::LK_OK
        );
        // The origin is privately fronted too, and its CA is a *different* one:
        // the two trust decisions are separate, which is the point.
        assert_eq!(
            lk_client_builder_set_use_native_certs(builder, false),
            lk_status_t::LK_OK
        );
        let origin_der = doubles.origin_ca_der();
        assert_eq!(
            lkrequest_ffi::lk_client_builder_add_ca_cert_memory(
                builder,
                origin_der.as_ptr(),
                origin_der.len(),
            ),
            lk_status_t::LK_OK
        );
        assert_eq!(
            lk_client_builder_set_masque_config(builder, masque),
            lk_status_t::LK_OK
        );
        // The settings were copied, so the handle can go now.
        lk_masque_config_free(masque);

        let mut client = ptr::null_mut::<lk_client_t>();
        let mut err = ptr::null_mut::<lk_error_t>();
        assert_eq!(
            lk_client_builder_build(builder, &mut client, &mut err),
            lk_status_t::LK_OK,
            "{}",
            if err.is_null() {
                String::new()
            } else {
                error_message(err)
            }
        );
        lk_client_builder_free(builder);
        assert!(!client.is_null());

        let session_builder = lk_session_builder_new(client);
        assert!(!session_builder.is_null());
        let proxy = parse_proxy_config(&doubles.proxy_url());
        assert_eq!(
            lk_session_builder_set_proxy_config(session_builder, proxy),
            lk_status_t::LK_OK
        );
        // A MASQUE proxy relays UDP only, so the request has to be HTTP/3.
        assert_eq!(
            lk_session_builder_set_http3_only(session_builder),
            lk_status_t::LK_OK
        );
        let mut session = ptr::null_mut::<lk_session_t>();
        let mut err = ptr::null_mut::<lk_error_t>();
        assert_eq!(
            lk_session_builder_build(session_builder, &mut session, &mut err),
            lk_status_t::LK_OK
        );
        lk_session_builder_free(session_builder);
        lk_proxy_config_free(proxy);

        let method = cstring("GET");
        let url = doubles.origin_url("/one");
        let url_c = cstring(&url);
        let mut request = ptr::null_mut();
        let mut err = ptr::null_mut::<lk_error_t>();
        assert_eq!(
            lk_request_new(
                session,
                method.as_ptr(),
                "GET".len(),
                url_c.as_ptr(),
                url.len(),
                &mut request,
                &mut err,
            ),
            lk_status_t::LK_OK
        );
        assert!(!request.is_null());

        let mut response = ptr::null_mut::<lk_response_t>();
        let mut err = ptr::null_mut::<lk_error_t>();
        let status = lk_request_send(request, &mut response, &mut err);
        assert_eq!(
            status,
            lk_status_t::LK_OK,
            "request through the private-CA MASQUE proxy failed: {}",
            if err.is_null() {
                "no error handle".to_string()
            } else {
                error_message(err)
            }
        );
        assert!(!response.is_null());

        assert_eq!(lk_response_status(response), 200);
        let mut ptr_out = ptr::null();
        let mut len_out = 0usize;
        assert_eq!(
            lk_response_text(response, &mut ptr_out, &mut len_out, ptr::null_mut()),
            lk_status_t::LK_OK
        );
        assert_eq!(
            view_string(ptr_out, len_out),
            ORIGIN_BODY,
            "the body must come from the origin behind the tunnel"
        );

        lk_response_free(response);
        lk_request_free(request);
        lk_session_free(session);
        lk_client_free(client);
    }

    assert!(
        doubles.tunnel_requests.load(Ordering::SeqCst) >= 1,
        "the proxy must have been asked for a CONNECT-UDP tunnel"
    );
}

// ---------------------------------------------------------------------------
// Consumer 2: the proxy pool's health check — the false negative itself
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The health check recorded a failure against the proxy.
    Blamed,
    /// The health check said nothing, either because it passed or because the
    /// proxy was skipped.
    NotBlamed,
}

struct HealthCheckWitness {
    runtime: Runtime,
    proxy_url: String,
    task: JoinHandle<()>,
}

impl HealthCheckWitness {
    fn start() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let listener = runtime.block_on(async {
            tokio::net::TcpListener::bind(localhost_addr(0))
                .await
                .unwrap()
        });
        let proxy_url = format!("http://{}", listener.local_addr().unwrap());
        let task = runtime.spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                assert!(request.len() < 8192, "oversized witness CONNECT request");
                request.push(stream.read_u8().await.unwrap());
            }
            assert!(request.starts_with(b"CONNECT target.test:443 HTTP/1.1\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
        });
        Self {
            runtime,
            proxy_url,
            task,
        }
    }

    fn wait(&mut self) {
        // The preceding target's probe and bookkeeping complete before this
        // second proxy is contacted by the serial health-check loop.
        let task = &mut self.task;
        self.runtime.block_on(async {
            tokio::time::timeout(SETTLE, task)
                .await
                .expect("health check did not reach the witness after the target")
                .expect("health-check witness failed");
        });
    }

    unsafe fn add_to_pool(&self, builder: *mut lkrequest_ffi::lk_proxy_pool_builder_t) -> String {
        let proxy = parse_proxy_config(&self.proxy_url);
        let identity = proxy_identity(proxy);
        assert_eq!(
            lk_proxy_pool_builder_add_proxy_config(builder, proxy),
            lk_status_t::LK_OK
        );
        lk_proxy_config_free(proxy);
        assert_eq!(
            lk_proxy_pool_builder_set_rotation(
                builder,
                lk_rotation_strategy_t::LK_ROTATION_ROUND_ROBIN
            ),
            lk_status_t::LK_OK
        );
        identity
    }
}

impl Drop for HealthCheckWitness {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct AcquireOperation(*mut lk_op_t);

impl Drop for AcquireOperation {
    fn drop(&mut self) {
        lk_op_cancel(self.0);
        lk_op_free(self.0);
    }
}

unsafe fn acquired_proxy_identity(pool: *const lk_proxy_pool_t) -> String {
    let mut op = ptr::null_mut();
    let mut err = ptr::null_mut::<lk_error_t>();
    assert_eq!(
        lk_proxy_pool_acquire_async(pool, &mut op, &mut err),
        lk_status_t::LK_OK
    );
    assert!(!op.is_null());
    let op = AcquireOperation(op);
    assert_eq!(
        lk_op_wait(op.0, MARK_BAD_SETTLE.as_millis() as u64),
        lk_op_state_t::LK_OP_COMPLETED_OK,
        "the witness must remain acquirable during target cooldown"
    );
    let mut guard = ptr::null_mut::<lk_proxy_guard_t>();
    assert_eq!(
        lk_op_take_proxy_guard(op.0, &mut guard, &mut err),
        lk_status_t::LK_OK
    );
    assert!(!guard.is_null());
    let mut ptr_out = ptr::null();
    let mut len_out = 0usize;
    let status = lk_proxy_guard_url(guard, &mut ptr_out, &mut len_out);
    let url = if status == lk_status_t::LK_OK {
        view_string(ptr_out, len_out)
    } else {
        String::new()
    };
    lk_proxy_guard_free(guard);
    assert_eq!(
        status,
        lk_status_t::LK_OK,
        "a configured fixed pool must never return a direct lease"
    );
    let proxy = parse_proxy_config(&url);
    let identity = proxy_identity(proxy);
    lk_proxy_config_free(proxy);
    identity
}

unsafe fn observed_verdict(pool: *const lk_proxy_pool_t, target: &str, witness: &str) -> Verdict {
    let mut target_seen = false;
    for _ in 0..2 {
        let identity = acquired_proxy_identity(pool);
        assert!(
            identity == target || identity == witness,
            "pool returned an unconfigured proxy"
        );
        target_seen |= identity == target;
    }
    if target_seen {
        Verdict::NotBlamed
    } else {
        Verdict::Blamed
    }
}

/// Read the pool's verdict back out through the C ABI.
///
/// A failed health check only appends to the pool's sliding failure window; it
/// never puts a proxy in cooldown by itself. So the verdict is inferred with a
/// little arithmetic: with `failure_threshold: 2`, one `lk_proxy_pool_mark_bad`
/// afterwards reaches the threshold *only if* the health check already blamed
/// the proxy. A proxy that then stops being acquirable was judged unhealthy;
/// one that stays acquirable was judged healthy, or skipped. A second CONNECT
/// proxy witnesses completion of that probe and keeps acquisitions available.
unsafe fn health_check_verdict(
    proxy_url: &str,
    masque_probe: Option<*const lk_masque_config_t>,
) -> Verdict {
    let proxy = parse_proxy_config(proxy_url);
    let identity = proxy_identity(proxy);
    let mut witness = HealthCheckWitness::start();

    let builder = lk_proxy_pool_builder_new();
    assert!(!builder.is_null());
    assert_eq!(
        lk_proxy_pool_builder_add_proxy_config(builder, proxy),
        lk_status_t::LK_OK
    );
    lk_proxy_config_free(proxy);
    let witness_identity = witness.add_to_pool(builder);

    assert_eq!(
        lk_proxy_pool_builder_set_bad_proxy_config(builder, 2, 600_000, 600_000, 5),
        lk_status_t::LK_OK
    );

    // One round only: the maintenance task's first tick is immediate.
    let host = cstring("target.test");
    assert_eq!(
        lk_proxy_pool_builder_set_health_check(
            builder,
            host.as_ptr(),
            "target.test".len(),
            443,
            3_600_000,
            PROBE_TIMEOUT.as_millis() as u64,
        ),
        lk_status_t::LK_OK
    );

    if let Some(masque) = masque_probe {
        assert_eq!(
            lk_proxy_pool_builder_set_masque_tunnel_probe(builder, masque),
            lk_status_t::LK_OK
        );
    }

    let mut pool = ptr::null_mut::<lk_proxy_pool_t>();
    let mut err = ptr::null_mut::<lk_error_t>();
    assert_eq!(
        lk_proxy_pool_builder_build(builder, &mut pool, &mut err),
        lk_status_t::LK_OK
    );
    lk_proxy_pool_builder_free(builder);
    assert!(!pool.is_null());

    witness.wait();
    let identity_c = cstring(&identity);
    assert_eq!(
        lk_proxy_pool_mark_bad(pool, identity_c.as_ptr(), identity.len()),
        lk_status_t::LK_OK
    );

    let verdict = observed_verdict(pool, &identity, &witness_identity);
    lk_proxy_pool_free(pool);
    verdict
}

/// **The motivating test.** A healthy MASQUE proxy fronted by a private CA is
/// probed *alive* once the probe is told about that CA, instead of failing its
/// handshake and being blacklisted.
///
/// This is the C-side half of the same fix `masque_health_check_e2e.rs` pins on
/// the Rust side. Without `lk_proxy_pool_builder_set_masque_tunnel_probe` there
/// was no way to reach it at all from C: the probe either did not run, or ran
/// against the operating system's store and took a working proxy out of
/// rotation.
#[test]
fn a_private_ca_masque_proxy_is_probed_alive_not_blacklisted() {
    let doubles = Doubles::start(ProxyMode::Accept, false);
    unsafe {
        let masque = private_ca_config(&doubles);
        let verdict = health_check_verdict(&doubles.proxy_url(), Some(masque));
        lk_masque_config_free(masque);
        assert_eq!(
            verdict,
            Verdict::NotBlamed,
            "a private-CA proxy that opens the tunnel is healthy once the probe knows its CA"
        );
    }
    assert!(
        doubles.tunnel_requests.load(Ordering::SeqCst) >= 1,
        "the probe must have actually opened a CONNECT-UDP tunnel"
    );
}

/// The false negative itself, pinned. The same healthy proxy, probed with a
/// config that does not cover it, is blamed — so the test above really is about
/// the CA reaching the probe rather than about the probe being lenient.
#[test]
fn a_private_ca_masque_proxy_without_its_ca_is_blacklisted() {
    let doubles = Doubles::start(ProxyMode::Accept, false);
    unsafe {
        // Defaults: the OS trust store and nothing else — which has never heard
        // of this proxy's CA.
        let masque = new_masque_config();
        let verdict = health_check_verdict(&doubles.proxy_url(), Some(masque));
        lk_masque_config_free(masque);
        assert_eq!(
            verdict,
            Verdict::Blamed,
            "a probe that cannot verify the proxy's certificate calls a healthy proxy dead"
        );
    }
}

/// The escape hatch, reachable from C: the same healthy proxy and the same
/// absent CA, but with verification turned off, is no longer blamed.
///
/// This is the last resort for a certificate that cannot be made to verify at
/// all — one naming a host that does not resolve, say. Without it a C caller in
/// that position has only the false negative above and no way out of it, while
/// a Rust caller has `masque_verify(false)`. Note that no trust anchor and no
/// server name are supplied here: with verification off neither is consulted,
/// so neither may be required.
#[test]
fn verification_off_makes_an_unverifiable_masque_proxy_probe_alive() {
    let doubles = Doubles::start(ProxyMode::Accept, false);
    unsafe {
        let masque = new_masque_config();
        assert_eq!(
            lk_masque_config_set_verify(masque, false),
            lk_status_t::LK_OK
        );
        let verdict = health_check_verdict(&doubles.proxy_url(), Some(masque));
        lk_masque_config_free(masque);
        assert_eq!(
            verdict,
            Verdict::NotBlamed,
            "with verification off, an unverifiable certificate must stop being fatal"
        );
    }
    assert!(
        doubles.tunnel_requests.load(Ordering::SeqCst) >= 1,
        "the probe must have opened a real CONNECT-UDP tunnel, not been skipped"
    );
}

/// The case the probe exists for: a proxy whose port is open and whose QUIC and
/// HTTP/3 layers work, but which refuses `connect-udp`. A TCP probe would call
/// this healthy; the tunnel probe must not.
#[test]
fn a_masque_proxy_that_refuses_connect_udp_is_blamed() {
    let doubles = Doubles::start(ProxyMode::Refuse, false);
    unsafe {
        let masque = private_ca_config(&doubles);
        let verdict = health_check_verdict(&doubles.proxy_url(), Some(masque));
        lk_masque_config_free(masque);
        assert_eq!(
            verdict,
            Verdict::Blamed,
            "a reachable proxy that refuses CONNECT-UDP is not healthy"
        );
    }
}

/// Without the probe configured, a MASQUE proxy is skipped rather than guessed
/// at — the Rust-side default, reachable unchanged from C.
///
/// The proxy here *refuses* CONNECT-UDP, so a probe that actually ran would
/// blame it. `NotBlamed` is therefore a statement about the skip, not about the
/// proxy being healthy.
#[test]
fn without_the_probe_a_masque_proxy_is_skipped() {
    let doubles = Doubles::start(ProxyMode::Refuse, false);
    unsafe {
        assert_eq!(
            health_check_verdict(&doubles.proxy_url(), None),
            Verdict::NotBlamed,
            "with no MASQUE probe configured a MASQUE proxy must be skipped entirely"
        );
    }
}

/// Control: the same pool, the same round, a non-MASQUE proxy. Its TCP probe
/// runs and fails exactly as it always did, which is what makes the test above
/// a statement about MASQUE rather than about health checking being off.
#[test]
fn the_tcp_health_check_path_is_unchanged() {
    unsafe {
        assert_eq!(
            health_check_verdict("http://127.0.0.1:1", None),
            Verdict::Blamed,
            "the non-MASQUE health check path must be unchanged"
        );
    }
}

/// A probe configured on a builder with no health check is reported at build
/// time rather than silently never running.
///
/// The probe needs both halves — the flag and the trust anchors — and health
/// checking has to be on for either to matter. Saying so at `build` is what
/// keeps the two setters order-independent from C, where there is no builder
/// chain to make the dependency obvious.
#[test]
fn a_probe_without_a_health_check_fails_the_build() {
    let doubles = Doubles::start(ProxyMode::Accept, false);
    unsafe {
        let masque = private_ca_config(&doubles);
        let builder = lk_proxy_pool_builder_new();
        let proxy = parse_proxy_config(&doubles.proxy_url());
        assert_eq!(
            lk_proxy_pool_builder_add_proxy_config(builder, proxy),
            lk_status_t::LK_OK
        );
        lk_proxy_config_free(proxy);
        assert_eq!(
            lk_proxy_pool_builder_set_masque_tunnel_probe(builder, masque),
            lk_status_t::LK_OK
        );

        let mut pool = ptr::null_mut::<lk_proxy_pool_t>();
        let mut err = ptr::null_mut::<lk_error_t>();
        assert_ne!(
            lk_proxy_pool_builder_build(builder, &mut pool, &mut err),
            lk_status_t::LK_OK
        );
        assert!(pool.is_null());
        assert!(!err.is_null(), "the refusal must carry an explanation");
        assert_eq!(lk_error_code(err), lk_error_code_t::LK_ERR_INVALID_CONFIG);
        let message = error_message(err);
        assert!(
            message.contains("health check"),
            "the message must name what is missing: {message}"
        );
        lk_error_free(err);
        lk_proxy_pool_builder_free(builder);
        lk_masque_config_free(masque);
    }
}

/// Order does not matter: setting the probe *before* the health check must
/// survive `set_health_check` rebuilding the config from its defaults.
#[test]
fn the_probe_survives_a_later_set_health_check() {
    let doubles = Doubles::start(ProxyMode::Refuse, false);
    let mut witness = HealthCheckWitness::start();
    unsafe {
        let masque = private_ca_config(&doubles);
        let proxy = parse_proxy_config(&doubles.proxy_url());
        let builder = lk_proxy_pool_builder_new();
        assert_eq!(
            lk_proxy_pool_builder_add_proxy_config(builder, proxy),
            lk_status_t::LK_OK
        );
        let witness_identity = witness.add_to_pool(builder);
        assert_eq!(
            lk_proxy_pool_builder_set_bad_proxy_config(builder, 2, 600_000, 600_000, 5),
            lk_status_t::LK_OK
        );
        // Probe first...
        assert_eq!(
            lk_proxy_pool_builder_set_masque_tunnel_probe(builder, masque),
            lk_status_t::LK_OK
        );
        // ...health check second, which replaces the whole inner config.
        let host = cstring("target.test");
        assert_eq!(
            lk_proxy_pool_builder_set_health_check(
                builder,
                host.as_ptr(),
                "target.test".len(),
                443,
                3_600_000,
                PROBE_TIMEOUT.as_millis() as u64,
            ),
            lk_status_t::LK_OK
        );

        let identity = proxy_identity(proxy);
        lk_proxy_config_free(proxy);
        lk_masque_config_free(masque);

        let mut pool = ptr::null_mut::<lk_proxy_pool_t>();
        let mut err = ptr::null_mut::<lk_error_t>();
        assert_eq!(
            lk_proxy_pool_builder_build(builder, &mut pool, &mut err),
            lk_status_t::LK_OK
        );
        lk_proxy_pool_builder_free(builder);

        witness.wait();
        let identity_c = cstring(&identity);
        assert_eq!(
            lk_proxy_pool_mark_bad(pool, identity_c.as_ptr(), identity.len()),
            lk_status_t::LK_OK
        );

        let verdict = observed_verdict(pool, &identity, &witness_identity);
        lk_proxy_pool_free(pool);

        assert_eq!(
            verdict,
            Verdict::Blamed,
            "the probe set before set_health_check must still have run"
        );
    }
}
