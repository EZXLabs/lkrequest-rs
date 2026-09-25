//! Tier-0 end-to-end tests for `ProxyPool`'s MASQUE health checking
//! (`HealthCheckConfig::tunnel_probe` and `masque_outer_config`).
//!
//! The proxy here is fronted by a CA that exists only inside this binary, which
//! is the deployment shape the probe used to get wrong: with no seam for trust
//! anchors it verified against the operating system's store, failed, and fed a
//! healthy proxy to the blacklist. So these tests are as much about
//! `masque_outer_config` — supplied, wrong, and absent — as about the flag.
//!
//! The unit tests in `proxy_pool.rs` cover the skip decision and the failure
//! side, both of which need no server. What they cannot cover is the one case
//! that gives the flag its meaning: a MASQUE proxy that is *reachable* but
//! answers CONNECT-UDP differently. That is what separates a real probe from
//! the TCP probe it replaces, so it needs a proxy that actually speaks
//! RFC 9298 — hence a local one, here.
//!
//! The proxy below is a deliberately minimal test double, unrelated to the one
//! in `masque_tunnel_e2e.rs`: the health-check probe opens a tunnel and closes
//! it again without sending a byte through it, so nothing past the CONNECT-UDP
//! response matters.
//!
//! ## Observing the verdict
//!
//! A health check failure only appends to the pool's sliding failure window; it
//! never puts a proxy in cooldown by itself (`run_health_checks`). So the
//! verdict is read out through the public API with a little arithmetic: with
//! `failure_threshold: 2`, a single `mark_bad_proxy()` afterwards is enough to
//! reach the threshold *only if* the health check already blamed the proxy. A
//! proxy that then stops being acquirable was judged unhealthy; one that stays
//! acquirable was judged healthy, or skipped.
//!
//! Requires the `masque` feature (`required-features` in `Cargo.toml`): without
//! it there is no CONNECT-UDP client and every MASQUE proxy is skipped, which
//! the ungated unit tests in `proxy_pool.rs` already cover.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Once, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use h3::ext::Protocol;
use http::{Method, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::task::JoinHandle;

use lkrequest::proxy::{MasqueOuterConfig, ProxyConfig};
use lkrequest::proxy_pool::{BadProxyConfig, HealthCheckConfig, ProxyPool};

const TUNNEL_TEMPLATE_PREFIX: &str = "/.well-known/masque/udp/";
const CAPSULE_PROTOCOL: &str = "capsule-protocol";
const CAPSULE_PROTOCOL_ENABLED: &str = "?1";

/// Health-check target. Never resolved by anyone: the MASQUE proxy is the one
/// that would resolve it, and this proxy only inspects the name.
const TARGET_HOST: &str = "target.test";
const TARGET_PORT: u16 = 443;

/// Bound on a single probe. Also the time an unreachable proxy costs.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// How long to let the pool's first (immediate) health-check round finish.
const SETTLE: Duration = Duration::from_secs(4);
/// How long to wait for a `mark_bad_proxy` to be reflected in the pool.
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
// Trust anchor
// ---------------------------------------------------------------------------

struct TestCertificate {
    der: CertificateDer<'static>,
    key: Vec<u8>,
}

/// One self-signed certificate for the whole binary, deliberately **not**
/// installed anywhere the operating system can see it.
///
/// That makes every proxy below a privately-fronted one, which is the normal
/// shape of a self-hosted or vendor-issued MASQUE deployment — and the case
/// that used to be probed as dead. The probe now takes its trust anchors from
/// [`HealthCheckConfig::masque_outer_config`], so the certificate is handed to
/// it through [`MasqueOuterConfig::extra_roots`] instead of through the
/// process environment.
fn test_certificate() -> &'static TestCertificate {
    static CERTIFICATE: OnceLock<TestCertificate> = OnceLock::new();
    CERTIFICATE.get_or_init(|| {
        // An IP SAN: the proxy is addressed as `masque://127.0.0.1:port`, and
        // the outer config derives the server name from that.
        let generated =
            rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()])
                .expect("self-signed certificate");
        TestCertificate {
            der: CertificateDer::from(generated.cert.der().to_vec()),
            key: generated.signing_key.serialize_der(),
        }
    })
}

/// The outer-connection settings that let a probe verify the local proxy: the
/// private CA and nothing else, so a pass really does mean "this certificate
/// was accepted" rather than "something in the machine's store vouched for it".
fn private_ca_outer_config() -> MasqueOuterConfig {
    // `MasqueOuterConfig` is `#[non_exhaustive]`: from `Default`, then assign.
    let mut config = MasqueOuterConfig::default();
    config.use_native_certs = false;
    config.extra_roots = vec![test_certificate().der.clone()];
    config
}

// ---------------------------------------------------------------------------
// Local MASQUE proxy
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Behaviour {
    /// Answer CONNECT-UDP with `200` and `capsule-protocol: ?1`.
    Accept,
    /// Reachable, handshakes, speaks HTTP/3 — and refuses the tunnel. The case
    /// a TCP probe cannot tell apart from a working proxy.
    Refuse,
}

struct LocalMasqueProxy {
    addr: SocketAddr,
    endpoint: quinn::Endpoint,
    _task: JoinHandle<()>,
}

impl LocalMasqueProxy {
    fn proxy_config(&self) -> ProxyConfig {
        ProxyConfig::parse(&format!("masque://127.0.0.1:{}", self.addr.port())).unwrap()
    }
}

impl Drop for LocalMasqueProxy {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"test over");
    }
}

fn spawn_local_masque_proxy(behaviour: Behaviour) -> LocalMasqueProxy {
    ensure_rustls_provider();
    let certificate = test_certificate();

    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(certificate.key.clone()));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.der.clone()], key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
        QuicServerConfig::try_from(tls).unwrap(),
    ));

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
                    serve(connection, behaviour).await;
                });
            }
        }
    });

    LocalMasqueProxy {
        addr,
        endpoint,
        _task: task,
    }
}

/// RFC 9298 §3 / RFC 9297 §3.4 validation, only as far as the probe exercises.
fn connect_udp_status(request: &http::Request<()>, behaviour: Behaviour) -> StatusCode {
    if request.method() != Method::CONNECT {
        return StatusCode::METHOD_NOT_ALLOWED;
    }
    if request.extensions().get::<Protocol>() != Some(&Protocol::CONNECT_UDP) {
        return StatusCode::BAD_REQUEST;
    }
    if request
        .headers()
        .get(CAPSULE_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        != Some(CAPSULE_PROTOCOL_ENABLED)
    {
        return StatusCode::BAD_REQUEST;
    }
    let Some(rest) = request.uri().path().strip_prefix(TUNNEL_TEMPLATE_PREFIX) else {
        return StatusCode::NOT_FOUND;
    };
    let segments: Vec<&str> = rest.split('/').collect();
    if segments.len() != 3 || !segments[2].is_empty() || segments[0] != TARGET_HOST {
        return StatusCode::BAD_REQUEST;
    }
    if segments[1].parse::<u16>() != Ok(TARGET_PORT) {
        return StatusCode::BAD_REQUEST;
    }
    match behaviour {
        Behaviour::Accept => StatusCode::OK,
        Behaviour::Refuse => StatusCode::FORBIDDEN,
    }
}

async fn serve(connection: quinn::Connection, behaviour: Behaviour) {
    let mut builder = h3::server::builder();
    builder
        .enable_extended_connect(true)
        .enable_datagram(true)
        .send_grease(false);
    let Ok(mut h3_connection) = builder
        .build::<_, Bytes>(h3_quinn::Connection::new(connection))
        .await
    else {
        return;
    };

    while let Ok(Some(resolver)) = h3_connection.accept().await {
        let Ok((request, mut stream)) = resolver.resolve_request().await else {
            continue;
        };
        let status = connect_udp_status(&request, behaviour);
        let mut response = http::Response::builder().status(status);
        if status == StatusCode::OK {
            response = response.header(CAPSULE_PROTOCOL, CAPSULE_PROTOCOL_ENABLED);
        }
        if stream
            .send_response(response.body(()).unwrap())
            .await
            .is_err()
        {
            continue;
        }
        if status == StatusCode::OK {
            // The probe closes the tunnel straight away; drain until it does.
            tokio::spawn(async move {
                while let Ok(Some(_capsule)) = stream.recv_data().await {}
                let _ = stream.finish().await;
            });
        } else {
            let _ = stream.finish().await;
        }
    }
}

// ---------------------------------------------------------------------------
// Reading the pool's verdict back out
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The health check recorded a failure against the proxy.
    Blamed,
    /// The health check said nothing, either because it passed or because the
    /// proxy was skipped.
    NotBlamed,
}

async fn health_check_verdict(
    proxy: ProxyConfig,
    tunnel_probe: bool,
    masque_outer_config: Option<MasqueOuterConfig>,
) -> Verdict {
    let identity = proxy.identity();
    // `HealthCheckConfig` is `#[non_exhaustive]`: from `Default`, then adjust.
    let mut health_check = HealthCheckConfig::default();
    // One round only: the maintenance task's first tick is immediate.
    health_check.interval = Duration::from_secs(3600);
    health_check.timeout = PROBE_TIMEOUT;
    health_check.target_host = TARGET_HOST.into();
    health_check.target_port = TARGET_PORT;
    health_check.tunnel_probe = tunnel_probe;
    health_check.masque_outer_config = masque_outer_config;

    let pool = ProxyPool::builder()
        .proxies(vec![proxy])
        .bad_proxy_config(BadProxyConfig {
            failure_threshold: 2,
            window: Duration::from_secs(600),
            cooldown_duration: Duration::from_secs(600),
            max_cooldowns: 5,
        })
        .health_check(health_check)
        .build();

    tokio::time::sleep(SETTLE).await;
    pool.mark_bad_proxy(&identity);

    let deadline = tokio::time::Instant::now() + MARK_BAD_SETTLE;
    while tokio::time::Instant::now() < deadline {
        if pool.acquire().await.proxy().is_none() {
            return Verdict::Blamed;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Verdict::NotBlamed
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The default: a MASQUE proxy is not probed at all, so nothing is learned
/// about it — not even about one that does not exist.
#[tokio::test]
async fn default_health_check_skips_a_nonexistent_masque_proxy() {
    let proxy = ProxyConfig::parse("masque://127.0.0.1:1").unwrap();
    assert_eq!(
        health_check_verdict(proxy, false, None).await,
        Verdict::NotBlamed,
        "with `tunnel_probe` off a MASQUE proxy must be skipped entirely"
    );
}

/// Control: the same pool, the same round, a non-MASQUE proxy. Its TCP probe
/// runs and fails exactly as it always did — which is also what makes the test
/// above a statement about MASQUE rather than about health checking being off.
#[tokio::test]
async fn default_health_check_still_blames_a_nonexistent_tcp_proxy() {
    let proxy = ProxyConfig::parse("http://127.0.0.1:1").unwrap();
    assert_eq!(
        health_check_verdict(proxy, false, None).await,
        Verdict::Blamed,
        "the non-MASQUE health check path must be unchanged"
    );
}

/// With the probe on, an unreachable MASQUE proxy is caught.
#[tokio::test]
async fn tunnel_probe_blames_a_nonexistent_masque_proxy() {
    let proxy = ProxyConfig::parse("masque://127.0.0.1:1").unwrap();
    assert_eq!(
        health_check_verdict(proxy, true, Some(private_ca_outer_config())).await,
        Verdict::Blamed,
        "with `tunnel_probe` on an unreachable MASQUE proxy must fail the probe"
    );
}

/// A proxy that completes the CONNECT-UDP handshake passes — including, and
/// especially, one fronted by a CA the operating system has never heard of.
/// Before the outer config was a caller-supplied seam this proxy was probed
/// against the OS store, failed the handshake and was fed to the blacklist: a
/// false negative that took a *healthy* proxy out of rotation.
#[tokio::test]
async fn tunnel_probe_accepts_a_working_private_ca_masque_proxy() {
    let proxy = spawn_local_masque_proxy(Behaviour::Accept);
    assert_eq!(
        health_check_verdict(proxy.proxy_config(), true, Some(private_ca_outer_config())).await,
        Verdict::NotBlamed,
        "a private-CA proxy that opens the tunnel is healthy when the probe is told about its CA"
    );
}

/// The false negative itself, pinned: the same healthy proxy, probed with
/// trust anchors that do not cover it, is blamed. This is what an implicit
/// `MasqueOuterConfig::default()` used to do to every privately-fronted
/// deployment, and why there is no default any more.
#[tokio::test]
async fn probing_a_private_ca_proxy_with_unrelated_trust_anchors_blames_it() {
    let proxy = spawn_local_masque_proxy(Behaviour::Accept);
    let os_store_only = MasqueOuterConfig::default();
    assert_eq!(
        health_check_verdict(proxy.proxy_config(), true, Some(os_store_only)).await,
        Verdict::Blamed,
        "a probe that cannot verify the proxy's certificate calls a healthy proxy dead"
    );
}

/// The probe takes its trust anchors — and its strictness — from the same
/// [`MasqueOuterConfig`] the requests use, so
/// [`MasqueOuterConfig::verify`]` = false` relaxes the probe too. Same healthy
/// proxy as the two tests above, and this time nothing that could vouch for it
/// — no private CA, not even the OS store — yet it is not blamed.
///
/// That is the point of sharing the configuration rather than the reason to
/// reach for it: a probe run this way no longer distinguishes "the proxy I
/// chose" from "something answering on its address". It is here so the coupling
/// is pinned in both directions.
#[tokio::test]
async fn a_probe_inherits_verify_from_the_outer_config_it_is_given() {
    let proxy = spawn_local_masque_proxy(Behaviour::Accept);
    let mut unverified = MasqueOuterConfig::default();
    unverified.use_native_certs = false;
    unverified.verify = false;
    assert_eq!(
        health_check_verdict(proxy.proxy_config(), true, Some(unverified)).await,
        Verdict::NotBlamed,
        "`verify: false` must reach the probe, not just the request path"
    );
}

/// `tunnel_probe` on with no outer config: the pool has nothing to verify the
/// proxy against, so it must say nothing rather than guess.
///
/// The proxy here *refuses* CONNECT-UDP, so a probe that actually ran would
/// blame it — which is what makes `NotBlamed` a statement about the probe being
/// skipped rather than about the proxy being healthy.
#[tokio::test]
async fn tunnel_probe_without_an_outer_config_is_skipped_not_blamed() {
    let proxy = spawn_local_masque_proxy(Behaviour::Refuse);
    assert_eq!(
        health_check_verdict(proxy.proxy_config(), true, None).await,
        Verdict::NotBlamed,
        "with no `masque_outer_config` the probe must be skipped, never guessed at"
    );
}

/// The case the whole flag exists for: a MASQUE proxy whose port is wide open
/// and whose QUIC and HTTP/3 layers work, but which refuses `connect-udp`. A
/// TCP probe would call this healthy; the tunnel probe must not.
#[tokio::test]
async fn tunnel_probe_blames_a_masque_proxy_that_refuses_connect_udp() {
    let proxy = spawn_local_masque_proxy(Behaviour::Refuse);
    assert_eq!(
        health_check_verdict(proxy.proxy_config(), true, Some(private_ca_outer_config())).await,
        Verdict::Blamed,
        "a reachable proxy that refuses CONNECT-UDP is not healthy"
    );
}

/// And the same refusing proxy is left alone by default — the skip is about the
/// scheme, not about reachability.
#[tokio::test]
async fn default_health_check_skips_a_refusing_masque_proxy() {
    let proxy = spawn_local_masque_proxy(Behaviour::Refuse);
    assert_eq!(
        health_check_verdict(proxy.proxy_config(), false, Some(private_ca_outer_config())).await,
        Verdict::NotBlamed,
        "with `tunnel_probe` off even a refusing MASQUE proxy is skipped"
    );
}
