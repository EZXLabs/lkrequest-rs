//! HSTS / scheme-upgrade policy tests against a local HTTPS server (Tier 0).
//!
//! The server speaks TLS only, so an `http://` request succeeds *only if* it is
//! upgraded to `https://` before connecting — which is exactly what an
//! `HstsPolicy` controls.

mod support;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::hsts::StaticHsts;
use lkrequest::Client;
use lktls::profile::presets;
use support::local_https::start_local_https_server;

fn chrome_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .build()
}

/// Build the http:// form of the server's base URL (same host/port, downgraded).
fn http_base(base_url: &str) -> String {
    base_url.replacen("https://", "http://", 1)
}

/// An HSTS policy upgrades an http:// request to https:// before connecting.
#[tokio::test]
async fn hsts_policy_upgrades_http_to_https() {
    let srv = start_local_https_server().await;
    let session = chrome_client()
        .session()
        .hsts_policy(StaticHsts::new(["127.0.0.1"]))
        .build();

    // Request the cleartext URL; the policy must upgrade it to https, so the
    // TLS-only server answers 200.
    let url = format!("{}/get", http_base(&srv.base_url));
    let resp = session
        .get(&url)
        .send()
        .await
        .expect("HSTS upgrade should make the https request succeed");
    assert_eq!(resp.status().as_u16(), 200);
}

/// A closure policy works the same way.
#[tokio::test]
async fn hsts_closure_policy_upgrades() {
    let srv = start_local_https_server().await;
    let session = chrome_client()
        .session()
        .hsts_policy(|host: &str| host == "127.0.0.1")
        .build();

    let url = format!("{}/get", http_base(&srv.base_url));
    let resp = session
        .get(&url)
        .send()
        .await
        .expect("closure HSTS upgrade");
    assert_eq!(resp.status().as_u16(), 200);
}

/// The default (NoHsts) does not upgrade: a cleartext request to the TLS-only
/// server fails.
#[tokio::test]
async fn default_no_hsts_does_not_upgrade() {
    let srv = start_local_https_server().await;
    let session = chrome_client().session().build();

    let url = format!("{}/get", http_base(&srv.base_url));
    let result = session.get(&url).send().await;
    assert!(
        result.is_err(),
        "without an HSTS policy the cleartext request must not be upgraded, got {:?}",
        result.map(|r| r.status())
    );
}

/// HSTS upgrade runs *before* the https_only gate: an upgraded host is allowed.
#[tokio::test]
async fn hsts_upgrade_runs_before_https_only() {
    let srv = start_local_https_server().await;
    let session = chrome_client()
        .session()
        .https_only(true)
        .hsts_policy(StaticHsts::new(["127.0.0.1"]))
        .build();

    let url = format!("{}/get", http_base(&srv.base_url));
    let resp = session
        .get(&url)
        .send()
        .await
        .expect("HSTS should upgrade before https_only rejects");
    assert_eq!(resp.status().as_u16(), 200);
}

/// https_only refuses an http:// initial request when nothing upgrades it.
#[tokio::test]
async fn https_only_refuses_http_initial_request() {
    let srv = start_local_https_server().await;
    let session = chrome_client().session().https_only(true).build();

    let url = format!("{}/get", http_base(&srv.base_url));
    let err = session
        .get(&url)
        .send()
        .await
        .expect_err("https_only must refuse a non-HTTPS initial request");
    let msg = format!("{err}");
    assert!(
        msg.contains("https_only") || msg.to_lowercase().contains("non-https"),
        "expected an https_only refusal, got: {msg}"
    );
}

// ============================================================================
// RFC 6797 §8.1 — when a Strict-Transport-Security header may be *noted*
// ============================================================================
//
// Two MUSTs, both exercised end-to-end below against a local server that
// stamps an STS header on every response:
//
//   * "If an HTTP response is received over insecure transport, the UA MUST
//     ignore any present STS header field(s)."
//   * "If the substring matching the host production ... is an IP address, the
//     UA MUST NOT note this host as a Known HSTS Host."

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use lkrequest::hsts::{DynamicHsts, HstsPolicy};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

/// Resolves every hostname to loopback, so these tests can drive a *DNS* host
/// (not an IP literal) at a local server — the IP-literal gate is exactly what
/// is under test, so `127.0.0.1` cannot stand in for a real name.
struct LoopbackDns;

#[async_trait::async_trait]
impl lkrequest::DnsResolver for LoopbackDns {
    async fn resolve(&self, _host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
    }
}

fn loopback_dns_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .dns_resolver(Arc::new(LoopbackDns))
        .build()
}

/// A [`DynamicHsts`] store the test keeps a handle on, so it can inspect what
/// the session actually learned from the response.
#[derive(Clone, Default)]
struct SharedHsts(Arc<DynamicHsts>);

impl HstsPolicy for SharedHsts {
    fn should_upgrade(&self, host: &str) -> bool {
        self.0.should_upgrade(host)
    }

    fn record_sts(&self, host: &str, sts_header: &str) {
        self.0.record_sts(host, sts_header)
    }
}

/// Local server that answers every request `200 OK` with an STS header.
/// Drop to stop the accept loop.
struct StsServer {
    port: u16,
    shutdown: Option<oneshot::Sender<()>>,
}

impl Drop for StsServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

async fn serve_sts<I>(io: I)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let svc = service_fn(|_req: Request<hyper::body::Incoming>| async move {
        Ok::<_, std::convert::Infallible>(
            Response::builder()
                .status(StatusCode::OK)
                .header(
                    "strict-transport-security",
                    "max-age=31536000; includeSubDomains",
                )
                .body(Full::new(Bytes::from("ok")))
                .unwrap(),
        )
    });
    let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
        .serve_connection(io, svc)
        .await;
}

/// Start the STS server: `tls = false` serves cleartext HTTP, `true` serves TLS.
async fn start_sts_server(tls: bool) -> StsServer {
    let acceptor = tls.then(|| {
        let cert = rcgen::generate_simple_self_signed(vec![
            "sts.test".to_string(),
            "127.0.0.1".to_string(),
        ])
        .expect("rcgen self-signed");
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let mut config = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .expect("rustls protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .expect("rustls server certificate");
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        TlsAcceptor::from(Arc::new(config))
    });

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .expect("bind 127.0.0.1");
    let port = listener.local_addr().expect("local_addr").port();
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    let acc = acceptor.clone();
                    tokio::spawn(async move {
                        match acc {
                            Some(acc) => {
                                if let Ok(tls) = acc.accept(stream).await {
                                    serve_sts(TokioIo::new(tls)).await;
                                }
                            }
                            None => serve_sts(TokioIo::new(stream)).await,
                        }
                    });
                }
            }
        }
    });

    tokio::task::yield_now().await;

    StsServer {
        port,
        shutdown: Some(shutdown_tx),
    }
}

/// RFC 6797 §8.1: an STS header received over *cleartext* HTTP must be
/// ignored. Otherwise anyone who can answer on the plaintext path pins the
/// host (or, with `max-age=0`, un-pins it) for the rest of the session.
#[tokio::test]
async fn sts_over_insecure_transport_is_ignored() {
    let srv = start_sts_server(false).await;
    let policy = SharedHsts::default();
    let session = loopback_dns_client()
        .session()
        .hsts_policy(policy.clone())
        .build();

    let url = format!("http://sts.test:{}/", srv.port);
    let resp = session
        .get(&url)
        .send()
        .await
        .expect("cleartext request to the local server");
    assert_eq!(resp.status().as_u16(), 200);
    assert!(
        resp.headers().contains_key("strict-transport-security"),
        "precondition: the server must have sent an STS header, headers: {:?}",
        resp.headers()
    );

    // The header MUST NOT have been noted.
    assert!(
        !policy.should_upgrade("sts.test"),
        "an STS header on an insecure-transport response must not pin the host"
    );

    // Observable consequence: the next cleartext request is still not upgraded.
    // Had the header been noted, this would attempt TLS against a plaintext
    // server and fail.
    let resp2 = session
        .get(&url)
        .send()
        .await
        .expect("second cleartext request must still not be upgraded to https");
    assert_eq!(resp2.status().as_u16(), 200);
}

/// RFC 6797 §8.1: a host that is an IP address literal must never be noted as
/// a Known HSTS Host, even when the response did arrive over TLS.
#[tokio::test]
async fn sts_from_ip_literal_host_is_not_noted() {
    let srv = start_sts_server(true).await;
    let policy = SharedHsts::default();
    let session = loopback_dns_client()
        .session()
        .hsts_policy(policy.clone())
        .build();

    let url = format!("https://127.0.0.1:{}/", srv.port);
    let resp = session
        .get(&url)
        .send()
        .await
        .expect("https request to the local server");
    assert_eq!(resp.status().as_u16(), 200);
    assert!(
        resp.headers().contains_key("strict-transport-security"),
        "precondition: the server must have sent an STS header, headers: {:?}",
        resp.headers()
    );
    assert!(
        !policy.should_upgrade("127.0.0.1"),
        "an IP-address host must not be noted as a Known HSTS Host"
    );
}

/// Positive control: over TLS, with a DNS host, the header *is* still noted —
/// the two gates above must not have disabled dynamic HSTS learning.
#[tokio::test]
async fn sts_over_https_with_dns_host_is_noted() {
    let srv = start_sts_server(true).await;
    let policy = SharedHsts::default();
    let session = loopback_dns_client()
        .session()
        .hsts_policy(policy.clone())
        .build();

    let url = format!("https://sts.test:{}/", srv.port);
    let resp = session
        .get(&url)
        .send()
        .await
        .expect("https request to the local server");
    assert_eq!(resp.status().as_u16(), 200);
    assert!(
        policy.should_upgrade("sts.test"),
        "a secure-transport STS response from a DNS host must be noted"
    );
    assert!(
        policy.should_upgrade("sub.sts.test"),
        "includeSubDomains must still apply to a noted host"
    );
}
