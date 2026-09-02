//! Tier-0 regression: a server that does not accept Encrypted ClientHello must
//! not yield a usable connection.
//!
//! RFC 9849 §6.1.6: when ECH is rejected, the outer handshake exists only to
//! authenticate the config's `public_name` and collect `retry_configs`. It must
//! not carry application data — the true server name was never protected, so
//! using the connection would silently send the request ECH was meant to hide.
//!
//! `lktls` used to log "ECH: server did not accept" and carry on, installing
//! application keys and handing the connection to the caller.
//!
//! The server here is a plain rustls listener with no ECH support at all. It
//! ignores the `encrypted_client_hello` extension and answers the outer
//! ClientHello, so `ServerHello.random` carries no accept confirmation and the
//! client sees a rejection — the same path a real server takes after rotating
//! its ECH keys, minus the `retry_configs`.

use std::sync::Arc;

use lkrequest::TlsConnector;
use lktls::profile::presets;
use rcgen::{CertifiedKey, KeyPair};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// The name the ECH config publishes — what a rejecting server is authenticated
/// as, and what the outer ClientHello carries as SNI.
const PUBLIC_NAME: &str = "public.ech-test.invalid";

/// Build a single-entry `ECHConfigList` (draft-ietf-tls-esni ECHConfig, version
/// 0xfe0d) naming `PUBLIC_NAME`.
///
/// The HPKE public key is arbitrary: every 32-byte string is a usable X25519
/// public key for encapsulation, and this server never decrypts anything.
fn ech_config_list(public_name: &str) -> Vec<u8> {
    const ECH_CONFIG_VERSION: u16 = 0xfe0d;
    const KEM_X25519_HKDF_SHA256: u16 = 0x0020;

    let public_key = [0x42u8; 32];
    let cipher_suites: &[(u16, u16)] = &[(0x0001, 0x0001)]; // HKDF-SHA256 / AES-128-GCM

    let mut contents = Vec::new();
    contents.push(1u8); // config_id
    contents.extend_from_slice(&KEM_X25519_HKDF_SHA256.to_be_bytes());
    contents.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
    contents.extend_from_slice(&public_key);
    contents.extend_from_slice(&((cipher_suites.len() * 4) as u16).to_be_bytes());
    for (kdf, aead) in cipher_suites {
        contents.extend_from_slice(&kdf.to_be_bytes());
        contents.extend_from_slice(&aead.to_be_bytes());
    }
    contents.push(64u8); // maximum_name_length
    let pn = public_name.as_bytes();
    contents.push(pn.len() as u8);
    contents.extend_from_slice(pn);
    contents.extend_from_slice(&0u16.to_be_bytes()); // extensions

    let mut config = Vec::new();
    config.extend_from_slice(&ECH_CONFIG_VERSION.to_be_bytes());
    config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    config.extend_from_slice(&contents);

    // ECHConfigList = length-prefixed sequence of ECHConfig.
    let mut list = Vec::with_capacity(config.len() + 2);
    list.extend_from_slice(&(config.len() as u16).to_be_bytes());
    list.extend_from_slice(&config);
    list
}

fn acceptor(cert: &CertifiedKey<KeyPair>) -> TlsAcceptor {
    let cert_chain = vec![cert.cert.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .expect("rustls protocol versions")
    .with_no_client_auth()
    .with_single_cert(cert_chain, key)
    .expect("rustls server certificate");
    TlsAcceptor::from(Arc::new(config))
}

/// Offering real ECH to a server that ignores it must fail the connection, not
/// return an unprotected one.
#[tokio::test]
async fn ech_rejection_aborts_instead_of_returning_the_outer_connection() {
    // The certificate names the ECH `public_name`, which is the identity a
    // rejecting server legitimately presents and the one we now authenticate.
    let cert = rcgen::generate_simple_self_signed(vec![PUBLIC_NAME.to_string()])
        .expect("rcgen self-signed");
    let acceptor = acceptor(&cert);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            // The handshake is expected to end in an `ech_required` alert.
            let _ = acceptor.accept(tcp).await;
        }
    });

    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let result = TlsConnector::new(presets::chrome_144())
        // Certificate validity is not what this test is about; the point is
        // that no connection comes back at all.
        .insecure_skip_verify(true)
        .ech_config(ech_config_list(PUBLIC_NAME))
        .connect("secret.ech-test.invalid", addr.port(), tcp)
        .await;

    let error = match result {
        Ok(_) => panic!(
            "a rejected ECH handshake must not produce a usable connection — \
             the true server name was never protected"
        ),
        Err(error) => error,
    };

    assert!(
        matches!(error, lktls::error::TlsError::EchRejected { .. }),
        "expected TlsError::EchRejected, got: {error:?}"
    );

    server.abort();
}

/// GREASE ECH is not an ECH offer, so a server ignoring it rejects nothing and
/// the handshake must still succeed.
///
/// Every shipped Chrome profile GREASEs ECH by default, so without this the
/// abort above would take down ordinary traffic.
#[tokio::test]
async fn grease_ech_is_not_treated_as_a_rejected_offer() {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
        .expect("rcgen self-signed");
    let acceptor = acceptor(&cert);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        if let Ok((tcp, _)) = listener.accept().await {
            let _ = acceptor.accept(tcp).await;
        }
    });

    let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    // chrome_144 GREASEs ECH; no `ech_config` is supplied, so no real offer.
    let result = TlsConnector::new(presets::chrome_144())
        .insecure_skip_verify(true)
        .connect("127.0.0.1", addr.port(), tcp)
        .await;

    assert!(
        result.is_ok(),
        "GREASE ECH must not be mistaken for a rejected ECH offer, got: {:?}",
        result.err()
    );

    server.abort();
}
