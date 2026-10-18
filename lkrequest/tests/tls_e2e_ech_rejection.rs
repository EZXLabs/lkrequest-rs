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

struct ObservedTcp {
    tcp: tokio::net::TcpStream,
    bytes: Arc<std::sync::Mutex<Vec<u8>>>,
}

impl tokio::io::AsyncRead for ObservedTcp {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buffer.filled().len();
        let result = std::pin::Pin::new(&mut self.tcp).poll_read(cx, buffer);
        if let std::task::Poll::Ready(Ok(())) = &result {
            let mut bytes = self.bytes.lock().unwrap();
            bytes.extend_from_slice(&buffer.filled()[before..]);
            assert!(bytes.len() < 65_536, "bounded synthetic TLS capture");
        }
        result
    }
}

impl tokio::io::AsyncWrite for ObservedTcp {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buffer: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.tcp).poll_write(cx, buffer)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.tcp).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.tcp).poll_shutdown(cx)
    }
}

#[derive(Debug, Default)]
struct TicketCounter(std::sync::atomic::AtomicUsize);

impl lktls::session_store::SessionStore for TicketCounter {
    fn store(&self, _host: &str, _ticket: lktls::session_store::SessionTicketData) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    fn take(&self, _host: &str) -> Option<lktls::session_store::SessionTicketData> {
        None
    }
}

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

#[tokio::test]
async fn hrr_rejection_authenticates_public_name_and_sends_ech_required() {
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    tokio::time::timeout(Duration::from_secs(15), async {
        for wrong_name in [false, true] {
            let cert = rcgen::generate_simple_self_signed(vec![if wrong_name {
                "secret.ech-test.invalid"
            } else {
                PUBLIC_NAME
            }
            .to_string()])
            .unwrap();
            let anchor =
                lktls::verify::certchain::parse_trust_anchor_from_der(cert.cert.der()).unwrap();
            let mut provider = rustls::crypto::ring::default_provider();
            provider.kx_groups = vec![rustls::crypto::ring::kx_group::SECP384R1];
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.cert.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        cert.signing_key.serialize_der(),
                    )),
                )
                .unwrap();
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
            let observed = bytes.clone();
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let error = match acceptor
                    .accept(ObservedTcp {
                        tcp,
                        bytes: observed,
                    })
                    .await
                {
                    Ok(mut stream) => {
                        let mut application = [0; 1];
                        stream
                            .read(&mut application)
                            .await
                            .expect_err("no application data after ECH rejection")
                    }
                    Err(error) => error,
                };
                error
            });
            let tickets = Arc::new(TicketCounter::default());
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let result = TlsConnector::new(presets::chrome_155())
                .custom_ca_anchors(Arc::new(vec![anchor]))
                .session_store(tickets.clone())
                .ech_config(ech_config_list(PUBLIC_NAME))
                .connect("secret.ech-test.invalid", addr.port(), tcp)
                .await;
            let error = match result {
                Ok(_) => panic!("rejected outer handshake must not return a connection"),
                Err(error) => error,
            };
            let peer_error = server.await.unwrap();
            if wrong_name {
                assert!(
                    matches!(error, lktls::error::TlsError::CertificateError(_)),
                    "wrong public-name identity: {error:?}"
                );
            } else {
                assert!(
                    matches!(error, lktls::error::TlsError::EchRejected { .. }),
                    "expected authenticated ECH rejection: {error:?}"
                );
                assert!(
                    matches!(
                        peer_error
                            .get_ref()
                            .and_then(|error| error.downcast_ref::<rustls::Error>()),
                        Some(rustls::Error::AlertReceived(
                            rustls::AlertDescription::EncryptedClientHelloRequired
                        ))
                    ),
                    "server sees ech_required, got {peer_error:?}"
                );
            }
            assert_eq!(tickets.0.load(std::sync::atomic::Ordering::SeqCst), 0);
            let wire = bytes.lock().unwrap();
            let mut offset = 0;
            let mut plaintext = Vec::new();
            while offset < wire.len() {
                assert!(offset + 5 <= wire.len());
                let kind = wire[offset];
                let length = u16::from_be_bytes([wire[offset + 3], wire[offset + 4]]) as usize;
                offset += 5;
                assert!(offset + length <= wire.len());
                if kind == 22 {
                    plaintext.extend_from_slice(&wire[offset..offset + length]);
                }
                offset += length;
            }
            let mut hellos = Vec::new();
            let mut offset = 0;
            while offset < plaintext.len() {
                assert!(offset + 4 <= plaintext.len());
                let length = ((plaintext[offset + 1] as usize) << 16)
                    | ((plaintext[offset + 2] as usize) << 8)
                    | plaintext[offset + 3] as usize;
                let end = offset + 4 + length;
                assert!(end <= plaintext.len());
                hellos.push(lkprofile::parse_client_hello(&plaintext[offset..end]).unwrap());
                offset = end;
            }
            assert_eq!(hellos.len(), 2, "real P-384 HRR occurred");
            let extension = |index: usize, kind: u16| {
                hellos[index]
                    .extensions
                    .iter()
                    .find(|extension| extension.extension_type == kind)
                    .unwrap()
                    .data
                    .clone()
            };
            assert_eq!(
                extension(0, 0xfe0d),
                extension(1, 0xfe0d),
                "retained ECH payload"
            );
            assert_eq!(extension(0, 0), extension(1, 0), "public SNI unchanged");
            assert_eq!(&extension(1, 51)[2..4], &[0, 24]);
            assert!(hellos[1]
                .extensions
                .iter()
                .all(|extension| extension.extension_type != 41));
        }
    })
    .await
    .expect("local ECH HRR rejection timed out");
}

#[tokio::test]
async fn tls12_ech_rejection_keeps_public_identity_and_never_returns_a_connection() {
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    tokio::time::timeout(Duration::from_secs(15), async {
        for identity in 0..3 {
            let names = match identity {
                0 => vec![
                    PUBLIC_NAME.to_string(),
                    "secret.ech-test.invalid".to_string(),
                ],
                1 => vec![PUBLIC_NAME.to_string()],
                _ => vec!["secret.ech-test.invalid".to_string()],
            };
            let cert = rcgen::generate_simple_self_signed(names).unwrap();
            let anchor =
                lktls::verify::certchain::parse_trust_anchor_from_der(cert.cert.der()).unwrap();
            let mut config = rustls::ServerConfig::builder_with_provider(
                rustls::crypto::ring::default_provider().into(),
            )
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
            )
            .unwrap();
            config.ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                match acceptor.accept(tcp).await {
                    Ok(mut stream) => {
                        assert_eq!(
                            stream.get_ref().1.protocol_version(),
                            Some(rustls::ProtocolVersion::TLSv1_2)
                        );
                        let mut application = [0; 1];
                        stream
                            .read(&mut application)
                            .await
                            .expect_err("no application data on rejected ECH")
                    }
                    Err(error) => error,
                }
            });
            let tickets = Arc::new(TicketCounter::default());
            let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
            let result = TlsConnector::new(presets::chrome_155())
                .custom_ca_anchors(Arc::new(vec![anchor]))
                .session_store(tickets.clone())
                .ech_config(ech_config_list(PUBLIC_NAME))
                .connect("secret.ech-test.invalid", address.port(), tcp)
                .await;
            let error = match result {
                Ok(_) => {
                    panic!("real ECH rejected by TLS 1.2 must never produce a usable connection")
                }
                Err(error) => error,
            };
            let remote = server.await.unwrap();
            if identity == 2 {
                assert!(
                    matches!(error, lktls::error::TlsError::CertificateError(_)),
                    "only-secret identity: {error:?}"
                );
            } else {
                assert!(
                    matches!(
                        error,
                        lktls::error::TlsError::EchRejected {
                            retry_configs: None
                        }
                    ),
                    "public identity: {error:?}"
                );
                assert!(
                    matches!(
                        remote
                            .get_ref()
                            .and_then(|error| error.downcast_ref::<rustls::Error>()),
                        Some(rustls::Error::AlertReceived(
                            rustls::AlertDescription::EncryptedClientHelloRequired
                        ))
                    ),
                    "peer sees ech_required: {remote:?}"
                );
            }
            assert_eq!(tickets.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        }
    })
    .await
    .expect("TLS 1.2 ECH rejection test timed out");
}
