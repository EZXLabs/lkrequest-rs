//! Tier-0: TLS 1.3 early-data offers and transport-specific completion.
//!
//! Built-in TCP profiles omit extension 42, so their normal resumption does
//! not negotiate early data. Custom TCP profiles can include an Auto early_data
//! extension. When a server accepts that valid offer, the client sends an empty
//! EndOfEarlyData with early write keys and includes it in the Finished transcript.
//! This completes a zero-byte early phase; there is no TCP early-application-data
//! sending API.
//!
//! QUIC templates retain their early-data offer but never emit EndOfEarlyData,
//! as required by RFC 9001 section 8.3. The child fixture verifies accepted and
//! rejected custom TCP offers against a real peer, including its Finished check.

use std::sync::Arc;

use lkrequest::TlsConnector;
use lktls::profile::presets;
use lktls::session_store::{InMemorySessionStore, SessionStore};
use rcgen::{CertifiedKey, KeyPair};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[path = "tls_e2e_early_data/tcp_offer.rs"]
mod tcp_offer;

/// TLS 1.3 `early_data` extension type.
const EXT_EARLY_DATA: u16 = 42;

/// A rustls server that issues resumption tickets and accepts 0-RTT.
fn early_data_acceptor(cert: &CertifiedKey<KeyPair>) -> TlsAcceptor {
    let cert_chain = vec![cert.cert.der().clone()];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .expect("rustls protocol versions")
    .with_no_client_auth()
    .with_single_cert(cert_chain, key)
    .expect("rustls server certificate");

    // A non-zero early-data budget is what makes the server answer an
    // `early_data` offer with an `early_data` extension in EncryptedExtensions.
    //
    // Deliberately no `ticketer`: rustls implements RFC 8446 §8.1 by allowing
    // 0-RTT only with *stateful* resumption, so configuring a stateless ticketer
    // would silently disable early data. The default in-memory `session_storage`
    // is what we want.
    config.max_early_data_size = 16 * 1024;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    TlsAcceptor::from(Arc::new(config))
}

/// Serve `connections` TLS sessions, writing a short greeting on each so the
/// client has something to read — which is also what drives it to consume the
/// post-handshake `NewSessionTicket`.
async fn serve(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    connections: usize,
    reports: tokio::sync::mpsc::UnboundedSender<(Option<rustls::HandshakeKind>, bool)>,
) {
    for _ in 0..connections {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let acceptor = acceptor.clone();
        let reports = reports.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(mut tls) => {
                    let peer = &mut tls.get_mut().1;
                    reports
                        .send((peer.handshake_kind(), peer.early_data().is_some()))
                        .unwrap();
                    let _ = tls.write_all(b"hello").await;
                    let _ = tls.flush().await;
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
                Err(error) => eprintln!("server handshake failed: {error}"),
            }
        });
    }
}

/// PSK resumption against a server that *would* accept 0-RTT: the handshake
/// completes, and the built-in TCP profile does not negotiate early data.
#[tokio::test]
async fn resumption_does_not_negotiate_early_data() {
    let cert =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string(), "localhost".to_string()])
            .expect("rcgen self-signed");
    let acceptor = early_data_acceptor(&cert);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (report_tx, mut reports) = tokio::sync::mpsc::unbounded_channel();
    let server = tokio::spawn(serve(listener, acceptor, 2, report_tx));

    let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());

    // --- Connection 1: full handshake, collect the session ticket ----------
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect 1");
    let mut tls = TlsConnector::new(presets::chrome_144())
        .insecure_skip_verify(true)
        .session_store(store.clone())
        .connect("127.0.0.1", addr.port(), tcp)
        .await
        .expect("first handshake");

    // Reading drives the post-handshake NewSessionTicket into the store.
    let mut buf = [0u8; 64];
    let n = tls.read(&mut buf).await.expect("read greeting");
    assert_eq!(&buf[..n], b"hello");
    let first = reports.recv().await.expect("full handshake report");
    assert!(first
        .0
        .is_some_and(|kind| kind != rustls::HandshakeKind::Resumed));
    assert!(!first.1);
    drop(tls);

    // The server must have issued a 0-RTT-capable ticket, otherwise the
    // early-data assertion below would hold for an uninteresting reason.
    let host_key = format!("127.0.0.1:{}", addr.port());
    let ticket = store
        .take(&host_key)
        .expect("ticket stored after first handshake");
    assert!(
        ticket.max_early_data_size > 0,
        "the local server must issue an early-data-capable ticket, got \
         max_early_data_size = {}",
        ticket.max_early_data_size
    );
    // `take` removes it; put it back for the resumption below.
    store.store(&host_key, ticket);

    // --- Connection 2: resume ----------------------------------------------
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect 2");
    let mut resumed = TlsConnector::new(presets::chrome_144())
        .insecure_skip_verify(true)
        .session_store(store.clone())
        .connect("127.0.0.1", addr.port(), tcp)
        .await
        .expect("resumed handshake");
    let n = resumed.read(&mut buf).await.expect("resumed greeting");
    assert_eq!(&buf[..n], b"hello");
    let second = reports.recv().await.expect("resumed handshake report");
    assert_eq!(second.0, Some(rustls::HandshakeKind::Resumed));
    assert!(
        !second.1,
        "the built-in TCP profile must not negotiate early data"
    );

    server.abort();
}

fn offers_early_data(profile: &lktls::profile::types::TlsProfile) -> bool {
    profile
        .extensions
        .iter()
        .any(|ext| ext.extension_type == EXT_EARLY_DATA)
}

/// Built-in TCP offers remain unchanged by support for custom early-data offers.
#[test]
fn built_in_tcp_profiles_do_not_offer_early_data() {
    let tcp_profiles: Vec<(&str, lktls::profile::types::TlsProfile)> = vec![
        ("chrome_131", presets::chrome_131()),
        ("chrome_144", presets::chrome_144()),
        ("chrome_145", presets::chrome_145()),
        ("chrome_146", presets::chrome_146()),
        ("chrome_147", presets::chrome_147()),
        ("chrome_148", presets::chrome_148()),
        ("chrome_149", presets::chrome_149()),
        ("chrome_150", presets::chrome_150()),
        ("chrome_151", presets::chrome_151()),
        ("chrome_152", presets::chrome_152()),
        ("chrome_153", presets::chrome_153()),
        ("chrome_154", presets::chrome_154()),
        ("chrome_155", presets::chrome_155()),
        ("firefox_133", presets::firefox_133()),
        ("firefox_147", presets::firefox_147()),
        ("firefox_156", presets::firefox_156()),
        ("safari_18", presets::safari_18()),
        ("safari_26", presets::safari_26()),
    ];

    for (name, profile) in tcp_profiles {
        assert!(
            !offers_early_data(&profile),
            "unexpected extension {EXT_EARLY_DATA} (early_data) in built-in TCP profile `{name}`"
        );
    }
}

/// The QUIC profiles *do* offer `early_data`, and correctly owe no
/// `EndOfEarlyData`: RFC 9001 §8.3 states a QUIC client "MUST NOT send the
/// EndOfEarlyData message", because the end of 0-RTT is signalled by the change
/// of packet number space rather than by a handshake message.
///
/// Pinned so the asymmetry with the TCP profiles reads as deliberate, and so
/// dropping the extension — a QUIC ClientHello fingerprint regression — is
/// caught.
#[test]
fn quic_profiles_offer_early_data_and_owe_no_end_of_early_data() {
    for (name, profile) in [
        ("chrome_146_quic", presets::chrome_146_quic()),
        ("chrome_150_quic", presets::chrome_150_quic()),
        ("chrome_151_quic", presets::chrome_151_quic()),
        ("chrome_152_quic", presets::chrome_152_quic()),
        ("chrome_153_quic", presets::chrome_153_quic()),
        ("chrome_154_quic", presets::chrome_154_quic()),
        ("chrome_155_quic", presets::chrome_155_quic()),
    ] {
        assert!(
            offers_early_data(&profile),
            "QUIC profile `{name}` must keep extension {EXT_EARLY_DATA} \
             (early_data) — real Chrome offers it on QUIC, and dropping it \
             changes the QUIC ClientHello fingerprint"
        );
    }
}
