//! Tier-0: TLS 1.3 early data (0-RTT) — why the missing `EndOfEarlyData` is
//! currently unreachable, and the guard that keeps it that way.
//!
//! `lktls` never sends an `EndOfEarlyData` message. RFC 8446 §4.5 requires one
//! once a server accepts early data: encrypted under
//! `client_early_traffic_secret` rather than the handshake keys, and folded into
//! the transcript the client Finished is computed over. Omitting it would fail
//! the server's Finished check on every accepted 0-RTT resumption.
//!
//! It is unreachable today, for two different reasons on the two transports:
//!
//! - **TCP** — `Tls13Handshake` calls `ClientHelloBuilder::with_early_data()`
//!   whenever the resumption ticket allows 0-RTT, which reads like an offer. But
//!   ClientHello extensions are emitted from the profile's extension list, and
//!   no TCP profile lists extension 42, so the flag never reaches the wire. The
//!   server never sees an offer and never accepts.
//! - **QUIC** — the QUIC profiles *do* offer extension 42, matching real Chrome.
//!   No `EndOfEarlyData` is owed there: RFC 9001 §8.3 states a QUIC client "MUST
//!   NOT send the EndOfEarlyData message", since the end of 0-RTT is signalled
//!   by the change of packet number space.
//!
//! So the gap only becomes real if a *TCP* profile starts offering early data.
//! These tests pin that: resumption against an early-data-capable server does
//! not negotiate early data, no TCP profile lists extension 42, and the QUIC
//! profiles still do.

use std::sync::{Arc, Mutex};

use lkrequest::TlsConnector;
use lktls::profile::presets;
use lktls::session_store::{InMemorySessionStore, SessionStore};
use rcgen::{CertifiedKey, KeyPair};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

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
async fn serve(listener: TcpListener, acceptor: TlsAcceptor, connections: usize) {
    for _ in 0..connections {
        let Ok((tcp, _)) = listener.accept().await else {
            return;
        };
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(mut tls) => {
                    let _ = tls.write_all(b"hello").await;
                    let _ = tls.flush().await;
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
                Err(error) => eprintln!("server handshake failed: {error}"),
            }
        });
    }
}

/// Capture `tracing` messages so the test can assert what the handshake actually
/// negotiated, rather than inferring it from success alone.
fn capture_logs() -> (Arc<Mutex<Vec<String>>>, tracing::subscriber::DefaultGuard) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;

    struct LogCapture {
        logs: Arc<Mutex<Vec<String>>>,
    }

    impl<S: tracing::Subscriber> Layer<S> for LogCapture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = MessageVisitor(String::new());
            event.record(&mut visitor);
            if let Ok(mut logs) = self.logs.lock() {
                logs.push(visitor.0);
            }
        }
    }

    struct MessageVisitor(String);
    impl tracing::field::Visit for MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            } else {
                if !self.0.is_empty() {
                    self.0.push(' ');
                }
                self.0.push_str(&format!("{}={:?}", field.name(), value));
            }
        }
    }

    let logs: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(LogCapture { logs: logs.clone() });
    let guard = tracing::subscriber::set_default(subscriber);
    (logs, guard)
}

/// PSK resumption against a server that *would* accept 0-RTT: the handshake
/// completes, and early data is not negotiated because we never offer it.
///
/// If a future change makes the client offer `early_data`, the server here will
/// accept it and this test's early-data assertion flips — which is the signal
/// that `EndOfEarlyData` must be implemented before that change can ship.
#[tokio::test]
async fn resumption_does_not_negotiate_early_data() {
    let (logs, _guard) = capture_logs();

    let cert =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string(), "localhost".to_string()])
            .expect("rcgen self-signed");
    let acceptor = early_data_acceptor(&cert);

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = tokio::spawn(serve(listener, acceptor, 2));

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
    let resumed = TlsConnector::new(presets::chrome_144())
        .insecure_skip_verify(true)
        .session_store(store.clone())
        .connect("127.0.0.1", addr.port(), tcp)
        .await;

    assert!(
        resumed.is_ok(),
        "resumed handshake must succeed, got {:?}",
        resumed.err()
    );

    let joined = logs.lock().expect("log mutex").join("\n");
    assert!(
        joined.contains("psk_accepted"),
        "the second connection must actually resume via PSK; logs:\n{joined}"
    );
    assert!(
        !joined.contains("Server accepted TLS early_data"),
        "early data was negotiated, but lktls never sends the EndOfEarlyData \
         message RFC 8446 §4.5 requires (encrypted under \
         client_early_traffic_secret and folded into the client Finished \
         transcript). Implement it before offering early_data; logs:\n{joined}"
    );

    server.abort();
}

fn offers_early_data(profile: &lktls::profile::types::TlsProfile) -> bool {
    profile
        .extensions
        .iter()
        .any(|ext| ext.extension_type == EXT_EARLY_DATA)
}

/// No **TCP** profile offers `early_data`, so the missing `EndOfEarlyData`
/// support is unreachable there.
///
/// Adding extension 42 to a TCP profile turns that gap into a handshake failure
/// on every accepted 0-RTT resumption, so this fails loudly rather than letting
/// the profile change ship on its own.
#[test]
fn no_tcp_profile_offers_early_data_while_end_of_early_data_is_unimplemented() {
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
        ("firefox_133", presets::firefox_133()),
        ("firefox_147", presets::firefox_147()),
        ("safari_18", presets::safari_18()),
        ("safari_26", presets::safari_26()),
    ];

    for (name, profile) in tcp_profiles {
        assert!(
            !offers_early_data(&profile),
            "TCP profile `{name}` lists extension {EXT_EARLY_DATA} (early_data), \
             but lktls does not send the EndOfEarlyData message RFC 8446 §4.5 \
             requires when a server accepts 0-RTT. Every accepted early-data \
             resumption would fail the client Finished check. Implement \
             EndOfEarlyData — encrypted under client_early_traffic_secret and \
             appended to the transcript after the server Finished, before the \
             client Finished — before shipping this profile."
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
    ] {
        assert!(
            offers_early_data(&profile),
            "QUIC profile `{name}` must keep extension {EXT_EARLY_DATA} \
             (early_data) — real Chrome offers it on QUIC, and dropping it \
             changes the QUIC ClientHello fingerprint"
        );
    }
}
