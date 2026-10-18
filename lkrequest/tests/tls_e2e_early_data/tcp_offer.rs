use std::io::{Cursor, Write};
use std::time::Duration;

use super::*;
use lktls::profile::types::{ExtensionSource, ExtensionSpec};

#[derive(Debug)]
struct ServerHandshakeReport {
    early_data_accepted: bool,
    handshake_kind: Option<rustls::HandshakeKind>,
    error: Option<String>,
}

#[derive(Debug)]
struct TcpEarlyDataReport {
    server: ServerHandshakeReport,
    connect_returned_ok: bool,
    read_result: Result<[u8; 5], String>,
}

async fn observe_server_handshake(
    mut tcp: tokio::net::TcpStream,
    config: Arc<rustls::ServerConfig>,
    reject_early_data: bool,
) -> ServerHandshakeReport {
    let mut connection = rustls::ServerConnection::new(config).unwrap();
    if reject_early_data {
        connection.reject_early_data();
    }
    let mut report = ServerHandshakeReport {
        early_data_accepted: false,
        handshake_kind: None,
        error: None,
    };
    let mut input = [0; 16 * 1024];
    loop {
        if !connection.is_handshaking() && report.error.is_none() {
            connection.writer().write_all(b"hello").unwrap();
        }
        while connection.wants_write() {
            let mut output = Vec::new();
            connection.write_tls(&mut output).unwrap();
            tcp.write_all(&output).await.unwrap();
        }
        if !connection.is_handshaking() || report.error.is_some() {
            report.handshake_kind = connection.handshake_kind();
            return report;
        }
        let read = tokio::time::timeout(Duration::from_secs(3), tcp.read(&mut input))
            .await
            .expect("local server read deadline")
            .expect("local server TCP read");
        assert!(
            read > 0,
            "client closed before the local server completed TLS"
        );
        connection
            .read_tls(&mut Cursor::new(&input[..read]))
            .unwrap();
        if let Err(error) = connection.process_new_packets() {
            report.error = Some(format!("{error:?}"));
        }
        report.early_data_accepted |= connection.early_data().is_some();
    }
}

async fn tcp_early_data_offer_scenario(
    cipher: rustls::CipherSuite,
    reject_early_data: bool,
) -> TcpEarlyDataReport {
    let cert =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()]).unwrap();
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .retain(|suite| suite.suite() == cipher);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .unwrap();
    config.max_early_data_size = 16 * 1024;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut reports = Vec::new();
        for index in 0..2 {
            let (tcp, _) = listener.accept().await.unwrap();
            reports.push(
                observe_server_handshake(tcp, config.clone(), index == 1 && reject_early_data)
                    .await,
            );
        }
        reports
    });

    let store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());
    let mut profile = presets::chrome_155();
    profile.alpn_protocols = vec!["http/1.1".into()];
    profile.extensions.push(ExtensionSpec {
        extension_type: EXT_EARLY_DATA,
        source: ExtensionSource::Auto,
    });
    let connector = TlsConnector::new(profile)
        .insecure_skip_verify(true)
        .session_store(store.clone());

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut first = connector
        .connect("127.0.0.1", addr.port(), tcp)
        .await
        .expect("first full handshake");
    let mut greeting = [0; 5];
    first.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"hello");
    drop(first);

    let host_key = format!("127.0.0.1:{}", addr.port());
    let ticket = store.take(&host_key).expect("real server ticket");
    assert!(ticket.max_early_data_size > 0);
    assert_eq!(ticket.cipher_suite, u16::from(cipher));
    store.store(&host_key, ticket);

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let resumed = connector.connect("127.0.0.1", addr.port(), tcp).await;
    let connect_returned_ok = resumed.is_ok();
    let read_result = match resumed {
        Ok(mut tls) => tokio::time::timeout(Duration::from_secs(3), tls.read_exact(&mut greeting))
            .await
            .expect("resumed application read deadline")
            .map(|_| ())
            .map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    };
    let mut reports = tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .expect("server report deadline")
        .unwrap();
    assert!(reports[0].error.is_none(), "{reports:?}");
    assert!(!reports[0].early_data_accepted);
    eprintln!(
        "TCP early offer: cipher={cipher:?}, reject_early_data={reject_early_data}, connect_ok={connect_returned_ok}, read={read_result:?}, server={:?}",
        reports[1]
    );
    TcpEarlyDataReport {
        server: reports.pop().expect("resumed server report"),
        connect_returned_ok,
        read_result: read_result.map(|()| greeting),
    }
}

#[tokio::test]
async fn tcp_profile_early_data_offer_completes_server_finished_without_application_0rtt() {
    for cipher in [
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
        rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
    ] {
        let report = tcp_early_data_offer_scenario(cipher, false).await;
        assert!(report.connect_returned_ok, "{cipher:?}: {report:?}");
        assert!(report.server.early_data_accepted, "{cipher:?}: {report:?}");
        assert_eq!(
            report.server.handshake_kind,
            Some(rustls::HandshakeKind::Resumed)
        );
        assert!(report.server.error.is_none(), "{cipher:?}: {report:?}");
        assert_eq!(report.read_result, Ok(*b"hello"), "{cipher:?}: {report:?}");
    }
}

#[tokio::test]
async fn tcp_profile_early_data_offer_rejection_completes_without_end_of_early_data() {
    let report =
        tcp_early_data_offer_scenario(rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, true).await;
    assert!(report.connect_returned_ok, "{report:?}");
    assert!(!report.server.early_data_accepted, "{report:?}");
    assert_eq!(
        report.server.handshake_kind,
        Some(rustls::HandshakeKind::Resumed)
    );
    assert!(report.server.error.is_none(), "{report:?}");
    assert_eq!(report.read_result, Ok(*b"hello"), "{report:?}");
}
