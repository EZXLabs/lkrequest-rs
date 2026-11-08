use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "quic-h3")]
use aws_lc_rs::{digest, signature};
use lkrequest::{
    Client, TrustAnchorBinding, TrustAnchorId, TrustAnchorPolicy, TrustAnchorRecovery,
};
use lktls::trust_anchor::anchor_identity;
#[cfg(feature = "quic-h3")]
use lktls::trust_anchor::encode_list;

#[path = "support/trust_anchor_peer.rs"]
mod peer;
use peer::{ids, read_hello, rejected_chain_flight};

#[path = "trust_anchor_negotiation/boringssl.rs"]
mod boringssl;
#[path = "trust_anchor_negotiation/lifecycle.rs"]
mod lifecycle;
#[path = "trust_anchor_negotiation/validation.rs"]
mod validation;

#[cfg(feature = "quic-h3")]
#[path = "trust_anchor_negotiation/quic.rs"]
mod quic;

#[cfg(feature = "quic-h3")]
fn message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

fn accept_bounded(listener: &std::net::TcpListener) -> std::net::TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                return socket;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(error) => panic!("expected local connection before deadline: {error}"),
        }
    }
}

#[derive(Clone)]
struct LocalDns;
#[async_trait::async_trait]
impl lkrequest::DnsResolver for LocalDns {
    async fn resolve(&self, _: &str, port: u16) -> std::io::Result<Vec<std::net::SocketAddr>> {
        Ok(vec![([127, 0, 0, 1], port).into()])
    }
}

async fn run_recovery(recovery: bool, wrong_name: bool, retry_fails: bool) {
    let trusted = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut params = rcgen::CertificateParams::new(vec![if wrong_name {
        "wrong.example"
    } else {
        "localhost"
    }
    .into()])
    .unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Untrusted TAI test CA");
    let signing_key = rcgen::KeyPair::generate().unwrap();
    let untrusted = rcgen::CertifiedKey {
        cert: params.self_signed(&signing_key).unwrap(),
        signing_key,
    };
    let anchor = lktls::verify::certchain::parse_trust_anchor_from_der(trusted.cert.der()).unwrap();
    let id = TrustAnchorId::from_hex("81fd5901").unwrap();
    let unknown = TrustAnchorId::from_hex("81fd5902").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![trusted.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(trusted.signing_key.serialize_der()).into(),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = Arc::new(tls);
    let server_id = id.clone();
    let server = tokio::task::spawn_blocking(move || {
        let mut socket = accept_bounded(&listener);
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let hello = read_hello(&mut socket);
        assert_ne!(ids(&hello), vec![server_id.clone()]);
        let flight = rejected_chain_flight(&hello, &untrusted, &[unknown, server_id.clone()]);
        socket.write_all(&flight).unwrap();
        drop(socket);
        if !recovery || wrong_name {
            listener.set_nonblocking(true).unwrap();
            std::thread::sleep(Duration::from_millis(200));
            assert!(
                listener.accept().is_err(),
                "terminal failure must not reconnect"
            );
            return;
        }
        let mut socket = accept_bounded(&listener);
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let hello = read_hello(&mut socket);
        assert_eq!(ids(&hello), vec![server_id]);
        if retry_fails {
            socket
                .write_all(&rejected_chain_flight(
                    &hello,
                    &untrusted,
                    &[TrustAnchorId::from_hex("81fd5901").unwrap()],
                ))
                .unwrap();
            drop(socket);
            listener.set_nonblocking(true).unwrap();
            std::thread::sleep(Duration::from_millis(200));
            assert!(
                listener.accept().is_err(),
                "failed recovery must not open a third connection"
            );
            return;
        }
        let mut connection = rustls::ServerConnection::new(tls).unwrap();
        connection
            .read_tls(&mut std::io::Cursor::new(hello))
            .unwrap();
        connection.process_new_packets().unwrap();
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let mut request = Vec::new();
        loop {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
            assert!(request.len() < 65536);
        }
        let mut body = [0; 7];
        stream.read_exact(&mut body).unwrap();
        assert_eq!(&body, b"payload");
        assert!(request.starts_with(b"POST /test HTTP/1.1"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .unwrap();
        stream.flush().unwrap();
    });
    let mut profile = lktls::profile::presets::chrome_157();
    profile.alpn_protocols = vec!["http/1.1".into()];
    profile.key_share_curves = vec![29];
    profile.alps_protocols = None;
    let client = Client::builder()
        .fingerprint(profile)
        .dns_resolver(Arc::new(LocalDns))
        .add_ca_cert_der(trusted.cert.der())
        .trust_anchor_binding(TrustAnchorBinding {
            anchor_identity: anchor_identity(&anchor),
            id,
        })
        .trust_anchor_policy(TrustAnchorPolicy {
            recovery: if recovery {
                TrustAnchorRecovery::Once
            } else {
                TrustAnchorRecovery::Disabled
            },
            ..Default::default()
        })
        .try_build()
        .unwrap();
    let mut session = client.session().http1_only();
    if retry_fails {
        session = session.retry_policy(lkrequest::retry::FixedInterval::new(
            3,
            Duration::from_millis(1),
        ));
    }
    let session = session.build();
    let result = session
        .post(&format!("https://localhost:{}/test", address.port()))
        .body("payload")
        .collect_diagnostics(true)
        .send()
        .await;
    if recovery && !wrong_name && !retry_fails {
        let response = result.unwrap();
        assert_eq!(response.status().as_u16(), 200);
        let info = response
            .diagnostics()
            .unwrap()
            .trust_anchor
            .as_ref()
            .unwrap();
        assert!(info.recovered && info.authenticated);
        assert!(info.previous_attempt.as_ref().unwrap().recovery_eligible);
        assert_eq!(response.text().unwrap(), "ok");
    } else {
        let error = result.unwrap_err();
        if retry_fails {
            assert!(!error.is_retryable());
            let lkrequest::error::Error::TrustAnchorRecovery { info, .. } = error else {
                panic!("expected typed recovery failure")
            };
            assert!(!info.recovered);
            assert!(info.previous_attempt.unwrap().recovery_eligible);
        }
    }
    server.await.unwrap();
}

#[tokio::test]
async fn tai_recovers_unknown_issuer_once_before_post() {
    assert!(
        tokio::time::timeout(Duration::from_secs(15), run_recovery(true, false, false))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn tai_recovery_is_opt_in() {
    assert!(
        tokio::time::timeout(Duration::from_secs(15), run_recovery(false, false, false))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn tai_wrong_hostname_is_terminal() {
    assert!(
        tokio::time::timeout(Duration::from_secs(15), run_recovery(true, true, false))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn tai_failed_recovery_retains_both_attempts_and_stops() {
    assert!(
        tokio::time::timeout(Duration::from_secs(15), run_recovery(true, false, true))
            .await
            .is_ok()
    );
}

#[test]
fn tai_policies_validate_profiles_and_keep_default_fingerprint() {
    use lkrequest::TrustAnchorAdvertisement;
    let profile = lktls::profile::presets::chrome_157();
    let expected = serde_json::to_value(&profile).unwrap();
    let client = Client::builder()
        .fingerprint(profile.clone())
        .try_build()
        .unwrap();
    assert_eq!(
        serde_json::to_value(client.tls_profile()).unwrap(),
        expected
    );
    let once = TrustAnchorPolicy {
        recovery: TrustAnchorRecovery::Once,
        ..Default::default()
    };
    assert!(Client::builder()
        .fingerprint(profile.clone())
        .verify(false)
        .trust_anchor_policy(once)
        .try_build()
        .is_err());
    assert!(Client::builder()
        .fingerprint(profile.clone())
        .proxy_fallback_direct(true)
        .trust_anchor_policy(once)
        .try_build()
        .is_err());
    let mut missing = profile.clone();
    missing
        .extensions
        .retain(|extension| extension.extension_type != 0xca34);
    assert!(Client::builder()
        .fingerprint(profile.clone())
        .quic_fingerprint(missing)
        .trust_anchor_policy(once)
        .try_build()
        .is_err());
    let client = Client::builder()
        .fingerprint(profile)
        .trust_anchor_policy(TrustAnchorPolicy {
            advertisement: TrustAnchorAdvertisement::Trusted,
            ..Default::default()
        })
        .try_build()
        .unwrap();
    let source = &client
        .tls_profile()
        .extensions
        .iter()
        .find(|extension| extension.extension_type == 0xca34)
        .unwrap()
        .source;
    let lktls::profile::types::ExtensionSource::TrustAnchorIds { ids, shuffle } = source else {
        panic!("expected bound IDs")
    };
    assert!(!shuffle && !ids.is_empty() && ids.len() <= 13);
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]));
}

#[cfg(feature = "synthetic-fp")]
#[test]
fn tai_rejects_tls_synthesis_but_allows_h2_synthesis() {
    use lkrequest::randomize::{Layers, Randomize};
    let policy = TrustAnchorPolicy {
        recovery: TrustAnchorRecovery::Once,
        ..Default::default()
    };
    assert!(Client::builder()
        .fingerprint(lktls::profile::presets::chrome_157())
        .trust_anchor_policy(policy)
        .randomize(Randomize::recombine())
        .try_build()
        .is_err());
    assert!(Client::builder()
        .fingerprint(lktls::profile::presets::chrome_157())
        .trust_anchor_policy(policy)
        .randomize(Randomize::recombine_layers(Layers::H2))
        .try_build()
        .is_ok());
}
