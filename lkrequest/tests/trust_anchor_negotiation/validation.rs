use super::*;
use peer::{flight, Flight};

fn options() -> Flight {
    Flight {
        available: Some(vec![TrustAnchorId::from_hex("81fd5901").unwrap()]),
        ..Default::default()
    }
}

fn certificate(params: rcgen::CertificateParams) -> rcgen::CertifiedKey<rcgen::KeyPair> {
    let signing_key = rcgen::KeyPair::generate().unwrap();
    rcgen::CertifiedKey {
        cert: params.self_signed(&signing_key).unwrap(),
        signing_key,
    }
}

async fn fail_handshake(
    cert: rcgen::CertifiedKey<rcgen::KeyPair>,
    options: Flight,
    trust_certificate: bool,
    ech: bool,
) -> (lkrequest::error::Error, lkrequest::TrustAnchorInfo) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let der = cert.cert.der().to_vec();
    let server = tokio::task::spawn_blocking(move || {
        let mut socket = accept_bounded(&listener);
        let hello = read_hello(&mut socket);
        socket.write_all(&flight(&hello, &cert, &options)).unwrap();
        drop(socket);
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_millis(150);
        while std::time::Instant::now() < deadline {
            assert!(
                listener.accept().is_err(),
                "terminal TAI failure reconnected"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let mut profile = lktls::profile::presets::chrome_157();
    profile.alpn_protocols = vec!["http/1.1".into()];
    profile.key_share_curves = vec![29];
    profile.alps_protocols = None;
    let mut builder = Client::builder()
        .fingerprint(profile)
        .dns_resolver(Arc::new(LocalDns))
        .trust_anchor_policy(TrustAnchorPolicy {
            recovery: TrustAnchorRecovery::Once,
            ..Default::default()
        });
    if trust_certificate {
        builder = builder.add_ca_cert_der(&der);
    }
    if ech {
        builder = builder.ech_config(ech_config("localhost"));
    }
    let session = builder.try_build().unwrap().session().http1_only().build();
    let (result, diagnostics) = lkrequest::diagnostics::capture_request_diagnostics(
        session.get(&format!("https://localhost:{port}/")).send(),
    )
    .await;
    let error = result.unwrap_err();
    let info = *diagnostics.trust_anchor.unwrap();
    assert!(!info.authenticated && !info.recovered && info.previous_attempt.is_none());
    server.await.unwrap();
    (error, info)
}

pub(super) fn ech_config(public_name: &str) -> Vec<u8> {
    let mut contents = vec![1, 0, 32, 0, 32];
    contents.extend([0x42; 32]);
    contents.extend([0, 4, 0, 1, 0, 1, 64]);
    contents.push(public_name.len() as u8);
    contents.extend(public_name.as_bytes());
    contents.extend([0, 0]);
    let mut config = vec![0xfe, 0x0d];
    config.extend((contents.len() as u16).to_be_bytes());
    config.extend(contents);
    let mut list = (config.len() as u16).to_be_bytes().to_vec();
    list.extend(config);
    list
}

#[tokio::test]
async fn tai_expired_certificate_is_terminal_on_the_wire() {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params.not_before = rcgen::date_time_ymd(2000, 1, 1);
    params.not_after = rcgen::date_time_ymd(2001, 1, 1);
    let (error, info) = fail_handshake(certificate(params), options(), true, false).await;
    assert!(
        error.to_string().to_lowercase().contains("expired"),
        "{error}"
    );
    assert!(!info.recovery_eligible);
}

#[tokio::test]
async fn tai_bad_certificate_verify_is_terminal_on_the_wire() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (error, info) = fail_handshake(
        cert,
        Flight {
            bad_signature: true,
            ..options()
        },
        false,
        false,
    )
    .await;
    assert!(
        error.to_string().to_lowercase().contains("signature"),
        "{error}"
    );
    assert!(!info.recovery_eligible);
}

#[tokio::test]
async fn tai_no_server_extension_does_not_recover() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (error, info) = fail_handshake(cert, Flight::default(), false, false).await;
    assert!(matches!(
        error,
        lkrequest::error::Error::Tls(lktls::error::TlsError::UnknownIssuer(_))
    ));
    assert!(info.available_ids.is_empty() && !info.recovery_eligible);
}

#[tokio::test]
async fn tai_no_usable_overlap_does_not_recover() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (_, info) = fail_handshake(cert, options(), false, false).await;
    assert!(info.recovery_eligible);
    assert!(
        lktls::trust_anchor::TrustAnchorCatalog::new(Vec::new(), &[])
            .unwrap()
            .select(&info)
            .is_none()
    );
}

#[tokio::test]
async fn tai_ech_rejection_does_not_use_outer_hints() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (_, info) = fail_handshake(cert, options(), false, true).await;
    assert!(info.ech_rejected && !info.available_ids.is_empty() && !info.recovery_eligible);
}

#[tokio::test]
async fn tai_compressed_certificate_retains_match_flag_and_hints() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (error, info) = fail_handshake(
        cert,
        Flight {
            compressed: true,
            certificate_flag: Some(Vec::new()),
            ..options()
        },
        false,
        false,
    )
    .await;
    assert!(error.to_string().contains("UnknownIssuer"), "{error}");
    assert!(info.matched_request && info.recovery_eligible);
}

#[tokio::test]
async fn tai_malformed_compressed_match_flag_is_terminal() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (error, info) = fail_handshake(
        cert,
        Flight {
            compressed: true,
            certificate_flag: Some(vec![1]),
            ..options()
        },
        false,
        false,
    )
    .await;
    assert!(
        error.to_string().contains("first CertificateEntry"),
        "{error}"
    );
    assert!(!info.recovery_eligible);
}

#[tokio::test]
async fn tai_empty_and_duplicate_server_extensions_are_terminal() {
    for options in [
        Flight {
            available: Some(Vec::new()),
            ..Default::default()
        },
        Flight {
            duplicate_ee: true,
            ..options()
        },
    ] {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let (_, info) = fail_handshake(cert, options, false, false).await;
        assert!(!info.recovery_eligible);
    }
}

#[tokio::test]
async fn tai_peer_alert_classification_uses_real_encrypted_records() {
    for (alert, eligible) in [(40, true), (48, true), (47, false)] {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let (_, info) = fail_handshake(
            cert,
            Flight {
                alert: Some(alert),
                ..options()
            },
            false,
            false,
        )
        .await;
        assert_eq!(info.recovery_eligible, eligible);
    }
}
