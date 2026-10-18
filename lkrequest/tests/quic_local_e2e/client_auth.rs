use super::*;
use bytes::Bytes;
use std::time::Duration;

#[derive(Debug)]
enum PeerObservation {
    Accepted {
        peer_identity_empty: bool,
        method: http::Method,
        path: String,
    },
    Rejected(quinn::ConnectionError),
}

struct ClientAuthPeer {
    endpoint: Endpoint,
    task: tokio::task::JoinHandle<PeerObservation>,
}

impl Drop for ClientAuthPeer {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"test complete");
        self.task.abort();
    }
}

struct ClientAuthOutcome {
    response: lkrequest::error::Result<lkrequest::Response>,
    peer: PeerObservation,
}

async fn client_auth_case(allow_unauthenticated: bool) -> ClientAuthOutcome {
    ensure_rustls_provider();
    let server_cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server_der = server_cert.cert.der().to_vec();
    let client_ca_key = rcgen::KeyPair::generate().unwrap();
    let mut client_ca_params = rcgen::CertificateParams::default();
    client_ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let client_ca = client_ca_params.self_signed(&client_ca_key).unwrap();
    let mut client_roots = rustls::RootCertStore::empty();
    client_roots.add(client_ca.der().clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots));
    let verifier = if allow_unauthenticated {
        verifier.allow_unauthenticated().build().unwrap()
    } else {
        verifier.build().unwrap()
    };
    assert!(verifier.offer_client_auth());
    assert_eq!(verifier.client_auth_mandatory(), !allow_unauthenticated);
    let mut tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                server_cert.signing_key.serialize_der(),
            )),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let endpoint = Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap())),
        localhost_addr(0),
    )
    .unwrap();
    let port = endpoint.local_addr().unwrap().port();
    let (finish_tx, finish_rx) = oneshot::channel();
    let task = tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            let connection = match endpoint.accept().await.unwrap().await {
                Ok(connection) => connection,
                Err(error) => return PeerObservation::Rejected(error),
            };
            let peer_identity_empty = connection.peer_identity().is_none();
            let mut h3 = server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                .await
                .unwrap();
            let (request, mut stream) = h3
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            let observation = PeerObservation::Accepted {
                peer_identity_empty,
                method: request.method().clone(),
                path: request.uri().path().to_string(),
            };
            let response = http::Response::builder()
                .status(StatusCode::OK)
                .body(())
                .unwrap();
            stream.send_response(response).await.unwrap();
            stream
                .send_data(Bytes::from_static(b"anonymous-client-auth-ok"))
                .await
                .unwrap();
            stream.finish().await.unwrap();
            let _ = finish_rx.await;
            observation
        }
    });
    let mut peer = ClientAuthPeer { endpoint, task };
    let session = lkrequest::Client::builder()
        .preset(lkrequest::preset::chrome_155())
        .add_ca_cert_der(&server_der)
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .retry_on_connection_close(false)
        .build()
        .session()
        .http3_only()
        .build();
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        session
            .get(&format!("https://localhost:{port}/client-auth"))
            .send(),
    )
    .await
    .expect("client-auth request deadline");
    let _ = finish_tx.send(());
    let observation = tokio::time::timeout(Duration::from_secs(5), &mut peer.task)
        .await
        .expect("client-auth server deadline")
        .unwrap();
    ClientAuthOutcome {
        response,
        peer: observation,
    }
}

#[tokio::test]
async fn h3_client_auth_optional_accepts_empty_certificate_and_completes_response() {
    let outcome = client_auth_case(true).await;
    let response = outcome.response.expect("optional client-auth response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), lkrequest::HttpVersion::H3);
    assert_eq!(response.bytes(), b"anonymous-client-auth-ok");
    let PeerObservation::Accepted {
        peer_identity_empty,
        method,
        path,
    } = outcome.peer
    else {
        panic!("optional client authentication must finish on the server");
    };
    assert!(
        peer_identity_empty,
        "anonymous peer must have no certificate identity"
    );
    assert_eq!(method, http::Method::GET);
    assert_eq!(path, "/client-auth");
}

#[tokio::test]
async fn h3_client_auth_required_rejects_empty_certificate() {
    let outcome = client_auth_case(false).await;
    assert!(
        outcome.response.is_err(),
        "required client authentication must reject an anonymous client"
    );
    let PeerObservation::Rejected(quinn::ConnectionError::TransportError(error)) = outcome.peer
    else {
        panic!("server must reject the TLS handshake with a transport crypto error");
    };
    assert_eq!(
        u64::from(error.code),
        0x100 + u64::from(u8::from(rustls::AlertDescription::CertificateRequired)),
        "required client authentication must fail for the missing certificate"
    );
}
