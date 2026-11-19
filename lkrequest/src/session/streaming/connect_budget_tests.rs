use super::super::execution::{ExecutionGuard, RequestExecution};
use super::*;
use std::time::{Duration, Instant};

struct WaitingRequest {
    request: StreamRequestBuilder,
    root: Option<ExecutionGuard>,
    _owner: RecoveryOwner,
}

impl WaitingRequest {
    fn new(session: Session, url: String) -> Self {
        Self::with_connect_limit(session, url, 0)
    }

    fn with_connect_limit(session: Session, url: String, limit: u64) -> Self {
        let limits = crate::AttemptLimits::default()
            .with_connect_attempts(limit)
            .resolve(None, crate::AttemptLimitScope::Request)
            .unwrap();
        let (execution, root) =
            RequestExecution::with_limits(crate::timeout::RequestTimeout::default(), Some(limits));
        let (attempt, owner) = execution.start_http().unwrap();
        Self {
            request: StreamRequestBuilder {
                session,
                execution,
                attempt,
                method: http::Method::POST,
                url,
                headers: HeaderMap::new(),
                body: Some(crate::body::RequestBody::reader(
                    tokio::io::empty(),
                    Some(0),
                )),
                extra_cookies: vec![],
                cookie_overrides: vec![],
                proxy_override: None,
                version_override: Some(PreferredHttpVersion::Http3Only),
                protocol_policy_override: None,
                no_decompress: false,
                header_order: None,
                h3_header_order: None,
                cookie_order: None,
                header_insertion_order: vec![],
                priority: None,
                h2_priority_weight: None,
                idempotency: super::super::Idempotency::NotIdempotent,
                race_send_gates: vec![],
            },
            root: Some(root),
            _owner: owner,
        }
    }

    async fn send(&self) -> Result<StreamingResponse> {
        let target = pipeline::parse_request_target(&self.request.url, None).unwrap();
        let discovery = pipeline::QuicDiscovery {
            route: target.conn_key.route.clone(),
            origin: crate::Origin::https(&target.host, target.port),
            learned_state: crate::alt_svc::LearnedProtocolState {
                alt_svc: None,
                h3_status: crate::alt_svc::H3Reachability::Unknown,
                last_validated_at: None,
            },
            source: None,
            force_attempt: true,
            advertised_host: None,
            advertised_port: None,
            dns_https: None,
            skip_reason: None,
        };
        let policy = self.request.effective_protocol_policy();
        self.request
            .execution
            .run(self.request.establish_and_send_streaming_quic(
                &target,
                &discovery,
                None,
                None,
                &policy,
                PreferredHttpVersion::Http3Only,
                Instant::now(),
            ))
            .await
    }

    fn assert_unsubmitted(&self) {
        let summary = self.request.execution.snapshot_summary();
        assert_eq!(summary.connect_initiations(), 0);
        assert_eq!(summary.http_submissions(), 0);
        assert!(self.request.body.as_ref().unwrap().can_replay());
    }
}

fn session() -> Session {
    crate::Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .quic_profile(lkh3::chrome_quic())
        .build()
        .session()
        .http3_only()
        .build()
}

#[tokio::test]
async fn zero_connect_streaming_waiter_defers_denial_until_leader_finishes() {
    let fixture = WaitingRequest::new(session(), "https://127.0.0.1/".into());
    let target = pipeline::parse_request_target(&fixture.request.url, None).unwrap();
    let leader = fixture
        .request
        .session
        .inner
        .acquisition
        .quic
        .try_start(&target.conn_key)
        .ok()
        .unwrap();
    let mut waiter = Box::pin(fixture.send());
    assert!(futures_util::poll!(&mut waiter).is_pending());
    fixture.assert_unsubmitted();
    drop(leader);
    let error = tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .unwrap()
        .unwrap_err();
    assert!(error.is_connect_attempt_denied());
    assert!(!fixture
        .request
        .session
        .broken_quic_tracker()
        .is_broken_for_route(
            &target.conn_key.route,
            &crate::Origin::https(&target.host, target.port),
        ));
    fixture.assert_unsubmitted();
}

#[tokio::test]
async fn cancelled_streaming_waiter_does_not_start_or_consume_upload() {
    let mut fixture = WaitingRequest::new(session(), "https://127.0.0.1/".into());
    let root = fixture.root.take().unwrap();
    let target = pipeline::parse_request_target(&fixture.request.url, None).unwrap();
    let _leader = fixture
        .request
        .session
        .inner
        .acquisition
        .quic
        .try_start(&target.conn_key)
        .ok()
        .unwrap();
    let mut waiter = Box::pin(fixture.send());
    assert!(futures_util::poll!(&mut waiter).is_pending());
    drop(root);
    let error = tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("no longer active"));
    fixture.assert_unsubmitted();
}

struct LocalH3 {
    session: Session,
    url: String,
    incoming: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for LocalH3 {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl LocalH3 {
    fn new() -> Self {
        use quinn::crypto::rustls::QuicServerConfig;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let certificate = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let certificate_der = CertificateDer::from(certificate.cert.der().to_vec());
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
            certificate.signing_key.serialize_der(),
        ));
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate_der.clone()], key)
        .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let url = format!("https://{}/", endpoint.local_addr().unwrap());
        let incoming = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let received = incoming.clone();
        let allowed = release.clone();
        let server = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap();
            received.notify_one();
            allowed.notified().await;
            let connection = connection.await.unwrap();
            let mut server = h3::server::Connection::<_, bytes::Bytes>::new(
                h3_quinn::Connection::new(connection),
            )
            .await
            .unwrap();
            let mut requests = tokio::task::JoinSet::new();
            while let Ok(Some(resolver)) = server.accept().await {
                requests.spawn(async move {
                    let (request, mut stream) = resolver.resolve_request().await.unwrap();
                    assert_eq!(request.method(), http::Method::POST);
                    while stream.recv_data().await.unwrap().is_some() {}
                    stream.send_response(http::Response::new(())).await.unwrap();
                    stream.finish().await.unwrap();
                });
            }
        });
        let session = crate::Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .quic_profile(lkh3::chrome_quic())
            .add_ca_cert_der(certificate_der.as_ref())
            .build()
            .session()
            .http3_only()
            .attempt_limits(crate::AttemptLimits::default().with_connect_attempts(1))
            .build();
        Self {
            session,
            url,
            incoming,
            release,
            server,
        }
    }
}

#[tokio::test]
async fn zero_connect_streaming_waiter_reuses_published_h3_connection() {
    let server = LocalH3::new();
    let mut leader = Box::pin(server.session.preconnect(&server.url));
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::select! {
            result = &mut leader => panic!("leader completed before server handshake: {result:?}"),
            _ = server.incoming.notified() => {},
        }
    })
    .await
    .unwrap();

    let fixture = WaitingRequest::new(server.session.clone(), server.url.clone());
    let mut waiter = Box::pin(fixture.send());
    assert!(futures_util::poll!(&mut waiter).is_pending());
    fixture.assert_unsubmitted();
    server.release.notify_one();
    let (connected, response) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(leader, waiter)
    })
    .await
    .unwrap();
    connected.unwrap();
    let response = response.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let summary = fixture.request.execution.snapshot_summary();
    assert_eq!(summary.connect_initiations(), 0);
    assert_eq!(summary.http_submissions(), 1);
    assert!(!fixture.request.body.as_ref().unwrap().can_replay());
}

#[tokio::test]
async fn finite_connect_streaming_leader_publishes_for_zero_connect_waiter() {
    let server = LocalH3::new();
    let leader_request =
        WaitingRequest::with_connect_limit(server.session.clone(), server.url.clone(), 1);
    let mut leader = Box::pin(leader_request.send());
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::select! {
            result = &mut leader => panic!("leader completed before server handshake: {result:?}"),
            _ = server.incoming.notified() => {},
        }
    })
    .await
    .unwrap();

    let follower = WaitingRequest::new(server.session.clone(), server.url.clone());
    let mut waiter = Box::pin(follower.send());
    assert!(futures_util::poll!(&mut waiter).is_pending());
    follower.assert_unsubmitted();
    server.release.notify_one();
    let (first, second) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(leader, waiter)
    })
    .await
    .unwrap();
    assert_eq!(first.unwrap().status(), http::StatusCode::OK);
    assert_eq!(second.unwrap().status(), http::StatusCode::OK);
    let leader_summary = leader_request.request.execution.snapshot_summary();
    assert_eq!(leader_summary.connect_initiations(), 1);
    assert_eq!(leader_summary.http_submissions(), 1);
    let follower_summary = follower.request.execution.snapshot_summary();
    assert_eq!(follower_summary.connect_initiations(), 0);
    assert_eq!(follower_summary.http_submissions(), 1);
}
