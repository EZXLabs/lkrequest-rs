use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

struct PooledH2 {
    request: StreamRequestBuilder,
    root: Option<super::super::execution::ExecutionGuard>,
    owner: Option<RecoveryOwner>,
    received: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
}

impl PooledH2 {
    async fn new(gate: pipeline::RaceSendGate) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let received = Arc::new(AtomicUsize::new(0));
        let seen = received.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut connection = ::h2::server::handshake(stream).await.unwrap();
            while let Some(request) = connection.accept().await {
                let (request, mut respond) = request.unwrap();
                assert_eq!(request.method(), http::Method::POST);
                seen.fetch_add(1, Ordering::SeqCst);
                respond
                    .send_response(http::Response::new(()), true)
                    .unwrap();
            }
        });
        let session = crate::Client::builder()
            .build()
            .session()
            .http2_only()
            .build();
        tokio::time::timeout(Duration::from_secs(3), session.preconnect(&url))
            .await
            .unwrap()
            .unwrap();
        let (execution, root) = super::super::execution::RequestExecution::new(
            crate::timeout::RequestTimeout::new(None),
        );
        let (attempt, owner) = execution.start_http().unwrap();
        Self {
            request: StreamRequestBuilder {
                session,
                execution,
                attempt,
                method: http::Method::POST,
                url,
                headers: HeaderMap::new(),
                body: None,
                extra_cookies: vec![],
                cookie_overrides: vec![],
                proxy_override: None,
                version_override: Some(PreferredHttpVersion::Http2Only),
                protocol_policy_override: None,
                no_decompress: false,
                header_order: None,
                h3_header_order: None,
                cookie_order: None,
                header_insertion_order: vec![],
                priority: None,
                h2_priority_weight: None,
                idempotency: super::super::Idempotency::NotIdempotent,
                race_send_gates: vec![gate],
            },
            root: Some(root),
            owner: Some(owner),
            received,
            server,
        }
    }

    async fn send_tcp(&self) -> Result<StreamingResponse> {
        let target = pipeline::parse_request_target(&self.request.url, None).unwrap();
        let policy = self.request.effective_protocol_policy();
        // Exercise the Ready branch used when another request has pooled H2.
        self.request
            .establish_and_send_streaming_tcp(
                &target,
                None,
                &policy,
                PreferredHttpVersion::Http2Only,
                Instant::now(),
            )
            .await
    }
}

impl Drop for PooledH2 {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[tokio::test]
async fn pooled_streaming_h2_loser_does_not_submit_post() {
    let (quic_gate, tcp_gate, _) = pipeline::RaceSendGate::pair();
    quic_gate.acquired().await;
    let fixture = PooledH2::new(tcp_gate).await;
    let outcome = tokio::time::timeout(Duration::from_millis(300), fixture.send_tcp()).await;
    let received = fixture.received.load(Ordering::SeqCst);
    eprintln!(
        "selected=quic tcp_completed={} server_post_count={received}",
        outcome.is_ok()
    );
    assert!(outcome.is_err(), "the TCP loser must wait at its send gate");
    assert_eq!(received, 0, "the losing branch must not enqueue a POST");
    assert_eq!(fixture.request.execution.snapshot(), (0, 0));
}

#[tokio::test]
async fn pooled_streaming_h2_loser_preserves_upload() {
    let (quic_gate, tcp_gate, _) = pipeline::RaceSendGate::pair();
    quic_gate.acquired().await;
    let mut fixture = PooledH2::new(tcp_gate).await;
    let body = crate::body::RequestBody::reader(tokio::io::empty(), Some(0));
    fixture.request.body = Some(body.clone());
    let outcome = tokio::time::timeout(Duration::from_millis(300), fixture.send_tcp()).await;
    assert!(outcome.is_err(), "the TCP loser must wait at its send gate");
    assert!(
        body.can_replay(),
        "the loser must not claim the upload source"
    );
    assert_eq!(fixture.received.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.request.execution.snapshot(), (0, 0));
    assert!(
        fixture.request.attempt.take().is_ok(),
        "the losing branch must leave the shared permit unclaimed"
    );
}

#[tokio::test]
async fn pooled_streaming_h2_winner_submits_upload_once() {
    let (_quic_gate, tcp_gate, selected) = pipeline::RaceSendGate::pair();
    let mut fixture = PooledH2::new(tcp_gate).await;
    let body = crate::body::RequestBody::reader(tokio::io::empty(), Some(0));
    fixture.request.body = Some(body.clone());
    let response = tokio::time::timeout(Duration::from_secs(3), fixture.send_tcp())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(*selected.borrow(), Some(pipeline::ProtocolDecision::Tcp));
    assert!(
        !body.can_replay(),
        "the winner must claim the upload source"
    );
    assert_eq!(fixture.received.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.request.execution.snapshot(), (1, 0));
}

#[tokio::test]
async fn stopped_streaming_root_preserves_retained_upload() {
    let (_quic_gate, tcp_gate, _) = pipeline::RaceSendGate::pair();
    let mut fixture = PooledH2::new(tcp_gate).await;
    let body = crate::body::RequestBody::reader(tokio::io::empty(), Some(0));
    fixture.request.body = Some(body.clone());
    let retained = fixture.request.clone();
    drop(fixture.root.take());

    let error = tokio::time::timeout(
        Duration::from_secs(3),
        retained.send_streaming_inner(fixture.owner.take().unwrap()),
    )
    .await
    .unwrap()
    .expect_err("a retained builder must not outlive the root authority");
    assert!(error.to_string().contains("no longer active"));
    assert!(body.can_replay(), "stopped requests must not claim uploads");
    assert_eq!(fixture.received.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.request.execution.snapshot(), (0, 0));
}

#[tokio::test]
async fn stopping_streaming_root_cancels_pending_race_gate() {
    let (quic_gate, tcp_gate, _) = pipeline::RaceSendGate::pair();
    quic_gate.acquired().await;
    let mut fixture = PooledH2::new(tcp_gate).await;
    let body = crate::body::RequestBody::reader(tokio::io::empty(), Some(0));
    fixture.request.body = Some(body.clone());
    let mut pending = fixture
        .request
        .clone()
        .send_streaming_inner(fixture.owner.take().unwrap());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut pending)
            .await
            .is_err(),
        "the TCP loser must be waiting at the race gate"
    );
    drop(fixture.root.take());

    let error = tokio::time::timeout(Duration::from_secs(3), pending)
        .await
        .unwrap()
        .expect_err("root cancellation must wake a retained branch");
    assert!(error.to_string().contains("no longer active"));
    assert!(body.can_replay());
    assert_eq!(fixture.received.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.request.execution.snapshot(), (0, 0));
}

#[tokio::test]
async fn published_streaming_root_rejects_retained_builder_but_keeps_response_readable() {
    let (_quic_gate, tcp_gate, _) = pipeline::RaceSendGate::pair();
    let mut fixture = PooledH2::new(tcp_gate).await;
    let mut response = tokio::time::timeout(Duration::from_secs(3), fixture.send_tcp())
        .await
        .unwrap()
        .unwrap();
    fixture.root.take().unwrap().publish().unwrap();
    let body = crate::body::RequestBody::reader(tokio::io::empty(), Some(0));
    fixture.request.body = Some(body.clone());

    let error = fixture
        .request
        .clone()
        .send_streaming_inner(fixture.owner.take().unwrap())
        .await
        .expect_err("publishing headers must end new submission authority");
    assert!(error.to_string().contains("no longer active"));
    assert!(body.can_replay());
    assert_eq!(fixture.received.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.request.execution.snapshot(), (1, 0));
    assert!(response.chunk().await.unwrap().is_none());
}

#[tokio::test]
async fn committed_streaming_attempt_cannot_claim_another_upload() {
    let (_quic_gate, tcp_gate, _) = pipeline::RaceSendGate::pair();
    let mut fixture = PooledH2::new(tcp_gate).await;
    let response = fixture.send_tcp().await.unwrap();
    let body = crate::body::RequestBody::reader(tokio::io::empty(), Some(0));
    fixture.request.body = Some(body.clone());

    fixture
        .send_tcp()
        .await
        .expect_err("a committed attempt must not submit again");
    assert!(body.can_replay(), "permit denial must precede body claim");
    assert_eq!(fixture.received.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.request.execution.snapshot(), (1, 0));
    drop(response);
}

#[tokio::test]
async fn stale_streaming_attempt_cannot_claim_recovery_upload() {
    let (_quic_gate, tcp_gate, _) = pipeline::RaceSendGate::pair();
    let mut fixture = PooledH2::new(tcp_gate).await;
    fixture.request.idempotency = super::super::Idempotency::Idempotent;
    let response = fixture.send_tcp().await.unwrap();
    let mut stale = fixture.request.clone();
    let closed = Error::ConnectionClosed {
        phase: ConnectionPhase::HttpRequest,
        kind: crate::error::ConnectionClosedKind::Generic,
        message: "failed submitted attempt".into(),
    };
    let successor = recovery::connection_retry(
        true,
        true,
        ReplayFacts::new(
            &fixture.request.method,
            fixture.request.idempotency,
            fixture.request.body.as_ref(),
        ),
        &closed,
        &fixture.request.attempt,
    )
    .expect("replay-safe recovery should issue a successor");
    fixture.request.attempt = successor;
    let body = crate::body::RequestBody::reader(tokio::io::empty(), Some(0));
    stale.body = Some(body.clone());
    fixture.request.body = Some(body.clone());

    stale
        .send_streaming_with_pool_retry(false)
        .await
        .expect_err("the old generation must not take a successor permit");
    assert!(body.can_replay());
    assert_eq!(fixture.received.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.request.execution.snapshot(), (1, 1));

    fixture.send_tcp().await.unwrap();
    assert!(!body.can_replay());
    assert_eq!(fixture.received.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.request.execution.snapshot(), (2, 1));
    drop(response);
}

#[tokio::test]
async fn outer_streaming_race_loser_cannot_enter_inner_race_or_claim_permit() {
    let (outer_quic, outer_tcp, _) = pipeline::RaceSendGate::pair();
    outer_tcp.acquired().await;
    let (_, inner_tcp, inner_selected) = pipeline::RaceSendGate::pair();
    let mut fixture = PooledH2::new(outer_quic).await;
    fixture.request.race_send_gates.push(inner_tcp);
    let body = crate::body::RequestBody::reader(tokio::io::empty(), Some(0));
    fixture.request.body = Some(body.clone());

    assert!(
        tokio::time::timeout(Duration::from_millis(100), fixture.send_tcp())
            .await
            .is_err(),
        "the outer loser must stop before the inner gate"
    );
    assert!(inner_selected.borrow().is_none());
    assert!(body.can_replay());
    assert_eq!(fixture.received.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.request.execution.snapshot(), (0, 0));
    assert!(fixture.request.attempt.take().is_ok());
}
