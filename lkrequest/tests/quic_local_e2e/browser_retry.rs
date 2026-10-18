use super::*;
use bytes::{Buf, Bytes};
use lkrequest::retry::{H3RetryMode, RetryPolicy};
use std::{
    collections::HashSet,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::task::JoinSet;

const BODY_SIZE: usize = 1024 * 1024;
const LIMIT: Duration = Duration::from_secs(5);
type RequestStream = server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stimulus {
    StopReset,
    StopClose,
    NoHeadersClose,
    DataAfterTrailers,
    Complete,
}

#[derive(Clone, Debug)]
struct Attempt {
    connection: usize,
    stream: u64,
    method: http::Method,
    received: usize,
    prefix: Vec<u8>,
    fin: bool,
}

struct Ready {
    release: oneshot::Sender<()>,
}

struct Peer {
    endpoint: Endpoint,
    certificate: Vec<u8>,
    attempts: Arc<Mutex<Vec<Attempt>>>,
    ready: mpsc::UnboundedReceiver<Ready>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"retry fixture complete");
        self.task.abort();
    }
}

impl Peer {
    fn new(stimulus: Stimulus) -> Self {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = cert.cert.der().to_vec();
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())),
        )
        .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.send_tls13_tickets = 0;
        let mut config =
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
        let mut transport = quinn::TransportConfig::default();
        transport
            .stream_receive_window(65_536u32.into())
            .receive_window(262_144u32.into());
        config.transport_config(Arc::new(transport));
        let endpoint = Endpoint::server(config, localhost_addr(0)).unwrap();
        let attempts = Arc::new(Mutex::new(Vec::new()));
        let (ready_tx, ready) = mpsc::unbounded_channel();
        let task = tokio::spawn({
            let endpoint = endpoint.clone();
            let attempts = attempts.clone();
            async move {
                let mut connections = JoinSet::new();
                let mut next_connection = 0;
                loop {
                    tokio::select! {
                        incoming = endpoint.accept() => {
                            let Some(incoming) = incoming else { break; };
                            let connection_id = next_connection;
                            next_connection += 1;
                            let attempts = attempts.clone();
                            let ready_tx = ready_tx.clone();
                            connections.spawn(async move {
                                let connection = incoming.await.unwrap();
                                let mut h3 = server::Connection::<_, Bytes>::new(
                                    h3_quinn::Connection::new(connection.clone()),
                                ).await.unwrap();
                                let mut requests = JoinSet::new();
                                loop {
                                    tokio::select! {
                                        request = h3.accept() => {
                                            let Ok(Some(resolver)) = request else { break; };
                                            let connection = connection.clone();
                                            let attempts = attempts.clone();
                                            let ready_tx = ready_tx.clone();
                                            requests.spawn(async move {
                                                let (request, stream) = resolver.resolve_request().await.unwrap();
                                                serve(request, stream, connection, connection_id,
                                                    stimulus, attempts, ready_tx).await;
                                            });
                                        }
                                        result = requests.join_next(), if !requests.is_empty() => {
                                            result.unwrap().expect("request fixture must not panic");
                                        }
                                    }
                                }
                            });
                        }
                        result = connections.join_next(), if !connections.is_empty() => {
                            result.unwrap().expect("connection fixture must not panic");
                        }
                    }
                }
            }
        });
        Self {
            endpoint,
            certificate,
            attempts,
            ready,
            task,
        }
    }
}

async fn serve(
    request: http::Request<()>,
    mut stream: RequestStream,
    connection: quinn::Connection,
    connection_id: usize,
    stimulus: Stimulus,
    attempts: Arc<Mutex<Vec<Attempt>>>,
    ready: mpsc::UnboundedSender<Ready>,
) {
    let warm = request.uri().path() == "/warm";
    assert!(warm || request.uri().path() == "/case");
    let drain = warm
        || matches!(stimulus, Stimulus::Complete | Stimulus::DataAfterTrailers)
        || request.method() == http::Method::GET;
    let mut attempt = Attempt {
        connection: connection_id,
        stream: stream.id().into_inner(),
        method: request.method().clone(),
        received: 0,
        prefix: Vec::new(),
        fin: false,
    };
    loop {
        match stream.recv_data().await.unwrap() {
            Some(mut data) => {
                attempt.received += data.remaining();
                let take = (16 - attempt.prefix.len()).min(data.remaining());
                attempt.prefix.extend_from_slice(&data.copy_to_bytes(take));
            }
            None => {
                attempt.fin = true;
                break;
            }
        }
        if !drain && attempt.prefix.len() == 16 {
            break;
        }
    }
    if warm {
        stream.send_response(http::Response::new(())).await.unwrap();
        stream.send_data(Bytes::from_static(b"warm")).await.unwrap();
        stream.finish().await.unwrap();
        return;
    }
    attempts.lock().unwrap().push(attempt);
    if matches!(stimulus, Stimulus::StopReset | Stimulus::StopClose) {
        stream
            .send_response(http::Response::builder().status(413).body(()).unwrap())
            .await
            .unwrap();
        stream
            .send_data(Bytes::from_static(b"rejected"))
            .await
            .unwrap();
        if stimulus == Stimulus::StopClose {
            stream.finish().await.unwrap();
        }
        let before = connection.stats().frame_rx.reset_stream;
        stream.stop_sending(h3::error::Code::H3_NO_ERROR);
        tokio::time::timeout(LIMIT, async {
            while connection.stats().frame_rx.reset_stream == before {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the actual STOP must reach the client's unfinished upload");
    }
    let (release, released) = oneshot::channel();
    if ready.send(Ready { release }).is_err() || released.await.is_err() {
        return;
    }
    match stimulus {
        Stimulus::StopReset => stream.stop_stream(h3::error::Code::H3_INTERNAL_ERROR),
        Stimulus::StopClose | Stimulus::NoHeadersClose => {
            connection.close(258u32.into(), b"retry fixture peer close");
        }
        Stimulus::DataAfterTrailers => {
            stream.send_response(http::Response::new(())).await.unwrap();
            stream.send_data(Bytes::from_static(b"body")).await.unwrap();
            stream.send_trailers(http::HeaderMap::new()).await.unwrap();
            // Real framing failure after valid response headers, without a reset
            // that could discard unread headers in the QUIC receive buffer.
            stream
                .send_data(Bytes::from_static(b"after trailers"))
                .await
                .unwrap();
            let _ = stream.finish().await;
        }
        Stimulus::Complete => {
            stream.send_response(http::Response::new(())).await.unwrap();
            stream
                .send_data(Bytes::from_static(b"complete"))
                .await
                .unwrap();
            stream.finish().await.unwrap();
        }
    }
}

#[derive(Debug)]
struct GenerousPolicy;
impl RetryPolicy for GenerousPolicy {
    fn should_retry(
        &self,
        attempt: u32,
        error: Option<&lkrequest::error::Error>,
        _status: Option<StatusCode>,
    ) -> Option<Duration> {
        (error.is_some() && attempt <= 8).then_some(Duration::ZERO)
    }
}

#[derive(Default)]
struct ProducerState {
    polls: AtomicUsize,
    dropped: AtomicBool,
}
struct OneShot {
    remaining: usize,
    state: Arc<ProducerState>,
}
impl futures_core::Stream for OneShot {
    type Item = io::Result<Bytes>;
    fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.state.polls.fetch_add(1, Ordering::SeqCst);
        let len = self.remaining.min(16 * 1024);
        self.remaining -= len;
        Poll::Ready((len != 0).then(|| Ok(Bytes::from(vec![b'x'; len]))))
    }
}
impl Drop for OneShot {
    fn drop(&mut self) {
        self.state.dropped.store(true, Ordering::SeqCst);
    }
}

struct Case {
    stimulus: Stimulus,
    method: http::Method,
    opt_in: bool,
    streaming_response: bool,
    one_shot: bool,
    forbid_replay: bool,
    outer_policy: bool,
    max_connections: Option<usize>,
}
impl Case {
    fn post(stimulus: Stimulus, opt_in: bool, streaming_response: bool) -> Self {
        Self {
            stimulus,
            method: http::Method::POST,
            opt_in,
            streaming_response,
            one_shot: false,
            forbid_replay: false,
            outer_policy: false,
            max_connections: None,
        }
    }
}
struct Outcome {
    attempts: Vec<Attempt>,
    result: lkrequest::error::Result<(StatusCode, Vec<u8>)>,
    producer: Arc<ProducerState>,
}

async fn warmed_session(peer: &Peer, case: &Case) -> (lkrequest::Session, String) {
    let mut builder = lkrequest::Client::builder()
        .preset(lkrequest::preset::chrome_155())
        .add_ca_cert_der(&peer.certificate)
        .dns_resolver(Arc::new(LocalIpv4Dns))
        .build()
        .session()
        .http3_only();
    if case.opt_in {
        builder = builder.h3_retry_mode(H3RetryMode::Chrome155ProtocolErrors);
    }
    if case.outer_policy {
        builder = builder.retry_policy(GenerousPolicy);
    }
    if let Some(limit) = case.max_connections {
        builder = builder.max_connections(limit);
    }
    let session = builder.build();
    assert_eq!(
        session.h3_retry_mode(),
        if case.opt_in {
            H3RetryMode::Chrome155ProtocolErrors
        } else {
            H3RetryMode::Safe
        }
    );
    let base = format!(
        "https://localhost:{}",
        peer.endpoint.local_addr().unwrap().port()
    );
    let warm = tokio::time::timeout(LIMIT, session.get(&format!("{base}/warm")).send())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(warm.bytes(), b"warm");
    (session, base)
}

async fn observe_quiet(peer: &mut Peer) {
    // Leave the listener alive after completion so a detached extra retry is
    // observed rather than hidden by fixture teardown.
    let quiet = tokio::time::sleep(Duration::from_millis(150));
    tokio::pin!(quiet);
    loop {
        tokio::select! {
            _ = &mut quiet => break,
            ready = peer.ready.recv() => { if let Some(ready) = ready { let _ = ready.release.send(()); } },
            peer_result = &mut peer.task => panic!("peer exited during retry observation: {peer_result:?}"),
        }
    }
}

async fn shutdown(peer: Peer, session: lkrequest::Session) {
    let endpoint = peer.endpoint.clone();
    drop((peer, session));
    tokio::time::timeout(LIMIT, endpoint.wait_idle())
        .await
        .unwrap();
}

async fn run(case: Case) -> Outcome {
    let mut peer = Peer::new(case.stimulus);
    let (session, base) = warmed_session(&peer, &case).await;
    let mut request = if case.method == http::Method::GET {
        session.get(&format!("{base}/case"))
    } else {
        session.post(&format!("{base}/case"))
    }
    .timeout(LIMIT);
    let producer = Arc::new(ProducerState::default());
    if case.one_shot {
        request = request.body_stream(
            OneShot {
                remaining: BODY_SIZE,
                state: producer.clone(),
            },
            Some(BODY_SIZE as u64),
        );
    } else if case.method == http::Method::POST {
        request = request.body(vec![b'x'; BODY_SIZE]);
    }
    if case.forbid_replay {
        request = request.idempotency(lkrequest::Idempotency::NotIdempotent);
    }
    let streaming = case.streaming_response;
    let mut response = tokio::spawn(async move {
        if streaming {
            let response = request.send_streaming().await?;
            Ok((response.status(), response.bytes().await?.to_vec()))
        } else {
            let response = request.send().await?;
            Ok((response.status(), response.bytes().to_vec()))
        }
    });
    let result = tokio::time::timeout(LIMIT + Duration::from_secs(1), async {
        loop {
            tokio::select! {
                result = &mut response => break result.unwrap(),
                ready = peer.ready.recv() => {
                    let ready = ready.expect("peer must keep its attempt channel alive");
                    assert!(peer.attempts.lock().unwrap().len() <= 12, "retry chain exceeded fixture bound");
                    ready.release.send(()).unwrap();
                }
                peer_result = &mut peer.task => panic!("peer exited unexpectedly: {peer_result:?}"),
            }
        }
    }).await.expect("request must finish within its original deadline");
    observe_quiet(&mut peer).await;
    let attempts = peer.attempts.lock().unwrap().clone();
    assert!(!attempts.is_empty());
    let keys: HashSet<_> = attempts
        .iter()
        .map(|attempt| (attempt.connection, attempt.stream))
        .collect();
    assert_eq!(
        keys.len(),
        attempts.len(),
        "count decoded requests, not repeated frames"
    );
    for attempt in &attempts {
        assert_eq!(attempt.method, case.method);
        if case.method == http::Method::POST {
            assert_eq!(attempt.prefix, b"xxxxxxxxxxxxxxxx");
            assert!(attempt.received > 0);
            if matches!(
                case.stimulus,
                Stimulus::StopReset | Stimulus::StopClose | Stimulus::NoHeadersClose
            ) {
                assert!(attempt.received < BODY_SIZE && !attempt.fin);
            } else {
                assert_eq!(attempt.received, BODY_SIZE);
                assert!(attempt.fin);
            }
        } else {
            assert_eq!(attempt.received, 0);
            assert!(attempt.fin);
        }
    }
    eprintln!(
        "browser retry {:?}, opt_in={}, streaming={streaming}: {attempts:?}; result={result:?}",
        case.stimulus, case.opt_in
    );
    shutdown(peer, session).await;
    Outcome {
        attempts,
        result,
        producer,
    }
}

#[tokio::test]
async fn browser_retry_safe_default_preserves_single_post_attempt() {
    for streaming in [false, true] {
        for stimulus in [Stimulus::StopReset, Stimulus::StopClose] {
            let outcome = run(Case::post(stimulus, false, streaming)).await;
            assert!(outcome.result.is_err());
            assert_eq!(outcome.attempts.len(), 1);
        }
    }
}

#[tokio::test]
async fn browser_retry_opt_in_retries_buffered_post_twice() {
    for streaming in [false, true] {
        for stimulus in [Stimulus::StopReset, Stimulus::StopClose] {
            let outcome = run(Case::post(stimulus, true, streaming)).await;
            assert!(outcome.result.is_err());
            assert_eq!(outcome.attempts.len(), 3, "two compatibility retries");
            let connections: HashSet<_> = outcome.attempts.iter().map(|a| a.connection).collect();
            assert_eq!(
                connections.len(),
                if stimulus == Stimulus::StopClose {
                    3
                } else {
                    1
                }
            );
        }
    }
}

#[tokio::test]
async fn browser_retry_get_budget_is_not_multiplied_by_pool_or_outer_policy() {
    for streaming in [false, true] {
        let mut case = Case::post(Stimulus::NoHeadersClose, true, streaming);
        case.method = http::Method::GET;
        case.outer_policy = true;
        let outcome = run(case).await;
        assert!(outcome.result.is_err());
        assert_eq!(outcome.attempts.len(), 3);
    }
}

#[tokio::test]
async fn browser_retry_not_idempotent_override_forbids_replay() {
    for streaming in [false, true] {
        for method in [http::Method::GET, http::Method::POST] {
            let mut case = Case::post(Stimulus::NoHeadersClose, true, streaming);
            case.method = method;
            case.forbid_replay = true;
            let outcome = run(case).await;
            assert!(outcome.result.is_err());
            assert_eq!(outcome.attempts.len(), 1);
        }
    }
}

#[tokio::test]
async fn browser_retry_one_shot_upload_is_not_replayed_before_response_headers() {
    for streaming in [false, true] {
        let mut case = Case::post(Stimulus::NoHeadersClose, true, streaming);
        case.one_shot = true;
        let outcome = run(case).await;
        assert!(outcome.result.is_err());
        assert_eq!(outcome.attempts.len(), 1);
        assert!(outcome.producer.polls.load(Ordering::SeqCst) > 0);
        assert!(outcome.producer.dropped.load(Ordering::SeqCst));
    }
}

#[tokio::test]
async fn browser_retry_response_body_framing_error_is_not_replayed() {
    for streaming in [false, true] {
        let outcome = run(Case::post(Stimulus::DataAfterTrailers, true, streaming)).await;
        assert!(outcome.result.is_err());
        assert_eq!(outcome.attempts.len(), 1);
    }
}

#[tokio::test]
async fn browser_retry_normal_complete_response_is_unchanged() {
    for streaming in [false, true] {
        let outcome = run(Case::post(Stimulus::Complete, true, streaming)).await;
        assert_eq!(
            outcome.result.unwrap(),
            (StatusCode::OK, b"complete".to_vec())
        );
        assert_eq!(outcome.attempts.len(), 1);
    }
}

#[tokio::test]
async fn browser_retry_body_error_get_is_not_replayed_by_outer_policy() {
    for streaming in [false, true] {
        let mut case = Case::post(Stimulus::DataAfterTrailers, true, streaming);
        case.method = http::Method::GET;
        case.outer_policy = true;
        let outcome = run(case).await;
        assert!(outcome.result.is_err());
        assert_eq!(
            outcome.attempts.len(),
            1,
            "GET replay safety must not override response-body phase"
        );
    }
}

#[tokio::test]
async fn browser_retry_closed_connections_release_a_single_connection_budget() {
    for streaming in [false, true] {
        let mut case = Case::post(Stimulus::StopClose, true, streaming);
        case.max_connections = Some(1);
        let outcome = run(case).await;
        assert!(outcome.result.is_err());
        assert_eq!(outcome.attempts.len(), 3);
        let connections: HashSet<_> = outcome.attempts.iter().map(|a| a.connection).collect();
        assert_eq!(
            connections.len(),
            3,
            "each closed connection must release its permit before replacement"
        );
    }
}

#[derive(Debug)]
struct ControlledOutcome {
    attempts: usize,
    timed_out: bool,
    cancelled: bool,
    elapsed: Duration,
    third_ready_at: Option<Duration>,
}

async fn controlled_termination(streaming: bool, cancel: bool) -> ControlledOutcome {
    const BUDGET: Duration = Duration::from_millis(600);
    let mut peer = Peer::new(Stimulus::NoHeadersClose);
    let mut case = Case::post(Stimulus::NoHeadersClose, true, streaming);
    case.method = http::Method::GET;
    case.outer_policy = true;
    let (session, base) = warmed_session(&peer, &case).await;
    let request = session.get(&format!("{base}/case")).timeout(BUDGET);
    let started = tokio::time::Instant::now();
    let mut response = tokio::spawn(async move {
        if streaming {
            request
                .send_streaming()
                .await
                .map(|response| response.status())
        } else {
            request.send().await.map(|response| response.status())
        }
    });
    let first = tokio::time::timeout(LIMIT, peer.ready.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(peer.attempts.lock().unwrap().len(), 1);
    assert!(
        !response.is_finished(),
        "first peer terminal has not been released"
    );
    let first_ready_at = started.elapsed();
    let (timed_out, cancelled, third_ready_at) =
        if cancel {
            response.abort();
            let error = response
                .await
                .expect_err("caller aborted the request future");
            let _ = first.release.send(());
            (false, error.is_cancelled(), None)
        } else {
            assert!(
                first_ready_at < BUDGET / 2,
                "fixture must reach the first gate before its scheduled release"
            );
            // Spend half the original deadline at a known peer gate. A per-attempt
            // timeout reset would let the third request survive beyond 800 ms.
            tokio::time::sleep_until(started + BUDGET / 2).await;
            first.release.send(()).unwrap();
            let second =
                tokio::time::timeout_at(started + Duration::from_millis(500), peer.ready.recv())
                    .await
                    .expect("second attempt must start within the original budget")
                    .unwrap();
            assert_eq!(peer.attempts.lock().unwrap().len(), 2);
            second.release.send(()).unwrap();
            let third =
                tokio::time::timeout_at(started + Duration::from_millis(500), peer.ready.recv())
                    .await
                    .expect("third attempt must start within the original budget")
                    .unwrap();
            let third_ready_at = started.elapsed();
            assert_eq!(peer.attempts.lock().unwrap().len(), 3);
            let result =
                match tokio::time::timeout_at(started + Duration::from_millis(800), &mut response)
                    .await
                {
                    Ok(result) => result.unwrap(),
                    Err(_) => {
                        response.abort();
                        let _ = response.await;
                        panic!("retries renewed the original request deadline");
                    }
                };
            let error = result.expect_err("the third peer terminal remains gated");
            drop(third);
            (error.is_timeout(), false, Some(third_ready_at))
        };
    let elapsed = started.elapsed();
    observe_quiet(&mut peer).await;
    let attempts = peer.attempts.lock().unwrap().len();
    eprintln!("controlled retry streaming={streaming}, cancel={cancel}, first_ready={first_ready_at:?}, third_ready={third_ready_at:?}, elapsed={elapsed:?}, attempts={attempts}");
    shutdown(peer, session).await;
    ControlledOutcome {
        attempts,
        timed_out,
        cancelled,
        elapsed,
        third_ready_at,
    }
}

#[tokio::test]
async fn browser_retry_total_deadline_is_not_renewed_per_attempt() {
    for streaming in [false, true] {
        let outcome = controlled_termination(streaming, false).await;
        assert!(outcome.timed_out && !outcome.cancelled, "{outcome:?}");
        assert_eq!(outcome.attempts, 3, "{outcome:?}");
        assert!(
            outcome.elapsed >= Duration::from_millis(600)
                && outcome.elapsed < Duration::from_millis(800),
            "{outcome:?}"
        );
        assert!(
            outcome.third_ready_at.unwrap() >= Duration::from_millis(300),
            "{outcome:?}"
        );
    }
}

#[tokio::test]
async fn browser_retry_caller_abort_does_not_launch_detached_attempts() {
    for streaming in [false, true] {
        let outcome = controlled_termination(streaming, true).await;
        assert!(outcome.cancelled && !outcome.timed_out, "{outcome:?}");
        assert_eq!(outcome.attempts, 1, "{outcome:?}");
    }
}
