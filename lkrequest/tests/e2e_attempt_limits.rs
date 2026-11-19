//! Public attempt limits and observations against bounded loopback fixtures.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use lkrequest::error::{Error, Result};
use lkrequest::middleware::{Middleware, MiddlewareRequest};
use lkrequest::retry::{FixedInterval, RetryPolicy};
use lkrequest::{
    AttemptDenialReason, AttemptLimitScope, AttemptLimits, AttemptOutcome, AttemptSummary, Client,
    Idempotency,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::{JoinHandle, JoinSet};

const BOUND: Duration = Duration::from_secs(5);

fn limits(extra: u64) -> AttemptLimits {
    AttemptLimits::default().with_extra_http_attempts(extra)
}

fn client(extra: Option<u64>) -> Client {
    Client::builder()
        .attempt_limits(extra.map_or_else(AttemptLimits::default, limits))
        .retry_on_connection_close(false)
        .timeout_config(lkrequest::TimeoutConfig {
            total_timeout: Some(BOUND),
            ..Default::default()
        })
        .build()
}

#[derive(Default)]
struct Received {
    requests: Mutex<Vec<(String, Bytes)>>,
    accepts: AtomicUsize,
    hanging: Notify,
}

struct Server {
    url: String,
    received: Arc<Received>,
    task: JoinHandle<()>,
}

impl Server {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let received = Arc::new(Received::default());
        let state = received.clone();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                state.accepts.fetch_add(1, Ordering::SeqCst);
                let state = state.clone();
                connections.spawn(async move {
                    let service =
                        service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                            let state = state.clone();
                            async move {
                                let path = request.uri().path().to_owned();
                                let body = request.into_body().collect().await.unwrap().to_bytes();
                                state.requests.lock().unwrap().push((path.clone(), body));
                                if path == "/hang" {
                                    state.hanging.notify_one();
                                    std::future::pending::<()>().await;
                                }
                                let (status, body) = match path.as_str() {
                                    "/busy" | "/busy-close" => (503, "original busy body"),
                                    "/redirect" | "/redirect-close" => (302, "redirect"),
                                    _ => (200, "ok"),
                                };
                                let mut response = hyper::Response::builder().status(status);
                                if path == "/redirect" || path == "/redirect-close" {
                                    response = response.header("location", "/busy");
                                }
                                if path.ends_with("-close") {
                                    response = response.header("connection", "close");
                                }
                                Ok::<_, Infallible>(
                                    response.body(Full::new(Bytes::from(body))).unwrap(),
                                )
                            }
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            url,
            received,
            task,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.url)
    }

    fn paths(&self) -> Vec<String> {
        self.received
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|(path, _)| path.clone())
            .collect()
    }

    async fn wait_for_hanging_request(&self) {
        tokio::time::timeout(BOUND, self.received.hanging.notified())
            .await
            .expect("request did not reach the server");
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct RawServer {
    url: String,
    task: JoinHandle<()>,
}

impl RawServer {
    async fn start(response: &'static [u8]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                headers.push(stream.read_u8().await.unwrap());
                assert!(headers.len() < 64 * 1024);
            }
            stream.write_all(response).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        Self { url, task }
    }
}

impl Drop for RawServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

type CallbackRecord = (u32, Option<String>, Option<u16>);

#[derive(Clone, Debug)]
struct Callback {
    calls: Arc<Mutex<Vec<CallbackRecord>>>,
    delay: Duration,
}

impl Callback {
    fn long_backoff() -> Self {
        Self {
            calls: Arc::default(),
            delay: Duration::from_secs(60),
        }
    }
}

impl RetryPolicy for Callback {
    fn should_retry(
        &self,
        attempt: u32,
        error: Option<&Error>,
        status: Option<http::StatusCode>,
    ) -> Option<Duration> {
        self.calls.lock().unwrap().push((
            attempt,
            error.map(ToString::to_string),
            status.map(|s| s.as_u16()),
        ));
        Some(self.delay)
    }
}

fn assert_counts(summary: AttemptSummary, total: u64, extra: u64, redirects: u64) {
    assert!(summary.started());
    assert_eq!(summary.http_submissions(), total);
    assert_eq!(summary.extra_http_submissions(), extra);
    assert_eq!(summary.redirects(), redirects);
    assert!(total <= 1 + redirects + extra);
}

fn connect_limits(count: u64) -> AttemptLimits {
    AttemptLimits::default().with_connect_attempts(count)
}

#[tokio::test]
async fn connect_zero_blocks_new_work_but_allows_buffered_and_streaming_pool_reuse() {
    let server = Server::start().await;
    let callback = Callback {
        calls: Arc::default(),
        delay: Duration::ZERO,
    };
    let session = client(None)
        .session()
        .http1_only()
        .retry_policy(callback.clone())
        .build();
    let (result, summary) = session
        .get(&server.url("/ok"))
        .attempt_limits(connect_limits(0))
        .send_with_attempt_summary()
        .await;
    assert!(matches!(result, Err(Error::ResourceLimitExceeded(_))));
    assert_counts(summary, 0, 0, 0);
    assert_eq!(summary.connect_initiations(), 0);
    assert_eq!(
        summary.denial_reason(),
        Some(AttemptDenialReason::ConnectLimit)
    );
    assert!(callback.calls.lock().unwrap().is_empty());
    assert_eq!(server.received.accepts.load(Ordering::SeqCst), 0);

    let (result, summary) = session
        .get(&server.url("/ok"))
        .attempt_limits(connect_limits(1))
        .send_with_attempt_summary()
        .await;
    assert_eq!(result.unwrap().status(), 200);
    assert_eq!(summary.connect_initiations(), 1);
    for _ in 0..2 {
        let (result, summary) = session
            .get(&server.url("/ok"))
            .attempt_limits(connect_limits(0))
            .send_with_attempt_summary()
            .await;
        assert_eq!(result.unwrap().status(), 200);
        assert_eq!(summary.connect_initiations(), 0);
        assert_eq!(summary.denial_reason(), None);
    }
    let (result, summary) = session
        .get(&server.url("/ok"))
        .attempt_limits(connect_limits(0))
        .send_streaming_with_attempt_summary()
        .await;
    assert_eq!(result.unwrap().bytes().await.unwrap(), "ok");
    assert_eq!(summary.connect_initiations(), 0);
    assert_eq!(summary.denial_reason(), None);
    assert_eq!(server.received.accepts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn connect_cap_preserves_status_and_stops_further_policy_calls() {
    for cap in [1, 2, 3] {
        let server = Server::start().await;
        let callback = Callback {
            calls: Arc::default(),
            delay: Duration::ZERO,
        };
        let session = client(None)
            .session()
            .http1_only()
            .attempt_limits(connect_limits(cap))
            .retry_policy(callback.clone())
            .build();
        for _ in 0..2 {
            let (result, summary) = session
                .get(&server.url("/busy-close"))
                .send_with_attempt_summary()
                .await;
            let response = result.unwrap();
            assert_eq!(response.status(), 503);
            assert_eq!(response.text().unwrap(), "original busy body");
            assert_eq!(summary.connect_initiations(), cap);
            assert_counts(summary, cap, cap - 1, 0);
            assert_eq!(
                summary.denial_reason(),
                Some(AttemptDenialReason::ConnectLimit)
            );
            assert_eq!(summary.outcome(), AttemptOutcome::Succeeded);
        }
        assert_eq!(callback.calls.lock().unwrap().len() as u64, cap * 2);
        assert_eq!(
            server.received.accepts.load(Ordering::SeqCst) as u64,
            cap * 2
        );
    }
}

#[tokio::test]
async fn connect_cap_preserves_redirect_response_if_next_hop_cannot_start() {
    let server = Server::start().await;
    let session = client(None).session().http1_only().build();
    let url = server.url("/redirect-close");
    let (result, summary) = session
        .get(&url)
        .attempt_limits(connect_limits(1))
        .send_with_attempt_summary()
        .await;
    let response = result.unwrap();
    assert_eq!(response.status(), 302);
    assert_eq!(response.url(), url);
    assert_eq!(response.text().unwrap(), "redirect");
    assert_eq!(summary.connect_initiations(), 1);
    assert_counts(summary, 1, 0, 1);
    assert_eq!(
        summary.denial_reason(),
        Some(AttemptDenialReason::ConnectLimit)
    );
    assert_eq!(server.paths(), vec!["/redirect-close"]);
}

#[tokio::test]
async fn connect_cap_preserves_original_error_after_admitted_failure() {
    let server = RawServer::start(b"").await;
    let callback = Callback {
        calls: Arc::default(),
        delay: Duration::ZERO,
    };
    let session = client(None)
        .session()
        .http1_only()
        .retry_policy(callback.clone())
        .build();
    let (result, summary) = session
        .get(&server.url)
        .attempt_limits(connect_limits(1))
        .send_with_attempt_summary()
        .await;
    let error = result.unwrap_err();
    assert!(!matches!(
        error,
        Error::ResourceLimitExceeded(_) | Error::ConnectAttemptDenied(_)
    ));
    assert_eq!(callback.calls.lock().unwrap().len(), 1);
    assert_eq!(
        callback.calls.lock().unwrap()[0].1.as_deref(),
        Some(error.to_string().as_str())
    );
    assert_eq!(summary.connect_initiations(), 1);
    assert_eq!(
        summary.denial_reason(),
        Some(AttemptDenialReason::ConnectLimit)
    );
}

#[tokio::test]
async fn deadline_during_backoff_does_not_restore_prior_status() {
    let server = Server::start().await;
    let session = client(None)
        .session()
        .http1_only()
        .retry_policy(Callback::long_backoff())
        .build();
    let (result, summary) = session
        .get(&server.url("/busy-close"))
        .attempt_limits(connect_limits(1))
        .timeout(Duration::from_millis(100))
        .send_with_attempt_summary()
        .await;
    assert!(result.unwrap_err().is_timeout());
    assert_eq!(summary.connect_initiations(), 1);
    assert_eq!(summary.denial_reason(), Some(AttemptDenialReason::Deadline));
}

#[tokio::test]
async fn caps_zero_one_and_multiple_are_per_request_and_default_is_unchanged() {
    for (cap, expected) in [(Some(0), 1), (Some(1), 2), (Some(3), 4), (None, 5)] {
        let server = Server::start().await;
        let session = client(cap)
            .session()
            .http1_only()
            .retry_policy(FixedInterval::new(4, Duration::ZERO))
            .build();
        for _ in 0..2 {
            let (response, summary) = session
                .get(&server.url("/busy"))
                .send_with_attempt_summary()
                .await;
            let response = response.unwrap();
            assert_eq!(response.status().as_u16(), 503);
            assert_eq!(response.text().unwrap(), "original busy body");
            assert!(response.diagnostics().is_none());
            assert_counts(summary, expected, expected - 1, 0);
            assert_eq!(summary.recoveries(), expected - 1);
            assert_eq!(summary.outcome(), AttemptOutcome::Succeeded);
            assert_eq!(
                summary.denial_reason(),
                cap.map(|_| AttemptDenialReason::ExtraHttpLimit)
            );
            assert_eq!(
                summary.effective_limits().unwrap().extra_http_attempts(),
                cap
            );
        }
        assert_eq!(server.paths().len() as u64, expected * 2);
    }
}

#[tokio::test]
async fn normal_redirects_do_not_consume_extra_cap_but_restarts_do() {
    for (cap, expected_paths, total, redirects) in [
        (0, vec!["/redirect", "/busy"], 2, 1),
        (1, vec!["/redirect", "/busy", "/redirect", "/busy"], 4, 2),
    ] {
        let server = Server::start().await;
        let session = client(Some(cap))
            .session()
            .http1_only()
            .retry_policy(FixedInterval::new(5, Duration::ZERO))
            .build();
        let (response, summary) = session
            .get(&server.url("/redirect"))
            .send_with_attempt_summary()
            .await;
        assert_eq!(response.unwrap().status().as_u16(), 503);
        assert_eq!(server.paths(), expected_paths);
        assert_counts(summary, total, cap, redirects);
        assert_eq!(summary.recoveries(), cap);
        assert_eq!(
            summary.denial_reason(),
            Some(AttemptDenialReason::ExtraHttpLimit)
        );
    }
}

#[tokio::test]
async fn exhausted_status_cap_calls_policy_but_preserves_response_without_backoff() {
    let server = Server::start().await;
    let callback = Callback::long_backoff();
    let session = client(Some(0))
        .session()
        .http1_only()
        .retry_policy(callback.clone())
        .build();
    let (result, summary) = tokio::time::timeout(
        Duration::from_secs(2),
        session
            .get(&server.url("/busy"))
            .send_with_attempt_summary(),
    )
    .await
    .expect("cap denial must not sleep for the policy's 60-second backoff");
    let response = result.unwrap();
    assert_eq!(response.status().as_u16(), 503);
    assert_eq!(response.text().unwrap(), "original busy body");
    assert_eq!(*callback.calls.lock().unwrap(), vec![(1, None, Some(503))]);
    assert_counts(summary, 1, 0, 0);
    assert_eq!(
        summary.denial_reason(),
        Some(AttemptDenialReason::ExtraHttpLimit)
    );
    assert_eq!(server.paths(), vec!["/busy"]);
}

#[tokio::test]
async fn exhausted_error_cap_preserves_original_transport_error_without_backoff() {
    let server = RawServer::start(b"").await;
    let callback = Callback::long_backoff();
    let session = client(Some(0))
        .session()
        .http1_only()
        .retry_policy(callback.clone())
        .build();
    let (result, summary) = tokio::time::timeout(
        Duration::from_secs(2),
        session.get(&server.url).send_with_attempt_summary(),
    )
    .await
    .expect("cap denial must not sleep for the policy's 60-second backoff");
    let error = result.unwrap_err();
    assert!(!matches!(error, Error::ResourceLimitExceeded(_)));
    assert_eq!(
        *callback.calls.lock().unwrap(),
        vec![(1, Some(error.to_string()), None)]
    );
    assert_counts(summary, 1, 0, 0);
    assert_eq!(summary.outcome(), AttemptOutcome::Failed);
    assert_eq!(
        summary.denial_reason(),
        Some(AttemptDenialReason::ExtraHttpLimit)
    );
}

#[test]
fn builders_report_requested_values_effective_caps_and_limiting_scopes() {
    let client = client(Some(8));
    assert_eq!(client.configured_attempt_limits(), limits(8));
    assert_eq!(
        client
            .effective_attempt_limits()
            .unwrap()
            .extra_http_scope(),
        Some(AttemptLimitScope::Client)
    );
    let inherited = client.session().build();
    assert_eq!(
        inherited.configured_attempt_limits(),
        AttemptLimits::default()
    );
    assert_eq!(
        inherited.effective_attempt_limits().unwrap(),
        client.effective_attempt_limits().unwrap()
    );
    let session = client.session().attempt_limits(limits(3)).build();
    assert_eq!(session.configured_attempt_limits(), limits(3));
    assert_eq!(
        session
            .effective_attempt_limits()
            .unwrap()
            .extra_http_scope(),
        Some(AttemptLimitScope::Session)
    );
    let equal = session.get("http://127.0.0.1/").attempt_limits(limits(3));
    assert_eq!(equal.configured_attempt_limits(), limits(3));
    assert_eq!(
        equal.effective_attempt_limits().unwrap().extra_http_scope(),
        Some(AttemptLimitScope::Session)
    );
    let zero = equal.attempt_limits(limits(0));
    assert_eq!(
        zero.effective_attempt_limits()
            .unwrap()
            .extra_http_attempts(),
        Some(0)
    );
    assert_eq!(
        zero.effective_attempt_limits().unwrap().extra_http_scope(),
        Some(AttemptLimitScope::Request)
    );
    let cleared = zero.attempt_limits(limits(0).without_extra_http_limit());
    assert_eq!(
        cleared.configured_attempt_limits(),
        AttemptLimits::default()
    );
    assert_eq!(
        cleared.effective_attempt_limits().unwrap(),
        session.effective_attempt_limits().unwrap()
    );
    let cleared_session = client
        .session()
        .attempt_limits(limits(1))
        .attempt_limits(limits(1).without_extra_http_limit())
        .build();
    assert_eq!(
        cleared_session.effective_attempt_limits().unwrap(),
        client.effective_attempt_limits().unwrap()
    );
}

struct CountingMiddleware(Arc<AtomicUsize>);

impl Middleware for CountingMiddleware {
    fn on_request(&self, request: MiddlewareRequest) -> Result<MiddlewareRequest> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(request)
    }
}

struct CountingReader {
    polls: Arc<AtomicUsize>,
    sent: bool,
}

impl AsyncRead for CountingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        if !self.sent {
            buf.put_slice(b"payload");
            self.sent = true;
        }
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn invalid_final_configuration_fails_before_middleware_body_or_network() {
    let server = Server::start().await;
    let middleware_calls = Arc::new(AtomicUsize::new(0));
    let body_polls = Arc::new(AtomicUsize::new(0));
    let client = client(Some(2));
    for invalid_session in [false, true] {
        let session = client
            .session()
            .http1_only()
            .attempt_limits(if invalid_session {
                limits(3)
            } else {
                AttemptLimits::default()
            })
            .middleware(CountingMiddleware(middleware_calls.clone()))
            .build();
        for streaming in [false, true] {
            let request = session
                .post(&server.url("/ok"))
                .attempt_limits(if invalid_session {
                    limits(0)
                } else {
                    limits(3)
                })
                .body_reader(
                    CountingReader {
                        polls: body_polls.clone(),
                        sent: false,
                    },
                    Some(7),
                );
            assert!(request.effective_attempt_limits().is_err());
            let (result, summary) = if streaming {
                let (result, summary) = request.send_streaming_with_attempt_summary().await;
                (result.map(|_| ()), summary)
            } else {
                let (result, summary) = request.send_with_attempt_summary().await;
                (result.map(|_| ()), summary)
            };
            assert!(matches!(result, Err(Error::InvalidConfig(_))));
            assert_counts(summary, 0, 0, 0);
            assert_eq!(summary.effective_limits(), None);
            assert_eq!(summary.outcome(), AttemptOutcome::Failed);
            assert_eq!(
                summary.denial_reason(),
                Some(AttemptDenialReason::InvalidConfiguration)
            );
        }
    }
    assert_eq!(middleware_calls.load(Ordering::SeqCst), 0);
    assert_eq!(body_polls.load(Ordering::SeqCst), 0);
    assert_eq!(server.received.accepts.load(Ordering::SeqCst), 0);
    assert!(server.paths().is_empty());
}

#[tokio::test]
async fn invalid_overrides_can_be_replaced_or_cleared_before_send() {
    let server = Server::start().await;
    let client = client(Some(2));
    for final_override in [limits(1), AttemptLimits::default()] {
        let session = client
            .session()
            .http1_only()
            .attempt_limits(limits(3))
            .attempt_limits(final_override)
            .build();
        let request = session
            .get(&server.url("/ok"))
            .attempt_limits(limits(3))
            .attempt_limits(final_override);
        let effective = request.effective_attempt_limits().unwrap();
        let (response, summary) = request.send_with_attempt_summary().await;
        assert_eq!(response.unwrap().status().as_u16(), 200);
        assert_counts(summary, 1, 0, 0);
        assert_eq!(summary.effective_limits(), Some(effective));
        assert_eq!(summary.denial_reason(), None);
    }
    assert_eq!(server.paths(), vec!["/ok", "/ok"]);
}

#[tokio::test]
async fn concurrent_requests_and_sessions_have_independent_roots() {
    let server = Server::start().await;
    let client = client(Some(1));
    let session_a = client
        .session()
        .http1_only()
        .retry_policy(FixedInterval::new(3, Duration::ZERO))
        .build();
    let session_b = client
        .session()
        .http1_only()
        .retry_policy(FixedInterval::new(3, Duration::ZERO))
        .build();
    let url = server.url("/busy");
    let (a, b, c) = tokio::join!(
        session_a.get(&url).send_with_attempt_summary(),
        session_a.get(&url).send_with_attempt_summary(),
        session_b.get(&url).send_with_attempt_summary(),
    );
    for (result, summary) in [a, b, c] {
        assert_eq!(result.unwrap().status().as_u16(), 503);
        assert_counts(summary, 2, 1, 0);
        assert_eq!(summary.recoveries(), 1);
        assert_eq!(summary.outcome(), AttemptOutcome::Succeeded);
    }
    assert_eq!(server.paths().len(), 6);
}

#[test]
fn dropping_an_unpolled_future_cancels_observation_without_starting() {
    let session = client(Some(0)).session().build();
    for streaming in [false, true] {
        let (request, observer) = session.get("http://127.0.0.1/").observe_attempts();
        let (request, second_observer) = request.observe_attempts();
        assert_eq!(observer.snapshot(), AttemptSummary::default());
        if streaming {
            drop(request.send_streaming());
        } else {
            drop(request.send());
        }
        let summary = observer.snapshot();
        assert!(!summary.started());
        assert_eq!(summary.http_submissions(), 0);
        assert_eq!(summary.effective_limits(), None);
        assert_eq!(summary.outcome(), AttemptOutcome::Cancelled);
        assert_eq!(
            summary.denial_reason(),
            Some(AttemptDenialReason::Cancelled)
        );
        assert_eq!(summary, second_observer.snapshot());
    }
}

#[tokio::test]
async fn abort_and_join_finalize_live_observation_without_erasing_charges() {
    let server = Server::start().await;
    let session = client(Some(1)).session().http1_only().build();
    for streaming in [false, true] {
        let (request, observer) = session.get(&server.url("/hang")).observe_attempts();
        let task = tokio::spawn(async move {
            if streaming {
                request.send_streaming().await.map(|_| ())
            } else {
                request.send().await.map(|_| ())
            }
        });
        server.wait_for_hanging_request().await;
        let active = observer.snapshot();
        assert_eq!(active.outcome(), AttemptOutcome::Active);
        assert_counts(active, 1, 0, 0);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let cancelled = observer.snapshot();
        assert_eq!(cancelled.outcome(), AttemptOutcome::Cancelled);
        assert_eq!(
            cancelled.denial_reason(),
            Some(AttemptDenialReason::Cancelled)
        );
        assert_counts(cancelled, 1, 0, 0);
        assert_eq!(observer.snapshot(), cancelled);
    }
}

struct RejectMiddleware;

impl Middleware for RejectMiddleware {
    fn on_request(&self, _: MiddlewareRequest) -> Result<MiddlewareRequest> {
        Err(Error::Http("middleware sentinel".to_string()))
    }
}

#[tokio::test]
async fn ordinary_errors_and_deadlines_finish_as_failed_not_cancelled() {
    let server = Server::start().await;
    let client = client(None);
    let rejected = client
        .session()
        .http1_only()
        .middleware(RejectMiddleware)
        .build();
    let (result, summary) = rejected
        .get(&server.url("/ok"))
        .send_with_attempt_summary()
        .await;
    assert!(matches!(result, Err(Error::Http(ref message)) if message == "middleware sentinel"));
    assert_counts(summary, 0, 0, 0);
    assert_eq!(summary.outcome(), AttemptOutcome::Failed);
    assert_eq!(summary.denial_reason(), None);
    assert!(server.paths().is_empty());

    let session = client.session().http1_only().build();
    let (request, observer) = session
        .get(&server.url("/hang"))
        .timeout(Duration::from_millis(500))
        .observe_attempts();
    let task = tokio::spawn(request.send());
    server.wait_for_hanging_request().await;
    let error = tokio::time::timeout(BOUND, task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.is_timeout());
    let summary = observer.snapshot();
    assert_counts(summary, 1, 0, 0);
    assert_eq!(summary.outcome(), AttemptOutcome::Failed);
    assert_eq!(summary.denial_reason(), Some(AttemptDenialReason::Deadline));
}

#[tokio::test]
async fn streaming_publication_freezes_success_even_when_body_read_fails() {
    let server =
        RawServer::start(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nx")
            .await;
    let session = client(Some(0)).session().http1_only().build();
    let (request, observer) = session.get(&server.url).observe_attempts();
    let (result, summary) = request.send_streaming_with_attempt_summary().await;
    let response = result.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    assert_counts(summary, 1, 0, 0);
    assert_eq!(summary.outcome(), AttemptOutcome::Succeeded);
    assert_eq!(summary.denial_reason(), None);
    assert_eq!(observer.snapshot(), summary);
    assert!(response.bytes().await.is_err());
    assert_eq!(observer.snapshot(), summary);
}

#[tokio::test]
async fn a_permissive_cap_does_not_override_method_or_body_replay_safety() {
    let server = Server::start().await;
    let session = client(Some(5))
        .session()
        .http1_only()
        .retry_policy(FixedInterval::new(2, Duration::ZERO))
        .build();
    let (result, unsafe_summary) = session
        .post(&server.url("/busy"))
        .body("payload")
        .send_with_attempt_summary()
        .await;
    assert_eq!(result.unwrap().status().as_u16(), 503);
    assert_counts(unsafe_summary, 1, 0, 0);
    assert_eq!(
        unsafe_summary.denial_reason(),
        Some(AttemptDenialReason::ReplayDenied)
    );

    let (result, safe_summary) = session
        .post(&server.url("/busy"))
        .body("payload")
        .idempotency(Idempotency::Idempotent)
        .send_with_attempt_summary()
        .await;
    assert_eq!(result.unwrap().status().as_u16(), 503);
    assert_counts(safe_summary, 3, 2, 0);
    assert_eq!(safe_summary.denial_reason(), None);

    let polls = Arc::new(AtomicUsize::new(0));
    let (result, stream_summary) = session
        .post(&server.url("/busy"))
        .body_reader(
            CountingReader {
                polls: polls.clone(),
                sent: false,
            },
            Some(7),
        )
        .idempotency(Idempotency::Idempotent)
        .send_with_attempt_summary()
        .await;
    assert_eq!(result.unwrap().status().as_u16(), 503);
    assert_counts(stream_summary, 1, 0, 0);
    assert_eq!(
        stream_summary.denial_reason(),
        Some(AttemptDenialReason::BodyUnavailable)
    );
    assert!(polls.load(Ordering::SeqCst) > 0);
    let received = server.received.requests.lock().unwrap();
    assert_eq!(received.len(), 5);
    assert!(received.iter().all(|(_, body)| body.as_ref() == b"payload"));
}

#[tokio::test]
async fn blocking_wrappers_expose_the_same_configuration_and_summaries() {
    let server = Server::start().await;
    let url = server.url.clone();
    tokio::task::spawn_blocking(move || {
        let client = lkrequest::blocking::Client::builder()
            .attempt_limits(limits(1))
            .timeout_config(lkrequest::TimeoutConfig {
                total_timeout: Some(BOUND),
                ..Default::default()
            })
            .build();
        assert_eq!(client.configured_attempt_limits(), limits(1));
        assert_eq!(
            client
                .effective_attempt_limits()
                .unwrap()
                .extra_http_scope(),
            Some(AttemptLimitScope::Client)
        );
        let session = client
            .session()
            .http1_only()
            .attempt_limits(limits(0))
            .retry_policy(FixedInterval::new(2, Duration::ZERO))
            .build();
        assert_eq!(session.configured_attempt_limits(), limits(0));
        assert_eq!(
            session
                .effective_attempt_limits()
                .unwrap()
                .extra_http_scope(),
            Some(AttemptLimitScope::Session)
        );
        let request = session
            .get(&format!("{url}/busy"))
            .attempt_limits(AttemptLimits::default());
        assert_eq!(
            request.configured_attempt_limits(),
            AttemptLimits::default()
        );
        assert_eq!(
            request.effective_attempt_limits().unwrap(),
            session.effective_attempt_limits().unwrap()
        );
        let (request, observer) = request.observe_attempts();
        assert_eq!(observer.snapshot().outcome(), AttemptOutcome::Pending);
        let (result, summary) = request.send_with_attempt_summary();
        assert_eq!(result.unwrap().status().as_u16(), 503);
        assert_counts(summary, 1, 0, 0);
        assert_eq!(
            summary.denial_reason(),
            Some(AttemptDenialReason::ExtraHttpLimit)
        );
        assert_eq!(observer.snapshot(), summary);
        let (result, summary) = session
            .get(&format!("{url}/ok"))
            .send_streaming_with_attempt_summary();
        assert_eq!(result.unwrap().status().as_u16(), 200);
        assert_counts(summary, 1, 0, 0);
        assert_eq!(summary.outcome(), AttemptOutcome::Succeeded);
        let (result, summary) = session
            .get(&format!("{url}/ok"))
            .attempt_limits(limits(1))
            .send_with_attempt_summary();
        assert!(matches!(result, Err(Error::InvalidConfig(_))));
        assert_counts(summary, 0, 0, 0);
        assert_eq!(summary.outcome(), AttemptOutcome::Failed);
    })
    .await
    .unwrap();
    assert_eq!(server.paths(), vec!["/busy", "/ok"]);
}
