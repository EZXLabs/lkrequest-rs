//! Retry strategies for HTTP requests.
//!
//! Provides a [`RetryPolicy`] trait and built-in strategies for retrying
//! failed requests based on error type, HTTP status code, and configurable
//! backoff timing.
//!
//! # Replay safety (idempotency)
//!
//! A retry re-sends the (buffered) request body, so error-based retries are
//! gated on whether the request is safe to replay — the policy decides the
//! backoff, [`retry_is_replay_safe`] decides whether a replay is allowed at
//! all. Safe methods (`GET`/`HEAD`/`OPTIONS`/`TRACE`) are always retried;
//! non-idempotent methods (`POST`/`PUT`/`PATCH`/`DELETE`) are retried only
//! when the failure proves the request was never processed
//! (connection-establishment failures, HTTP/2 `REFUSED_STREAM` or GOAWAY
//! excluding an unprocessed request, or HTTP/3 `H3_REQUEST_REJECTED`), or when the
//! request is explicitly marked [`Idempotency::Idempotent`](crate::Idempotency).
//! This prevents a timeout/reset *after* a `POST` was sent from silently
//! duplicating a side effect.
//!
//! Status-code retries are gated the same way, by
//! [`status_retry_is_replay_safe`]. Because the server answered, a
//! non-idempotent method is never replayed by default: a status code cannot
//! prove that the request was not applied. Safe methods and callers that
//! explicitly opt into replay with [`Idempotency::Idempotent`](crate::Idempotency)
//! remain eligible for status-code retries.
//!
//! With `quic-h3`, the explicit `H3RetryMode::Chrome155ProtocolErrors` mode
//! separately authorizes limited replay of buffered requests after selected
//! HTTP/3 protocol errors. It is disabled by default and does not change
//! status retries or QUIC 0-RTT eligibility.
//!
//! # Built-in Strategies
//!
//! - [`ExponentialBackoff`]: Doubles the delay between retries (with jitter).
//! - [`FixedInterval`]: Waits a fixed duration between retries.
//!
//! # Usage
//!
//! ```rust,no_run
//! # use lkrequest::Client;
//! # use lktls::profile::presets;
//! use lkrequest::retry::ExponentialBackoff;
//!
//! # let client = Client::builder().fingerprint(presets::chrome_131()).build();
//! let session = client.session()
//!     .retry_policy(ExponentialBackoff::default())
//!     .build();
//! ```

use std::time::Duration;

use crate::error::Error;

/// HTTP/3 protocol-error retry behavior for a session.
///
/// This is independent of [`RetryPolicy`] and the request's QUIC 0-RTT gate.
/// Existing client presets use [`Safe`](Self::Safe).
#[cfg(feature = "quic-h3")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum H3RetryMode {
    /// Preserve the existing automatic replay safety checks.
    #[default]
    Safe,
    /// Retry selected HTTP/3 protocol errors up to twice per redirect hop,
    /// before response headers reach the request transaction.
    ///
    /// This explicitly permits replay of a finite buffered request, including
    /// a POST the peer may already have processed. Absent or buffered bodies
    /// are eligible; streaming uploads are excluded. Set the request's
    /// [`Idempotency`](crate::Idempotency) to `NotIdempotent` to opt out.
    ///
    /// Applies to buffered and streaming response APIs only before their H3
    /// sender returns response headers. It does not add status-code retries,
    /// retries after response headers, or the other Chrome retry classes.
    /// Existing deadlines and 0-RTT eligibility remain in force.
    ///
    /// H3-only requests retry over H3. Other requests require
    /// [`FallbackPolicy::AllowFallback`](crate::FallbackPolicy::AllowFallback)
    /// and a route that permits TCP; their retry disables H3 for that redirect
    /// hop while retaining H1/H2 ALPN negotiation. A protocol error handled by
    /// this mode is not retried again by the outer [`RetryPolicy`].
    Chrome155ProtocolErrors,
}

#[cfg(feature = "quic-h3")]
pub(crate) const MAX_CHROME_H3_RETRIES: u32 = 2;

#[cfg(feature = "quic-h3")]
pub(crate) fn chrome_h3_owns_error(mode: H3RetryMode, error: &Error) -> bool {
    mode == H3RetryMode::Chrome155ProtocolErrors
        && error
            .h3_request_context()
            .is_some_and(|context| context.kind == crate::error::H3FailureKind::Protocol)
}

#[cfg(feature = "quic-h3")]
pub(crate) fn chrome_h3_can_retry(
    error: &Error,
    idempotency: crate::Idempotency,
    body: Option<&crate::body::RequestBody>,
    retries: u32,
) -> bool {
    retries < MAX_CHROME_H3_RETRIES
        && idempotency != crate::Idempotency::NotIdempotent
        && body.is_none_or(|body| body.buffered().is_some())
        && error.h3_request_context().is_some_and(|context| {
            context.stage == crate::error::H3ResponseStage::AwaitingResponse
                && context.kind == crate::error::H3FailureKind::Protocol
        })
}

// ---------------------------------------------------------------------------
// RetryPolicy trait
// ---------------------------------------------------------------------------

/// Policy that determines whether a failed request should be retried.
///
/// Implementors inspect the attempt number, error (if any), and HTTP status
/// code to decide whether to retry and how long to wait.
pub trait RetryPolicy: Send + Sync + std::fmt::Debug {
    /// Determine whether to retry after a failure.
    ///
    /// # Arguments
    ///
    /// * `attempt` - The current attempt number (1 = first retry, 2 = second, etc.)
    /// * `error` - The error from the request (if it failed at the transport/TLS/proxy level).
    /// * `status` - The HTTP status code (if a response was received).
    ///
    /// # Returns
    ///
    /// * `Some(duration)` — retry after waiting `duration`.
    /// * `None` — do not retry; propagate the error.
    fn should_retry(
        &self,
        attempt: u32,
        error: Option<&Error>,
        status: Option<http::StatusCode>,
    ) -> Option<Duration>;
}

// ---------------------------------------------------------------------------
// Default retryable status codes
// ---------------------------------------------------------------------------

/// Default set of HTTP status codes that should trigger a retry.
///
/// Includes server errors and rate limiting responses:
/// - 429 Too Many Requests
/// - 502 Bad Gateway
/// - 503 Service Unavailable
/// - 520-530 Cloudflare custom errors
pub fn is_retryable_status(status: http::StatusCode) -> bool {
    matches!(status.as_u16(), 429 | 502 | 503 | 520..=530)
}

// ---------------------------------------------------------------------------
// Replay safety (idempotency-aware retry gate)
// ---------------------------------------------------------------------------

/// Whether a request that failed with `error` is safe to **auto-retry** given
/// its HTTP method and idempotency setting.
///
/// A retry re-sends the (fully buffered) request body, so a non-idempotent
/// request — `POST`/`PUT`/`PATCH`/`DELETE`, or any custom non-safe method —
/// must only be retried when **either**:
///
/// - the failure proves the server never processed the request
///   ([`Error::is_safe_to_replay`]: connection-establishment failures and
///   HTTP/2 `REFUSED_STREAM`, a GOAWAY cutoff before response headers, or
///   HTTP/3 `H3_REQUEST_REJECTED` before response headers); or
/// - the caller has declared the request replay-safe via
///   [`Idempotency::Idempotent`](crate::Idempotency) (e.g. it carries an
///   `Idempotency-Key` header).
///
/// Safe methods (`GET`/`HEAD`/`OPTIONS`/`TRACE`) with default idempotency and
/// requests explicitly marked idempotent can be replayed. This is this client's
/// deliberate automatic replay safety contract: a timeout or connection reset
/// after a default `POST` was transmitted does not authorize retry, because the
/// server may already have applied it and replay could duplicate the side effect.
///
/// The [`RetryPolicy`] still decides *whether and how long* to back off; this
/// gate is an additional safety check applied to the error-retry path.
pub fn retry_is_replay_safe(
    method: &http::Method,
    idempotency: crate::session::Idempotency,
    error: &Error,
) -> bool {
    error.is_safe_to_replay() || crate::session::can_send_early_data(method, idempotency)
}

/// Whether a *status-code* retry is safe to auto-replay.
///
/// The server answered, so the request reached the HTTP peer. Even statuses
/// such as `429 Too Many Requests` and `503 Service Unavailable` do not prove
/// that an unsafe request was not observed or applied by an upstream gateway
/// or application. Consequently, only safe methods or an explicit
/// [`Idempotency::Idempotent`](crate::Idempotency) opt-in may be replayed.
pub fn status_retry_is_replay_safe(
    method: &http::Method,
    idempotency: crate::session::Idempotency,
    status: http::StatusCode,
) -> bool {
    let _ = status;
    crate::session::can_send_early_data(method, idempotency)
}

// ---------------------------------------------------------------------------
// ExponentialBackoff
// ---------------------------------------------------------------------------

/// Exponential backoff retry strategy with optional jitter.
///
/// Delay doubles with each retry: base_delay * 2^(attempt-1), capped at max_delay.
/// When jitter is enabled, a random factor ±25% is applied to avoid thundering herd.
///
/// # Default Configuration
///
/// - `max_retries`: 3
/// - `base_delay`: 500ms
/// - `max_delay`: 30s
/// - `jitter`: true
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    /// Maximum number of retries before giving up.
    pub max_retries: u32,
    /// Base delay for the first retry.
    pub base_delay: Duration,
    /// Maximum delay between retries.
    pub max_delay: Duration,
    /// Whether to add random jitter (±25%) to the delay.
    pub jitter: bool,
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            jitter: true,
        }
    }
}

impl ExponentialBackoff {
    /// Create with custom settings.
    pub fn new(max_retries: u32, base_delay: Duration, max_delay: Duration) -> Self {
        Self {
            max_retries,
            base_delay,
            max_delay,
            jitter: true,
        }
    }

    /// Enable or disable jitter.
    pub fn with_jitter(mut self, jitter: bool) -> Self {
        self.jitter = jitter;
        self
    }
}

impl RetryPolicy for ExponentialBackoff {
    fn should_retry(
        &self,
        attempt: u32,
        error: Option<&Error>,
        status: Option<http::StatusCode>,
    ) -> Option<Duration> {
        if attempt > self.max_retries {
            return None;
        }

        // Check if the error/status is retryable
        let retryable = match (error, status) {
            (Some(e), _) => e.is_retryable(),
            (None, Some(s)) => is_retryable_status(s),
            (None, None) => false,
        };

        if !retryable {
            return None;
        }

        // Calculate delay: base_delay * 2^(attempt-1)
        let multiplier = 2u64.saturating_pow(attempt.saturating_sub(1));
        let delay_ms = self.base_delay.as_millis() as u64 * multiplier;
        let delay_ms = delay_ms.min(self.max_delay.as_millis() as u64);

        let delay = if self.jitter {
            apply_jitter(delay_ms)
        } else {
            Duration::from_millis(delay_ms)
        };

        Some(delay)
    }
}

// ---------------------------------------------------------------------------
// FixedInterval
// ---------------------------------------------------------------------------

/// Fixed interval retry strategy — waits a constant duration between retries.
///
/// # Default Configuration
///
/// - `max_retries`: 3
/// - `interval`: 1s
#[derive(Debug, Clone)]
pub struct FixedInterval {
    /// Maximum number of retries before giving up.
    pub max_retries: u32,
    /// Fixed delay between retries.
    pub interval: Duration,
}

impl Default for FixedInterval {
    fn default() -> Self {
        Self {
            max_retries: 3,
            interval: Duration::from_secs(1),
        }
    }
}

impl FixedInterval {
    /// Create with custom settings.
    pub fn new(max_retries: u32, interval: Duration) -> Self {
        Self {
            max_retries,
            interval,
        }
    }
}

impl RetryPolicy for FixedInterval {
    fn should_retry(
        &self,
        attempt: u32,
        error: Option<&Error>,
        status: Option<http::StatusCode>,
    ) -> Option<Duration> {
        if attempt > self.max_retries {
            return None;
        }

        let retryable = match (error, status) {
            (Some(e), _) => e.is_retryable(),
            (None, Some(s)) => is_retryable_status(s),
            (None, None) => false,
        };

        if retryable {
            Some(self.interval)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Apply ±25% random jitter to a delay.
fn apply_jitter(delay_ms: u64) -> Duration {
    use aws_lc_rs::rand::{SecureRandom, SystemRandom};

    let rng = SystemRandom::new();
    let mut buf = [0u8; 4];
    if rng.fill(&mut buf).is_ok() {
        let random_u32 = u32::from_ne_bytes(buf);
        // Map to range [0.75, 1.25]
        let factor = 0.75 + (random_u32 as f64 / u32::MAX as f64) * 0.5;
        let jittered = (delay_ms as f64 * factor) as u64;
        Duration::from_millis(jittered.max(1))
    } else {
        Duration::from_millis(delay_ms)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exponential_backoff_within_max_retries() {
        let policy = ExponentialBackoff {
            max_retries: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            jitter: false,
        };

        let timeout_error = Error::timeout("test", None, None);

        // Attempt 1: 100ms
        let d1 = policy.should_retry(1, Some(&timeout_error), None).unwrap();
        assert_eq!(d1, Duration::from_millis(100));

        // Attempt 2: 200ms
        let d2 = policy.should_retry(2, Some(&timeout_error), None).unwrap();
        assert_eq!(d2, Duration::from_millis(200));

        // Attempt 3: 400ms
        let d3 = policy.should_retry(3, Some(&timeout_error), None).unwrap();
        assert_eq!(d3, Duration::from_millis(400));

        // Attempt 4: exceeded max_retries
        assert!(policy.should_retry(4, Some(&timeout_error), None).is_none());
    }

    #[test]
    fn test_exponential_backoff_max_delay_cap() {
        let policy = ExponentialBackoff {
            max_retries: 10,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(5),
            jitter: false,
        };

        let timeout_error = Error::timeout("test", None, None);
        let d = policy.should_retry(5, Some(&timeout_error), None).unwrap();
        assert_eq!(d, Duration::from_secs(5)); // 1*16=16, capped at 5
    }

    #[test]
    fn test_non_retryable_error_returns_none() {
        let policy = ExponentialBackoff::default();
        let config_error = Error::InvalidConfig("test".into());
        assert!(policy.should_retry(1, Some(&config_error), None).is_none());
    }

    #[test]
    fn test_retryable_status_codes() {
        assert!(is_retryable_status(http::StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable_status(http::StatusCode::BAD_GATEWAY));
        assert!(is_retryable_status(http::StatusCode::SERVICE_UNAVAILABLE));
        assert!(!is_retryable_status(http::StatusCode::OK));
        assert!(!is_retryable_status(http::StatusCode::NOT_FOUND));
        assert!(!is_retryable_status(
            http::StatusCode::INTERNAL_SERVER_ERROR
        ));
    }

    #[test]
    fn test_fixed_interval() {
        let policy = FixedInterval::new(2, Duration::from_millis(500));
        let timeout_error = Error::timeout("test", None, None);

        let d1 = policy.should_retry(1, Some(&timeout_error), None).unwrap();
        assert_eq!(d1, Duration::from_millis(500));

        let d2 = policy.should_retry(2, Some(&timeout_error), None).unwrap();
        assert_eq!(d2, Duration::from_millis(500));

        assert!(policy.should_retry(3, Some(&timeout_error), None).is_none());
    }

    /// Regression: the status-code retry path had no replay-safety gate at all,
    /// so a `POST` answered with `502` — where the origin may already have
    /// applied it — was silently sent again.
    #[test]
    fn status_retry_gate_blocks_ambiguous_statuses_for_non_idempotent_methods() {
        use crate::session::Idempotency;
        use http::{Method, StatusCode};

        let ambiguous = [502u16, 504, 520, 522, 524, 530];
        for code in ambiguous {
            let status = StatusCode::from_u16(code).unwrap();
            assert!(
                !status_retry_is_replay_safe(&Method::POST, Idempotency::Default, status),
                "POST must not be auto-replayed on {code}: the origin may have applied it"
            );
        }

        for code in [429u16, 503] {
            let status = StatusCode::from_u16(code).unwrap();
            assert!(
                !status_retry_is_replay_safe(&Method::POST, Idempotency::Default, status),
                "POST must not be auto-replayed on {code}: the status does not prove non-application"
            );
        }
    }

    /// Safe methods and an explicit idempotency opt-in are replayable on every
    /// retryable status — the gate only constrains non-idempotent methods.
    #[test]
    fn status_retry_gate_allows_safe_methods_and_explicit_idempotency() {
        use crate::session::Idempotency;
        use http::{Method, StatusCode};

        let bad_gateway = StatusCode::from_u16(502).unwrap();

        for method in [Method::GET, Method::HEAD, Method::OPTIONS, Method::TRACE] {
            assert!(
                status_retry_is_replay_safe(&method, Idempotency::Default, bad_gateway),
                "{method} is safe and carries no side effect to duplicate"
            );
        }

        assert!(
            status_retry_is_replay_safe(&Method::POST, Idempotency::Idempotent, bad_gateway),
            "an explicit Idempotency-Key opts a POST back into replay"
        );
    }

    #[test]
    fn poc_non_idempotent_post_not_replayed_after_post_send_failure() {
        use crate::error::{ConnectionClosedKind, ConnectionError, ConnectionPhase};
        use crate::session::Idempotency;

        // A response timeout can fire *after* the request bytes were
        // transmitted — the server may already have processed the POST. The
        // backoff policy alone (the only pre-fix gatekeeper) treats it as
        // retryable, which is exactly how the duplicate-POST bug arose:
        let policy = ExponentialBackoff::default();
        let post_send = Error::timeout("response timeout", None, None);
        assert!(
            policy.should_retry(1, Some(&post_send), None).is_some(),
            "baseline: the backoff policy alone treats a timeout as retryable",
        );

        // ...but replaying a POST risks a duplicate side effect, so the replay
        // gate must refuse it.
        assert!(
            !retry_is_replay_safe(&http::Method::POST, Idempotency::Default, &post_send),
            "POST must not be auto-replayed after a possibly-processed failure",
        );

        // Safe methods (RFC 9110 §9.2.1) are always replay-safe.
        assert!(retry_is_replay_safe(
            &http::Method::GET,
            Idempotency::Default,
            &post_send
        ));

        // An explicit replay guard (e.g. an Idempotency-Key) opts a POST in.
        assert!(retry_is_replay_safe(
            &http::Method::POST,
            Idempotency::Idempotent,
            &post_send
        ));

        // A failure that proves the request was never processed is replay-safe
        // for any method — pre-send connection failure...
        let pre_send = Error::Connection(Box::new(ConnectionError {
            phase: ConnectionPhase::TcpConnect,
            message: "connection refused".into(),
            source: None,
        }));
        assert!(retry_is_replay_safe(
            &http::Method::POST,
            Idempotency::Default,
            &pre_send
        ));

        // ...and HTTP/2 REFUSED_STREAM (declined before processing).
        let refused = Error::ConnectionClosed {
            phase: ConnectionPhase::HttpRequest,
            kind: ConnectionClosedKind::RefusedStream,
            message: "refused stream".into(),
        };
        assert!(retry_is_replay_safe(
            &http::Method::POST,
            Idempotency::Default,
            &refused
        ));

        // An explicit opt-out is never replayed on a post-send failure.
        assert!(!retry_is_replay_safe(
            &http::Method::DELETE,
            Idempotency::NotIdempotent,
            &post_send
        ));
    }

    #[test]
    fn test_retry_on_status_code() {
        let policy = ExponentialBackoff {
            max_retries: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            jitter: false,
        };

        // 429 should trigger retry
        let d = policy.should_retry(1, None, Some(http::StatusCode::TOO_MANY_REQUESTS));
        assert!(d.is_some());

        // 200 should not
        let d = policy.should_retry(1, None, Some(http::StatusCode::OK));
        assert!(d.is_none());
    }
}
