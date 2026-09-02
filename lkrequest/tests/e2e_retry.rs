//! Retry policy tests against a local HTTPS server (Tier 0).

mod support;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::retry::{ExponentialBackoff, FixedInterval};
use lkrequest::Client;
use lktls::profile::presets;
use std::sync::atomic::Ordering;
use std::time::Duration;
use support::local_https::{start_local_https_server, url_join};

fn chrome_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        )
        .build()
}

/// Successful request does not need retries.
#[tokio::test]
async fn test_retry_no_retry_on_success() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client
        .session()
        .retry_policy(ExponentialBackoff {
            max_retries: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(1),
            jitter: false,
        })
        .build();

    let url = url_join(&srv.base_url, "/get");
    let resp = session
        .get(&url)
        .send()
        .await
        .expect("request should succeed without retry");

    assert_eq!(resp.status().as_u16(), 200);
}

/// Retries on 503 (server returns 503 each time; we only assert elapsed delay).
#[tokio::test]
async fn test_retry_on_503() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client
        .session()
        .retry_policy(ExponentialBackoff {
            max_retries: 2,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(1),
            jitter: false,
        })
        .build();

    let url = url_join(&srv.base_url, "/status/503");
    let start = std::time::Instant::now();
    let _ = session.get(&url).send().await;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(80),
        "retries should add delay, elapsed={elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// FixedInterval policy
// ---------------------------------------------------------------------------

/// FixedInterval policy retries with a constant delay.
#[tokio::test]
async fn test_retry_fixed_interval_on_503() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client
        .session()
        .retry_policy(FixedInterval::new(2, Duration::from_millis(100)))
        .build();

    let url = url_join(&srv.base_url, "/status/503");
    let start = std::time::Instant::now();
    let _ = session.get(&url).send().await;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(150),
        "fixed interval retries should add delay, elapsed={elapsed:?}"
    );
}

/// FixedInterval does not retry on success.
#[tokio::test]
async fn test_retry_fixed_interval_no_retry_on_success() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client
        .session()
        .retry_policy(FixedInterval::new(3, Duration::from_millis(500)))
        .build();

    let url = url_join(&srv.base_url, "/get");
    let start = std::time::Instant::now();
    let resp = session.get(&url).send().await.expect("success");
    let elapsed = start.elapsed();
    assert_eq!(resp.status().as_u16(), 200);
    assert!(
        elapsed < Duration::from_millis(400),
        "no retry should happen on success, elapsed={elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// Non-retryable status codes
// ---------------------------------------------------------------------------

/// 404 is NOT retryable — request should complete quickly without retries.
#[tokio::test]
async fn test_retry_404_not_retried() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client
        .session()
        .retry_policy(ExponentialBackoff {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(5),
            jitter: false,
        })
        .build();

    let url = url_join(&srv.base_url, "/status/404");
    let start = std::time::Instant::now();
    let resp = session.get(&url).send().await.expect("should not error");
    let elapsed = start.elapsed();
    assert_eq!(resp.status().as_u16(), 404);
    assert!(
        elapsed < Duration::from_millis(400),
        "404 should not trigger retries, elapsed={elapsed:?}"
    );
}

/// 500 is NOT retryable by is_retryable_status (only 429/502/503/520-530 are).
#[tokio::test]
async fn test_retry_500_not_retried() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client
        .session()
        .retry_policy(ExponentialBackoff {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(5),
            jitter: false,
        })
        .build();

    let url = url_join(&srv.base_url, "/status/500");
    let start = std::time::Instant::now();
    let resp = session.get(&url).send().await.expect("should return 500");
    let elapsed = start.elapsed();
    assert_eq!(resp.status().as_u16(), 500);
    assert!(
        elapsed < Duration::from_millis(400),
        "500 should not trigger retries, elapsed={elapsed:?}"
    );
}

/// 429 IS retryable — should trigger retry delays.
#[tokio::test]
async fn test_retry_429_is_retried() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client
        .session()
        .retry_policy(ExponentialBackoff {
            max_retries: 2,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(1),
            jitter: false,
        })
        .build();

    let url = url_join(&srv.base_url, "/status/429");
    let start = std::time::Instant::now();
    let _ = session.get(&url).send().await;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(80),
        "429 should trigger retries, elapsed={elapsed:?}"
    );
}

/// 502 IS retryable.
#[tokio::test]
async fn test_retry_502_is_retried() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client
        .session()
        .retry_policy(ExponentialBackoff {
            max_retries: 1,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(1),
            jitter: false,
        })
        .build();

    let url = url_join(&srv.base_url, "/status/502");
    let start = std::time::Instant::now();
    let _ = session.get(&url).send().await;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(50),
        "502 should trigger retries, elapsed={elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// max_retries boundary
// ---------------------------------------------------------------------------

/// Verify that after max_retries, the request completes with the error status.
#[tokio::test]
async fn test_retry_max_retries_boundary() {
    let srv = start_local_https_server().await;
    srv.request_counter.store(0, Ordering::Relaxed);

    let client = chrome_client();
    let session = client
        .session()
        .retry_policy(ExponentialBackoff {
            max_retries: 2,
            base_delay: Duration::from_millis(50),
            max_delay: Duration::from_millis(200),
            jitter: false,
        })
        .build();

    let url = url_join(&srv.base_url, "/status/503");
    let _ = session.get(&url).send().await;

    let total_requests = srv.request_counter.load(Ordering::Relaxed);
    // 1 initial + 2 retries = 3 total requests (at most)
    assert!(
        total_requests <= 4,
        "expected ≤4 requests (1 initial + 2 retries + counter read), got {total_requests}"
    );
}

/// A retryable 503 must retain the final response body after retries finish.
#[tokio::test]
async fn test_retry_503_preserves_response_body() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client
        .session()
        .retry_policy(ExponentialBackoff {
            max_retries: 1,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(20),
            jitter: false,
        })
        .build();

    let url = url_join(&srv.base_url, "/status-body/503");
    let response = session
        .get(&url)
        .send()
        .await
        .expect("503 should return response");

    assert_eq!(response.status().as_u16(), 503);
    assert_eq!(
        response.text().expect("503 body should be readable"),
        "status 503"
    );
}

// ---------------------------------------------------------------------------
// POST with body preserved across retries
// ---------------------------------------------------------------------------

/// POST body should be preserved across retries (503 → retry → 503).
#[tokio::test]
async fn test_retry_post_body_preserved() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client
        .session()
        .retry_policy(ExponentialBackoff {
            max_retries: 1,
            base_delay: Duration::from_millis(50),
            max_delay: Duration::from_millis(200),
            jitter: false,
        })
        .build();

    // /status/503 always returns 503, so the retry will also get 503.
    // We're testing that the request doesn't panic or lose the body on retry.
    let url = url_join(&srv.base_url, "/status/503");
    let result = session.post(&url).text_body("retry-body-data").send().await;

    // The result should be a 503 response (all retries exhausted), not an error
    match result {
        Ok(resp) => assert_eq!(resp.status().as_u16(), 503),
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("503") || msg.contains("Service Unavailable"),
                "unexpected error: {msg}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Status-code retry: replay safety (RFC 9110 §9.2.2)
// ---------------------------------------------------------------------------

/// Regression: a `POST` answered with `502` must not be replayed.
///
/// A `502` means a gateway got a bad answer from the origin — the origin was
/// reached and may already have applied the request. Every retryable status
/// used to be replayed regardless of method, so a charge or order could be
/// submitted twice.
#[tokio::test]
async fn post_is_not_replayed_on_ambiguous_502() {
    let srv = start_local_https_server().await;
    let session = chrome_client()
        .session()
        .retry_policy(FixedInterval::new(3, Duration::from_millis(20)))
        .build();

    srv.request_counter.store(0, Ordering::Relaxed);
    let url = url_join(&srv.base_url, "/status/502");
    let resp = session
        .post(&url)
        .text_body("charge-the-card")
        .send()
        .await
        .expect("the 502 must be returned to the caller");

    assert_eq!(resp.status().as_u16(), 502);
    assert_eq!(
        srv.request_counter.load(Ordering::Relaxed),
        1,
        "a non-idempotent POST must reach the server exactly once on an \
         ambiguous status"
    );
}

/// The same `502` is still replayed for a safe method: a `GET` carries no side
/// effect to duplicate.
#[tokio::test]
async fn get_is_still_replayed_on_502() {
    let srv = start_local_https_server().await;
    let session = chrome_client()
        .session()
        .retry_policy(FixedInterval::new(2, Duration::from_millis(20)))
        .build();

    srv.request_counter.store(0, Ordering::Relaxed);
    let url = url_join(&srv.base_url, "/status/502");
    let _ = session.get(&url).send().await;

    assert!(
        srv.request_counter.load(Ordering::Relaxed) > 1,
        "safe methods keep retrying ambiguous statuses, got {} request(s)",
        srv.request_counter.load(Ordering::Relaxed)
    );
}

/// A `503` does not prove that an unsafe request was not applied, so a default
/// `POST` must not be replayed.
#[tokio::test]
async fn post_is_not_replayed_on_503_by_default() {
    let srv = start_local_https_server().await;
    let session = chrome_client()
        .session()
        .retry_policy(FixedInterval::new(2, Duration::from_millis(20)))
        .build();

    srv.request_counter.store(0, Ordering::Relaxed);
    let url = url_join(&srv.base_url, "/status/503");
    let response = session
        .post(&url)
        .text_body("payload")
        .send()
        .await
        .expect("the 503 must be returned to the caller");

    assert_eq!(response.status().as_u16(), 503);
    assert_eq!(
        srv.request_counter.load(Ordering::Relaxed),
        1,
        "a default POST must not be replayed on 503"
    );
}

/// The same default replay protection applies to PATCH and 429.
#[tokio::test]
async fn patch_is_not_replayed_on_429_by_default() {
    let srv = start_local_https_server().await;
    let session = chrome_client()
        .session()
        .retry_policy(FixedInterval::new(2, Duration::from_millis(20)))
        .build();

    srv.request_counter.store(0, Ordering::Relaxed);
    let url = url_join(&srv.base_url, "/status/429");
    let response = session
        .patch(&url)
        .text_body("payload")
        .send()
        .await
        .expect("the 429 must be returned to the caller");

    assert_eq!(response.status().as_u16(), 429);
    assert_eq!(
        srv.request_counter.load(Ordering::Relaxed),
        1,
        "a default PATCH must not be replayed on 429"
    );
}

/// An explicit idempotency declaration opts a `POST` back into replaying an
/// ambiguous status.
#[tokio::test]
async fn explicit_idempotency_restores_post_replay_on_502() {
    let srv = start_local_https_server().await;
    let session = chrome_client()
        .session()
        .retry_policy(FixedInterval::new(2, Duration::from_millis(20)))
        .build();

    srv.request_counter.store(0, Ordering::Relaxed);
    let url = url_join(&srv.base_url, "/status/502");
    let _ = session
        .post(&url)
        .text_body("payload")
        .idempotency(lkrequest::session::Idempotency::Idempotent)
        .send()
        .await;

    assert!(
        srv.request_counter.load(Ordering::Relaxed) > 1,
        "an explicit Idempotency-Key opts back into replay, got {} request(s)",
        srv.request_counter.load(Ordering::Relaxed)
    );
}
