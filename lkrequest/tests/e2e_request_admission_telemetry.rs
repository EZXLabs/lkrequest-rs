#![cfg(feature = "telemetry")]

use std::time::Duration;

use lkrequest::Client;

#[tokio::test]
async fn expired_admission_counts_both_public_request_entries() {
    let session = Client::builder()
        .total_timeout(Duration::ZERO)
        .build()
        .session()
        .build();
    let before = lkrequest::telemetry::metrics_snapshot();

    let buffered = session.get("http://127.0.0.1:1/").send().await;
    assert!(buffered.is_err_and(|error| error.is_timeout()));
    let streaming = session.get("http://127.0.0.1:1/").send_streaming().await;
    assert!(streaming.is_err_and(|error| error.is_timeout()));

    let after = lkrequest::telemetry::metrics_snapshot();
    assert_eq!(after.requests_total - before.requests_total, 2);
    assert_eq!(after.requests_failed - before.requests_failed, 2);
    assert_eq!(after.total_connections, before.total_connections);
}
