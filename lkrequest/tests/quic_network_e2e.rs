use lkrequest::{Client, HttpVersion};

// Tier-2 (public network): off by default per docs/TESTING.md, so normal
// CI runs don't fail without internet. Run with
// `--include-ignored` when validating against the real network.
#[tokio::test]
#[ignore = "Tier-2: hits cloudflare-quic.com; run with --include-ignored"]
async fn cloudflare_quic_homepage_uses_h3() {
    let client = Client::builder()
        .fingerprint(lktls::profile::presets::chrome_144())
        .quic_profile(lkh3::chrome_quic())
        .build();

    let session = client.session().http3_only().build();
    let response = session
        .get("https://cloudflare-quic.com/")
        .send()
        .await
        .expect("cloudflare h3 request should succeed");

    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(response.version(), HttpVersion::H3);
    assert!(
        response
            .text()
            .expect("response must be valid utf-8")
            .contains("HTTP/3"),
        "expected Cloudflare QUIC page to mention HTTP/3"
    );
}
