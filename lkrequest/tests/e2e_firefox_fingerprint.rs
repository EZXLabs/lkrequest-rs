//! Firefox 147 and 156 full-stack TLS + H2 fingerprint verification tests.
//!
//! Verifies JA3/JA4 (TLS-layer) and Akamai H2 hash against real Firefox 147
//! reference data captured from `tlsleak/firefox147.0.3_tlsleak.json`.
//!
//! Requires network access to tls.browserleaks.com.

#[macro_use]
mod support;

use lkrequest::h2::profile::firefox_147_h2;
use lkrequest::{Client, HttpVersion, Session};
use lktls::profile::presets;
use support::MAX_RETRIES;

/// Override via `TEST_PROXY` env var (e.g. in CI: `TEST_PROXY=http://proxy.example.com:8080`).
fn proxy() -> String {
    support::test_proxy()
}

/// Reference fingerprints from real Firefox 147.0.3 (captured via browserleaks).
const EXPECTED_JA3_HASH: &str = "6f7889b9fb1a62a9577e685c1fcfa919";
const EXPECTED_JA4_PREFIX: &str = "t13d1717h2";
const EXPECTED_AKAMAI_TEXT: &str = "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s";
const EXPECTED_AKAMAI_HASH: &str = "6ea73faa8fc5aac76bded7bd238f6433";
const FIREFOX_156_JA3_HASH: &str = "9d42e90b0225e779f03141ddcd699df2";
const FIREFOX_156_JA4_PREFIX: &str = "t13d1517h2";

fn firefox_147_client() -> Client {
    Client::builder()
        .fingerprint(presets::firefox_147())
        .h2_profile(firefox_147_h2())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0",
        )
        .default_header(
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .default_header("accept-language", "en-US,en;q=0.5")
        .build()
}

fn firefox_156_client() -> Client {
    Client::builder()
        .preset(lkrequest::preset::firefox_156())
        .default_header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0",
        )
        .default_header(
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .default_header("accept-language", "en-US,en;q=0.5")
        .build()
}

fn proxied_session(client: &Client) -> Session {
    client.session().proxy(&proxy()).build()
}

/// Full-stack fingerprint: JA3 + JA4 + Akamai H2 for Firefox 147.
#[tokio::test]
#[ignore = "Tier-2: tls.browserleaks.com via proxy"]
async fn test_firefox147_full_stack_fingerprint() {
    let client = firefox_147_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/json").send(),
        "request should succeed"
    );

    assert_eq!(resp.status().as_u16(), 200, "expected HTTP 200");

    let json: serde_json::Value = resp.json().expect("should deserialize as JSON");

    // TLS fingerprint (JA3)
    let ja3_hash = json["ja3_hash"]
        .as_str()
        .expect("response missing 'ja3_hash'");
    println!("Firefox 147 JA3 hash: {ja3_hash}");
    assert_eq!(
        ja3_hash, EXPECTED_JA3_HASH,
        "JA3 hash mismatch — TLS fingerprint does not match Firefox 147"
    );

    // TLS fingerprint (JA4)
    let ja4 = json["ja4"].as_str().expect("response missing 'ja4'");
    println!("Firefox 147 JA4:      {ja4}");
    assert!(
        ja4.starts_with(EXPECTED_JA4_PREFIX),
        "JA4 prefix mismatch — expected {EXPECTED_JA4_PREFIX}..., got: {ja4}"
    );

    // HTTP/2 fingerprint (Akamai)
    let akamai_text = json["akamai_text"]
        .as_str()
        .expect("response missing 'akamai_text'");
    let akamai_hash = json["akamai_hash"]
        .as_str()
        .expect("response missing 'akamai_hash'");
    println!("Firefox 147 Akamai FP:   {akamai_text}");
    println!("Firefox 147 Akamai hash: {akamai_hash}");

    assert_eq!(
        akamai_text, EXPECTED_AKAMAI_TEXT,
        "Akamai H2 fingerprint text does not match Firefox 147"
    );
    assert_eq!(
        akamai_hash, EXPECTED_AKAMAI_HASH,
        "Akamai H2 hash does not match Firefox 147"
    );

    println!("\n=== PASSED: Full-stack Firefox 147 fingerprint (TLS + H2) verified! ===");
}

#[tokio::test]
#[ignore = "Tier-2: tls.browserleaks.com via proxy"]
async fn test_firefox156_full_stack_fingerprint() {
    let client = firefox_156_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/json").send(),
        "request should succeed"
    );
    assert_eq!(resp.status().as_u16(), 200, "expected HTTP 200");
    let json: serde_json::Value = resp.json().expect("should deserialize as JSON");

    assert_eq!(json["ja3_hash"], FIREFOX_156_JA3_HASH);
    assert!(json["ja4"]
        .as_str()
        .expect("response missing ja4")
        .starts_with(FIREFOX_156_JA4_PREFIX));
    assert_eq!(json["akamai_text"], EXPECTED_AKAMAI_TEXT);
    assert_eq!(json["akamai_hash"], EXPECTED_AKAMAI_HASH);
}

#[tokio::test]
#[ignore = "Tier-2: public Cloudflare; set TEST_ALLOW_NETWORK=1"]
async fn test_firefox156_complete_preset_reaches_public_h2() {
    if !support::test_allow_network() {
        eprintln!("skipped: set TEST_ALLOW_NETWORK=1 to run");
        return;
    }

    let client = firefox_156_client();
    let session = client.session().http2_only().build();
    let response = session
        .get("https://www.cloudflare.com/cdn-cgi/trace")
        .send()
        .await
        .expect("Firefox 156 public H2 request failed");
    assert!(response.status().is_success());
    assert_eq!(response.version(), HttpVersion::H2);
}

/// Verify JA3 full string structure.
#[tokio::test]
#[ignore = "Tier-2: tls.browserleaks.com via proxy"]
async fn test_firefox147_ja3_full_string() {
    let client = firefox_147_client();
    let session = proxied_session(&client);

    let resp = retry!(
        MAX_RETRIES,
        session.get("https://tls.browserleaks.com/json").send(),
        "request should succeed"
    );

    let json: serde_json::Value = resp.json().expect("should be JSON");

    let ja3_text = json["ja3_text"].as_str().unwrap_or("N/A");
    println!("Firefox 147 JA3 full: {ja3_text}");

    assert!(
        ja3_text.starts_with("771,"),
        "JA3 should start with version 771"
    );
    // Firefox should include CBC suites (47=AES_128_CBC_SHA, 53=AES_256_CBC_SHA)
    assert!(
        ja3_text.contains("47") || ja3_text.contains("53"),
        "Firefox JA3 should include legacy CBC cipher suites"
    );
}
