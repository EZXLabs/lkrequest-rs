//! Public-origin interoperability probes for passive fingerprint comparisons.
//! These tests print protocol/status metadata only. Capture analysis supplies
//! the independent wire evidence; HTTP success alone is not fingerprint proof.

use std::time::Duration;

use lkrequest::{Client, HttpVersion};

const CHROME_HEADERS: &[(&str, &str)] = &[
    ("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"),
    ("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8"),
    ("sec-fetch-site", "none"), ("sec-fetch-mode", "navigate"),
    ("sec-fetch-dest", "document"), ("priority", "u=0, i"),
];
const FIREFOX_HEADERS: &[(&str, &str)] = &[
    (
        "user-agent",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0",
    ),
    (
        "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ),
    ("sec-fetch-site", "none"),
    ("sec-fetch-mode", "navigate"),
    ("sec-fetch-dest", "document"),
    ("priority", "u=0, i"),
];

fn capture_client(mut builder: lkrequest::client::ClientBuilder) -> Client {
    if let Some(path) = std::env::var_os("FINGERPRINT_CAPTURE_KEYLOG") {
        let path = std::path::PathBuf::from(path);
        assert!(path.is_absolute());
        builder =
            builder.keylog(lkrequest::keylog_to_file(path).expect("temporary capture keylog"));
    }
    builder.build()
}

async fn fresh_navigations(
    protocol: HttpVersion,
    preset: lkrequest::preset::ClientPreset,
    headers: &[(&str, &str)],
) -> Vec<HttpVersion> {
    assert_eq!(std::env::var("TEST_ALLOW_NETWORK").as_deref(), Ok("1"));
    let client = capture_client(Client::builder().preset(preset));
    let mut negotiated = Vec::new();
    for index in 0..4 {
        let builder = client.session();
        let session = match protocol {
            HttpVersion::H2 => builder.http2_only().build(),
            #[cfg(feature = "quic-h3")]
            HttpVersion::H3 => builder.http3_only().build(),
            _ => panic!("unsupported capture protocol"),
        };
        let response = session
            .get("https://www.cloudflare.com/cdn-cgi/trace")
            .headers_ordered(headers.iter().copied())
            .timeout(Duration::from_secs(20))
            .send()
            .await
            .expect("public navigation succeeds");
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.version(), protocol);
        negotiated.push(response.version());
        assert!(!response.text().expect("consume response body").is_empty());
        println!("fresh session {index}: {protocol:?}, status 200");
    }
    negotiated
}

#[tokio::test]
#[ignore = "Tier-2: public Cloudflare; TEST_ALLOW_NETWORK=1 and passive capture"]
async fn chrome_155_fresh_h2_navigations() {
    assert_eq!(
        fresh_navigations(
            HttpVersion::H2,
            lkrequest::preset::chrome_155(),
            CHROME_HEADERS
        )
        .await,
        [HttpVersion::H2; 4]
    );
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
#[ignore = "Tier-2: public Cloudflare; TEST_ALLOW_NETWORK=1 and passive capture"]
async fn chrome_155_fresh_h3_navigations() {
    assert_eq!(
        fresh_navigations(
            HttpVersion::H3,
            lkrequest::preset::chrome_155(),
            CHROME_HEADERS
        )
        .await,
        [HttpVersion::H3; 4]
    );
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
#[ignore = "Tier-2: public Cloudflare; TEST_ALLOW_NETWORK=1 and passive capture"]
async fn chrome_155_h3_auto_priority_switch() {
    assert_eq!(std::env::var("TEST_ALLOW_NETWORK").as_deref(), Ok("1"));
    for automatic in [false, true] {
        let mut preset = lkrequest::preset::chrome_155();
        preset.h2_profile.priority_config.auto_priority_header = automatic;
        let client = capture_client(Client::builder().preset(preset));
        let session = client.session().http3_only().build();
        for index in 0..4 {
            let mut request = session
                .get("https://www.cloudflare.com/cdn-cgi/trace")
                .headers_ordered(
                    CHROME_HEADERS
                        .iter()
                        .copied()
                        .filter(|(name, _)| *name != "priority"),
                )
                .timeout(Duration::from_secs(20));
            if index >= 2 {
                request = request.header("priority", "u=4");
            }
            if index % 2 == 0 {
                let response = request.send().await.unwrap();
                assert_eq!(response.status().as_u16(), 200);
                assert_eq!(response.version(), HttpVersion::H3);
                assert!(!response.bytes().is_empty());
            } else {
                let response = request.send_streaming().await.unwrap();
                assert_eq!(response.status().as_u16(), 200);
                assert!(!response.bytes().await.unwrap().is_empty());
            }
            println!("H3 automatic={automatic}, request={index}, status 200");
        }
    }
}

#[cfg(feature = "quic-h3")]
#[tokio::test]
#[ignore = "Tier-2: public Cloudflare; TEST_ALLOW_NETWORK=1 and passive capture"]
async fn chrome_155_h3_navigation_and_favicon_control_updates() {
    assert_eq!(std::env::var("TEST_ALLOW_NETWORK").as_deref(), Ok("1"));
    let client = capture_client(Client::builder().preset(lkrequest::preset::chrome_155()));
    let session = client.session().http3_only().build();
    for favicon in [false, true] {
        let request = session
            .get(if favicon {
                "https://www.cloudflare.com/favicon.ico"
            } else {
                "https://www.cloudflare.com/cdn-cgi/trace"
            })
            .headers_ordered(CHROME_HEADERS.iter().copied());
        let request = if favicon {
            request
                .header("priority", "u=1, i")
                .header("sec-fetch-dest", "image")
                .header("sec-fetch-mode", "no-cors")
        } else {
            request
        };
        let response = request
            .timeout(Duration::from_secs(20))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.version(), HttpVersion::H3);
        assert!(!response.bytes().is_empty());
        println!("H3 favicon={favicon}, status 200; control updates require packet analysis");
    }
}

#[tokio::test]
#[ignore = "Tier-2: public Cloudflare; TEST_ALLOW_NETWORK=1 and passive capture"]
async fn firefox_156_fresh_h2_navigations() {
    assert_eq!(
        fresh_navigations(
            HttpVersion::H2,
            lkrequest::preset::firefox_156(),
            FIREFOX_HEADERS
        )
        .await,
        [HttpVersion::H2; 4]
    );
}

#[tokio::test]
#[ignore = "Tier-2: public Cloudflare; TEST_ALLOW_NETWORK=1 and passive capture"]
async fn chrome_155_reused_h2_navigation_and_favicon() {
    assert_eq!(std::env::var("TEST_ALLOW_NETWORK").as_deref(), Ok("1"));
    let builder = Client::builder()
        .preset(lkrequest::preset::chrome_155())
        .default_header("user-agent", CHROME_HEADERS[0].1)
        .default_header("accept", CHROME_HEADERS[1].1)
        .default_header("sec-fetch-site", "none")
        .default_header("sec-fetch-mode", "navigate")
        .default_header("sec-fetch-dest", "document");
    let client = capture_client(builder);
    let session = client.session().http2_only().build();
    let first = session
        .get("https://www.cloudflare.com/cdn-cgi/trace")
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .expect("navigation succeeds");
    assert_eq!(first.status().as_u16(), 200);
    assert_eq!(first.version(), HttpVersion::H2);
    assert!(!first.bytes().is_empty());
    let second = session
        .get("https://www.cloudflare.com/favicon.ico")
        .header("sec-fetch-mode", "no-cors")
        .header("sec-fetch-dest", "image")
        .header("priority", "u=1, i")
        .timeout(Duration::from_secs(20))
        .send()
        .await
        .expect("favicon succeeds");
    assert_eq!(second.status().as_u16(), 200);
    assert_eq!(second.version(), HttpVersion::H2);
    assert!(!second.bytes().is_empty());
    println!(
        "navigation and favicon: H2, status 200; navigation priority derived from client defaults"
    );
}

#[tokio::test]
#[ignore = "Tier-2: public Cloudflare; TEST_ALLOW_NETWORK=1 and passive capture"]
async fn firefox_156_reused_h2_navigation_and_favicon() {
    assert_eq!(std::env::var("TEST_ALLOW_NETWORK").as_deref(), Ok("1"));
    let client = capture_client(
        Client::builder()
            .preset(lkrequest::preset::firefox_156())
            .default_header("user-agent", FIREFOX_HEADERS[0].1)
            .default_header("accept", FIREFOX_HEADERS[1].1)
            .default_header("sec-fetch-mode", "navigate")
            .default_header("sec-fetch-dest", "document"),
    );
    let session = client.session().http2_only().build();
    for (url, favicon) in [
        ("https://www.cloudflare.com/cdn-cgi/trace", false),
        ("https://www.cloudflare.com/favicon.ico", true),
    ] {
        let mut request = session.get(url);
        if favicon {
            request = request
                .header("sec-fetch-mode", "no-cors")
                .header("sec-fetch-dest", "image")
                .header("priority", "u=6")
                .h2_priority_weight(21);
        }
        let response = request
            .timeout(Duration::from_secs(20))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.version(), HttpVersion::H2);
        assert!(!response.bytes().is_empty());
    }
    println!("Firefox navigation and favicon: H2, status 200");
}
