use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use lkrequest::{Client, DnsResolver, HttpVersion, QuicProfile};

mod support;

const CLOUDFLARE_HOST: &str = "www.cloudflare.com";
const CLOUDFLARE_URL: &str = "https://www.cloudflare.com/cdn-cgi/trace";
const LITESPEED_HOST: &str = "www.litespeedtech.com";
const LITESPEED_URL: &str = "https://www.litespeedtech.com/";
const PREFLIGHT_ATTEMPTS: usize = 3;
const LITESPEED_ATTEMPTS: usize = 12;
const LITESPEED_REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

struct FixedHostDns {
    host: &'static str,
    ip: IpAddr,
}

#[async_trait]
impl DnsResolver for FixedHostDns {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        if host != self.host {
            return Err(std::io::Error::other(format!(
                "the fixed test resolver for {} cannot resolve {host}",
                self.host
            )));
        }
        Ok(vec![SocketAddr::new(self.ip, port)])
    }
}

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

#[tokio::test]
#[ignore = "Tier-2: requires public QUIC access; set TEST_ALLOW_NETWORK=1 and run with --include-ignored"]
async fn chrome_154_cloudflare_quic_uses_h3() {
    if !support::test_allow_network() {
        eprintln!("skipped: set TEST_ALLOW_NETWORK=1 to run");
        return;
    }

    let client = Client::builder()
        .preset(lkrequest::preset::chrome_154())
        .build();
    let session = client.session().http3_only().build();
    let response = tokio::time::timeout(
        Duration::from_secs(20),
        session.get("https://cloudflare-quic.com/").send(),
    )
    .await
    .expect("Chrome 154 public H3 request timed out")
    .expect("Chrome 154 public H3 request failed");

    assert!(response.status().is_success());
    assert_eq!(response.version(), HttpVersion::H3);
}

async fn h3_attempt(
    mut profile: QuicProfile,
    chaos: bool,
    host: &'static str,
    url: &'static str,
    dial_ip: Option<IpAddr>,
) -> Result<String, String> {
    profile.packetization.initial_packet_chaos = chaos;
    let mut client = Client::builder()
        .preset(lkrequest::preset::chrome_153())
        .quic_profile(profile);
    if let Some(ip) = dial_ip {
        client = client.dns_resolver(Arc::new(FixedHostDns { host, ip }));
    }
    let client = client.build();
    let session = client.session().http3_only().build();

    match tokio::time::timeout(LITESPEED_REQUEST_TIMEOUT, session.get(url).send()).await {
        Ok(Ok(response))
            if response.status().is_success() && response.version() == HttpVersion::H3 =>
        {
            Ok(format!("{} {}", response.status(), response.version()))
        }
        Ok(Ok(response)) => Err(format!(
            "unexpected response: {} {}",
            response.status(),
            response.version()
        )),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err(format!("timed out after {LITESPEED_REQUEST_TIMEOUT:?}")),
    }
}

async fn require_h3_preflight(
    label: &str,
    profile: &QuicProfile,
    chaos: bool,
    host: &'static str,
    url: &'static str,
    dial_ip: Option<IpAddr>,
) {
    let mut failures = Vec::new();
    for attempt in 1..=PREFLIGHT_ATTEMPTS {
        match h3_attempt(profile.clone(), chaos, host, url, dial_ip).await {
            Ok(result) => {
                eprintln!("{label} preflight {attempt:02} chaos={chaos}: {result}");
                return;
            }
            Err(error) => {
                eprintln!("{label} preflight {attempt:02} chaos={chaos}: ERR {error}");
                failures.push(format!("attempt {attempt:02}: {error}"));
            }
        }
    }
    panic!("{label} did not establish an H3 baseline with chaos={chaos}: {failures:#?}");
}

#[tokio::test]
#[ignore = "Tier-2: opens fresh H3 connections to Cloudflare and LiteSpeed; set TEST_ALLOW_NETWORK=1 and run with --include-ignored"]
async fn litespeed_accepts_chrome_153_initial_packet_chaos() {
    if !support::test_allow_network() {
        eprintln!("skipped: set TEST_ALLOW_NETWORK=1 to run");
        return;
    }

    let profile = lkh3::chrome_153_quic();
    let parse_ip = |name: &str| {
        std::env::var(name).ok().map(|value| {
            value
                .parse::<IpAddr>()
                .unwrap_or_else(|error| panic!("invalid {name} {value:?}: {error}"))
        })
    };
    let cloudflare_ip = parse_ip("TEST_CLOUDFLARE_IP");
    let litespeed_ip = parse_ip("TEST_LITESPEED_IP");
    if let Some(ip) = cloudflare_ip {
        eprintln!("using TEST_CLOUDFLARE_IP={ip} instead of the system resolver");
    }
    if let Some(ip) = litespeed_ip {
        eprintln!("using TEST_LITESPEED_IP={ip} instead of the system resolver");
    }

    require_h3_preflight(
        "Cloudflare",
        &profile,
        false,
        CLOUDFLARE_HOST,
        CLOUDFLARE_URL,
        cloudflare_ip,
    )
    .await;
    require_h3_preflight(
        "Cloudflare",
        &profile,
        true,
        CLOUDFLARE_HOST,
        CLOUDFLARE_URL,
        cloudflare_ip,
    )
    .await;
    require_h3_preflight(
        "LiteSpeed",
        &profile,
        false,
        LITESPEED_HOST,
        LITESPEED_URL,
        litespeed_ip,
    )
    .await;

    let mut control_failures = Vec::new();
    let mut chaos_failures = Vec::new();

    for attempt in 1..=LITESPEED_ATTEMPTS {
        // Alternate the order so a temporary target or path change does not
        // consistently favor either side of the comparison.
        for chaos in [attempt % 2 == 0, attempt % 2 != 0] {
            let label = if chaos { "chaos=on " } else { "chaos=off" };
            match h3_attempt(
                profile.clone(),
                chaos,
                LITESPEED_HOST,
                LITESPEED_URL,
                litespeed_ip,
            )
            .await
            {
                Ok(result) => eprintln!("attempt {attempt:02} {label}: {result}"),
                Err(error) => {
                    eprintln!("attempt {attempt:02} {label}: ERR {error}");
                    if chaos {
                        chaos_failures.push(format!("attempt {attempt:02}: {error}"));
                    } else {
                        control_failures.push(format!("attempt {attempt:02}: {error}"));
                    }
                }
            }
        }
    }

    assert!(
        control_failures.len() <= 1,
        "the no-chaos control could not establish a stable LiteSpeed baseline: {control_failures:#?}"
    );
    assert!(
        chaos_failures.is_empty(),
        "Chrome 153 Initial packet chaos must interoperate with LiteSpeed; failures: {chaos_failures:#?}"
    );
}
