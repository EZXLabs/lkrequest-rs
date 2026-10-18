//! Tier-0 redirect header safety and raw UTF-8 Location regressions.

mod support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use lkrequest::{Client, RedirectPolicy, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const BOUND: Duration = Duration::from_secs(4);
const FAKE_AUTH: &str = "Bearer FAKE_WREQ_AUDIT";
const FAKE_COOKIE: &str = "fixture_session=FAKE_WREQ_AUDIT";

#[derive(Clone)]
struct ObservedRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
}

impl ObservedRequest {
    fn values(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }
}

struct Fixture {
    base_url: String,
    observed: Arc<Mutex<Vec<ObservedRequest>>>,
    task: Option<JoinHandle<()>>,
}

impl Fixture {
    async fn start(reply: impl Fn(&ObservedRequest) -> Vec<u8> + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let observed = Arc::new(Mutex::new(Vec::new()));
        let records = Arc::clone(&observed);
        let task = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                tokio::time::timeout(BOUND, async {
                    while !bytes.ends_with(b"\r\n\r\n") {
                        assert!(bytes.len() < 16_384, "oversized fixture request head");
                        bytes.push(stream.read_u8().await.unwrap());
                    }
                })
                .await
                .expect("fixture request head timeout");
                let head = std::str::from_utf8(&bytes).unwrap();
                let mut lines = head.split("\r\n");
                let mut request_line = lines.next().unwrap().split_whitespace();
                let method = request_line.next().unwrap().to_owned();
                let target = request_line.next().unwrap().to_owned();
                let headers = lines
                    .take_while(|line| !line.is_empty())
                    .map(|line| {
                        let (name, value) = line.split_once(':').unwrap();
                        (name.to_ascii_lowercase(), value.trim().to_owned())
                    })
                    .collect();
                let request = ObservedRequest {
                    method,
                    target,
                    headers,
                };
                let response = reply(&request);
                records.lock().unwrap().push(request);
                tokio::time::timeout(BOUND, stream.write_all(&response))
                    .await
                    .expect("fixture response timeout")
                    .unwrap();
                tokio::time::timeout(BOUND, stream.shutdown())
                    .await
                    .expect("fixture shutdown timeout")
                    .unwrap();
            }
        });
        Self {
            base_url,
            observed,
            task: Some(task),
        }
    }

    async fn finish(mut self) -> Vec<ObservedRequest> {
        let task = self.task.take().unwrap();
        task.abort();
        if let Err(error) = tokio::time::timeout(BOUND, task)
            .await
            .expect("fixture task did not stop")
        {
            assert!(error.is_cancelled(), "fixture task panicked");
        }
        let observed = self.observed.lock().unwrap().clone();
        observed
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn ok_response() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".to_vec()
}

fn redirect_response(location: &[u8]) -> Vec<u8> {
    let mut response = b"HTTP/1.1 302 Found\r\nLocation: ".to_vec();
    response.extend_from_slice(location);
    response.extend_from_slice(b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    response
}

async fn send(request: lkrequest::session::RequestBuilder) -> lkrequest::error::Result<Response> {
    tokio::time::timeout(BOUND, request.send())
        .await
        .expect("fixture client request timeout")
}

#[tokio::test]
async fn raw_utf8_location_is_followed_with_percent_encoded_control() {
    let raw = Fixture::start(|request| {
        if request.target == "/start" {
            redirect_response(b"/caf\xc3\xa9")
        } else {
            ok_response()
        }
    })
    .await;
    let session = Client::builder()
        .build()
        .session()
        .http1_only()
        .redirect_policy(RedirectPolicy::Follow(3))
        .build();
    let result = send(session.get(&format!("{}/start", raw.base_url))).await;
    let raw_seen = raw.finish().await;
    let response = result.expect("valid UTF-8 Location must be resolved");
    assert_eq!(response.status(), 200);
    assert_eq!(raw_seen.len(), 2);
    assert_eq!(raw_seen[1].target, "/caf%C3%A9");

    let encoded = Fixture::start(|request| {
        if request.target == "/start" {
            redirect_response(b"/caf%C3%A9")
        } else {
            ok_response()
        }
    })
    .await;
    let response = send(session.get(&format!("{}/start", encoded.base_url)))
        .await
        .expect("percent-encoded Location must redirect successfully");
    assert_eq!(response.status(), 200);
    let encoded_seen = encoded.finish().await;
    assert_eq!(encoded_seen.len(), 2);
    assert_eq!(encoded_seen[1].target, "/caf%C3%A9");
}

#[tokio::test]
async fn cross_origin_redirect_does_not_reapply_default_sensitive_headers() {
    let target = Fixture::start(|_| ok_response()).await;
    let target_url = format!(
        "{}/landing",
        target.base_url.replace("127.0.0.1", "localhost")
    );
    let source = Fixture::start(move |_| redirect_response(target_url.as_bytes())).await;
    assert_ne!(source.base_url, target.base_url);

    let defaults_session = Client::builder()
        .default_header("authorization", FAKE_AUTH)
        .default_header("cookie", FAKE_COOKIE)
        .default_header("host", "fixture.invalid")
        .build()
        .session()
        .http1_only()
        .build();
    let response = send(defaults_session.get(&format!("{}/start", source.base_url)))
        .await
        .expect("default-header redirect fixture request");
    assert_eq!(response.status(), 200);

    let request_session = Client::builder().build().session().http1_only().build();
    let response = send(
        request_session
            .get(&format!("{}/start", source.base_url))
            .header("authorization", FAKE_AUTH)
            .header("cookie", FAKE_COOKIE),
    )
    .await
    .expect("request-header redirect control");
    assert_eq!(response.status(), 200);

    let response = send(defaults_session.get(&format!("{}/direct", target.base_url)))
        .await
        .expect("a new explicit request must retain the original client defaults");
    assert_eq!(response.status(), 200);

    let source_seen = source.finish().await;
    let target_seen = target.finish().await;
    assert_eq!(source_seen.len(), 2);
    assert_eq!(target_seen.len(), 3);
    for request in &source_seen {
        assert_eq!(request.values("authorization"), vec![FAKE_AUTH]);
        assert_eq!(request.values("cookie"), vec![FAKE_COOKIE]);
    }
    assert!(target_seen[0].values("authorization").is_empty());
    assert!(target_seen[0].values("cookie").is_empty());
    assert!(target_seen[0].values("host")[0].starts_with("localhost:"));
    assert!(target_seen[1].values("authorization").is_empty());
    assert!(target_seen[1].values("cookie").is_empty());
    assert_eq!(target_seen[2].values("authorization"), vec![FAKE_AUTH]);
    assert_eq!(target_seen[2].values("cookie"), vec![FAKE_COOKIE]);
}

#[tokio::test]
async fn same_origin_keeps_authorization_and_rebuilds_cookies_from_the_jar() {
    let server = Fixture::start(|request| {
        if request.target == "/start" {
            b"HTTP/1.1 302 Found\r\nLocation: /landing\r\nSet-Cookie: server=fresh; Path=/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
        } else {
            ok_response()
        }
    })
    .await;
    let session = Client::builder()
        .default_header("authorization", FAKE_AUTH)
        .default_header("cookie", FAKE_COOKIE)
        .build()
        .session()
        .http1_only()
        .build();
    send(session.get(&format!("{}/start", server.base_url)))
        .await
        .unwrap();
    let observed = server.finish().await;
    assert_eq!(observed.len(), 2);
    assert_eq!(observed[1].values("authorization"), vec![FAKE_AUTH]);
    let expected_cookie = format!("{FAKE_COOKIE}; server=fresh");
    assert_eq!(observed[1].values("cookie"), vec![expected_cookie.as_str()]);
}

#[tokio::test]
async fn body_header_defaults_follow_the_redirect_method_rewrite() {
    for status in [302, 307] {
        let server = Fixture::start(move |request| {
            if request.target == "/start" {
                format!("HTTP/1.1 {status} Redirect\r\nLocation: /landing\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
            } else {
                ok_response()
            }
        })
        .await;
        let session = Client::builder()
            .default_header("content-type", "application/fixture")
            .default_header("content-encoding", "identity")
            .default_header("content-language", "en")
            .default_header("content-location", "/original")
            .default_header("content-length", "0")
            .build()
            .session()
            .http1_only()
            .build();
        send(session.post(&format!("{}/start", server.base_url)))
            .await
            .unwrap();
        let observed = server.finish().await;
        assert_eq!(observed.len(), 2);
        assert_eq!(
            observed[1].method,
            if status == 302 { "GET" } else { "POST" }
        );
        for name in [
            "content-type",
            "content-encoding",
            "content-language",
            "content-location",
            "content-length",
        ] {
            assert_eq!(
                observed[1].values(name).is_empty(),
                status == 302,
                "status {status}, header {name}"
            );
        }
    }
}

#[tokio::test]
async fn invalid_utf8_location_is_an_explicit_url_error() {
    let server = Fixture::start(|_| redirect_response(b"/invalid\xff")).await;
    let session = Client::builder().build().session().http1_only().build();
    let error = send(session.get(&format!("{}/start", server.base_url)))
        .await
        .unwrap_err();
    assert!(
        matches!(error, lkrequest::error::Error::UrlParse(ref message)
        if message.contains("Location is not valid UTF-8"))
    );
    assert_eq!(server.finish().await.len(), 1);
}

#[tokio::test]
async fn returning_to_the_original_origin_does_not_restore_stripped_defaults() {
    let return_url = Arc::new(Mutex::new(String::new()));
    let next_url = Arc::clone(&return_url);
    let target =
        Fixture::start(move |_| redirect_response(next_url.lock().unwrap().as_bytes())).await;
    let target_url = format!(
        "{}/middle",
        target.base_url.replace("127.0.0.1", "localhost")
    );
    let source = Fixture::start(move |request| {
        if request.target == "/start" {
            redirect_response(target_url.as_bytes())
        } else {
            ok_response()
        }
    })
    .await;
    *return_url.lock().unwrap() = format!("{}/returned", source.base_url);
    let session = Client::builder()
        .default_header("authorization", FAKE_AUTH)
        .default_header("cookie", FAKE_COOKIE)
        .build()
        .session()
        .http1_only()
        .build();
    send(session.get(&format!("{}/start", source.base_url)))
        .await
        .unwrap();
    let source_seen = source.finish().await;
    let target_seen = target.finish().await;
    assert_eq!(source_seen.len(), 2);
    assert_eq!(target_seen.len(), 1);
    assert_eq!(source_seen[0].values("authorization"), vec![FAKE_AUTH]);
    for request in [&source_seen[1], &target_seen[0]] {
        assert!(request.values("authorization").is_empty());
        assert!(request.values("cookie").is_empty());
    }
}

#[tokio::test]
async fn outer_retry_restores_initial_defaults_without_forwarding_them_to_the_redirect() {
    let attempts = std::sync::atomic::AtomicUsize::new(0);
    let target = Fixture::start(move |_| {
        if attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
        } else {
            ok_response()
        }
    })
    .await;
    let target_url = format!(
        "{}/landing",
        target.base_url.replace("127.0.0.1", "localhost")
    );
    let source = Fixture::start(move |_| redirect_response(target_url.as_bytes())).await;
    let session = Client::builder()
        .default_header("authorization", FAKE_AUTH)
        .default_header("cookie", FAKE_COOKIE)
        .build()
        .session()
        .http1_only()
        .retry_policy(lkrequest::retry::FixedInterval::new(
            1,
            Duration::from_millis(1),
        ))
        .build();
    assert_eq!(
        send(session.get(&format!("{}/start", source.base_url)))
            .await
            .unwrap()
            .status(),
        200
    );
    let source_seen = source.finish().await;
    let target_seen = target.finish().await;
    assert_eq!(source_seen.len(), 2);
    assert_eq!(target_seen.len(), 2);
    for request in source_seen {
        assert_eq!(request.values("authorization"), vec![FAKE_AUTH]);
        assert_eq!(request.values("cookie"), vec![FAKE_COOKIE]);
    }
    for request in target_seen {
        assert!(request.values("authorization").is_empty());
        assert!(request.values("cookie").is_empty());
    }
}

#[tokio::test]
async fn https_to_http_redirect_does_not_reapply_default_referer() {
    let source = support::local_https::start_local_https_server().await;
    let target = Fixture::start(|_| ok_response()).await;
    let session = Client::builder()
        .verify(false)
        .default_header("referer", "https://fixture.invalid/private")
        .build()
        .session()
        .build();
    send(session.get(&format!(
        "{}/redirect-to?url={}/landing&status_code=302",
        source.base_url, target.base_url
    )))
    .await
    .unwrap();
    let observed = target.finish().await;
    assert_eq!(observed.len(), 1);
    assert!(observed[0].values("referer").is_empty());
}
