//! Redirect-handling tests against a local HTTPS server (Tier 0).
//!
//! Covers behavior validated against the Fetch Standard / Chromium net stack:
//! - 303 See Other is followed as GET (previously not followed at all).
//! - The method-rewrite matrix: which status/method pairs become a GET and
//!   which survive the hop unchanged.
//! - The opt-in `https_only` knob refuses a scheme-downgrade redirect, while
//!   the default still follows it (Chrome-faithful).
//! - A total timeout bounds the entire redirect chain, not each hop.

mod support;

use http::Method;
use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::Client;
use lktls::profile::presets;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use support::local_https::{start_local_https_server, url_join};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn chrome_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .build()
}

async fn run_h1_redirect_server(listener: TcpListener) {
    let (mut first, _) = listener.accept().await.expect("accept POST connection");
    let mut request = vec![0_u8; 4096];
    let request_len = first.read(&mut request).await.expect("read POST");
    let request_text = String::from_utf8_lossy(&request[..request_len]);
    assert!(request_text.starts_with("POST /submit HTTP/1.1\r\n"));
    first
        .write_all(b"HTTP/1.1 302 Found\r\nLocation: /result\r\nContent-Length: 0\r\n\r\n")
        .await
        .expect("write redirect");
    first.shutdown().await.expect("close POST connection");

    let (mut second, _) = listener.accept().await.expect("accept redirect connection");
    let request_len = second.read(&mut request).await.expect("read redirect GET");
    let request_text = String::from_utf8_lossy(&request[..request_len]);
    assert!(request_text.starts_with("GET /result HTTP/1.1\r\n"));
    second
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
        .await
        .expect("write final response");
}

/// 303 See Other must be followed, rewriting the method to GET.
#[tokio::test]
async fn redirect_303_is_followed_as_get() {
    let srv = start_local_https_server().await;
    let session = chrome_client().session().build();

    // POST to a 303 whose Location is /get (GET-only on the server). If the 303
    // is followed as GET, the final response is 200; before the fix the 303 was
    // returned verbatim.
    let url = url_join(&srv.base_url, "/redirect-to?url=/get&status_code=303");
    let resp = session
        .post(&url)
        .text_body("payload")
        .send()
        .await
        .expect("303 should be followed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "303 must be followed to GET /get, got {}",
        resp.status()
    );
}

/// A `304 Not Modified` is a 3xx but not a redirect: it is the normal answer to
/// a conditional request and carries no `Location`. It must reach the caller,
/// not fail with `redirect response missing Location header`.
#[tokio::test]
async fn not_modified_304_is_returned_not_treated_as_redirect() {
    let srv = start_local_https_server().await;
    let session = chrome_client().session().build();

    let url = url_join(&srv.base_url, "/status/304");
    let resp = session
        .get(&url)
        .header("If-None-Match", "\"etag-v1\"")
        .send()
        .await
        .expect("304 must be returned to the caller, not treated as a redirect");

    assert_eq!(resp.status().as_u16(), 304);
}

/// The other non-followable 3xx codes take the same path.
#[tokio::test]
async fn other_non_followable_3xx_are_returned_verbatim() {
    let srv = start_local_https_server().await;
    let session = chrome_client().session().build();

    for code in [300u16, 305, 306] {
        let url = url_join(&srv.base_url, &format!("/status/{code}"));
        let resp = session
            .get(&url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("{code} must be returned verbatim, got error: {e}"));
        assert_eq!(resp.status().as_u16(), code);
    }
}

#[tokio::test]
async fn redirect_reconnects_when_pooled_h1_was_closed_after_302() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("local address");
    let server = tokio::spawn(run_h1_redirect_server(listener));

    let client = Client::builder()
        .total_timeout(Duration::from_secs(2))
        .build();
    let session = client.session().http1_only().build();
    let response = session
        .post(&format!("http://{address}/submit"))
        .text_body("payload")
        .send()
        .await
        .expect("redirect should retry on a fresh H1 connection");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.text().expect("response text"), "OK");
    server.await.expect("server task");
}

/// With `https_only`, a redirect that downgrades to http:// is refused.
#[tokio::test]
async fn https_only_refuses_downgrade_redirect() {
    let srv = start_local_https_server().await;

    // Server 302-redirects to an http:// URL (same host, downgraded scheme).
    let http_target = format!("{}/get", srv.base_url.replacen("https://", "http://", 1));
    let path = format!("/redirect-to?url={http_target}&status_code=302");
    let url = url_join(&srv.base_url, &path);

    let session = chrome_client().session().https_only(true).build();
    let err = session
        .get(&url)
        .send()
        .await
        .expect_err("https_only must refuse the downgrade redirect");

    let msg = format!("{err}");
    assert!(
        msg.contains("https_only") || msg.to_lowercase().contains("non-https"),
        "expected an https_only refusal, got: {msg}"
    );
}

/// A total timeout must bound the whole redirect chain, not reset per hop.
#[tokio::test]
async fn total_timeout_spans_redirect_chain() {
    let srv = start_local_https_server().await;

    // 6 hops, each sleeping ~300ms (~1.8s total). With a 500ms total timeout,
    // a per-hop timer would let every hop through (each < 500ms) and succeed
    // after ~1.8s; a correct total deadline fails at ~500ms.
    let client = Client::builder()
        .fingerprint(presets::chrome_144())
        .h2_profile(chrome_144_h2())
        .verify(false)
        .total_timeout(Duration::from_millis(500))
        .build();
    let session = client.session().build();

    let url = url_join(&srv.base_url, "/slow-redirect/5");
    let start = Instant::now();
    let result = session.get(&url).send().await;
    let elapsed = start.elapsed();

    let err = result.expect_err("expected a total-timeout error");
    assert!(err.is_timeout(), "expected a timeout error, got: {err}");
    assert!(
        elapsed < Duration::from_millis(1200),
        "total timeout must bound the chain (~500ms), elapsed={elapsed:?}"
    );
}

// ===========================================================================
// Method-rewrite matrix
//
// Fetch Standard, "HTTP-redirect fetch":
//
//   If one of the following is true
//     - internalResponse's status is 301 or 302 and request's method is `POST`
//     - internalResponse's status is 303 and request's method is not `GET` or
//       `HEAD`
//   then:
//     1. Set request's method to `GET` and request's body to null.
//     2. For each headerName of request-body-header name, delete headerName
//        from request's header list.
//
// RFC 9110 agrees: 15.4.2/15.4.3 permit the rewrite only "from POST to GET",
// and 15.4.4 has the user agent perform "a GET or HEAD request".
//
// These tests observe the bytes on the wire through a raw-TCP H1 server rather
// than trusting the client's own account of what it sent.
// ===========================================================================

/// One request exactly as the local H1 server saw it on the wire.
#[derive(Clone, Debug)]
struct SeenRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl SeenRequest {
    /// Look up a header by its lowercased name.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Read one HTTP/1.1 request off `stream`, leaving any surplus bytes in `buf`
/// so a keep-alive connection can serve the next one. Returns `None` at EOF.
async fn read_one_request(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<SeenRequest> {
    let head_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let mut chunk = [0_u8; 4096];
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut start = lines.next()?.split(' ');
    let method = start.next()?.to_string();
    let path = start.next()?.to_string();

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
    }

    let content_length: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + content_length {
        let mut chunk = [0_u8; 4096];
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    let body = String::from_utf8_lossy(&buf[head_end..head_end + content_length]).into_owned();
    buf.drain(..head_end + content_length);

    Some(SeenRequest {
        method,
        path,
        headers,
        body,
    })
}

/// Two-hop redirect server: `/start` answers `status` with `Location: /landing`
/// and `/landing` answers 200. Every request is appended to `log` *before* its
/// response goes out, so the log is complete once the client has the 200.
///
/// Serves both the pooled-reuse and the reconnect case, since either is a legal
/// way for the client to make the second hop.
async fn run_redirect_matrix_server(
    listener: TcpListener,
    status: u16,
    log: Arc<Mutex<Vec<SeenRequest>>>,
) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let log = log.clone();
        tokio::spawn(async move {
            let mut buf = Vec::new();
            while let Some(request) = read_one_request(&mut stream, &mut buf).await {
                let first_hop = request.path == "/start";
                let is_head = request.method == "HEAD";
                log.lock().expect("request log").push(request);

                // A HEAD response carries no body; keep the framing trivial so
                // a mis-parse cannot masquerade as a redirect bug.
                let response = if first_hop {
                    format!(
                        "HTTP/1.1 {status} Redirect\r\n\
                         Location: /landing\r\n\
                         Content-Length: 0\r\n\r\n"
                    )
                } else if is_head {
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string()
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".to_string()
                };

                if stream.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
            }
        });
    }
}

/// Drive `method` (optionally with a body) into a `status` redirect and return
/// the two requests the server saw, in order.
async fn redirect_matrix_hop(status: u16, method: Method, body: Option<&str>) -> Vec<SeenRequest> {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("local address");
    let log: Arc<Mutex<Vec<SeenRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let server = tokio::spawn(run_redirect_matrix_server(listener, status, log.clone()));

    let client = Client::builder()
        .total_timeout(Duration::from_secs(5))
        .build();
    let session = client.session().http1_only().build();

    let mut request = session.request(method, &format!("http://{address}/start"));
    if let Some(body) = body {
        request = request.text_body(body).header("Content-Type", "text/plain");
    }
    let response = request
        .send()
        .await
        .expect("redirect chain should complete");
    let final_status = response.status().as_u16();
    server.abort();

    // Snapshot the log and drop the guard before asserting — re-locking inside
    // an assertion message would deadlock instead of failing.
    let seen = log.lock().expect("request log").clone();
    assert_eq!(
        final_status, 200,
        "the chain should end at the 200 landing page"
    );
    seen
}

/// 301 rewrites POST to GET and drops the body plus the request-body headers.
#[tokio::test]
async fn redirect_301_rewrites_post_to_get() {
    let seen = redirect_matrix_hop(301, Method::POST, Some("payload")).await;

    assert_eq!(seen.len(), 2, "expected two hops, saw: {seen:?}");
    assert_eq!(seen[0].method, "POST", "first hop should be the POST");
    assert_eq!(seen[0].body, "payload", "first hop should carry the body");
    assert_eq!(seen[1].method, "GET", "301 must rewrite POST to GET");
    assert_eq!(seen[1].body, "", "the body must go with the method");
    assert_eq!(
        seen[1].header("content-type"),
        None,
        "request-body headers must be dropped alongside the body, saw: {:?}",
        seen[1].headers
    );
}

/// 301 must not turn a HEAD into a GET: that would pull down a body no browser
/// asked for. Fetch rewrites 301/302 for POST only.
#[tokio::test]
async fn redirect_301_preserves_head() {
    let seen = redirect_matrix_hop(301, Method::HEAD, None).await;

    assert_eq!(seen.len(), 2, "expected two hops, saw: {seen:?}");
    assert_eq!(seen[0].method, "HEAD", "first hop should be the HEAD");
    assert_eq!(
        seen[1].method, "HEAD",
        "301 must preserve HEAD, not rewrite it to GET"
    );
}

/// 302 preserves PUT / DELETE / PATCH together with their bodies.
#[tokio::test]
async fn redirect_302_preserves_put_delete_patch_with_body() {
    for method in [Method::PUT, Method::DELETE, Method::PATCH] {
        let name = method.as_str().to_string();
        let seen = redirect_matrix_hop(302, method, Some("payload")).await;

        assert_eq!(seen.len(), 2, "{name}: expected two hops, saw: {seen:?}");
        assert_eq!(
            seen[1].method, name,
            "302 must preserve {name}, not downgrade it to GET"
        );
        assert_eq!(
            seen[1].body, "payload",
            "302 must resend the {name} body on the second hop"
        );
        assert_eq!(
            seen[1].header("content-type"),
            Some("text/plain"),
            "{name}: request-body headers must survive a preserved method"
        );
    }
}

/// 303 rewrites POST to GET and drops the body — "See Other" always points at
/// a retrieval.
#[tokio::test]
async fn redirect_303_rewrites_post_to_get() {
    let seen = redirect_matrix_hop(303, Method::POST, Some("payload")).await;

    assert_eq!(seen.len(), 2, "expected two hops, saw: {seen:?}");
    assert_eq!(seen[1].method, "GET", "303 must rewrite POST to GET");
    assert_eq!(seen[1].body, "", "the body must go with the method");
    assert_eq!(
        seen[1].header("content-type"),
        None,
        "request-body headers must be dropped alongside the body, saw: {:?}",
        seen[1].headers
    );
}

/// 303 rewrites every method *except* GET and HEAD; a HEAD stays a HEAD.
#[tokio::test]
async fn redirect_303_preserves_head() {
    let seen = redirect_matrix_hop(303, Method::HEAD, None).await;

    assert_eq!(seen.len(), 2, "expected two hops, saw: {seen:?}");
    assert_eq!(seen[0].method, "HEAD", "first hop should be the HEAD");
    assert_eq!(
        seen[1].method, "HEAD",
        "303 must preserve HEAD — Fetch exempts GET and HEAD"
    );
}

/// 303 does rewrite the other non-retrieval methods.
#[tokio::test]
async fn redirect_303_rewrites_put_delete_patch() {
    for method in [Method::PUT, Method::DELETE, Method::PATCH] {
        let name = method.as_str().to_string();
        let seen = redirect_matrix_hop(303, method, Some("payload")).await;

        assert_eq!(seen.len(), 2, "{name}: expected two hops, saw: {seen:?}");
        assert_eq!(seen[1].method, "GET", "303 must rewrite {name} to GET");
        assert_eq!(seen[1].body, "", "{name}: the body must go with the method");
    }
}

/// 307/308 preserve method, body and request-body headers for every method.
#[tokio::test]
async fn redirect_307_308_preserve_method_and_body() {
    for status in [307_u16, 308] {
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            let name = method.as_str().to_string();
            let seen = redirect_matrix_hop(status, method, Some("payload")).await;

            assert_eq!(
                seen.len(),
                2,
                "{status}/{name}: expected two hops, saw: {seen:?}"
            );
            assert_eq!(
                seen[1].method, name,
                "{status} must preserve {name} verbatim"
            );
            assert_eq!(seen[1].body, "payload", "{status} must resend the body");
            assert_eq!(
                seen[1].header("content-type"),
                Some("text/plain"),
                "{status}/{name}: request-body headers must survive"
            );
        }
    }

    // GET and HEAD are equally untouched.
    let seen = redirect_matrix_hop(307, Method::HEAD, None).await;
    assert_eq!(seen.len(), 2, "expected two hops, saw: {seen:?}");
    assert_eq!(seen[1].method, "HEAD", "307 must preserve HEAD");
}
