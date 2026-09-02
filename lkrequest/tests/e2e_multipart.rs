//! Multipart uploads — local HTTPS server (Tier 0).
//! Single test runs both scenarios sequentially to avoid flaky parallel TLS to the embedded server.

mod support;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::multipart::{Multipart, Part};
use lkrequest::Client;
use lktls::profile::presets;
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

#[tokio::test]
async fn test_multipart_text_and_file() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/post");

    let form = Multipart::new()
        .text("field1", "value1")
        .text("field2", "value2");

    let resp = session
        .post(&url)
        .multipart(form)
        .send()
        .await
        .expect("multipart POST");

    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().expect("utf-8");
    assert!(body.contains("value1"), "body={body}");
    assert!(body.contains("value2"), "body={body}");

    let form2 = Multipart::new().text("description", "test file").part(
        Part::new("file", "Hello from lkrequest multipart test!")
            .filename("test.txt")
            .content_type("text/plain"),
    );

    let resp2 = session
        .post(&url)
        .multipart(form2)
        .send()
        .await
        .expect("multipart file");

    assert_eq!(resp2.status().as_u16(), 200);
    let body2 = resp2.text().expect("utf-8");
    assert!(
        body2.contains("test.txt") || body2.contains("Hello from lkrequest"),
        "body={body2}"
    );
}

#[tokio::test]
async fn test_multipart_large_file() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/post");

    let large_content = "x".repeat(1_048_576); // 1 MB "file"
    let form = Multipart::new()
        .text("description", "large file upload test")
        .part(
            Part::new("bigfile", large_content)
                .filename("big.bin")
                .content_type("application/octet-stream"),
        );

    let resp = session
        .post(&url)
        .multipart(form)
        .send()
        .await
        .expect("large multipart POST");
    assert_eq!(resp.status().as_u16(), 200);
}

#[tokio::test]
async fn test_multipart_many_fields() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/post");

    let mut form = Multipart::new();
    for i in 0..50 {
        form = form.text(&format!("field_{i}"), &format!("value_{i}"));
    }

    let resp = session
        .post(&url)
        .multipart(form)
        .send()
        .await
        .expect("many-field multipart");
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().expect("utf-8");
    assert!(body.contains("field_0"), "body={body}");
    assert!(body.contains("field_49"), "body={body}");
}

#[tokio::test]
async fn test_multipart_empty_part() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/post");

    let form = Multipart::new()
        .text("nonempty", "has-value")
        .text("empty", "");

    let resp = session
        .post(&url)
        .multipart(form)
        .send()
        .await
        .expect("empty-part multipart");
    assert_eq!(resp.status().as_u16(), 200);
}

// =========================================================================
// Part-header injection (CR/LF)
//
// A field name / filename / content type is interpolated into the part's
// `Content-Disposition` / `Content-Type` header line, so a CR or LF in one of
// them would end the header and let the caller append headers of their own --
// or close the part and forge the boundary.
//
// Chrome's answer, captured in `b_layer_chrome_multipart.rs`, is to
// percent-encode the character rather than refuse the form: a name or filename
// is a quoted parameter, and `%0D%0A` inside the quotes is inert. A MIME type
// has no quoted form, so that one is still refused.
//
// These tests go through a real server so the assertion is about what actually
// arrived, not about what the encoder claims it built.
// =========================================================================

/// Send `form` and return the raw body the server received (`/post` echoes it
/// back under `data`), so a test can assert on the actual wire bytes.
async fn multipart_echo(form: Multipart) -> String {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/post");

    let resp = session
        .post(&url)
        .multipart(form)
        .send()
        .await
        .expect("an escaped form must still be sent");
    assert_eq!(resp.status().as_u16(), 200);
    let json: serde_json::Value =
        serde_json::from_str(resp.text().expect("utf-8")).expect("/post returns JSON");
    json["data"]
        .as_str()
        .expect("/post echoes the raw body under `data`")
        .to_string()
}

/// Whether any line of `body` starts with `prefix`.
///
/// A substring check would not do: the escaped text still *contains* the
/// injected words, trapped on one line inside the quotes. Only a line that
/// starts with them is a real header.
fn starts_a_line(body: &str, prefix: &str) -> bool {
    body.split(
        "
",
    )
    .any(|line| line.starts_with(prefix))
}

/// `Session` isn't needed for the rejection itself, but the request must be
/// refused end to end, before anything reaches the wire.
async fn multipart_send_error(form: Multipart) -> String {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/post");

    match session.post(&url).multipart(form).send().await {
        Ok(resp) => panic!(
            "multipart form with an injected CR/LF was sent anyway (status {})",
            resp.status().as_u16()
        ),
        Err(e) => e.to_string(),
    }
}

/// The filename is the value an attacker most often controls (an uploaded
/// file's own name).
#[tokio::test]
async fn test_multipart_crlf_in_filename_is_escaped_not_injected() {
    let form = Multipart::new().part(
        Part::new("file", "payload")
            .filename("ok.txt\r\nX-Injected: yes")
            .content_type("text/plain"),
    );

    let received = multipart_echo(form).await;

    assert!(
        received.contains(r#"filename="ok.txt%0D%0AX-Injected: yes""#),
        "the CRLF must arrive percent-encoded inside the quotes: {received}"
    );
    assert!(
        !starts_a_line(&received, "X-Injected:"),
        "the injected text must not become a header line: {received}"
    );
}

#[tokio::test]
async fn test_multipart_crlf_in_field_name_is_escaped_not_injected() {
    let form = Multipart::new().text("field\r\nX-Injected: yes", "value");

    let received = multipart_echo(form).await;

    assert!(
        received.contains(r#"name="field%0D%0AX-Injected: yes""#),
        "the CRLF must arrive percent-encoded inside the quotes: {received}"
    );
    assert!(
        !starts_a_line(&received, "X-Injected:"),
        "the injected text must not become a header line: {received}"
    );
}

/// The boundary must not name the library. This is the end-to-end guard for
/// what used to be `----lkrequest{hex}` in the `Content-Type` of every upload.
#[tokio::test]
async fn test_multipart_boundary_does_not_name_the_library() {
    let form = Multipart::new().text("field", "value");

    let received = multipart_echo(form).await;

    assert!(
        received.contains("------WebKitFormBoundary"),
        "the delimiter must match Chrome: {received}"
    );
    assert!(
        !received.to_ascii_lowercase().contains("lkrequest"),
        "nothing on the wire may name the library: {received}"
    );
}

#[tokio::test]
async fn test_multipart_crlf_in_content_type_is_rejected() {
    let form = Multipart::new().part(
        Part::new("file", "payload")
            .filename("ok.txt")
            .content_type("text/plain\r\nX-Injected: yes"),
    );

    let err = multipart_send_error(form).await;
    assert!(
        err.contains("content type") && err.contains("CR or LF"),
        "a CRLF content type must be refused with a clear error, got: {err}"
    );
}

/// Counter-case: an ordinary filename with spaces and non-ASCII characters
/// must still upload untouched, so the fix cannot pass by rejecting
/// everything.
#[tokio::test]
async fn test_multipart_ordinary_filename_still_uploads() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();
    let url = url_join(&srv.base_url, "/post");

    let form = Multipart::new().text("description", "café ☕ report").part(
        Part::new("file", "Hello from lkrequest multipart test!")
            .filename("my report (final) — café.txt")
            .content_type("text/plain; charset=utf-8"),
    );

    let resp = session
        .post(&url)
        .multipart(form)
        .send()
        .await
        .expect("ordinary filename must still upload");
    assert_eq!(resp.status().as_u16(), 200);

    let body = resp.text().expect("utf-8");
    assert!(
        body.contains("my report (final) \\u2014 café.txt")
            || body.contains("my report (final) — café.txt"),
        "the filename must reach the server verbatim: body={body}"
    );
    assert!(
        body.contains("text/plain; charset=utf-8"),
        "a parameterised content type must reach the server verbatim: body={body}"
    );
}
