//! Compression / auto-decompression tests — local HTTPS server (Tier 0).
//!
//! Covers: gzip, brotli, deflate, zstd auto-decompression via the
//! local server's /compress/{encoding} endpoint.

mod support;

use std::time::Duration;

use lkrequest::h2::profile::chrome_144_h2;
use lkrequest::Client;
use lktls::profile::presets;
use support::local_https::{start_local_https_server, url_join};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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

const EXPECTED_PAYLOAD: &str = "Hello, compressed world! ";

// ---------------------------------------------------------------------------
// gzip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_auto_decompress_gzip() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/compress/gzip"))
        .send()
        .await
        .expect("gzip request");

    assert_eq!(resp.status().as_u16(), 200);
    let text = resp.text().expect("utf-8 text");
    assert!(
        text.contains(EXPECTED_PAYLOAD),
        "gzip decompression failed: body len={}",
        text.len()
    );
}

// ---------------------------------------------------------------------------
// brotli
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_auto_decompress_brotli() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/compress/br"))
        .send()
        .await
        .expect("brotli request");

    assert_eq!(resp.status().as_u16(), 200);
    let text = resp.text().expect("utf-8 text");
    assert!(
        text.contains(EXPECTED_PAYLOAD),
        "brotli decompression failed: body len={}",
        text.len()
    );
}

// ---------------------------------------------------------------------------
// deflate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_auto_decompress_deflate() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/compress/deflate"))
        .send()
        .await
        .expect("deflate request");

    assert_eq!(resp.status().as_u16(), 200);
    let text = resp.text().expect("utf-8 text");
    assert!(
        text.contains(EXPECTED_PAYLOAD),
        "deflate decompression failed: body len={}",
        text.len()
    );
}

// ---------------------------------------------------------------------------
// zstd
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_auto_decompress_zstd() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/compress/zstd"))
        .send()
        .await
        .expect("zstd request");

    assert_eq!(resp.status().as_u16(), 200);
    let text = resp.text().expect("utf-8 text");
    assert!(
        text.contains(EXPECTED_PAYLOAD),
        "zstd decompression failed: body len={}",
        text.len()
    );
}

// ---------------------------------------------------------------------------
// no_auto_decompress returns raw compressed bytes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_no_auto_decompress_returns_raw() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/compress/gzip"))
        .no_auto_decompress()
        .send()
        .await
        .expect("raw gzip request");

    assert_eq!(resp.status().as_u16(), 200);
    let raw = resp.bytes();
    // Gzip magic bytes: 0x1f 0x8b
    assert!(
        raw.len() >= 2 && raw[0] == 0x1f && raw[1] == 0x8b,
        "expected raw gzip bytes, got {} bytes starting with {:02x?}",
        raw.len(),
        &raw[..raw.len().min(4)]
    );
}

// ---------------------------------------------------------------------------
// unknown encoding endpoint returns 400
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_compress_unknown_encoding() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/compress/lz4"))
        .send()
        .await
        .expect("unknown encoding request");

    assert_eq!(resp.status().as_u16(), 400);
}

// ---------------------------------------------------------------------------
// streaming chunk_decoded — incremental decompression
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_streaming_chunk_decoded_gzip() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let mut resp = session
        .get(&url_join(&srv.base_url, "/compress/gzip"))
        .send_streaming()
        .await
        .expect("streaming gzip request");

    assert_eq!(resp.status().as_u16(), 200);

    let mut total = 0;
    let mut chunks = 0;
    while let Some(chunk) = resp.chunk_decoded().await.expect("chunk_decoded") {
        total += chunk.len();
        chunks += 1;
    }

    assert!(total > 0, "should receive decompressed data");
    let expected_payload = EXPECTED_PAYLOAD;
    // Re-read via buffered to verify same content
    let resp2 = session
        .get(&url_join(&srv.base_url, "/compress/gzip"))
        .send()
        .await
        .expect("buffered gzip request");
    let buffered_text = resp2.text().expect("utf-8");
    assert_eq!(
        total,
        buffered_text.len(),
        "streaming and buffered should produce same length"
    );
    println!("streaming chunk_decoded gzip: {chunks} chunks, {total} bytes");
    // Verify the payload contains expected content
    assert!(
        buffered_text.contains(expected_payload),
        "decompressed content mismatch"
    );
}

#[tokio::test]
async fn test_streaming_chunk_decoded_brotli() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let mut resp = session
        .get(&url_join(&srv.base_url, "/compress/br"))
        .send_streaming()
        .await
        .expect("streaming brotli request");

    assert_eq!(resp.status().as_u16(), 200);

    let mut decoded_body = Vec::new();
    while let Some(chunk) = resp.chunk_decoded().await.expect("chunk_decoded") {
        decoded_body.extend_from_slice(&chunk);
    }

    let text = String::from_utf8(decoded_body).expect("utf-8");
    assert!(
        text.contains(EXPECTED_PAYLOAD),
        "streaming brotli decompression failed: body len={}",
        text.len()
    );
}

#[tokio::test]
async fn test_streaming_chunk_decoded_deflate() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let mut resp = session
        .get(&url_join(&srv.base_url, "/compress/deflate"))
        .send_streaming()
        .await
        .expect("streaming deflate request");

    assert_eq!(resp.status().as_u16(), 200);

    let mut decoded_body = Vec::new();
    while let Some(chunk) = resp.chunk_decoded().await.expect("chunk_decoded") {
        decoded_body.extend_from_slice(&chunk);
    }

    let text = String::from_utf8(decoded_body).expect("utf-8");
    assert!(
        text.contains(EXPECTED_PAYLOAD),
        "streaming deflate decompression failed: body len={}",
        text.len()
    );
}

#[tokio::test]
async fn test_streaming_chunk_decoded_zstd() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let mut resp = session
        .get(&url_join(&srv.base_url, "/compress/zstd"))
        .send_streaming()
        .await
        .expect("streaming zstd request");

    assert_eq!(resp.status().as_u16(), 200);

    let mut decoded_body = Vec::new();
    while let Some(chunk) = resp.chunk_decoded().await.expect("chunk_decoded") {
        decoded_body.extend_from_slice(&chunk);
    }

    let text = String::from_utf8(decoded_body).expect("utf-8");
    assert!(
        text.contains(EXPECTED_PAYLOAD),
        "streaming zstd decompression failed: body len={}",
        text.len()
    );
}

// ---------------------------------------------------------------------------
// streaming chunk_decoded — identity passthrough
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_streaming_chunk_decoded_identity_passthrough() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let mut resp = session
        .get(&url_join(&srv.base_url, "/text-plain"))
        .send_streaming()
        .await
        .expect("streaming plain request");

    assert_eq!(resp.status().as_u16(), 200);

    let mut total = 0;
    while let Some(chunk) = resp.chunk_decoded().await.expect("chunk_decoded") {
        total += chunk.len();
    }

    assert!(total > 0, "should receive passthrough data");
}

// ---------------------------------------------------------------------------
// streaming bytes() — full buffered decompression (regression)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_streaming_bytes_decompresses_all_encodings() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    for encoding in &["gzip", "br", "deflate", "zstd"] {
        let resp = session
            .get(&url_join(&srv.base_url, &format!("/compress/{encoding}")))
            .send_streaming()
            .await
            .unwrap_or_else(|_| panic!("streaming {encoding} request"));

        assert_eq!(resp.status().as_u16(), 200);

        let body = resp
            .bytes()
            .await
            .unwrap_or_else(|_| panic!("bytes() {encoding}"));
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains(EXPECTED_PAYLOAD),
            "streaming bytes() {encoding} decompression failed"
        );
    }
}

// ---------------------------------------------------------------------------
// no_auto_decompress
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_streaming_no_auto_decompress_returns_raw() {
    let srv = start_local_https_server().await;
    let client = chrome_client();
    let session = client.session().build();

    let resp = session
        .get(&url_join(&srv.base_url, "/compress/gzip"))
        .no_auto_decompress()
        .send_streaming()
        .await
        .expect("raw gzip streaming request");

    assert_eq!(resp.status().as_u16(), 200);
    let raw = resp.bytes().await.expect("raw streaming bytes");
    assert!(
        raw.len() >= 2 && raw[0] == 0x1f && raw[1] == 0x8b,
        "expected raw gzip bytes from streaming response, got {} bytes starting with {:02x?}",
        raw.len(),
        &raw[..raw.len().min(4)]
    );
}

// ---------------------------------------------------------------------------
// Multi-coding content-encoding (RFC 9110 §8.4)
//
// `content-encoding` is a list: `gzip, br` means gzip was applied first and
// brotli second, so it decodes in reverse. The shared local server only ever
// emits one coding per response, so these tests bring their own plain
// HTTP/1.1 server — which is also the only way to control chunk boundaries
// exactly, as the streaming case needs.
// ---------------------------------------------------------------------------

/// Repeated so the compressed forms are large enough to span many small chunks.
fn multi_payload() -> String {
    "multi-layer content-encoding payload ".repeat(40)
}

fn gzip_compress(data: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).expect("gzip write");
    enc.finish().expect("gzip finish")
}

fn brotli_compress(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut buf = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut buf, 4096, 6, 22);
        writer.write_all(data).expect("brotli write");
    }
    buf
}

/// Spawn a plain HTTP/1.1 server answering every request with the same canned
/// response.
///
/// One `content-encoding` header line is emitted per entry in
/// `content_encodings`, so a list can be tested both inline (`["gzip, br"]`)
/// and split across lines (`["gzip", "br"]`). `chunk_size` selects chunked
/// transfer-encoding with pieces of that size; `None` sends a single
/// content-length framed body.
async fn spawn_canned_server(
    content_encodings: &'static [&'static str],
    body: Vec<u8>,
    chunk_size: Option<usize>,
) -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind canned server");
    let addr = listener.local_addr().expect("canned server addr");

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let body = body.clone();
            tokio::spawn(async move {
                // Read the request head; these tests never send a request body.
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }

                let mut response_head =
                    String::from("HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n");
                for value in content_encodings {
                    response_head.push_str("content-encoding: ");
                    response_head.push_str(value);
                    response_head.push_str("\r\n");
                }
                match chunk_size {
                    Some(_) => response_head.push_str("transfer-encoding: chunked\r\n"),
                    None => response_head.push_str(&format!("content-length: {}\r\n", body.len())),
                }
                response_head.push_str("connection: close\r\n\r\n");

                if stream.write_all(response_head.as_bytes()).await.is_err() {
                    return;
                }

                match chunk_size {
                    Some(size) => {
                        for piece in body.chunks(size) {
                            let prefix = format!("{:x}\r\n", piece.len());
                            if stream.write_all(prefix.as_bytes()).await.is_err()
                                || stream.write_all(piece).await.is_err()
                                || stream.write_all(b"\r\n").await.is_err()
                            {
                                return;
                            }
                            let _ = stream.flush().await;
                            // Nudge the pieces into separate client-side reads.
                            tokio::time::sleep(Duration::from_millis(1)).await;
                        }
                        let _ = stream.write_all(b"0\r\n\r\n").await;
                    }
                    None => {
                        let _ = stream.write_all(&body).await;
                    }
                }
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
            });
        }
    });

    format!("http://127.0.0.1:{}/", addr.port())
}

/// Regression: the whole header value was matched as a single token, so
/// `content-encoding: gzip, br` fell through as "unknown" and the caller
/// received still-compressed bytes with only a log line to say so.
#[tokio::test]
async fn test_multi_coding_gzip_then_brotli_buffered() {
    let payload = multi_payload();
    let body = brotli_compress(&gzip_compress(payload.as_bytes()));
    let url = spawn_canned_server(&["gzip, br"], body, None).await;

    let session = chrome_client().session().build();
    let resp = session
        .get(&url)
        .send()
        .await
        .expect("multi-coding request");

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.text().expect("utf-8 text"),
        payload,
        "`content-encoding: gzip, br` must decode both layers"
    );
}

#[tokio::test]
async fn test_multi_coding_streaming_small_chunks() {
    let payload = multi_payload();
    let body = brotli_compress(&gzip_compress(payload.as_bytes()));
    // 8-byte chunks: the layers must survive boundaries falling anywhere.
    let url = spawn_canned_server(&["gzip, br"], body, Some(8)).await;

    let session = chrome_client().session().build();
    let mut resp = session
        .get(&url)
        .send_streaming()
        .await
        .expect("streaming multi-coding request");

    assert_eq!(resp.status().as_u16(), 200);

    let mut decoded = Vec::new();
    while let Some(chunk) = resp.chunk_decoded().await.expect("chunk_decoded") {
        decoded.extend_from_slice(&chunk);
    }

    assert_eq!(String::from_utf8(decoded).expect("utf-8"), payload);
}

#[tokio::test]
async fn test_multi_coding_streaming_bytes_matches_buffered() {
    let payload = multi_payload();
    let body = brotli_compress(&gzip_compress(payload.as_bytes()));
    let url = spawn_canned_server(&["gzip, br"], body, Some(16)).await;

    let session = chrome_client().session().build();
    let resp = session
        .get(&url)
        .send_streaming()
        .await
        .expect("streaming multi-coding request");

    assert_eq!(resp.status().as_u16(), 200);
    let bytes = resp.bytes().await.expect("streaming bytes()");
    assert_eq!(String::from_utf8_lossy(&bytes), payload);
}

/// A list value may legally be split across several header lines
/// (RFC 9110 §5.3); reading only the first line loses codings.
#[tokio::test]
async fn test_multi_coding_split_across_header_lines() {
    let payload = multi_payload();
    let body = brotli_compress(&gzip_compress(payload.as_bytes()));
    let url = spawn_canned_server(&["gzip", "br"], body, None).await;

    let session = chrome_client().session().build();
    let resp = session
        .get(&url)
        .send()
        .await
        .expect("split content-encoding request");

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.text().expect("utf-8 text"), payload);
}

/// Decoding only the layers we implement would return bytes that are still
/// compressed, with nothing in the response for the caller to detect that
/// from — so a partially-understood list is refused outright.
#[tokio::test]
async fn test_multi_coding_with_unknown_token_errors() {
    let payload = multi_payload();
    let body = gzip_compress(payload.as_bytes());
    let url = spawn_canned_server(&["gzip, lz4"], body, None).await;

    let session = chrome_client().session().build();
    let err = session
        .get(&url)
        .send()
        .await
        .expect_err("a partially unknown coding list must not succeed");

    assert!(
        matches!(err, lkrequest::error::Error::Body(_)),
        "expected a body error, got {err:?}"
    );
    assert!(
        err.to_string().contains("lz4"),
        "error should name the unsupported coding: {err}"
    );
}

#[tokio::test]
async fn test_multi_coding_with_unknown_token_errors_when_streaming() {
    let payload = multi_payload();
    let body = gzip_compress(payload.as_bytes());
    let url = spawn_canned_server(&["gzip, lz4"], body, Some(8)).await;

    let session = chrome_client().session().build();
    let mut resp = session
        .get(&url)
        .send_streaming()
        .await
        .expect("streaming request headers");

    let err = resp
        .chunk_decoded()
        .await
        .expect_err("a partially unknown coding list must not stream through");

    assert!(
        err.to_string().contains("lz4"),
        "error should name the unsupported coding: {err}"
    );
}

/// A *single* unrecognized coding keeps its long-standing pass-through
/// behavior — only partially-understood lists became an error.
#[tokio::test]
async fn test_single_unknown_coding_passes_through() {
    let payload = multi_payload();
    let url = spawn_canned_server(&["lz4"], payload.as_bytes().to_vec(), None).await;

    let session = chrome_client().session().build();
    let resp = session
        .get(&url)
        .send()
        .await
        .expect("single unknown coding request");

    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.text().expect("utf-8 text"), payload);
}
