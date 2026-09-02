//! WebSocket tests — local WSS echo server (Tier 0) + public server (Tier 2).
//!
//! Tier-0 tests use a local self-signed WSS echo server.
//! Tier-2 tests (marked #[ignore]) require network access.

#[macro_use]
mod support;

use lkrequest::ws::WsMessage;
use lkrequest::Client;
use lktls::profile::presets;
use support::local_wss::start_local_wss_server;

fn chrome_client() -> Client {
    Client::builder()
        .fingerprint(presets::chrome_144())
        .verify(false)
        .build()
}

// ===========================================================================
// Tier-0: local WSS echo server
// ===========================================================================

/// Basic text echo over WSS.
#[tokio::test]
async fn ws_local_text_echo() {
    let wss = start_local_wss_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let mut ws = session
        .websocket(&wss.url)
        .connect()
        .await
        .expect("WSS connect");

    ws.send_text("hello from lkrequest")
        .await
        .expect("send_text");

    let msg = ws.recv().await.expect("recv");
    match msg {
        WsMessage::Text(t) => {
            assert_eq!(t, "hello from lkrequest");
        }
        other => panic!("expected text echo, got: {other:?}"),
    }

    ws.close(None).await.expect("close");
}

/// Binary echo over WSS.
#[tokio::test]
async fn ws_local_binary_echo() {
    let wss = start_local_wss_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let mut ws = session
        .websocket(&wss.url)
        .connect()
        .await
        .expect("WSS connect");

    let data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03];
    ws.send_binary(&data).await.expect("send_binary");

    let msg = ws.recv().await.expect("recv");
    match msg {
        WsMessage::Binary(b) => {
            assert_eq!(b, data);
        }
        other => panic!("expected binary echo, got: {other:?}"),
    }

    ws.close(None).await.expect("close");
}

/// Multiple messages in sequence.
#[tokio::test]
async fn ws_local_multiple_messages() {
    let wss = start_local_wss_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let mut ws = session
        .websocket(&wss.url)
        .connect()
        .await
        .expect("WSS connect");

    for i in 0..5 {
        let msg = format!("message #{i}");
        ws.send_text(&msg).await.expect("send_text");

        let echo = ws.recv().await.expect("recv");
        match echo {
            WsMessage::Text(t) => assert_eq!(t, msg, "echo #{i}"),
            other => panic!("expected text echo #{i}, got: {other:?}"),
        }
    }

    ws.close(None).await.expect("close");
}

/// Close with custom code and reason.
#[tokio::test]
async fn ws_local_close_with_code() {
    let wss = start_local_wss_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let mut ws = session
        .websocket(&wss.url)
        .connect()
        .await
        .expect("WSS connect");
    assert_eq!(ws.url(), wss.url);

    ws.send_text("before close").await.expect("send");
    let echo = ws.recv().await.expect("recv echo");
    match echo {
        WsMessage::Text(text) => assert_eq!(text, "before close"),
        other => panic!("expected echoed text before close, got {other:?}"),
    }

    ws.close(Some((1000, "normal closure")))
        .await
        .expect("close with code");

    let close = ws.recv().await.expect("recv close");
    match close {
        WsMessage::Close(code, _) => assert_eq!(code, Some(1000)),
        other => panic!("expected close frame after close(), got {other:?}"),
    }
}

/// URL accessor returns the connection URL.
#[tokio::test]
async fn ws_local_url_accessor() {
    let wss = start_local_wss_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let ws = session
        .websocket(&wss.url)
        .connect()
        .await
        .expect("WSS connect");

    assert!(
        ws.url().starts_with("wss://127.0.0.1:"),
        "url should start with wss://127.0.0.1:, got: {}",
        ws.url()
    );
}

/// Send via the generic send() method with WsMessage enum.
#[tokio::test]
async fn ws_local_send_message_enum() {
    let wss = start_local_wss_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let mut ws = session
        .websocket(&wss.url)
        .connect()
        .await
        .expect("WSS connect");

    ws.send(WsMessage::Text("via enum".to_string()))
        .await
        .expect("send");

    let msg = ws.recv().await.expect("recv");
    match msg {
        WsMessage::Text(t) => assert_eq!(t, "via enum"),
        other => panic!("expected text, got: {other:?}"),
    }

    ws.close(None).await.expect("close");
}

/// Custom headers on WsBuilder.
#[tokio::test]
async fn ws_local_custom_headers() {
    let wss = start_local_wss_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let mut ws = session
        .websocket(&wss.url)
        .header("X-Custom-WS", "test-value")
        .header("Origin", "https://localhost")
        .connect()
        .await
        .expect("WSS connect with custom headers");

    ws.send_text("with headers").await.expect("send");
    let msg = ws.recv().await.expect("recv");
    match msg {
        WsMessage::Text(t) => assert_eq!(t, "with headers"),
        other => panic!("expected text, got: {other:?}"),
    }

    ws.close(None).await.expect("close");
}

// ===========================================================================
// Close-code validation (RFC 6455 §7.4.1 / §7.4.2)
// ===========================================================================

/// A code an endpoint may not send must be refused *before* it is framed:
/// `fastwebsockets::Frame::close` does no validation, and a peer that receives
/// e.g. 1006 fails the connection with 1002 (protocol error).
///
/// The connection is left untouched, which is what the follow-up echo proves —
/// once a close frame is written, `fastwebsockets` marks the write half closed
/// and refuses every later data frame.
#[tokio::test]
async fn ws_local_close_rejects_unsendable_codes() {
    let wss = start_local_wss_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let mut ws = session
        .websocket(&wss.url)
        .connect()
        .await
        .expect("WSS connect");

    // 1005/1006/1015: "MUST NOT be set as a status code in a Close control
    // frame by an endpoint". 1004: reserved with no defined meaning.
    // 999/1016/5000: outside every sendable range in §7.4.2.
    for code in [1004_u16, 1005, 1006, 1015, 999, 1016, 5000] {
        let err = ws
            .close(Some((code, "nope")))
            .await
            .expect_err("an unsendable close code must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains(&code.to_string()),
            "the error should name the offending code {code}, got: {msg}"
        );
    }

    ws.send_text("still open")
        .await
        .expect("the refused closes must not have touched the wire");
    let echo = ws.recv().await.expect("recv");
    match echo {
        WsMessage::Text(t) => assert_eq!(t, "still open"),
        other => panic!("expected the echo back, got: {other:?}"),
    }

    ws.close(Some((1000, "normal closure")))
        .await
        .expect("1000 is sendable");
}

/// RFC 6455 §5.5 caps a control frame payload at 125 bytes, so a close reason
/// gets 123 after the 2-byte status code. `fastwebsockets` would happily frame
/// a longer one with a 16-bit length field, which is not a legal control frame.
#[tokio::test]
async fn ws_local_close_rejects_oversized_reason() {
    let wss = start_local_wss_server().await;
    let client = chrome_client();
    let session = client.session().http1_only().build();

    let mut ws = session
        .websocket(&wss.url)
        .connect()
        .await
        .expect("WSS connect");

    let too_long = "x".repeat(124);
    let err = ws
        .close(Some((1000, &too_long)))
        .await
        .expect_err("a 124-byte reason does not fit in a control frame");
    assert!(
        err.to_string().contains("124"),
        "the error should report the offending length, got: {err}"
    );

    // Still untouched, and the largest legal reason goes through.
    let at_limit = "x".repeat(123);
    ws.close(Some((1000, &at_limit)))
        .await
        .expect("123 bytes is exactly the limit");

    let close = ws.recv().await.expect("recv close");
    match close {
        WsMessage::Close(code, _) => assert_eq!(code, Some(1000)),
        other => panic!("expected a close frame, got {other:?}"),
    }
}

// ===========================================================================
// Scheme validation (no server needed)
// ===========================================================================

/// ftp:// scheme is rejected.
#[tokio::test]
async fn ws_invalid_scheme_rejected() {
    let client = Client::builder().fingerprint(presets::chrome_144()).build();
    let session = client.session().build();

    let result = session.websocket("ftp://example.com").connect().await;
    assert!(result.is_err(), "ftp:// scheme should be rejected");
}

/// ws:// (non-TLS) is rejected.
#[tokio::test]
async fn ws_non_tls_rejected() {
    let client = Client::builder().fingerprint(presets::chrome_144()).build();
    let session = client.session().build();

    let result = session
        .websocket("ws://echo.websocket.events")
        .connect()
        .await;
    assert!(
        result.is_err(),
        "ws:// should be rejected (only wss:// supported)"
    );
}

// ===========================================================================
// Tier-2: public echo server (requires network)
// ===========================================================================

#[tokio::test]
#[ignore = "Tier-2: requires network to ws.postman-echo.com"]
async fn ws_public_text_echo() {
    let client = Client::builder().fingerprint(presets::chrome_144()).build();

    let mut builder = client.session();
    if let Ok(proxy) = std::env::var("TEST_PROXY") {
        if !proxy.is_empty() {
            builder = builder.proxy(&proxy);
        }
    }
    let session = builder.build();

    let mut ws = retry!(
        support::MAX_RETRIES,
        session.websocket("wss://ws.postman-echo.com/raw").connect(),
        "WebSocket connect"
    );

    ws.send_text("hello from lkrequest")
        .await
        .expect("send_text");

    let echo = ws.recv().await.expect("recv echo");
    match echo {
        WsMessage::Text(t) => assert_eq!(t, "hello from lkrequest"),
        other => panic!("expected text echo, got: {other:?}"),
    }

    ws.close(None).await.expect("close");
}
