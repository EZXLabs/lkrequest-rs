//! HTTP/1.1 WebSocket Upgrade — establishes a WebSocket connection via
//! the classic HTTP/1.1 `Upgrade: websocket` mechanism (RFC 6455).

use base64::Engine;
use http::header::{CONNECTION, HOST, UPGRADE};
use http::{Request, StatusCode};
use http_body_util::Empty;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};

use super::builder::WsBuilder;
use super::WsConnection;
use crate::error::{Error, Result};

/// Generate a random Sec-WebSocket-Key using fastwebsockets.
fn generate_ws_key() -> String {
    fastwebsockets::handshake::generate_key()
}

/// The WebSocket GUID from RFC 6455 §1.3, concatenated with the client key
/// before hashing.
///
/// This exact string is what makes `Sec-WebSocket-Accept` verifiable; a peer
/// using any other value cannot produce an accept token we would recognise.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Compute the expected Sec-WebSocket-Accept value for the given key (RFC 6455 §4.2.2).
fn compute_accept(key: &str) -> String {
    use aws_lc_rs::digest;
    let mut input = key.to_string();
    input.push_str(WS_GUID);
    let hash = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, input.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hash.as_ref())
}

/// Perform WebSocket upgrade over an HTTP/1.1 connection.
///
/// Takes ownership of the TLS stream, sends an Upgrade request via hyper,
/// validates the 101 response and Sec-WebSocket-Accept, then returns a
/// `WsConnection` wrapping the upgraded stream.
pub(crate) async fn ws_upgrade_h1<S>(
    tls_stream: S,
    host: &str,
    path: &str,
    builder: &WsBuilder,
    default_headers: &http::HeaderMap,
) -> Result<WsConnection<TokioIo<hyper::upgrade::Upgraded>>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ws_key = generate_ws_key();
    let expected_accept = compute_accept(&ws_key);

    // Build the HTTP/1.1 Upgrade request
    let authority = host.to_string();
    let uri = format!("https://{authority}{path}");

    let mut req_builder = Request::builder()
        .method("GET")
        .uri(&uri)
        .header(HOST, &authority)
        .header(CONNECTION, "Upgrade")
        .header(UPGRADE, "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", &ws_key);

    // Add Sec-WebSocket-Protocol if specified
    if !builder.protocols.is_empty() {
        req_builder = req_builder.header("Sec-WebSocket-Protocol", builder.protocols.join(", "));
    }

    // Add Sec-WebSocket-Extensions if specified
    if !builder.extensions.is_empty() {
        req_builder = req_builder.header("Sec-WebSocket-Extensions", builder.extensions.join(", "));
    }

    // Add default headers from Client (User-Agent, Accept-Language, etc.)
    // We build the request first, then merge headers
    let mut req = req_builder
        .body(Empty::<Bytes>::new())
        .map_err(|e| Error::Http(format!("Failed to build WS upgrade request: {e}")))?;

    // Merge default headers (don't overwrite WS-specific ones)
    for (name, value) in default_headers.iter() {
        if !req.headers().contains_key(name) {
            req.headers_mut().insert(name.clone(), value.clone());
        }
    }

    // Merge extra headers from the WsBuilder
    for (name, value) in builder.extra_headers.iter() {
        req.headers_mut().insert(name.clone(), value.clone());
    }

    // Perform the HTTP/1.1 handshake using hyper
    let io = TokioIo::new(tls_stream);
    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .title_case_headers(true)
        .preserve_header_case(true)
        .handshake(io)
        .await
        .map_err(|e| Error::Http(format!("H1 handshake for WS upgrade failed: {e}")))?;

    // Spawn the connection driver
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::debug!(error = %e, "ws.h1_connection_closed");
        }
    });

    // Send the upgrade request
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| Error::Http(format!("WS upgrade request failed: {e}")))?;

    // Validate the response. RFC 6455 §4.1 makes every one of these checks a
    // MUST for the client, and requires it to _Fail the WebSocket Connection_
    // when any fails. A 101 alone proves nothing: a plain HTTP upgrade to some
    // other protocol, a confused endpoint, or an intermediary synthesising a
    // 101 would all satisfy it. `Sec-WebSocket-Accept` is what proves the peer
    // read our key and actually speaks WebSocket.
    validate_upgrade_response(resp.headers(), resp.status(), &expected_accept, builder)?;

    // Extract the upgraded stream
    let upgraded = hyper::upgrade::on(resp)
        .await
        .map_err(|e| Error::Http(format!("WebSocket upgrade extraction failed: {e}")))?;

    let ws_stream = TokioIo::new(upgraded);
    Ok(WsConnection::new(ws_stream, builder.url.clone()))
}

// ---------------------------------------------------------------------------
// Handshake response validation (RFC 6455 §4.1)
// ---------------------------------------------------------------------------

/// Split a comma-separated header value into trimmed, non-empty items.
fn comma_items(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim).filter(|s| !s.is_empty())
}

/// The name of an extension offer/acceptance, i.e. the token before any
/// parameters (`permessage-deflate; client_max_window_bits` → `permessage-deflate`).
fn extension_name(value: &str) -> &str {
    value.split(';').next().unwrap_or(value).trim()
}

/// Validate a WebSocket handshake response.
///
/// Every check here is a MUST in RFC 6455 §4.1, and failing any of them
/// requires the client to fail the connection rather than proceed.
fn validate_upgrade_response(
    headers: &http::HeaderMap,
    status: StatusCode,
    expected_accept: &str,
    builder: &WsBuilder,
) -> Result<()> {
    // §4.1/4: the status MUST be 101.
    if status != StatusCode::SWITCHING_PROTOCOLS {
        return Err(Error::Http(format!(
            "WebSocket upgrade failed: expected 101 Switching Protocols, got {status}"
        )));
    }

    // §4.1/5: `Upgrade` MUST be present and equal "websocket", case-insensitively.
    let upgrade = headers
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Error::Http("WebSocket upgrade failed: no Upgrade header".into()))?;
    if !upgrade.trim().eq_ignore_ascii_case("websocket") {
        return Err(Error::Http(format!(
            "WebSocket upgrade failed: Upgrade header is `{upgrade}`, expected `websocket`"
        )));
    }

    // §4.1/6: `Connection` MUST be present and include the token "Upgrade".
    let connection = headers
        .get(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| Error::Http("WebSocket upgrade failed: no Connection header".into()))?;
    if !comma_items(connection).any(|token| token.eq_ignore_ascii_case("upgrade")) {
        return Err(Error::Http(format!(
            "WebSocket upgrade failed: Connection header is `{connection}`, expected it to \
             include `Upgrade`"
        )));
    }

    // §4.1/7: `Sec-WebSocket-Accept` MUST equal base64(SHA1(key + GUID)).
    //
    // This is the only part of the handshake that proves the peer read our
    // nonce, so a mismatch means we are not talking to the WebSocket endpoint
    // we addressed — a cached response, a confused intermediary, or a
    // cross-protocol attack.
    let accept = headers
        .get("sec-websocket-accept")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            Error::Http("WebSocket upgrade failed: no Sec-WebSocket-Accept header".into())
        })?;
    if accept.trim() != expected_accept {
        return Err(Error::Http(format!(
            "WebSocket upgrade failed: Sec-WebSocket-Accept is `{}`, expected `{expected_accept}`",
            accept.trim()
        )));
    }

    // §4.1/8: an extension the client did not offer MUST fail the connection.
    if let Some(value) = headers
        .get("sec-websocket-extensions")
        .and_then(|v| v.to_str().ok())
    {
        let offered: Vec<&str> = builder
            .extensions
            .iter()
            .map(|e| extension_name(e))
            .collect();
        for negotiated in comma_items(value).map(extension_name) {
            if !offered.iter().any(|o| o.eq_ignore_ascii_case(negotiated)) {
                return Err(Error::Http(format!(
                    "WebSocket upgrade failed: server enabled extension `{negotiated}`, which \
                     was not offered"
                )));
            }
        }
    }

    // §4.1/9: a subprotocol the client did not offer MUST fail the connection.
    if let Some(value) = headers
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok())
    {
        let selected: Vec<&str> = comma_items(value).collect();
        // The server selects at most one.
        if selected.len() > 1 {
            return Err(Error::Http(format!(
                "WebSocket upgrade failed: server selected {} subprotocols (`{value}`), at most \
                 one is allowed",
                selected.len()
            )));
        }
        if let Some(chosen) = selected.first() {
            if !builder
                .protocols
                .iter()
                .any(|p| p.eq_ignore_ascii_case(chosen))
            {
                return Err(Error::Http(format!(
                    "WebSocket upgrade failed: server selected subprotocol `{chosen}`, which was \
                     not offered"
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    fn builder() -> WsBuilder {
        WsBuilder::new("wss://example.com/socket")
    }

    /// A well-formed handshake response, which individual tests then perturb.
    fn ok_headers() -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::UPGRADE, "websocket".parse().unwrap());
        headers.insert(http::header::CONNECTION, "Upgrade".parse().unwrap());
        headers.insert("sec-websocket-accept", ACCEPT.parse().unwrap());
        headers
    }

    fn validate(headers: &http::HeaderMap, builder: &WsBuilder) -> Result<()> {
        validate_upgrade_response(headers, StatusCode::SWITCHING_PROTOCOLS, ACCEPT, builder)
    }

    #[test]
    fn well_formed_handshake_is_accepted() {
        assert!(validate(&ok_headers(), &builder()).is_ok());
    }

    /// The worked example from RFC 6455 §1.3.
    ///
    /// Regression: `compute_accept` used a GUID that is not the one the RFC
    /// specifies, so the accept token never matched what any conforming server
    /// produces. It went unnoticed because the comparison only logged a
    /// warning — and because the local test server had independently invented a
    /// third, different GUID, so it agreed with nobody either.
    #[test]
    fn compute_accept_matches_the_rfc_6455_test_vector() {
        assert_eq!(compute_accept("dGhlIHNhbXBsZSBub25jZQ=="), ACCEPT);
    }

    #[test]
    fn ws_guid_is_the_value_rfc_6455_specifies() {
        assert_eq!(WS_GUID, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    }

    /// Regression: a wrong or missing `Sec-WebSocket-Accept` used to log a
    /// warning and continue, so anything answering `101` — a cached response, a
    /// confused endpoint, an intermediary — was treated as a WebSocket peer.
    /// RFC 6455 §4.1 requires failing the connection.
    #[test]
    fn wrong_or_missing_accept_fails_the_handshake() {
        let mut headers = ok_headers();
        headers.insert(
            "sec-websocket-accept",
            "not-the-right-digest".parse().unwrap(),
        );
        assert!(
            validate(&headers, &builder()).is_err(),
            "a mismatched Sec-WebSocket-Accept must fail the connection"
        );

        let mut headers = ok_headers();
        headers.remove("sec-websocket-accept");
        assert!(
            validate(&headers, &builder()).is_err(),
            "a missing Sec-WebSocket-Accept must fail the connection"
        );
    }

    #[test]
    fn upgrade_header_must_name_websocket() {
        let mut headers = ok_headers();
        headers.remove(http::header::UPGRADE);
        assert!(validate(&headers, &builder()).is_err(), "missing Upgrade");

        let mut headers = ok_headers();
        headers.insert(http::header::UPGRADE, "h2c".parse().unwrap());
        assert!(
            validate(&headers, &builder()).is_err(),
            "wrong Upgrade token"
        );

        // Case-insensitive per RFC 6455 §4.1.
        let mut headers = ok_headers();
        headers.insert(http::header::UPGRADE, "WebSocket".parse().unwrap());
        assert!(validate(&headers, &builder()).is_ok());
    }

    #[test]
    fn connection_header_must_include_the_upgrade_token() {
        let mut headers = ok_headers();
        headers.remove(http::header::CONNECTION);
        assert!(
            validate(&headers, &builder()).is_err(),
            "missing Connection"
        );

        let mut headers = ok_headers();
        headers.insert(http::header::CONNECTION, "keep-alive".parse().unwrap());
        assert!(validate(&headers, &builder()).is_err(), "no Upgrade token");

        // A token list is fine as long as `Upgrade` is one of them.
        let mut headers = ok_headers();
        headers.insert(
            http::header::CONNECTION,
            "keep-alive, upgrade".parse().unwrap(),
        );
        assert!(validate(&headers, &builder()).is_ok());
    }

    #[test]
    fn server_may_not_enable_an_unoffered_extension() {
        let mut headers = ok_headers();
        headers.insert(
            "sec-websocket-extensions",
            "permessage-deflate".parse().unwrap(),
        );
        assert!(
            validate(&headers, &builder()).is_err(),
            "an extension the client never offered must fail the connection"
        );

        // Offered — and parameters on the acceptance do not change the name.
        let with_offer = builder().extension("permessage-deflate");
        let mut headers = ok_headers();
        headers.insert(
            "sec-websocket-extensions",
            "permessage-deflate; client_max_window_bits=10"
                .parse()
                .unwrap(),
        );
        assert!(validate(&headers, &with_offer).is_ok());
    }

    #[test]
    fn server_may_not_select_an_unoffered_subprotocol() {
        let mut headers = ok_headers();
        headers.insert("sec-websocket-protocol", "chat".parse().unwrap());
        assert!(
            validate(&headers, &builder()).is_err(),
            "a subprotocol the client never offered must fail the connection"
        );

        let with_offer = builder().protocol("chat");
        assert!(validate(&headers, &with_offer).is_ok());

        // At most one subprotocol may be selected.
        let mut headers = ok_headers();
        headers.insert("sec-websocket-protocol", "chat, superchat".parse().unwrap());
        let both = builder().protocol("chat").protocol("superchat");
        assert!(
            validate(&headers, &both).is_err(),
            "selecting more than one subprotocol must fail the connection"
        );
    }

    #[test]
    fn non_101_status_fails_before_anything_else() {
        let result = validate_upgrade_response(&ok_headers(), StatusCode::OK, ACCEPT, &builder());
        assert!(result.is_err());
    }
}
