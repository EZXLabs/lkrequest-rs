//! Unified H2 sender for the native backend.
//!
//! The downstream call sequence:
//! 1. `sender.ready().await` → `Result<H2ReadySender>`
//! 2. `ready.send_request(req, end_stream)` → `(H2ResponseFuture, H2SendStream)`
//! 3. `send_stream.send_data(body, true)` (optional, if has body)
//! 4. `response_future.await_response()` → `http::Response<H2RecvStream>`
//! 5. `recv_stream.data().await` → `Option<Result<Bytes>>` (streaming!)
//! 6. `recv_stream.flow_control().release_capacity(len)`

use bytes::Bytes;

use tokio::sync::oneshot;

// ─── NativeH2Request ─────────────────────────────────────────────────────────

/// Internal request type for the native H2 backend.
/// Uses Vec instead of HeaderMap for deterministic header ordering.
#[derive(Debug)]
pub(crate) struct NativeH2Request {
    pub method: http::Method,
    pub uri: http::Uri,
    pub ordered_headers: Vec<(String, String)>,
    pub body: Option<Bytes>,
    pub priority: Option<crate::profile::RequestPriority>,
}

// ─── H2 Sender (Clone, pool-compatible) ──────────────────────────────────────

/// Unified cloneable H2 sender for the connection pool.
#[derive(Clone)]
pub enum H2Sender {
    Native(crate::driver::NativeSendRequest),
}

impl H2Sender {
    /// Wait for the connection to be ready to accept a new request.
    pub async fn ready(self) -> Result<H2ReadySender, H2SendError> {
        match self {
            Self::Native(mut sender) => {
                sender.ready().await.map_err(H2SendError::from_native)?;
                Ok(H2ReadySender::Native(sender))
            }
        }
    }
}

impl std::fmt::Debug for H2Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Native(_) => write!(f, "H2Sender::Native"),
        }
    }
}

// ─── Ready Sender ────────────────────────────────────────────────────────────

pub enum H2ReadySender {
    Native(crate::driver::NativeSendRequest),
}

impl H2ReadySender {
    /// Send an HTTP/2 request.
    ///
    /// The actual network send is deferred to
    /// `H2ResponseFuture::await_response()`.  `H2SendStream::send_data()`
    /// stores the body in shared state so it can be included.
    pub fn send_request(
        self,
        request: http::Request<()>,
        end_stream: bool,
    ) -> Result<(H2ResponseFuture, H2SendStream), H2SendError> {
        match self {
            Self::Native(sender) => {
                let (body_tx, body_rx) = oneshot::channel::<Option<Bytes>>();
                Ok((
                    H2ResponseFuture::Native {
                        sender,
                        request: Box::new(Some(request)),
                        end_stream,
                        body_rx: Some(body_rx),
                    },
                    H2SendStream::Native {
                        body_tx: Some(body_tx),
                    },
                ))
            }
        }
    }
}

// ─── Response Future ─────────────────────────────────────────────────────────

pub enum H2ResponseFuture {
    Native {
        sender: crate::driver::NativeSendRequest,
        request: Box<Option<http::Request<()>>>,
        end_stream: bool,
        body_rx: Option<oneshot::Receiver<Option<Bytes>>>,
    },
}

impl H2ResponseFuture {
    /// Await the HTTP response headers and obtain a streaming body.
    pub async fn await_response(self) -> Result<http::Response<H2RecvStream>, H2SendError> {
        match self {
            Self::Native {
                mut sender,
                request,
                end_stream,
                body_rx,
            } => {
                let orig_req =
                    (*request).ok_or_else(|| H2SendError("request already consumed".into()))?;
                let body = if end_stream {
                    None
                } else {
                    match body_rx {
                        Some(rx) => rx.await.unwrap_or(None),
                        None => None,
                    }
                };
                let (parts, _) = orig_req.into_parts();

                let http_req = build_native_request(&parts, body);
                let (resp_headers, body_rx) = sender
                    .send_native_request(http_req)
                    .await
                    .map_err(H2SendError::from_native)?;

                let recv = H2RecvStream::Native { body_rx };
                build_native_response(resp_headers, recv)
            }
        }
    }
}

/// Await the first request's response (piggybacked on connection setup).
///
/// Converts a `FirstRequestResponse` into the same `http::Response<H2RecvStream>`
/// that the normal `H2ResponseFuture::await_response()` path produces.
pub async fn await_first_response(
    resp: crate::driver::FirstRequestResponse,
) -> Result<http::Response<H2RecvStream>, H2SendError> {
    let resp_headers = resp
        .headers_rx
        .await
        .map_err(|_| H2SendError("first request channel closed".into()))?
        .map_err(H2SendError::from_native)?;

    let recv = H2RecvStream::Native {
        body_rx: resp.body_rx,
    };
    build_native_response(resp_headers, recv)
}

fn build_native_request(parts: &http::request::Parts, body: Option<Bytes>) -> NativeH2Request {
    let ordered_headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter(|(name, _)| !name.as_str().starts_with(':'))
        .filter_map(|(name, value)| match value.to_str() {
            Ok(v) => Some((name.as_str().to_owned(), v.to_owned())),
            Err(_) => {
                tracing::warn!(
                    header = %name,
                    "h2.native.non_utf8_header_value_skipped"
                );
                None
            }
        })
        .collect();

    let priority = parts
        .extensions
        .get::<crate::profile::RequestPriority>()
        .copied();

    NativeH2Request {
        method: parts.method.clone(),
        uri: parts.uri.clone(),
        ordered_headers,
        body,
        priority,
    }
}

fn build_native_response(
    resp_headers: crate::driver::NativeResponseHeaders,
    recv: H2RecvStream,
) -> Result<http::Response<H2RecvStream>, H2SendError> {
    // RFC 9113 §8.3.2: `:status` is mandatory and must be a usable status
    // code. Substituting an invented 500 would make a protocol error
    // indistinguishable from a server that really answered 500, so the
    // malformed response is surfaced as an error instead.
    let status = http::StatusCode::from_u16(resp_headers.status).map_err(|_| {
        H2SendError(format!(
            "{MALFORMED_PREFIX}: :status {} is not a valid status code (RFC 9113 §8.3.2)",
            resp_headers.status
        ))
    })?;

    let mut builder = http::Response::builder().status(status);
    for (name, value) in &resp_headers.headers {
        if name.starts_with(':') {
            continue;
        }
        // RFC 9113 §8.2: a field the caller cannot be given verbatim makes the
        // response malformed. Silently dropping it would hand back a response
        // missing headers the caller was never told about.
        validate_response_field(name, value)
            .map_err(|reason| H2SendError(format!("{MALFORMED_PREFIX}: {reason}")))?;
        let hn = http::header::HeaderName::try_from(name.as_str()).map_err(|_| {
            H2SendError(format!(
                "{MALFORMED_PREFIX}: field name {name:?} is not a valid HTTP field name (RFC 9113 §8.2.1)"
            ))
        })?;
        let hv = http::header::HeaderValue::from_str(value).map_err(|_| {
            H2SendError(format!(
                "{MALFORMED_PREFIX}: field {name:?} has a value that is not a valid HTTP field value (RFC 9113 §8.2.1)"
            ))
        })?;
        builder = builder.header(hn, hv);
    }

    builder
        .body(recv)
        .map_err(|e| H2SendError(format!("failed to build response: {e}")))
}

// ─── Received-response validation (RFC 9113 §8.1.1 / §8.2 / §8.3.2) ─────────
//
// Everything below is **receive side only**: it inspects field sections the
// peer sent us and never influences a single byte this client emits. The
// request path (`build_native_request`) is deliberately untouched, because the
// bytes it produces are the fingerprint this crate exists to reproduce.

/// Prefix shared by every malformed-response diagnostic, so a caller can tell
/// a protocol violation apart from a status the server actually sent.
pub(crate) const MALFORMED_PREFIX: &str = "malformed response";

/// Connection-specific field names that make an HTTP/2 message malformed
/// (RFC 9113 §8.2.2). These are the H2→H1 downgrade / request-smuggling
/// surface, so they are rejected outright rather than stripped.
const CONNECTION_SPECIFIC_FIELDS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

/// Validate the `:status` pseudo-header of a received response.
///
/// RFC 9113 §8.3.2 requires exactly one `:status`, carrying a three-digit
/// status code. A missing or unusable `:status` is a protocol error, not a
/// server-sent status, and is reported as such.
pub(crate) fn validate_response_status(raw: Option<&str>) -> Result<u16, String> {
    let Some(raw) = raw else {
        return Err("response has no :status pseudo-header (RFC 9113 §8.3.2)".to_string());
    };
    let three_digits = raw.len() == 3 && raw.bytes().all(|b| b.is_ascii_digit());
    let code = three_digits.then(|| raw.parse::<u16>().ok()).flatten();
    let code = code.filter(|&c| http::StatusCode::from_u16(c).is_ok());
    code.ok_or_else(|| {
        format!(":status {raw:?} is not a three-digit status code (RFC 9113 §8.3.2)")
    })
}

/// Validate the pseudo-header fields of a received field section.
///
/// RFC 9113 §8.3 defines exactly one pseudo-header field for a response —
/// `:status` — and requires every pseudo-header to appear *before* any regular
/// field. §8.1 forbids pseudo-headers in a trailer section outright. Each of
/// these makes the response malformed, which §8.1.1 makes a stream error of
/// type PROTOCOL_ERROR.
///
/// `trailers` selects which rule set applies: a trailer section admits no
/// pseudo-header at all, so `:status` is just as illegal there as `:method`.
///
/// Receive side only — this never looks at, or influences, the field section
/// this client sends.
pub(crate) fn validate_response_pseudo_headers(
    headers: &[(String, String)],
    trailers: bool,
) -> Result<(), String> {
    let mut seen_regular = false;
    let mut seen_status = false;

    for (name, _) in headers {
        if !name.starts_with(':') {
            seen_regular = true;
            continue;
        }
        if trailers {
            return Err(format!(
                "pseudo-header {name:?} is not allowed in a trailer section (RFC 9113 §8.1)"
            ));
        }
        // §8.3: "All pseudo-header fields MUST appear ... before any regular
        // field". Checked before the name itself so the diagnostic names the
        // rule that was broken first.
        if seen_regular {
            return Err(format!(
                "pseudo-header {name:?} appears after a regular field (RFC 9113 §8.3)"
            ));
        }
        if name != ":status" {
            return Err(format!(
                "pseudo-header {name:?} is not defined for responses (RFC 9113 §8.3)"
            ));
        }
        // §8.3.2: a response carries exactly one `:status`.
        if std::mem::replace(&mut seen_status, true) {
            return Err(
                "response has more than one :status pseudo-header (RFC 9113 §8.3.2)".to_string(),
            );
        }
    }

    Ok(())
}

/// Validate every regular field of a received field section.
///
/// Pseudo-headers are skipped; they are validated by their own rules.
pub(crate) fn validate_response_fields(headers: &[(String, String)]) -> Result<(), String> {
    for (name, value) in headers {
        if name.starts_with(':') {
            continue;
        }
        validate_response_field(name, value)?;
    }
    Ok(())
}

/// Validate one received field per RFC 9113 §8.2.1 (field validity) and
/// §8.2.2 (connection-specific fields).
fn validate_response_field(name: &str, value: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("field name is empty (RFC 9113 §8.2.1)".to_string());
    }
    // §8.2.1: a field name must not contain bytes in 0x00-0x20, 0x41-0x5a
    // (ASCII uppercase) or 0x7f-0xff. `http::HeaderName` silently *lowercases*
    // ASCII uppercase instead of rejecting it, so the range check has to run
    // before parsing or an uppercase name would be normalized away.
    if let Some(bad) = name
        .bytes()
        .find(|&b| matches!(b, 0x00..=0x20 | 0x41..=0x5a | 0x7f..=0xff))
    {
        return Err(format!(
            "field name {name:?} contains the forbidden byte {bad:#04x} (RFC 9113 §8.2.1)"
        ));
    }
    if http::header::HeaderName::try_from(name).is_err() {
        return Err(format!(
            "field name {name:?} is not a valid HTTP field name (RFC 9113 §8.2.1)"
        ));
    }

    // §8.2.1: a field value must not contain NUL / LF / CR, and must not begin
    // or end with ASCII whitespace.
    if let Some(bad) = value.bytes().find(|&b| matches!(b, 0x00 | 0x0a | 0x0d)) {
        return Err(format!(
            "field {name:?} has a value containing the forbidden byte {bad:#04x} (RFC 9113 §8.2.1)"
        ));
    }
    if value.starts_with([' ', '\t']) || value.ends_with([' ', '\t']) {
        return Err(format!(
            "field {name:?} has a value with leading or trailing whitespace (RFC 9113 §8.2.1)"
        ));
    }
    if http::header::HeaderValue::from_str(value).is_err() {
        return Err(format!(
            "field {name:?} has a value that is not a valid HTTP field value (RFC 9113 §8.2.1)"
        ));
    }

    // §8.2.2: connection-specific fields have no meaning in HTTP/2 and make
    // the message malformed. `TE` is tolerated only as exactly "trailers".
    if CONNECTION_SPECIFIC_FIELDS.contains(&name) {
        return Err(format!(
            "connection-specific field {name:?} is not allowed in HTTP/2 (RFC 9113 §8.2.2)"
        ));
    }
    if name == "te" && value != "trailers" {
        return Err(format!(
            "te field value {value:?} must be exactly \"trailers\" in HTTP/2 (RFC 9113 §8.2.2)"
        ));
    }

    Ok(())
}

/// Extract the declared `content-length` of a received response.
///
/// `Ok(None)` means the response declared no content length, so RFC 9113
/// §8.1.1's "content-length equals the sum of the DATA payload lengths" rule
/// does not apply.
pub(crate) fn response_content_length(headers: &[(String, String)]) -> Result<Option<u64>, String> {
    let mut declared: Option<u64> = None;
    for (name, value) in headers {
        if name != "content-length" {
            continue;
        }
        let parsed = (!value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()))
            .then(|| value.parse::<u64>().ok())
            .flatten()
            .ok_or_else(|| {
                format!("content-length {value:?} is not a non-negative integer (RFC 9110 §8.6)")
            })?;
        match declared {
            Some(previous) if previous != parsed => {
                return Err(format!(
                    "conflicting content-length values {previous} and {parsed} (RFC 9110 §8.6)"
                ));
            }
            _ => declared = Some(parsed),
        }
    }
    Ok(declared)
}

// ─── Send Stream ─────────────────────────────────────────────────────────────

pub enum H2SendStream {
    Native {
        body_tx: Option<oneshot::Sender<Option<Bytes>>>,
    },
}

impl H2SendStream {
    pub fn send_data(&mut self, data: Bytes, _end_stream: bool) -> Result<(), H2SendError> {
        match self {
            Self::Native { body_tx } => {
                let tx = body_tx
                    .take()
                    .ok_or_else(|| H2SendError("body already sent".into()))?;
                tx.send(Some(data))
                    .map_err(|_| H2SendError("response future dropped".into()))
            }
        }
    }
}

impl Drop for H2SendStream {
    fn drop(&mut self) {
        match self {
            Self::Native { body_tx } => {
                if let Some(tx) = body_tx.take() {
                    let _ = tx.send(None);
                }
            }
        }
    }
}

// ─── Recv Stream ─────────────────────────────────────────────────────────────

pub enum H2RecvStream {
    Native {
        body_rx: tokio::sync::mpsc::UnboundedReceiver<Result<Bytes, crate::driver::DriverError>>,
    },
}

impl H2RecvStream {
    /// Read the next data chunk from the body.
    ///
    /// Returns `None` when the body is complete (EOF).
    pub async fn data(&mut self) -> Option<Result<Bytes, H2SendError>> {
        match self {
            Self::Native { body_rx } => match body_rx.recv().await {
                Some(Ok(data)) => Some(Ok(data)),
                Some(Err(e)) => Some(Err(H2SendError::from_native(e))),
                None => None,
            },
        }
    }

    pub fn flow_control(&mut self) -> H2FlowControl<'_> {
        H2FlowControl { stream: self }
    }
}

/// Flow control handle.
pub struct H2FlowControl<'a> {
    stream: &'a mut H2RecvStream,
}

impl H2FlowControl<'_> {
    pub fn release_capacity(&mut self, _amount: usize) -> Result<(), H2SendError> {
        match self.stream {
            H2RecvStream::Native { .. } => Ok(()),
        }
    }
}

// ─── Error ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct H2SendError(pub String);

impl H2SendError {
    fn from_native(e: crate::driver::DriverError) -> Self {
        Self(e.to_string())
    }
}

impl std::fmt::Display for H2SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for H2SendError {}

// ─── Unified H2Connection ───────────────────────────────────────────────────

/// Unified H2 connection.
pub struct UnifiedH2Connection {
    sender: H2Sender,
    conn_task: tokio::task::JoinHandle<()>,
    first_response: Option<crate::driver::FirstRequestResponse>,
}

impl UnifiedH2Connection {
    pub(crate) fn from_native(
        sender: crate::driver::NativeSendRequest,
        conn_task: tokio::task::JoinHandle<()>,
    ) -> Self {
        Self {
            sender: H2Sender::Native(sender),
            conn_task,
            first_response: None,
        }
    }

    pub(crate) fn from_native_with_first(
        sender: crate::driver::NativeSendRequest,
        conn_task: tokio::task::JoinHandle<()>,
        first_response: crate::driver::FirstRequestResponse,
    ) -> Self {
        Self {
            sender: H2Sender::Native(sender),
            conn_task,
            first_response: Some(first_response),
        }
    }

    /// Take the first request's response channels, if available.
    /// Only meaningful when a first request was piggybacked on connection setup.
    pub fn take_first_response(&mut self) -> Option<crate::driver::FirstRequestResponse> {
        self.first_response.take()
    }

    pub fn clone_sender(&self) -> H2Sender {
        self.sender.clone()
    }

    pub fn into_task(self) -> tokio::task::JoinHandle<()> {
        self.conn_task
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
            .collect()
    }

    fn response(
        status: u16,
        pairs: &[(&str, &str)],
    ) -> Result<http::Response<H2RecvStream>, H2SendError> {
        let (_body_tx, body_rx) = tokio::sync::mpsc::unbounded_channel();
        build_native_response(
            crate::driver::NativeResponseHeaders {
                status,
                headers: headers(pairs),
            },
            H2RecvStream::Native { body_rx },
        )
    }

    // ── H-04: an unusable :status must not be disguised as a 500 ──

    #[test]
    fn invalid_status_is_an_error_not_a_synthesized_500() {
        for bad in [0u16, 1, 99, 1000] {
            let built = response(bad, &[]);
            let message = built.err().map(|e| e.to_string());
            assert!(
                message
                    .as_deref()
                    .is_some_and(|m| m.contains("malformed response") && m.contains(":status")),
                ":status {bad} must surface as a malformed-response error, got {message:?}"
            );
        }
    }

    #[test]
    fn a_server_sent_500_is_still_an_ordinary_response() {
        let built = response(500, &[]).unwrap();
        assert_eq!(
            built.status(),
            http::StatusCode::INTERNAL_SERVER_ERROR,
            "a real 500 must remain distinguishable from a protocol error"
        );
    }

    // ── H-02: fields must be rejected, never silently dropped or lowercased ──

    #[test]
    fn uppercase_field_name_is_rejected_not_lowercased() {
        let built = response(200, &[("X-Trace", "abc")]);
        let message = built.err().map(|e| e.to_string());
        assert!(
            message.as_deref().is_some_and(|m| m.contains("X-Trace")),
            "an uppercase field name must be rejected, not normalized, got {message:?}"
        );
    }

    #[test]
    fn unrepresentable_field_is_rejected_not_dropped() {
        for (name, value) in [("x bad", "v"), ("x-nul", "a\u{0}b"), ("", "v")] {
            let built = response(200, &[(name, value)]);
            assert!(
                built.is_err(),
                "field ({name:?}, {value:?}) must be reported, not silently dropped"
            );
        }
    }

    #[test]
    fn well_formed_fields_all_survive() {
        let built = response(200, &[("x-a", "1"), ("x-b", "2"), (":status", "200")]).unwrap();
        assert_eq!(
            built.headers().len(),
            2,
            "every regular field must be present: {:?}",
            built.headers()
        );
    }

    // ── H-03: connection-specific fields ──

    #[test]
    fn connection_specific_fields_are_rejected() {
        for name in CONNECTION_SPECIFIC_FIELDS {
            let built = response(200, &[(name, "x")]);
            assert!(built.is_err(), "{name} must make the response malformed");
        }
        assert!(response(200, &[("te", "gzip")]).is_err());
        assert!(response(200, &[("te", "trailers")]).is_ok());
    }

    // ── validator unit coverage ──

    #[test]
    fn validate_response_status_accepts_only_three_digit_codes() {
        assert_eq!(validate_response_status(Some("204")), Ok(204));
        assert!(validate_response_status(None).is_err());
        for bad in ["", "20", "0200", "abc", " 200", "200 ", "099", "+20"] {
            assert!(
                validate_response_status(Some(bad)).is_err(),
                ":status {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn validate_response_fields_ignores_pseudo_headers() {
        let ok = validate_response_fields(&headers(&[(":status", "200"), ("x-a", "1")]));
        assert!(ok.is_ok(), "pseudo-headers are validated elsewhere: {ok:?}");
    }

    #[test]
    fn response_content_length_parses_validates_and_deduplicates() {
        assert_eq!(response_content_length(&headers(&[])), Ok(None));
        assert_eq!(
            response_content_length(&headers(&[("content-length", "12")])),
            Ok(Some(12))
        );
        assert_eq!(
            response_content_length(&headers(&[
                ("content-length", "12"),
                ("content-length", "12")
            ])),
            Ok(Some(12))
        );
        assert!(response_content_length(&headers(&[
            ("content-length", "12"),
            ("content-length", "13")
        ]))
        .is_err());
        for bad in ["", "abc", "-1", "+5", "0x10", "5 ", " 5"] {
            assert!(
                response_content_length(&headers(&[("content-length", bad)])).is_err(),
                "content-length {bad:?} must be rejected"
            );
        }
    }
}
