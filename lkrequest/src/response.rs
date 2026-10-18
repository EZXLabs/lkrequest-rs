//! HTTP response type.
//!
//! The [`Response`] struct wraps an HTTP response (status, headers, body)
//! and provides convenience methods for reading the body in different formats.
//!
//! Response bodies are **automatically decompressed** based on the
//! `content-encoding` header. Supported encodings: `br` (Brotli),
//! `gzip`/`deflate`, `zstd`.

use bytes::Bytes;
use http::{HeaderMap, StatusCode};

/// Legacy HTTP version type.
///
/// This type is kept for backwards compatibility with
/// [`Response::version`]. New response-side code should prefer
/// [`NegotiatedHttpVersion`]. New request-side code should prefer
/// [`crate::PreferredHttpVersion`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
    /// HTTP/2
    H2,
    /// HTTP/3
    H3,
    /// Unknown / not determined on the wire for responses.
    ///
    /// When passed to [`crate::session::RequestBuilder::version`], this selects
    /// no HTTP-version override (ALPN / session preference decides).
    Unknown,
}

/// HTTP version negotiated for a response.
///
/// Unlike [`HttpVersion`], this type has no `Unknown` variant: a completed
/// response always has an observed protocol version. If an internal fallback
/// path cannot report a better value, lkrequest uses HTTP/1.1 as the most
/// conservative compatibility value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiatedHttpVersion {
    /// HTTP/1.0
    Http10,
    /// HTTP/1.1
    Http11,
    /// HTTP/2
    Http2,
    /// HTTP/3
    Http3,
}

impl NegotiatedHttpVersion {
    pub(crate) fn from_legacy_or_default(version: HttpVersion) -> Self {
        match version {
            HttpVersion::Http10 => Self::Http10,
            HttpVersion::Http11 | HttpVersion::Unknown => Self::Http11,
            HttpVersion::H2 => Self::Http2,
            HttpVersion::H3 => Self::Http3,
        }
    }
}

impl From<NegotiatedHttpVersion> for HttpVersion {
    fn from(version: NegotiatedHttpVersion) -> Self {
        match version {
            NegotiatedHttpVersion::Http10 => Self::Http10,
            NegotiatedHttpVersion::Http11 => Self::Http11,
            NegotiatedHttpVersion::Http2 => Self::H2,
            NegotiatedHttpVersion::Http3 => Self::H3,
        }
    }
}

impl std::fmt::Display for HttpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpVersion::Http10 => write!(f, "HTTP/1.0"),
            HttpVersion::Http11 => write!(f, "HTTP/1.1"),
            HttpVersion::H2 => write!(f, "h2"),
            HttpVersion::H3 => write!(f, "h3"),
            HttpVersion::Unknown => write!(f, "unknown"),
        }
    }
}

/// A single hop in the redirect chain.
///
/// When a request follows redirects (301, 302, 307, 308), each intermediate
/// response is captured as a `RedirectRecord`. The full chain is available
/// via [`Response::redirect_history()`].
#[derive(Debug, Clone)]
pub struct RedirectRecord {
    /// The URL that was requested (before redirect).
    url: String,
    /// The HTTP status code (301, 302, 307, 308).
    status: StatusCode,
    /// The response headers from this hop.
    headers: HeaderMap,
    /// The target URL from the Location header.
    redirect_to: String,
}

impl RedirectRecord {
    pub(crate) fn new(
        url: String,
        status: StatusCode,
        headers: HeaderMap,
        redirect_to: String,
    ) -> Self {
        Self {
            url,
            status,
            headers,
            redirect_to,
        }
    }

    /// Returns the URL that was requested **for this redirect hop** (before
    /// following `Location`).
    ///
    /// This is **not** the same as [`Response::url`], which is the **final**
    /// URL after the full redirect chain completes.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns the HTTP status code of this redirect response.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns a reference to the response headers of this hop.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns the target URL that this hop redirected to.
    pub fn redirect_to(&self) -> &str {
        &self.redirect_to
    }
}

/// An HTTP response.
///
/// The body is automatically decompressed if the `content-encoding` header
/// indicates compression (br, gzip, deflate, zstd).
///
/// # Example
///
/// ```rust,no_run
/// # async fn example() -> Result<(), lkrequest::error::Error> {
/// # use lkrequest::Client;
/// # use lktls::profile::presets;
/// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
/// # let session = client.session().build();
/// let resp = session.get("https://example.com").send().await?;
/// println!("Status: {}", resp.status());
/// println!("Body: {}", resp.text()?);
/// # Ok(())
/// # }
/// ```
pub struct Response {
    /// HTTP status code.
    status: StatusCode,
    /// Response headers.
    headers: HeaderMap,
    /// Response body bytes (decompressed if content-encoding was present).
    body: Bytes,
    /// The final URL (after redirects).
    url: String,
    /// The HTTP version used for this response.
    http_version: HttpVersion,
    /// Strict negotiated HTTP version used for this response.
    negotiated_version: NegotiatedHttpVersion,
    /// The redirect chain that led to this response (empty if no redirects).
    redirect_history: Vec<RedirectRecord>,
    /// Per-request diagnostics (phase timings, protocol, remote address).
    /// Present only when the request opted in via `collect_diagnostics(true)`;
    /// `None` (and zero extra cost) otherwise. Boxed to keep `Response` small on
    /// the common path (the allocation only happens when diagnostics are set).
    diagnostics: Option<Box<crate::diagnostics::RequestDiagnostics>>,
}

impl Response {
    /// Create a new Response from parts, automatically decompressing the body
    /// if a `content-encoding` header is present.
    pub(crate) fn new(
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
    ) -> crate::error::Result<Self> {
        let decompressed = decompress_body(&headers, body)?;
        Ok(Self {
            status,
            headers,
            body: decompressed,
            url: String::new(),
            http_version: HttpVersion::Unknown,
            negotiated_version: NegotiatedHttpVersion::Http11,
            redirect_history: Vec::new(),
            diagnostics: None,
        })
    }

    /// Create a Response from pre-processed parts (no decompression).
    ///
    /// Used after middleware processing where the body has already been
    /// decompressed.
    pub(crate) fn from_parts(status: StatusCode, headers: HeaderMap, body: Bytes) -> Self {
        Self {
            status,
            headers,
            body,
            url: String::new(),
            http_version: HttpVersion::Unknown,
            negotiated_version: NegotiatedHttpVersion::Http11,
            redirect_history: Vec::new(),
            diagnostics: None,
        }
    }

    /// Set the final URL (called internally after redirect chain completes).
    pub(crate) fn set_url(&mut self, url: String) {
        self.url = url;
    }

    /// Set the HTTP version (called internally based on ALPN result).
    pub(crate) fn set_http_version(&mut self, version: HttpVersion) {
        self.http_version = version;
        self.negotiated_version = NegotiatedHttpVersion::from_legacy_or_default(version);
    }

    /// Set the redirect history (called internally after redirect chain completes).
    pub(crate) fn set_redirect_history(&mut self, history: Vec<RedirectRecord>) {
        self.redirect_history = history;
    }

    /// Attach per-request diagnostics (called internally when the session opted
    /// into diagnostics collection).
    pub(crate) fn set_diagnostics(&mut self, diagnostics: crate::diagnostics::RequestDiagnostics) {
        self.diagnostics = Some(Box::new(diagnostics));
    }

    /// Per-request diagnostics (phase timings, protocol, remote address), if the
    /// session enabled collection via `collect_diagnostics(true)`.
    ///
    /// Returns `None` when diagnostics collection was not enabled.
    pub fn diagnostics(&self) -> Option<&crate::diagnostics::RequestDiagnostics> {
        self.diagnostics.as_deref()
    }

    /// Take ownership of the redirect history, leaving an empty vec behind.
    pub(crate) fn take_redirect_history(&mut self) -> Vec<RedirectRecord> {
        std::mem::take(&mut self.redirect_history)
    }

    /// Returns the redirect chain that led to this response.
    ///
    /// Each entry represents one hop: the URL that was requested,
    /// the 3xx status code received, the response headers, and the
    /// `Location` URL the server redirected to.
    ///
    /// Returns an empty slice if no redirects occurred.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://example.com/old").send().await?;
    /// for hop in resp.redirect_history() {
    ///     println!("{} -> {} ({})", hop.url(), hop.redirect_to(), hop.status());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn redirect_history(&self) -> &[RedirectRecord] {
        &self.redirect_history
    }

    /// Returns `true` if the request followed at least one redirect.
    pub fn was_redirected(&self) -> bool {
        !self.redirect_history.is_empty()
    }

    /// Returns the HTTP status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns a reference to the response headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns the final URL of this response.
    ///
    /// If the request followed redirects, this is the URL of the final
    /// response (not the original request URL). For per-hop URLs in the chain,
    /// see [`RedirectRecord::url`](RedirectRecord::url) on
    /// [`redirect_history`](Self::redirect_history) entries.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://example.com/old-page").send().await?;
    /// // If 301 redirected to /new-page:
    /// assert_eq!(resp.url(), "https://example.com/new-page");
    /// # Ok(())
    /// # }
    /// ```
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns the HTTP version used for this response.
    ///
    /// This legacy method returns [`HttpVersion`] for backwards
    /// compatibility. New response-side code should call
    /// [`Response::negotiated_version`], whose return type has no
    /// `Unknown` variant.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://example.com").send().await?;
    /// println!("Protocol: {}", resp.version()); // "h2" or "HTTP/1.1"
    /// # Ok(())
    /// # }
    /// ```
    pub fn version(&self) -> HttpVersion {
        self.http_version
    }

    /// Returns the negotiated HTTP version for this response.
    pub fn negotiated_version(&self) -> NegotiatedHttpVersion {
        self.negotiated_version
    }

    /// Returns the `Content-Length` of the response body, if known.
    ///
    /// Reads the `content-length` header. Note that after decompression,
    /// the actual body length may differ from this value.
    pub fn content_length(&self) -> Option<u64> {
        self.headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
    }

    /// Returns the cookies set by this response (`Set-Cookie` headers).
    ///
    /// Returns a list of `(name, value)` pairs from all `Set-Cookie` headers.
    /// This is useful for inspecting what cookies the server sent, even
    /// though they are automatically stored in the session's cookie jar.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://example.com").send().await?;
    /// for (name, value) in resp.cookies() {
    ///     println!("Set-Cookie: {name}={value}");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn cookies(&self) -> Vec<(&str, &str)> {
        self.headers
            .get_all(http::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter_map(|s| {
                let name_value = s.trim().split(';').next()?;
                let mut parts = name_value.splitn(2, '=');
                let name = parts.next()?.trim();
                let value = parts.next().unwrap_or("").trim();
                Some((name, value))
            })
            .collect()
    }

    /// Returns the response body as a UTF-8 string.
    ///
    /// Returns an error if the body is not valid UTF-8.
    pub fn text(&self) -> crate::error::Result<&str> {
        std::str::from_utf8(&self.body).map_err(|e| {
            crate::error::Error::Http(format!("response body is not valid UTF-8: {e}"))
        })
    }

    /// Consume the response and return the body as an owned UTF-8 string.
    ///
    /// This is the owned version of [`text()`](Self::text). Use this when
    /// you need to move the string out of the response (e.g. to store it
    /// in a struct or return from a function) without an extra copy.
    ///
    /// Returns an error if the body is not valid UTF-8.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// # let resp = session.get("https://example.com").send().await?;
    /// let body: String = resp.into_text()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn into_text(self) -> crate::error::Result<String> {
        // Try zero-copy path: if Bytes is sole owner, Vec conversion is free.
        String::from_utf8(self.body.into()).map_err(|e| {
            crate::error::Error::Http(format!("response body is not valid UTF-8: {e}"))
        })
    }

    /// Returns the response body as raw bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    /// Consume the response and return the body as `Bytes` (zero-copy).
    pub fn into_bytes(self) -> Bytes {
        self.body
    }

    /// Consume the response and return the body as `Vec<u8>`.
    ///
    /// Use [`into_bytes()`](Self::into_bytes) when possible to avoid a copy.
    pub fn into_vec(self) -> Vec<u8> {
        self.body.into()
    }

    /// Deserialize the response body as JSON.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # use serde::Deserialize;
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// # let resp = session.get("https://example.com").send().await?;
    /// #[derive(Deserialize)]
    /// struct ApiResponse { data: String }
    ///
    /// let api: ApiResponse = resp.json()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> crate::error::Result<T> {
        serde_json::from_slice(&self.body)
            .map_err(|e| crate::error::Error::Http(format!("failed to deserialize JSON: {e}")))
    }

    /// Turn a response into an error if the server returned a client (4xx)
    /// or server (5xx) error status code.
    ///
    /// Consumes the response. If the status is 1xx/2xx/3xx, returns `Ok(self)`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://example.com/api")
    ///     .send()
    ///     .await?
    ///     .error_for_status()?;
    /// // If status was 404, error_for_status returns Err(Error::Status { .. })
    /// # Ok(())
    /// # }
    /// ```
    pub fn error_for_status(self) -> crate::error::Result<Self> {
        let status = self.status;
        if status.is_client_error() || status.is_server_error() {
            Err(crate::error::Error::Status {
                status,
                url: self.url.clone(),
            })
        } else {
            Ok(self)
        }
    }

    /// Check the status code, returning a reference to the response on
    /// success or an error on 4xx/5xx — without consuming the response.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://example.com/api").send().await?;
    /// resp.error_for_status_ref()?;
    /// println!("Body: {}", resp.text()?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn error_for_status_ref(&self) -> crate::error::Result<&Self> {
        if self.status.is_client_error() || self.status.is_server_error() {
            Err(crate::error::Error::Status {
                status: self.status,
                url: self.url.clone(),
            })
        } else {
            Ok(self)
        }
    }
}

// ---------------------------------------------------------------------------
// Body decompression
// ---------------------------------------------------------------------------

/// One content coding from a `content-encoding` header that we can act on.
///
/// `Identity` is recognized but decodes to nothing at all — RFC 9110 §8.4.1.1
/// defines it as the absence of any coding.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ContentCoding {
    Brotli,
    Gzip,
    Deflate,
    Zstd,
    Identity,
}

impl ContentCoding {
    /// Map one content-coding token, or `None` if we cannot decode it.
    fn from_token(token: &str) -> Option<Self> {
        // Content codings are case-insensitive (RFC 9110 §8.4.1).
        match token.to_ascii_lowercase().as_str() {
            "br" => Some(Self::Brotli),
            "gzip" | "x-gzip" => Some(Self::Gzip),
            "deflate" => Some(Self::Deflate),
            "zstd" => Some(Self::Zstd),
            "identity" => Some(Self::Identity),
            _ => None,
        }
    }

    /// Canonical token, used for log fields, error messages, and to build the
    /// matching [`StreamDecoder`].
    fn token(self) -> &'static str {
        match self {
            Self::Brotli => "br",
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
            Self::Zstd => "zstd",
            Self::Identity => "identity",
        }
    }

    /// Decode one whole layer.
    fn decode(self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Self::Brotli => decompress_brotli(data),
            Self::Gzip => decompress_gzip(data),
            Self::Deflate => decompress_deflate(data),
            Self::Zstd => decompress_zstd(data),
            Self::Identity => Ok(data.to_vec()),
        }
    }
}

/// What a response's `content-encoding` header asks us to do.
enum ContentEncodingPlan {
    /// Nothing to decode: header absent, empty, or `identity` only.
    Passthrough,
    /// A lone coding we do not implement. Handing the body back untouched is
    /// long-standing behavior, so it is preserved rather than turned into an
    /// error.
    UnknownSingle(String),
    /// Codings to apply, already ordered for decoding. `content-encoding` lists
    /// codings in the order the sender applied them, so decoding runs in
    /// reverse (RFC 9110 §8.4).
    Decode(Vec<ContentCoding>),
    /// A multi-coding list holding at least one coding we do not implement.
    /// Peeling off only the layers we understand would hand back bytes that are
    /// still compressed, with nothing in the response for the caller to detect
    /// that from — so this is refused instead.
    UnknownInList { unknown: String, list: String },
}

/// Join every `content-encoding` header line into one comma-separated list.
///
/// A list-valued field may legally be split across multiple header lines
/// (RFC 9110 §5.3), so reading only the first line can silently drop codings.
fn content_encoding_list(headers: &HeaderMap) -> String {
    let mut list = String::new();
    for value in headers.get_all(http::header::CONTENT_ENCODING) {
        let Ok(text) = value.to_str() else { continue };
        if !list.is_empty() {
            list.push(',');
        }
        list.push_str(text);
    }
    list
}

/// Turn a `content-encoding` list into a decoding plan.
fn parse_content_encoding(list: &str) -> ContentEncodingPlan {
    // RFC 9110 §5.6.1: recipients ignore empty list elements.
    let tokens: Vec<&str> = list
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect();

    match tokens.as_slice() {
        [] => ContentEncodingPlan::Passthrough,
        [only] => match ContentCoding::from_token(only) {
            Some(ContentCoding::Identity) => ContentEncodingPlan::Passthrough,
            Some(coding) => ContentEncodingPlan::Decode(vec![coding]),
            None => ContentEncodingPlan::UnknownSingle((*only).to_string()),
        },
        many => {
            let mut codings = Vec::with_capacity(many.len());
            // Reverse order: the coding listed last was applied last, so it is
            // the first one to peel off.
            for token in many.iter().rev() {
                match ContentCoding::from_token(token) {
                    // `identity` contributes no layer.
                    Some(ContentCoding::Identity) => {}
                    Some(coding) => codings.push(coding),
                    None => {
                        return ContentEncodingPlan::UnknownInList {
                            unknown: (*token).to_string(),
                            list: list.trim().to_string(),
                        };
                    }
                }
            }
            if codings.is_empty() {
                ContentEncodingPlan::Passthrough
            } else {
                ContentEncodingPlan::Decode(codings)
            }
        }
    }
}

/// Error for a multi-coding list we only partially understand. Shared so the
/// buffered and streaming paths refuse identically.
fn unsupported_coding_in_list(unknown: &str, list: &str) -> crate::error::Error {
    crate::error::Error::Body(format!(
        "unsupported content-encoding `{unknown}` in list `{list}`: \
         refusing to return a partially decoded body"
    ))
}

/// Decompress the response body based on the `content-encoding` header.
///
/// The header is a list: a sender may apply several codings, and
/// `content-encoding: gzip, br` means gzip was applied first and brotli
/// second, so decoding walks the list in reverse (RFC 9110 §8.4). Values split
/// across multiple header lines are treated as one list.
///
/// Returns the original body unchanged if:
/// - No content-encoding header is present
/// - The list is empty or names only `identity`
/// - The list holds a *single* coding we do not implement
///
/// Returns [`crate::error::Error::Body`] if a declared coding cannot be
/// decoded, or if a multi-coding list names a coding we do not implement —
/// decoding it halfway would return still-compressed bytes that the caller
/// cannot distinguish from real content.
fn decompress_body(headers: &HeaderMap, body: Bytes) -> crate::error::Result<Bytes> {
    // An empty body carries nothing that could be silently mis-decoded, so it
    // passes through whatever the header says (HEAD and 204 responses keep
    // their origin's `content-encoding`).
    if body.is_empty() {
        return Ok(body);
    }

    let list = content_encoding_list(headers);
    let codings = match parse_content_encoding(&list) {
        ContentEncodingPlan::Passthrough => return Ok(body),
        ContentEncodingPlan::UnknownSingle(token) => {
            tracing::warn!(encoding = %token, "http.unknown_content_encoding");
            return Ok(body);
        }
        ContentEncodingPlan::UnknownInList { unknown, list } => {
            tracing::warn!(
                encoding = %unknown,
                content_encoding = %list,
                "http.unknown_content_encoding_in_list",
            );
            return Err(unsupported_coding_in_list(&unknown, &list));
        }
        ContentEncodingPlan::Decode(codings) => codings,
    };

    let raw_bytes = body.len();
    let mut current = body;
    for coding in codings {
        match coding.decode(&current) {
            Ok(decompressed) => current = Bytes::from(decompressed),
            Err(e) => {
                tracing::warn!(
                    encoding = %coding.token(),
                    content_encoding = %list,
                    raw_bytes,
                    error = %e,
                    "http.decompress_failed",
                );
                return Err(crate::error::Error::Body(format!(
                    "decompression failed for content-encoding `{}`: {e}",
                    coding.token()
                )));
            }
        }
    }

    tracing::trace!(
        content_encoding = %list,
        raw_bytes,
        decoded_bytes = current.len(),
        "http.body_decompressed",
    );
    Ok(current)
}

/// Hard cap on decompressed body size to prevent decompression bombs.
/// A small compressed payload can decompress to gigabytes; this limit
/// caps decompressed output regardless of `ResourceLimits` (which may
/// not be available at decompression time).
const MAX_DECOMPRESSED_SIZE: usize = 256 * 1024 * 1024; // 256 MB

fn size_limited_read(reader: &mut dyn std::io::Read, encoding: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut output = Vec::new();
    reader
        .take((MAX_DECOMPRESSED_SIZE as u64) + 1)
        .read_to_end(&mut output)
        .map_err(|e| format!("{encoding} decompression failed: {e}"))?;
    if output.len() > MAX_DECOMPRESSED_SIZE {
        return Err(format!(
            "{encoding} decompressed data exceeds {MAX_DECOMPRESSED_SIZE} byte safety limit"
        ));
    }
    Ok(output)
}

fn decompress_brotli(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = brotli::Decompressor::new(data, 4096);
    size_limited_read(&mut decoder, "brotli")
}

fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = flate2::read::GzDecoder::new(data);
    size_limited_read(&mut decoder, "gzip")
}

/// Whether `data` starts with an RFC 1950 zlib header.
///
/// CM (low nibble of CMF) must be 8 (deflate), CINFO (high nibble) at most 7
/// (32 KiB window), and the two header bytes read as a big-endian u16 must be a
/// multiple of 31 — RFC 1950 §2.2. A raw RFC 1951 stream starts with block
/// header bits instead, but a stored raw block can satisfy all three too.
fn looks_like_zlib(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    let cmf = data[0];
    let flg = data[1];
    (cmf & 0x0f) == 8 && (cmf >> 4) <= 7 && (u16::from(cmf) * 256 + u16::from(flg)) % 31 == 0
}

/// Decompress a `Content-Encoding: deflate` body.
///
/// RFC 9110 §8.4.1.2 defines `deflate` as the **zlib** format (RFC 1950)
/// wrapping a deflate stream, but a sizable minority of servers send a bare RFC
/// 1951 stream instead. Use the same bounded format detection as streaming
/// responses so a raw stored-block prefix cannot be mistaken for a zlib header.
fn decompress_deflate(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = DeflateStream::new();
    let mut output = Vec::new();
    for chunk in data.chunks(DEFLATE_PROBE_LIMIT) {
        output.extend_from_slice(&decoder.feed(chunk)?);
    }
    output.extend_from_slice(&decoder.finish()?);
    Ok(output)
}

fn decompress_zstd(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder =
        zstd::Decoder::new(data).map_err(|e| format!("zstd decoder init failed: {e}"))?;
    size_limited_read(&mut decoder, "zstd")
}

// ---------------------------------------------------------------------------
// Streaming decompression
// ---------------------------------------------------------------------------

/// Stateful streaming decompressor wrapping Write-based decoders.
///
/// Compressed chunks are fed via [`decode_chunk`](Self::decode_chunk) and
/// decompressed output is returned incrementally. Call [`finish`](Self::finish)
/// after the compressed stream ends to flush any remaining buffered output.
enum StreamDecoder {
    Gzip(flate2::write::GzDecoder<Vec<u8>>),
    Deflate(DeflateStream),
    Brotli(Box<brotli::DecompressorWriter<Vec<u8>>>),
    Zstd(zstd::stream::write::Decoder<'static, Vec<u8>>),
}

const DEFLATE_PROBE_LIMIT: usize = 32 * 1024;
const DEFLATE_OUTPUT_CHUNK: usize = 8 * 1024;

/// Prefer zlib, allowing one bounded raw retry before zlib produces any output.
/// After 32 KiB without a decision, retain zlib and release the replay buffer.
enum DeflateStream {
    Undecided {
        prefix: Vec<u8>,
        output_limit: usize,
    },
    Probing {
        prefix: Vec<u8>,
        inflater: DeflateInflater,
    },
    Active(DeflateInflater),
    Failed,
}

struct DeflateInflater {
    decoder: flate2::Decompress,
    ended: bool,
    output_limit: usize,
}

enum DeflateFailure {
    Corrupt(flate2::DecompressError),
    Invalid(&'static str),
    Limit(usize),
}

impl std::fmt::Display for DeflateFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Corrupt(error) => write!(f, "deflate stream decode: {error}"),
            Self::Invalid(message) => write!(f, "deflate stream: {message}"),
            Self::Limit(limit) => write!(
                f,
                "deflate decompressed data exceeds {limit} byte safety limit"
            ),
        }
    }
}

impl DeflateInflater {
    fn new(zlib: bool, output_limit: usize) -> Self {
        Self {
            decoder: flate2::Decompress::new(zlib),
            ended: false,
            output_limit,
        }
    }

    fn feed(&mut self, mut input: &[u8], output: &mut Vec<u8>) -> Result<(), DeflateFailure> {
        while !self.ended {
            let mut buffer = [0; DEFLATE_OUTPUT_CHUNK];
            let remaining = self
                .output_limit
                .saturating_sub(self.decoder.total_out() as usize);
            let available = remaining.saturating_add(1).min(buffer.len());
            let before_in = self.decoder.total_in();
            let before_out = self.decoder.total_out();
            let status = self.decoder.decompress(
                input,
                &mut buffer[..available],
                flate2::FlushDecompress::None,
            );
            let consumed = (self.decoder.total_in() - before_in) as usize;
            let produced = (self.decoder.total_out() - before_out) as usize;
            if self.decoder.total_out() > self.output_limit as u64 {
                return Err(DeflateFailure::Limit(self.output_limit));
            }
            let status = status.map_err(DeflateFailure::Corrupt)?;
            output.extend_from_slice(&buffer[..produced]);
            input = &input[consumed..];
            if status == flate2::Status::StreamEnd {
                self.ended = true;
            } else if consumed == 0 && produced == 0 {
                if !input.is_empty() {
                    return Err(DeflateFailure::Invalid("decoder made no progress"));
                }
                break;
            }
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Bytes, String> {
        let mut output = Vec::new();
        self.feed(&[], &mut output)
            .map_err(|error| error.to_string())?;
        if !self.ended {
            return Err("deflate stream: incomplete compressed body".into());
        }
        Ok(Bytes::from(output))
    }
}

fn raw_stored_prefix(prefix: &[u8]) -> bool {
    prefix.len() >= 5
        && prefix[0] & 7 == 0
        && prefix[1] ^ prefix[3] == 0xff
        && prefix[2] ^ prefix[4] == 0xff
}

/// A complete or output-producing zlib payload is not an early format failure.
/// Check with the same inflate core without the wrapper, never by error strings.
fn zlib_payload_has_progress(prefix: &[u8]) -> bool {
    let mut decoder = flate2::Decompress::new(false);
    let mut output = [0; 1];
    let status = decoder.decompress(&prefix[2..], &mut output, flate2::FlushDecompress::None);
    decoder.total_out() > 0 || matches!(status, Ok(flate2::Status::StreamEnd))
}

impl DeflateStream {
    fn new() -> Self {
        Self::Undecided {
            prefix: Vec::new(),
            output_limit: MAX_DECOMPRESSED_SIZE,
        }
    }

    fn feed(&mut self, input: &[u8]) -> Result<Bytes, String> {
        self.feed_inner(input).map_err(|error| error.to_string())
    }

    fn feed_inner(&mut self, mut input: &[u8]) -> Result<Bytes, DeflateFailure> {
        let mut output = Vec::new();
        loop {
            match std::mem::replace(self, Self::Failed) {
                Self::Undecided {
                    mut prefix,
                    output_limit,
                } => {
                    let count = (2 - prefix.len()).min(input.len());
                    prefix.extend_from_slice(&input[..count]);
                    input = &input[count..];
                    if prefix.len() < 2 {
                        *self = Self::Undecided {
                            prefix,
                            output_limit,
                        };
                        break;
                    }
                    let zlib = looks_like_zlib(&prefix);
                    let mut inflater = DeflateInflater::new(zlib, output_limit);
                    if zlib {
                        *self = Self::Probing { prefix, inflater };
                    } else {
                        inflater.feed(&prefix, &mut output)?;
                        *self = Self::Active(inflater);
                    }
                }
                Self::Probing {
                    mut prefix,
                    mut inflater,
                } => {
                    let count = (DEFLATE_PROBE_LIMIT - prefix.len()).min(input.len());
                    prefix.extend_from_slice(&input[..count]);
                    input = &input[count..];
                    if prefix.len() < 5 {
                        *self = Self::Probing { prefix, inflater };
                        break;
                    }
                    let consumed = inflater.decoder.total_in() as usize;
                    match inflater.feed(&prefix[consumed..], &mut output) {
                        Err(DeflateFailure::Corrupt(error))
                            if inflater.decoder.total_out() == 0
                                && error.needs_dictionary().is_none()
                                && prefix[1] & 0x20 == 0
                                && raw_stored_prefix(&prefix)
                                && !zlib_payload_has_progress(&prefix) =>
                        {
                            let mut raw = DeflateInflater::new(false, inflater.output_limit);
                            raw.feed(&prefix, &mut output)?;
                            *self = Self::Active(raw);
                        }
                        Err(error) => return Err(error),
                        Ok(())
                            if inflater.decoder.total_out() > 0
                                || inflater.ended
                                || prefix.len() == DEFLATE_PROBE_LIMIT =>
                        {
                            *self = Self::Active(inflater);
                        }
                        Ok(()) => {
                            *self = Self::Probing { prefix, inflater };
                            break;
                        }
                    }
                }
                Self::Active(mut inflater) => {
                    inflater.feed(input, &mut output)?;
                    *self = Self::Active(inflater);
                    break;
                }
                Self::Failed => return Err(DeflateFailure::Invalid("decoder previously failed")),
            }
        }
        Ok(Bytes::from(output))
    }

    fn finish(self) -> Result<Bytes, String> {
        match self {
            Self::Undecided { prefix, .. } if prefix.is_empty() => Ok(Bytes::new()),
            Self::Undecided { .. } | Self::Probing { .. } => {
                Err("deflate stream: incomplete compressed body".into())
            }
            Self::Active(inflater) => inflater.finish(),
            Self::Failed => Err("deflate stream: decoder previously failed".into()),
        }
    }
}

impl StreamDecoder {
    fn new(encoding: &str) -> Result<Self, String> {
        match encoding {
            "gzip" | "x-gzip" => Ok(Self::Gzip(flate2::write::GzDecoder::new(Vec::new()))),
            "deflate" => Ok(Self::Deflate(DeflateStream::new())),
            "br" => Ok(Self::Brotli(Box::new(brotli::DecompressorWriter::new(
                Vec::new(),
                4096,
            )))),
            "zstd" => {
                let dec = zstd::stream::write::Decoder::new(Vec::new())
                    .map_err(|e| format!("zstd stream decoder init: {e}"))?;
                Ok(Self::Zstd(dec))
            }
            other => Err(format!("unsupported stream encoding: {other}")),
        }
    }

    /// Feed a compressed chunk and return whatever decompressed output is
    /// available. May return empty `Bytes` if the decoder is still
    /// accumulating header/dictionary data.
    fn decode_chunk(&mut self, data: &[u8]) -> Result<Bytes, String> {
        use std::io::Write;
        let inner = match self {
            Self::Gzip(d) => {
                d.write_all(data)
                    .map_err(|e| format!("gzip stream decode: {e}"))?;
                d.get_mut()
            }
            // The deflate stream owns its own zlib/raw resolution and returns
            // decoded output directly rather than exposing an inner buffer.
            Self::Deflate(d) => return d.feed(data),
            Self::Brotli(d) => {
                d.write_all(data)
                    .map_err(|e| format!("brotli stream decode: {e}"))?;
                d.get_mut()
            }
            Self::Zstd(d) => {
                d.write_all(data)
                    .map_err(|e| format!("zstd stream decode: {e}"))?;
                d.get_mut()
            }
        };
        Ok(Bytes::from(std::mem::take(inner)))
    }

    /// Finalize the decoder and return any remaining buffered output.
    fn finish(self) -> Result<Bytes, String> {
        match self {
            Self::Gzip(d) => d
                .finish()
                .map(Bytes::from)
                .map_err(|e| format!("gzip stream finish: {e}")),
            Self::Deflate(d) => d.finish(),
            Self::Brotli(mut d) => {
                d.close()
                    .map_err(|e| format!("brotli stream finish: {e}"))?;
                Ok(Bytes::from(std::mem::take(d.get_mut())))
            }
            Self::Zstd(mut d) => {
                use std::io::Write;
                d.flush().map_err(|e| format!("zstd stream finish: {e}"))?;
                Ok(Bytes::from(d.into_inner()))
            }
        }
    }
}

/// A stack of [`StreamDecoder`]s applied in sequence, for bodies whose
/// `content-encoding` names more than one coding.
///
/// `layers[0]` receives the raw body bytes and each later layer consumes the
/// previous layer's output, so the vector is ordered last-applied-first — the
/// reverse of the header's own order (RFC 9110 §8.4). A single-coding response
/// is just the one-layer case.
struct LayeredStreamDecoder {
    layers: Vec<StreamDecoder>,
}

impl LayeredStreamDecoder {
    /// Build one decoder per coding. `codings` must already be in decode order,
    /// as produced by [`parse_content_encoding`].
    fn new(codings: &[ContentCoding]) -> Result<Self, String> {
        let mut layers = Vec::with_capacity(codings.len());
        for coding in codings {
            // `identity` adds no layer; the parser drops it, this is belt-and-braces.
            if *coding == ContentCoding::Identity {
                continue;
            }
            layers.push(StreamDecoder::new(coding.token())?);
        }
        Ok(Self { layers })
    }

    /// Feed a raw chunk through every layer and return whatever fully decoded
    /// output is available. May be empty while any layer is still buffering.
    fn decode_chunk(&mut self, data: &[u8]) -> Result<Bytes, String> {
        let Some((first, rest)) = self.layers.split_first_mut() else {
            return Ok(Bytes::copy_from_slice(data));
        };
        let mut current = first.decode_chunk(data)?;
        for layer in rest {
            if current.is_empty() {
                // Nothing to hand down; deeper layers stay as they are.
                return Ok(Bytes::new());
            }
            current = layer.decode_chunk(&current)?;
        }
        Ok(current)
    }

    /// Finalize every layer, flushing each one's residual output into the next
    /// before finalizing that one in turn.
    fn finish(self) -> Result<Bytes, String> {
        let mut carried = Bytes::new();
        for mut layer in self.layers {
            let mut flushed = bytes::BytesMut::new();
            if !carried.is_empty() {
                flushed.extend_from_slice(&layer.decode_chunk(&carried)?);
            }
            flushed.extend_from_slice(&layer.finish()?);
            carried = flushed.freeze();
        }
        Ok(carried)
    }
}

/// State machine for the streaming decoder in [`StreamingResponse`].
enum DecoderState {
    /// Not yet initialized — will inspect `content-encoding` on first use.
    Uninit,
    /// No decoding needed (identity / unknown / no content-encoding).
    Passthrough,
    /// Actively decoding compressed chunks.
    Active(LayeredStreamDecoder),
    /// The compressed stream has been fully consumed and finalized.
    Finished,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("Response");
        s.field("status", &self.status)
            .field("url", &self.url)
            .field("version", &self.http_version)
            .field("headers", &self.headers)
            .field("body_len", &self.body.len());
        if !self.redirect_history.is_empty() {
            s.field("redirect_history", &self.redirect_history);
        }
        s.finish()
    }
}

// ===========================================================================
// Streaming response
// ===========================================================================

/// Internal enum wrapping different body stream types.
#[allow(clippy::large_enum_variant)]
pub(crate) enum BodyStream {
    /// HTTP/2 body stream.
    H2(lkh2::H2RecvStream),
    /// HTTP/1.1 body chunks forwarded from a bridge task via mpsc channel.
    ///
    /// A dedicated bridge task drives the hyper Connection and reads from
    /// `Incoming` in a single `select!` loop, forwarding chunks through
    /// this channel.  This avoids a deadlock that occurs when the
    /// connection driver and body consumer live in separate tasks: the
    /// connection parks its waker on the TCP transport (which has no more
    /// data) while the body consumer waits for data that is buffered
    /// inside hyper but never pushed.
    H1(tokio::sync::mpsc::Receiver<Result<bytes::Bytes, String>>),
    /// HTTP/3 body stream.
    #[cfg(feature = "quic-h3")]
    H3(Box<H3BodyStream>),
}

#[cfg(feature = "quic-h3")]
pub(crate) struct H3BodyStream {
    pub(crate) stream: lkh3::H3RecvStream,
    pub(crate) data_eof: bool,
    // The backend closes the connection when its final sender is dropped.
    // An unpooled response must therefore retain one through body completion.
    pub(crate) sender: Option<lkh3::H3Sender>,
}

#[cfg(feature = "quic-h3")]
impl H3BodyStream {
    async fn chunk(&mut self) -> crate::error::Result<Option<Bytes>> {
        if self.sender.is_none() {
            return Ok(None);
        }
        if !self.data_eof {
            match self.stream.data().await {
                Some(Ok(chunk)) => return Ok(Some(chunk)),
                Some(Err(error)) => {
                    self.sender.take();
                    return Err(crate::error::Error::h3_request_error(
                        crate::error::ConnectionPhase::HttpRequest,
                        error,
                        true,
                    ));
                }
                None => self.data_eof = true,
            }
        }
        // Keep this phase across cancelled chunk futures: DATA ends at trailers,
        // but success requires validated trailers and the final stream boundary.
        let completion = self.stream.trailers().await;
        self.sender.take();
        completion.map(|_| None).map_err(|error| {
            crate::error::Error::h3_request_error(
                crate::error::ConnectionPhase::HttpRequest,
                error,
                true,
            )
        })
    }
}

/// A streaming HTTP response whose body is read on demand.
///
/// Unlike [`Response`], the body is **not** buffered into memory upfront.
/// Instead, callers read it chunk by chunk via [`chunk()`](Self::chunk),
/// making it suitable for large downloads, SSE, and long-lived streams.
///
/// # Example
///
/// ```rust,no_run
/// # async fn example() -> Result<(), lkrequest::error::Error> {
/// # use lkrequest::Client;
/// # use lktls::profile::presets;
/// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
/// # let session = client.session().build();
/// # fn write_to_disk(_: &[u8]) {}
/// let mut resp = session.get("https://example.com/large-file")
///     .send_streaming()
///     .await?;
///
/// println!("Status: {}", resp.status());
///
/// while let Some(chunk) = resp.chunk().await? {
///     // Process chunk (bytes::Bytes)
///     write_to_disk(&chunk);
/// }
/// # Ok(())
/// # }
/// ```
pub struct StreamingResponse {
    /// HTTP status code.
    status: StatusCode,
    /// Response headers.
    headers: HeaderMap,
    /// The underlying body stream.
    body_stream: BodyStream,
    /// Streaming decompression state (lazy-initialized on first `chunk_decoded()` call).
    decoder: DecoderState,
    /// Cumulative decompressed bytes produced by the streaming decoder (bomb protection).
    decompressed_total: usize,
    /// Maximum response body size (from ResourceLimits). `usize::MAX` = unlimited.
    max_body_size: usize,
    /// Cumulative bytes received so far (for body size limit enforcement).
    body_received: usize,
    /// Skip automatic decompression in `bytes()` / `chunk_decoded()`.
    no_decompress: bool,
}

impl StreamingResponse {
    /// Create a new streaming response (internal).
    pub(crate) fn new(status: StatusCode, headers: HeaderMap, body_stream: BodyStream) -> Self {
        Self {
            status,
            headers,
            body_stream,
            decoder: DecoderState::Uninit,
            decompressed_total: 0,
            max_body_size: usize::MAX,
            body_received: 0,
            no_decompress: false,
        }
    }

    pub(crate) fn with_max_body_size(mut self, max: usize) -> Self {
        self.max_body_size = max;
        self
    }

    pub(crate) fn with_no_decompress(mut self, no_decompress: bool) -> Self {
        self.no_decompress = no_decompress;
        self
    }

    /// Returns the HTTP status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns a reference to the response headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Read the next chunk of the response body.
    ///
    /// Returns `Ok(Some(chunk))` for each data chunk and `Ok(None)` when
    /// the body has been fully consumed (EOF).
    ///
    /// Chunks are returned as raw bytes — no automatic decompression is
    /// applied in streaming mode.  Use [`bytes()`](Self::bytes) or
    /// [`text()`](Self::text) for decompressed full-body reads.
    pub async fn chunk(&mut self) -> crate::error::Result<Option<bytes::Bytes>> {
        let result = match &mut self.body_stream {
            BodyStream::H2(recv_stream) => match recv_stream.data().await {
                Some(Ok(chunk)) => {
                    let len = chunk.len();
                    let _ = recv_stream.flow_control().release_capacity(len);
                    Ok(Some(chunk))
                }
                Some(Err(e)) => Err(crate::error::Error::h2_or_connection_closed(
                    crate::error::ConnectionPhase::HttpRequest,
                    e.to_string(),
                )),
                None => Ok(None),
            },
            BodyStream::H1(rx) => match rx.recv().await {
                Some(Ok(data)) => Ok(Some(data)),
                Some(Err(e)) => Err(crate::error::Error::http_or_connection_closed(
                    crate::error::ConnectionPhase::HttpRequest,
                    e,
                )),
                None => Ok(None),
            },
            #[cfg(feature = "quic-h3")]
            BodyStream::H3(body) => body.chunk().await,
        };

        if let Ok(Some(ref data)) = result {
            self.body_received += data.len();
            if self.body_received > self.max_body_size {
                return Err(crate::error::Error::ResourceLimitExceeded(format!(
                    "response body exceeded limit: {} > {} bytes",
                    self.body_received, self.max_body_size,
                )));
            }
        }

        result
    }

    /// Consume the streaming response and read the full body into memory.
    ///
    /// The body is automatically decompressed based on the `content-encoding`
    /// header (same behavior as [`Response`]), unless `no_auto_decompress()`
    /// was set on the request.
    pub async fn bytes(mut self) -> crate::error::Result<Bytes> {
        let mut buf = bytes::BytesMut::new();
        while let Some(chunk) = self.chunk().await? {
            buf.extend_from_slice(&chunk);
        }
        let raw = buf.freeze();
        if self.no_decompress {
            Ok(raw)
        } else {
            decompress_body(&self.headers, raw)
        }
    }

    /// Consume the streaming response and read the full body as a UTF-8 string.
    ///
    /// The body is automatically decompressed.
    pub async fn text(self) -> crate::error::Result<String> {
        let bytes = self.bytes().await?;
        String::from_utf8(bytes.into()).map_err(|e| {
            crate::error::Error::Http(format!("response body is not valid UTF-8: {e}"))
        })
    }

    /// Read the next chunk of the response body with automatic decompression.
    ///
    /// Unlike [`chunk()`](Self::chunk) which returns raw (possibly compressed)
    /// bytes, this method decompresses each chunk incrementally using a
    /// stateful streaming decoder. Decompressed output is returned as it
    /// becomes available — callers do **not** need to wait for the entire
    /// body to arrive before processing.
    ///
    /// Returns:
    /// - `Ok(Some(chunk))` — a decompressed chunk of data.
    /// - `Ok(None)` — the body has been fully consumed.
    ///
    /// For uncompressed responses (`identity` or no `content-encoding`),
    /// this behaves identically to [`chunk()`](Self::chunk).
    pub async fn chunk_decoded(&mut self) -> crate::error::Result<Option<Bytes>> {
        if self.no_decompress {
            return self.chunk().await;
        }

        // Lazy-initialize the decoder on first call. The header may name several
        // codings, in which case one decoder per coding is stacked in decode
        // order (RFC 9110 §8.4) — see [`LayeredStreamDecoder`].
        if matches!(self.decoder, DecoderState::Uninit) {
            let list = content_encoding_list(&self.headers);
            self.decoder = match parse_content_encoding(&list) {
                ContentEncodingPlan::Passthrough => DecoderState::Passthrough,
                ContentEncodingPlan::UnknownSingle(token) => {
                    tracing::warn!(encoding = %token, "http.unknown_content_encoding");
                    DecoderState::Passthrough
                }
                ContentEncodingPlan::UnknownInList { unknown, list } => {
                    tracing::warn!(
                        encoding = %unknown,
                        content_encoding = %list,
                        "http.unknown_content_encoding_in_list",
                    );
                    return Err(unsupported_coding_in_list(&unknown, &list));
                }
                ContentEncodingPlan::Decode(codings) => match LayeredStreamDecoder::new(&codings) {
                    Ok(dec) => DecoderState::Active(dec),
                    Err(e) => {
                        return Err(crate::error::Error::Body(format!(
                            "failed to init stream decoder: {e}"
                        )));
                    }
                },
            };
        }

        if matches!(self.decoder, DecoderState::Passthrough) {
            return self.chunk().await;
        }

        if matches!(self.decoder, DecoderState::Finished) {
            return Ok(None);
        }

        // Active decoder — feed raw chunks and return decoded output.
        loop {
            match self.chunk().await? {
                Some(chunk) => {
                    let decoded = match &mut self.decoder {
                        DecoderState::Active(dec) => dec.decode_chunk(&chunk).map_err(|e| {
                            crate::error::Error::Body(format!("stream decompression error: {e}"))
                        })?,
                        _ => {
                            return Err(crate::error::Error::Http(
                                "internal error: chunk_decoded expected active decoder".into(),
                            ));
                        }
                    };

                    self.decompressed_total += decoded.len();
                    if self.decompressed_total > MAX_DECOMPRESSED_SIZE {
                        return Err(crate::error::Error::Body(format!(
                            "decompressed stream exceeds {} byte safety limit",
                            MAX_DECOMPRESSED_SIZE,
                        )));
                    }

                    if !decoded.is_empty() {
                        return Ok(Some(decoded));
                    }
                    // Decoder buffering internally (e.g. headers); keep reading.
                }
                None => {
                    // EOF — finalize the decoder and return residual output.
                    let prev = std::mem::replace(&mut self.decoder, DecoderState::Finished);
                    let remaining = match prev {
                        DecoderState::Active(dec) => dec.finish().map_err(|e| {
                            crate::error::Error::Body(format!(
                                "stream decompression finish error: {e}"
                            ))
                        })?,
                        _ => {
                            return Err(crate::error::Error::Http(
                                "internal error: chunk_decoded finish expected active decoder"
                                    .into(),
                            ));
                        }
                    };

                    self.decompressed_total += remaining.len();
                    if self.decompressed_total > MAX_DECOMPRESSED_SIZE {
                        return Err(crate::error::Error::Body(format!(
                            "decompressed stream exceeds {} byte safety limit",
                            MAX_DECOMPRESSED_SIZE,
                        )));
                    }

                    if remaining.is_empty() {
                        return Ok(None);
                    }
                    return Ok(Some(remaining));
                }
            }
        }
    }
}

impl std::fmt::Debug for StreamingResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamingResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- HttpVersion -------------------------------------------------------

    #[test]
    fn http_version_display() {
        assert_eq!(HttpVersion::Http10.to_string(), "HTTP/1.0");
        assert_eq!(HttpVersion::Http11.to_string(), "HTTP/1.1");
        assert_eq!(HttpVersion::H2.to_string(), "h2");
        assert_eq!(HttpVersion::H3.to_string(), "h3");
        assert_eq!(HttpVersion::Unknown.to_string(), "unknown");
    }

    #[test]
    fn negotiated_http_version_maps_to_legacy_version() {
        assert_eq!(
            HttpVersion::from(NegotiatedHttpVersion::Http10),
            HttpVersion::Http10
        );
        assert_eq!(
            HttpVersion::from(NegotiatedHttpVersion::Http11),
            HttpVersion::Http11
        );
        assert_eq!(
            HttpVersion::from(NegotiatedHttpVersion::Http2),
            HttpVersion::H2
        );
        assert_eq!(
            HttpVersion::from(NegotiatedHttpVersion::Http3),
            HttpVersion::H3
        );
    }

    #[test]
    fn response_exposes_legacy_and_negotiated_versions() {
        let mut resp = Response::new(StatusCode::OK, HeaderMap::new(), Bytes::new()).unwrap();
        resp.set_http_version(HttpVersion::H2);

        assert_eq!(resp.version(), HttpVersion::H2);
        assert_eq!(resp.negotiated_version(), NegotiatedHttpVersion::Http2);
    }

    // -- Response construction + accessors ---------------------------------

    #[test]
    fn response_no_encoding() {
        let body = Bytes::from("hello world");
        let headers = HeaderMap::new();
        let resp = Response::new(StatusCode::OK, headers, body.clone()).unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.bytes(), &body[..]);
        assert_eq!(resp.text().unwrap(), "hello world");
    }

    #[test]
    fn response_empty_body() {
        let resp = Response::new(StatusCode::NO_CONTENT, HeaderMap::new(), Bytes::new()).unwrap();
        assert_eq!(resp.bytes().len(), 0);
        assert_eq!(resp.text().unwrap(), "");
    }

    // -- Decompression: gzip -----------------------------------------------

    #[test]
    fn decompress_gzip_roundtrip() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let original = b"Hello, gzip compressed world!";
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "gzip".parse().unwrap());

        let resp = Response::new(StatusCode::OK, headers, Bytes::from(compressed)).unwrap();
        assert_eq!(resp.text().unwrap(), "Hello, gzip compressed world!");
    }

    // -- Decompression: brotli ---------------------------------------------

    #[test]
    fn decompress_brotli_roundtrip() {
        use std::io::Write;

        let original = b"Hello, brotli compressed world!";
        let mut compressed = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 6, 22);
            writer.write_all(original).unwrap();
        }

        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "br".parse().unwrap());

        let resp = Response::new(StatusCode::OK, headers, Bytes::from(compressed)).unwrap();
        assert_eq!(resp.text().unwrap(), "Hello, brotli compressed world!");
    }

    // -- Decompression: deflate -------------------------------------------

    /// Regression: RFC 9110 §8.4.1.2 defines `deflate` as the zlib format
    /// (RFC 1950). The one-shot path used a bare `DeflateDecoder`, so every
    /// spec-correct server failed with `decompression failed`.
    #[test]
    fn deflate_zlib_wrapped_body_is_decoded() {
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        let original = b"zlib-wrapped deflate, the format the RFC actually specifies";
        let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        assert!(
            looks_like_zlib(&compressed),
            "ZlibEncoder output must carry an RFC 1950 header"
        );

        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "deflate".parse().unwrap());
        let resp = Response::new(StatusCode::OK, headers, Bytes::from(compressed)).unwrap();

        assert_eq!(resp.bytes(), &original[..]);
    }

    /// The non-conforming raw form (RFC 1951, classically IIS) must keep
    /// working — browsers accept both and so do we.
    #[test]
    fn deflate_raw_body_is_still_decoded() {
        use flate2::write::DeflateEncoder;
        use std::io::Write;

        let original = b"raw deflate, what a sizable minority of servers actually send";
        let mut encoder = DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "deflate".parse().unwrap());
        let resp = Response::new(StatusCode::OK, headers, Bytes::from(compressed)).unwrap();

        assert_eq!(resp.bytes(), &original[..]);
    }

    #[test]
    fn looks_like_zlib_discriminates_the_two_formats() {
        use flate2::write::{DeflateEncoder, ZlibEncoder};
        use std::io::Write;

        let payload = vec![b'x'; 512];

        let mut z = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&payload).unwrap();
        assert!(looks_like_zlib(&z.finish().unwrap()));

        let mut d = DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        d.write_all(&payload).unwrap();
        assert!(!looks_like_zlib(&d.finish().unwrap()));

        // Too short to decide.
        assert!(!looks_like_zlib(&[]));
        assert!(!looks_like_zlib(&[0x78]));
        // 0x78 0x9C is the canonical zlib header; flipping FLG breaks the
        // mod-31 check.
        assert!(looks_like_zlib(&[0x78, 0x9C]));
        assert!(!looks_like_zlib(&[0x78, 0x9D]));
    }

    /// The streaming decoder resolves the format from the first bytes, for both
    /// formats and even when the 2-byte header is split across chunks.
    #[test]
    fn streaming_deflate_handles_both_formats() {
        use flate2::write::{DeflateEncoder, ZlibEncoder};
        use std::io::Write;

        let original = b"streamed deflate payload that is long enough to matter";

        let mut z = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(original).unwrap();
        let zlib_bytes = z.finish().unwrap();

        let mut d = DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        d.write_all(original).unwrap();
        let raw_bytes = d.finish().unwrap();

        for compressed in [zlib_bytes, raw_bytes] {
            // Feed one byte at a time so the header itself spans chunks — the
            // decoder must hold back until the format is decidable.
            let mut dec = StreamDecoder::new("deflate").unwrap();
            let mut out = bytes::BytesMut::new();
            for byte in &compressed {
                out.extend_from_slice(&dec.decode_chunk(&[*byte]).unwrap());
            }
            out.extend_from_slice(&dec.finish().unwrap());
            assert_eq!(out.as_ref(), original);
        }
    }

    fn colliding_raw_deflate(tail: &[u8]) -> Vec<u8> {
        let mut raw = vec![0x78, 0x9c, 0x00, 0x63, 0xff];
        raw.extend_from_slice(&[b'A'; 156]);
        raw.extend_from_slice(&compress_deflate(tail));
        raw
    }

    fn zlib_compress(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn deflate_ambiguous_prefix_survives_split_and_large_source_chunks() {
        let tail: Vec<u8> = (0..100_000).map(|index| (index % 251) as u8).collect();
        let raw = colliding_raw_deflate(&tail);
        let mut expected = vec![b'A'; 156];
        expected.extend_from_slice(&tail);
        assert!(looks_like_zlib(&raw));
        assert_eq!(decompress_deflate(&raw).unwrap(), expected);

        for first_len in [1, 2, 4] {
            for chunk_len in [1, 2, 4, DEFLATE_PROBE_LIMIT, usize::MAX] {
                let mut decoder = DeflateStream::new();
                let mut decoded = decoder.feed(&raw[..first_len]).unwrap().to_vec();
                for chunk in raw[first_len..].chunks(chunk_len) {
                    decoded.extend_from_slice(&decoder.feed(chunk).unwrap());
                }
                decoded.extend_from_slice(&decoder.finish().unwrap());
                assert_eq!(decoded, expected, "first={first_len}, chunk={chunk_len}");
            }
        }
    }

    #[test]
    fn deflate_corrupt_checksum_and_incomplete_streams_are_errors() {
        let payload = b"complete data followed by a verified end of stream".repeat(256);
        let zlib = zlib_compress(&payload);
        let raw = compress_deflate(&payload);
        let mut checksum = zlib.clone();
        *checksum.last_mut().unwrap() ^= 1;
        for malformed in [
            vec![0x78],
            vec![0x78, 0x9c],
            vec![0x78, 0x9c, 0xff, 0xff, 0xff],
            checksum,
            zlib[..zlib.len() - 1].to_vec(),
            raw[..raw.len() - 1].to_vec(),
            colliding_raw_deflate(&payload)[..7].to_vec(),
        ] {
            assert!(decompress_deflate(&malformed).is_err());
            for chunk_len in [1, 2, 4, usize::MAX] {
                let mut decoder = DeflateStream::new();
                let failed_during_feed = malformed
                    .chunks(chunk_len)
                    .any(|chunk| decoder.feed(chunk).is_err());
                assert!(
                    failed_during_feed || decoder.finish().is_err(),
                    "chunk={chunk_len}"
                );
            }
        }
        for valid in [zlib, raw, zlib_compress(&[]), compress_deflate(&[])] {
            let expected = if valid.len() <= 8 {
                &[][..]
            } else {
                payload.as_slice()
            };
            assert_eq!(decompress_deflate(&valid).unwrap(), expected);
        }
    }

    #[test]
    fn deflate_does_not_replay_after_output_or_checksum_failure() {
        let payload = b"already delivered decoded bytes".repeat(128);
        let mut zlib = zlib_compress(&payload);
        let checksum_start = zlib.len() - 4;
        *zlib.last_mut().unwrap() ^= 1;
        let mut decoder = DeflateStream::new();
        let decoded = decoder.feed(&zlib[..checksum_start]).unwrap();
        assert_eq!(decoded.as_ref(), payload);
        assert!(matches!(decoder, DeflateStream::Active(_)));
        assert!(decoder.feed(&zlib[checksum_start..]).is_err());
        assert!(decoder
            .feed(&colliding_raw_deflate(b"must not replay"))
            .is_err());
        assert!(decoder.finish().is_err());

        let mut truncated = DeflateStream::new();
        assert_eq!(
            truncated.feed(&zlib[..checksum_start]).unwrap().as_ref(),
            payload
        );
        assert!(truncated.finish().is_err());
    }

    #[test]
    fn deflate_ambiguous_empty_zlib_checksum_is_not_a_raw_fallback() {
        use std::io::Read;

        // Both a valid raw stored block and an empty zlib payload with a bad checksum.
        // The completed zlib payload takes precedence over raw compatibility.
        let mut ambiguous = vec![0x18, 0x57, 0x03, 0xa8, 0xfc];
        ambiguous.extend_from_slice(&[b'A'; 855]);
        ambiguous.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff]);
        let mut raw = Vec::new();
        flate2::read::DeflateDecoder::new(ambiguous.as_slice())
            .read_to_end(&mut raw)
            .unwrap();
        assert_eq!(raw, vec![b'A'; 855]);
        assert!(looks_like_zlib(&ambiguous));
        assert!(raw_stored_prefix(&ambiguous));
        assert!(zlib_payload_has_progress(&ambiguous));
        assert!(decompress_deflate(&ambiguous).is_err());
        for chunk_len in [1, 4, usize::MAX] {
            let mut decoder = DeflateStream::new();
            assert!(ambiguous
                .chunks(chunk_len)
                .any(|chunk| decoder.feed(chunk).is_err()));
        }
    }

    #[test]
    fn deflate_probe_limit_commits_zlib_and_releases_replay_prefix() {
        let mut zlib = vec![0x78, 0x9c];
        for _ in 0..7000 {
            zlib.extend_from_slice(&[0x00, 0x00, 0x00, 0xff, 0xff]);
        }
        zlib.extend_from_slice(&[0x01, 0x01, 0x00, 0xfe, 0xff, b'Z']);
        zlib.extend_from_slice(&[0x00, 0x5b, 0x00, 0x5b]);
        assert!(zlib.len() > DEFLATE_PROBE_LIMIT);
        let mut decoder = DeflateStream::new();
        assert!(decoder
            .feed(&zlib[..DEFLATE_PROBE_LIMIT - 1])
            .unwrap()
            .is_empty());
        assert!(
            matches!(&decoder, DeflateStream::Probing { prefix, .. } if prefix.len() == DEFLATE_PROBE_LIMIT - 1)
        );
        assert!(decoder
            .feed(&zlib[DEFLATE_PROBE_LIMIT - 1..DEFLATE_PROBE_LIMIT])
            .unwrap()
            .is_empty());
        assert!(matches!(decoder, DeflateStream::Active(_)));
        let mut decoded = decoder.feed(&zlib[DEFLATE_PROBE_LIMIT..]).unwrap().to_vec();
        decoded.extend_from_slice(&decoder.finish().unwrap());
        assert_eq!(decoded, b"Z");
        assert_eq!(decompress_deflate(&zlib).unwrap(), b"Z");

        let mut invalid = DeflateStream::new();
        assert!(invalid
            .feed(&zlib[..DEFLATE_PROBE_LIMIT])
            .unwrap()
            .is_empty());
        assert!(matches!(invalid, DeflateStream::Active(_)));
        assert!(invalid.feed(&colliding_raw_deflate(&[])).is_err());
    }

    #[test]
    fn deflate_output_limit_applies_before_allocation_and_never_retries_raw() {
        let limit = 1024;
        for length in [limit, limit + 1] {
            let payload = vec![b'X'; length];
            let mut colliding_payload = vec![b'A'; 156];
            colliding_payload.extend_from_slice(&payload[..length - 156]);
            for encoded in [
                zlib_compress(&payload),
                compress_deflate(&payload),
                colliding_raw_deflate(&payload[..length - 156]),
            ] {
                for chunk_len in [1, DEFLATE_PROBE_LIMIT, usize::MAX] {
                    let mut decoder = DeflateStream::Undecided {
                        prefix: Vec::new(),
                        output_limit: limit,
                    };
                    let mut decoded = Vec::new();
                    let mut failure = None;
                    for chunk in encoded.chunks(chunk_len) {
                        match decoder.feed(chunk) {
                            Ok(bytes) => decoded.extend_from_slice(&bytes),
                            Err(error) => {
                                failure = Some(error);
                                break;
                            }
                        }
                    }
                    if length == limit {
                        decoded.extend_from_slice(&decoder.finish().unwrap());
                        assert!(decoded == payload || decoded == colliding_payload);
                    } else {
                        assert!(failure.unwrap().contains("safety limit"));
                        assert!(decoded.len() <= limit);
                        assert!(matches!(decoder, DeflateStream::Failed));
                    }
                }
            }
        }
    }

    #[test]
    fn decompress_deflate_roundtrip() {
        use flate2::write::DeflateEncoder;
        use std::io::Write;

        let original = b"Hello, deflate compressed world!";
        let mut encoder = DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "deflate".parse().unwrap());

        let resp = Response::new(StatusCode::OK, headers, Bytes::from(compressed)).unwrap();
        assert_eq!(resp.text().unwrap(), "Hello, deflate compressed world!");
    }

    // -- Decompression: zstd -----------------------------------------------

    #[test]
    fn decompress_zstd_roundtrip() {
        let original = b"Hello, zstd compressed world!";
        let compressed = zstd::stream::encode_all(&original[..], 3).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "zstd".parse().unwrap());

        let resp = Response::new(StatusCode::OK, headers, Bytes::from(compressed)).unwrap();
        assert_eq!(resp.text().unwrap(), "Hello, zstd compressed world!");
    }

    // -- Decompression: invalid data --------------------------------------

    #[test]
    fn decompress_invalid_gzip_returns_body_error() {
        let bad_data = Bytes::from(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "gzip".parse().unwrap());

        let err = Response::new(StatusCode::OK, headers, bad_data).unwrap_err();
        assert!(matches!(err, crate::error::Error::Body(_)));
        assert!(err.to_string().contains("decompression failed"));
    }

    // -- Decompression: identity/unknown encoding -------------------------

    #[test]
    fn decompress_identity_passes_through() {
        let body = Bytes::from("plain text");
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "identity".parse().unwrap());

        let resp = Response::new(StatusCode::OK, headers, body.clone()).unwrap();
        assert_eq!(resp.bytes(), &body[..]);
    }

    #[test]
    fn decompress_unknown_encoding_passes_through() {
        let body = Bytes::from("data");
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "lz4".parse().unwrap());

        let resp = Response::new(StatusCode::OK, headers, body.clone()).unwrap();
        assert_eq!(resp.bytes(), &body[..]);
    }

    // -- error_for_status --------------------------------------------------

    #[test]
    fn error_for_status_ok() {
        let mut resp = Response::new(StatusCode::OK, HeaderMap::new(), Bytes::new()).unwrap();
        resp.set_url("https://example.com".into());
        assert!(resp.error_for_status_ref().is_ok());
    }

    #[test]
    fn error_for_status_404() {
        let mut resp =
            Response::new(StatusCode::NOT_FOUND, HeaderMap::new(), Bytes::new()).unwrap();
        resp.set_url("https://example.com".into());
        assert!(resp.error_for_status_ref().is_err());
    }

    #[test]
    fn error_for_status_500() {
        let mut resp = Response::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            HeaderMap::new(),
            Bytes::new(),
        )
        .unwrap();
        resp.set_url("https://example.com".into());
        assert!(resp.error_for_status_ref().is_err());
    }

    // -- decompress_body (function-level) ------------------------------------

    #[test]
    fn decompress_body_no_encoding_is_identity() {
        let body = Bytes::from("raw data");
        let result = decompress_body(&HeaderMap::new(), body.clone()).unwrap();
        assert_eq!(result, body);
    }

    #[test]
    fn decompress_body_gzip_works() {
        use flate2::write::GzEncoder;
        use std::io::Write;

        let original = b"decompress_body gzip test";
        let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(original).unwrap();
        let compressed = enc.finish().unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "gzip".parse().unwrap());

        let result = decompress_body(&headers, Bytes::from(compressed)).unwrap();
        assert_eq!(&result[..], original);
    }

    #[test]
    fn decompress_body_identity_encoding_passes_through() {
        let body = Bytes::from("identity");
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_ENCODING, "identity".parse().unwrap());
        let result = decompress_body(&headers, body.clone()).unwrap();
        assert_eq!(result, body);
    }

    // -- StreamDecoder: single-chunk roundtrip ---------------------------------

    fn compress_gzip(data: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use std::io::Write;
        let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn compress_brotli(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut buf = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut buf, 4096, 6, 22);
            writer.write_all(data).unwrap();
        }
        buf
    }

    fn compress_deflate(data: &[u8]) -> Vec<u8> {
        use flate2::write::DeflateEncoder;
        use std::io::Write;
        let mut enc = DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn compress_zstd(data: &[u8]) -> Vec<u8> {
        zstd::stream::encode_all(data, 3).unwrap()
    }

    /// Collect all decoded output from a StreamDecoder (decode + finish).
    fn decode_all(dec: &mut StreamDecoder, compressed: &[u8]) -> bytes::BytesMut {
        let mut out = bytes::BytesMut::new();
        out.extend_from_slice(&dec.decode_chunk(compressed).unwrap());
        out
    }

    fn finish_into(dec: StreamDecoder, buf: &mut bytes::BytesMut) {
        buf.extend_from_slice(&dec.finish().unwrap());
    }

    #[test]
    fn stream_decoder_gzip_single_chunk() {
        let original = b"Hello, streaming gzip world!";
        let compressed = compress_gzip(original);

        let mut dec = StreamDecoder::new("gzip").unwrap();
        let mut out = decode_all(&mut dec, &compressed);
        finish_into(dec, &mut out);
        assert_eq!(&out[..], &original[..]);
    }

    #[test]
    fn stream_decoder_brotli_single_chunk() {
        let original = b"Hello, streaming brotli world!";
        let compressed = compress_brotli(original);

        let mut dec = StreamDecoder::new("br").unwrap();
        let mut out = decode_all(&mut dec, &compressed);
        finish_into(dec, &mut out);
        assert_eq!(&out[..], &original[..]);
    }

    #[test]
    fn stream_decoder_deflate_single_chunk() {
        let original = b"Hello, streaming deflate world!";
        let compressed = compress_deflate(original);

        let mut dec = StreamDecoder::new("deflate").unwrap();
        let mut out = decode_all(&mut dec, &compressed);
        finish_into(dec, &mut out);
        assert_eq!(&out[..], &original[..]);
    }

    #[test]
    fn stream_decoder_zstd_single_chunk() {
        let original = b"Hello, streaming zstd world!";
        let compressed = compress_zstd(original);

        let mut dec = StreamDecoder::new("zstd").unwrap();
        let mut out = decode_all(&mut dec, &compressed);
        finish_into(dec, &mut out);
        assert_eq!(&out[..], &original[..]);
    }

    // -- StreamDecoder: multi-chunk roundtrip ----------------------------------

    /// Split data into chunks of the given size.
    fn split_chunks(data: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
        data.chunks(chunk_size).map(|c| c.to_vec()).collect()
    }

    #[test]
    fn stream_decoder_gzip_multi_chunk() {
        let original = "Streaming gzip multi-chunk test. ".repeat(100);
        let compressed = compress_gzip(original.as_bytes());
        let chunks = split_chunks(&compressed, 32);
        assert!(chunks.len() > 1, "test requires multiple chunks");

        let mut dec = StreamDecoder::new("gzip").unwrap();
        let mut out = bytes::BytesMut::new();
        for chunk in &chunks {
            out.extend_from_slice(&dec.decode_chunk(chunk).unwrap());
        }
        finish_into(dec, &mut out);
        assert_eq!(&out[..], original.as_bytes());
    }

    #[test]
    fn stream_decoder_brotli_multi_chunk() {
        let original = "Streaming brotli multi-chunk test. ".repeat(100);
        let compressed = compress_brotli(original.as_bytes());
        let chunks = split_chunks(&compressed, 32);
        assert!(chunks.len() > 1, "test requires multiple chunks");

        let mut dec = StreamDecoder::new("br").unwrap();
        let mut out = bytes::BytesMut::new();
        for chunk in &chunks {
            out.extend_from_slice(&dec.decode_chunk(chunk).unwrap());
        }
        finish_into(dec, &mut out);
        assert_eq!(&out[..], original.as_bytes());
    }

    #[test]
    fn stream_decoder_deflate_multi_chunk() {
        let original = "Streaming deflate multi-chunk test. ".repeat(100);
        let compressed = compress_deflate(original.as_bytes());
        let chunks = split_chunks(&compressed, 32);
        assert!(chunks.len() > 1, "test requires multiple chunks");

        let mut dec = StreamDecoder::new("deflate").unwrap();
        let mut out = bytes::BytesMut::new();
        for chunk in &chunks {
            out.extend_from_slice(&dec.decode_chunk(chunk).unwrap());
        }
        finish_into(dec, &mut out);
        assert_eq!(&out[..], original.as_bytes());
    }

    #[test]
    fn stream_decoder_zstd_multi_chunk() {
        let original = "Streaming zstd multi-chunk test. ".repeat(100);
        let compressed = compress_zstd(original.as_bytes());
        let chunks = split_chunks(&compressed, 32);
        assert!(chunks.len() > 1, "test requires multiple chunks");

        let mut dec = StreamDecoder::new("zstd").unwrap();
        let mut out = bytes::BytesMut::new();
        for chunk in &chunks {
            out.extend_from_slice(&dec.decode_chunk(chunk).unwrap());
        }
        finish_into(dec, &mut out);
        assert_eq!(&out[..], original.as_bytes());
    }

    // -- StreamDecoder: x-gzip alias ------------------------------------------

    #[test]
    fn stream_decoder_x_gzip_alias() {
        let original = b"x-gzip alias test";
        let compressed = compress_gzip(original);

        let mut dec = StreamDecoder::new("x-gzip").unwrap();
        let mut out = decode_all(&mut dec, &compressed);
        finish_into(dec, &mut out);
        assert_eq!(&out[..], &original[..]);
    }

    // -- StreamDecoder: unsupported encoding ----------------------------------

    #[test]
    fn stream_decoder_unsupported_encoding() {
        assert!(StreamDecoder::new("lz4").is_err());
    }

    // -- StreamDecoder: empty input -------------------------------------------

    #[test]
    fn stream_decoder_gzip_empty_finish_errors() {
        let dec = StreamDecoder::new("gzip").unwrap();
        // Finishing with no data is an invalid gzip stream.
        assert!(dec.finish().is_err());
    }

    #[test]
    fn stream_decoder_deflate_empty_finish_ok() {
        let dec = StreamDecoder::new("deflate").unwrap();
        let remaining = dec.finish().unwrap();
        assert!(remaining.is_empty());
    }

    // -- Multi-coding content-encoding (RFC 9110 §8.4) -------------------------

    /// Build a header map with one `content-encoding` line per value, so tests
    /// can cover both `"gzip, br"` on one line and `"gzip"` + `"br"` on two.
    fn encodings(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(http::header::CONTENT_ENCODING, value.parse().unwrap());
        }
        headers
    }

    #[test]
    fn content_encoding_list_joins_split_header_lines() {
        assert_eq!(
            content_encoding_list(&encodings(&["gzip", "br"])),
            "gzip,br"
        );
        assert_eq!(content_encoding_list(&encodings(&["gzip, br"])), "gzip, br");
        assert_eq!(content_encoding_list(&HeaderMap::new()), "");
    }

    #[test]
    fn parse_content_encoding_classifies_lists() {
        assert!(matches!(
            parse_content_encoding(""),
            ContentEncodingPlan::Passthrough
        ));
        assert!(matches!(
            parse_content_encoding("identity"),
            ContentEncodingPlan::Passthrough
        ));
        assert!(matches!(
            parse_content_encoding(" identity , identity "),
            ContentEncodingPlan::Passthrough
        ));
        assert!(matches!(
            parse_content_encoding("lz4"),
            ContentEncodingPlan::UnknownSingle(token) if token == "lz4"
        ));
        assert!(matches!(
            parse_content_encoding("gzip, lz4"),
            ContentEncodingPlan::UnknownInList { unknown, list } if unknown == "lz4" && list == "gzip, lz4"
        ));
    }

    #[test]
    fn parse_content_encoding_orders_codings_for_decoding() {
        // Codings are listed in the order applied, so they decode in reverse —
        // and the tokens are case-insensitive.
        let cases: &[(&str, &[ContentCoding])] = &[
            ("GZip , Br", &[ContentCoding::Brotli, ContentCoding::Gzip]),
            // `identity` contributes no layer; empty list elements are ignored.
            ("identity, gzip", &[ContentCoding::Gzip]),
            ("gzip,,br", &[ContentCoding::Brotli, ContentCoding::Gzip]),
            (
                "deflate, x-gzip, zstd",
                &[
                    ContentCoding::Zstd,
                    ContentCoding::Gzip,
                    ContentCoding::Deflate,
                ],
            ),
        ];

        for (list, expected) in cases {
            match parse_content_encoding(list) {
                ContentEncodingPlan::Decode(codings) => {
                    assert_eq!(codings, expected.to_vec(), "list={list}");
                }
                _ => panic!("expected a decode plan for `{list}`"),
            }
        }
    }

    /// Regression: `content-encoding: gzip, br` was matched as a single opaque
    /// token, so the caller silently received still-compressed bytes.
    #[test]
    fn decompress_body_decodes_multi_coding_in_reverse_order() {
        let original = b"gzip was applied first, brotli second";
        let compressed = compress_brotli(&compress_gzip(original));

        let result = decompress_body(&encodings(&["gzip, br"]), Bytes::from(compressed.clone()))
            .expect("gzip, br must decode");

        assert_eq!(&result[..], &original[..]);
        assert_ne!(
            &result[..],
            &compressed[..],
            "must not hand back compressed bytes"
        );
    }

    #[test]
    fn decompress_body_decodes_three_codings() {
        let original = b"deflate, then gzip, then brotli";
        let compressed = compress_brotli(&compress_gzip(&compress_deflate(original)));

        let result = decompress_body(&encodings(&["deflate, gzip, br"]), Bytes::from(compressed))
            .expect("three codings must decode");

        assert_eq!(&result[..], &original[..]);
    }

    /// A list-valued field may be split across header lines (RFC 9110 §5.3);
    /// reading only the first line loses codings.
    #[test]
    fn decompress_body_joins_split_content_encoding_headers() {
        let original = b"one list, two header lines";
        let compressed = compress_brotli(&compress_gzip(original));

        let result = decompress_body(&encodings(&["gzip", "br"]), Bytes::from(compressed))
            .expect("split header lines must decode");

        assert_eq!(&result[..], &original[..]);
    }

    #[test]
    fn decompress_body_skips_identity_inside_a_list() {
        let original = b"identity is not a layer";
        let compressed = compress_gzip(original);

        let result = decompress_body(&encodings(&["identity, gzip"]), Bytes::from(compressed))
            .expect("identity must be a no-op layer");

        assert_eq!(&result[..], &original[..]);
    }

    /// Peeling off only the codings we implement would return bytes that are
    /// still compressed with no way for the caller to notice, so the whole
    /// response is refused instead.
    #[test]
    fn decompress_body_rejects_unknown_coding_inside_a_list() {
        let compressed = compress_gzip(b"never fully decodable");
        let err = decompress_body(&encodings(&["gzip, lz4"]), Bytes::from(compressed)).unwrap_err();

        assert!(matches!(err, crate::error::Error::Body(_)));
        let msg = err.to_string();
        assert!(msg.contains("lz4"), "error should name the coding: {msg}");
        assert!(
            msg.contains("gzip, lz4"),
            "error should quote the list: {msg}"
        );
    }

    /// A *single* unrecognized coding keeps its long-standing pass-through
    /// behavior — only partially-understood lists are an error.
    #[test]
    fn decompress_body_single_unknown_coding_still_passes_through() {
        let body = Bytes::from_static(b"opaque payload");
        let result = decompress_body(&encodings(&["lz4"]), body.clone()).unwrap();
        assert_eq!(result, body);
    }

    #[test]
    fn decompress_body_multi_coding_empty_body_passes_through() {
        let result = decompress_body(&encodings(&["gzip, lz4"]), Bytes::new()).unwrap();
        assert!(result.is_empty());
    }

    // -- LayeredStreamDecoder -------------------------------------------------

    /// Feed a layered decoder `chunk_size` bytes at a time and collect
    /// everything it produces, finish included.
    fn layered_decode_in_chunks(
        codings: &[ContentCoding],
        compressed: &[u8],
        chunk_size: usize,
    ) -> Vec<u8> {
        let mut dec = LayeredStreamDecoder::new(codings).unwrap();
        let mut out = Vec::new();
        for piece in compressed.chunks(chunk_size) {
            out.extend_from_slice(&dec.decode_chunk(piece).unwrap());
        }
        out.extend_from_slice(&dec.finish().unwrap());
        out
    }

    #[test]
    fn layered_stream_decoder_gzip_then_brotli_in_small_chunks() {
        let original = "streamed through two codings ".repeat(40);
        let compressed = compress_brotli(&compress_gzip(original.as_bytes()));

        for chunk_size in [1, 3, 64, compressed.len()] {
            let out = layered_decode_in_chunks(
                &[ContentCoding::Brotli, ContentCoding::Gzip],
                &compressed,
                chunk_size,
            );
            assert_eq!(out, original.as_bytes(), "chunk_size={chunk_size}");
        }
    }

    #[test]
    fn layered_stream_decoder_three_codings_in_small_chunks() {
        let original = "three codings streamed ".repeat(30);
        let compressed = compress_brotli(&compress_gzip(&compress_deflate(original.as_bytes())));

        let out = layered_decode_in_chunks(
            &[
                ContentCoding::Brotli,
                ContentCoding::Gzip,
                ContentCoding::Deflate,
            ],
            &compressed,
            2,
        );

        assert_eq!(out, original.as_bytes());
    }

    #[test]
    fn layered_stream_decoder_single_coding_still_works() {
        let original = "a single coding is just the one-layer case ".repeat(20);
        let cases = [
            (ContentCoding::Gzip, compress_gzip(original.as_bytes())),
            (ContentCoding::Brotli, compress_brotli(original.as_bytes())),
            (
                ContentCoding::Deflate,
                compress_deflate(original.as_bytes()),
            ),
            (ContentCoding::Zstd, compress_zstd(original.as_bytes())),
        ];

        for (coding, compressed) in cases {
            let out = layered_decode_in_chunks(&[coding], &compressed, 5);
            assert_eq!(out, original.as_bytes(), "coding={}", coding.token());
        }
    }

    #[test]
    fn layered_stream_decoder_matches_the_buffered_path() {
        let original = "both paths must agree ".repeat(50);
        let compressed = compress_brotli(&compress_gzip(original.as_bytes()));

        let streamed = layered_decode_in_chunks(
            &[ContentCoding::Brotli, ContentCoding::Gzip],
            &compressed,
            7,
        );
        let buffered = decompress_body(&encodings(&["gzip, br"]), Bytes::from(compressed)).unwrap();

        assert_eq!(streamed, buffered.to_vec());
        assert_eq!(streamed, original.as_bytes());
    }
}
