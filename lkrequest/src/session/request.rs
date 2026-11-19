use std::sync::Arc;
use std::time::Duration;
use tracing::Instrument;

use http::HeaderMap;
use url::Url;

use crate::attempt_observer::{AttemptObserver, ObservationBinding};
use crate::attempts::{AttemptLimitScope, AttemptLimits, AttemptSummary, EffectiveAttemptLimits};
use crate::body::RequestBody;
use crate::error::{Error, Result};
use crate::protocol::{HttpIntent, ProtocolPolicy};
use crate::proxy::ProxyConfig;
use crate::response::{HttpVersion, Response, StreamingResponse};

use super::execution::{ExecutionGuard, HttpAttempt, RecoveryOwner, RequestExecution};
use super::next_request_id;
use super::streaming::StreamRequestBuilder;
use super::{AcceptEncoding, Idempotency, PreferredHttpVersion, Session};

/// Builder for a single HTTP request.
///
/// Created via `session.get(url)`, `session.post(url)`, etc.
///
/// # Merging headers vs. wire order
///
/// | What you want | Use |
/// |---------------|-----|
/// | Merge extra headers into the request (`HeaderMap` or one-by-one) | [`header`](Self::header), [`headers`](Self::headers), [`headers_with_order`](Self::headers_with_order), [`headers_ordered`](Self::headers_ordered) |
/// | Control **send order** of header *names* (fingerprint / browser-like ordering) | [`header_order`](Self::header_order) on the builder, or session/client defaults |
///
/// `headers_with_order` only affects **insertion order** for keys coming from a merged map; it does **not** replace [`header_order`](Self::header_order). When a TLS/H2 fingerprint template applies, its ordering rules can still take precedence over plain insertion order.
///
/// # Example
///
/// ```rust,no_run
/// # use lkrequest::Client;
/// # use lktls::profile::presets;
/// # use std::time::Duration;
/// # async fn example() -> Result<(), lkrequest::error::Error> {
/// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
/// # let session = client.session().build();
/// let resp = session.get("https://example.com")
///     .header("Accept", "application/json")
///     .bearer_auth("my-token")
///     .timeout(Duration::from_secs(5))
///     .send()
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct RequestBuilder {
    attempt_limits: AttemptLimits,
    observation: Option<ObservationBinding>,
    pub(crate) session: Session,
    pub(crate) method: http::Method,
    pub(crate) url: String,
    pub(crate) headers: HeaderMap,
    /// Per-attempt defaults after redirect filtering; absent until the first hop.
    pub(crate) redirect_defaults: Option<HeaderMap>,
    pub(crate) body: Option<RequestBody>,
    pub(crate) query_params: Vec<(String, String)>,
    /// Request-level cookies (appended to jar cookies at send time).
    pub(crate) extra_cookies: Vec<(String, String)>,
    /// Cookie names that should fully replace all same-name jar cookies.
    pub(crate) cookie_overrides: Vec<String>,
    /// Per-request end-to-end deadline override (see [`RequestBuilder::timeout`]).
    pub(crate) timeout: Option<Duration>,
    pub(crate) request_timeout: crate::timeout::RequestTimeout,
    pub(crate) execution: Option<RequestExecution>,
    pub(crate) attempt: Option<HttpAttempt>,
    /// Per-request proxy override (overrides session proxy).
    pub(crate) proxy_override: Option<ProxyConfig>,
    /// Per-request HTTP version override.
    pub(crate) version_override: Option<PreferredHttpVersion>,
    /// Per-request protocol policy override.
    pub(crate) protocol_policy_override: Option<ProtocolPolicy>,
    /// Per-request Accept-Encoding override.
    pub(crate) accept_encoding: Option<AcceptEncoding>,
    /// Whether to skip automatic response body decompression.
    pub(crate) no_decompress: bool,
    /// Per-request header sending order override.
    pub(crate) header_order: Option<Vec<http::header::HeaderName>>,
    /// Per-request HTTP/3-specific header sending order override.
    pub(crate) h3_header_order: Option<Vec<http::header::HeaderName>>,
    /// Per-request cookie sending order override.
    pub(crate) cookie_order: Option<Vec<Box<str>>>,
    /// Tracks the order in which headers were added via .header() calls.
    pub(crate) header_insertion_order: Vec<http::header::HeaderName>,
    /// Per-request RFC 9218 priority (urgency + incremental).
    /// Used for the HTTP priority header and profile-specific H2 weight mapping.
    pub(crate) priority: Option<lkh2::RequestPriority>,
    pub(crate) h2_priority_weight: Option<u8>,
    /// Per-request 0-RTT / early-data gate. See [`Idempotency`].
    pub(crate) idempotency: Idempotency,
    /// Deferred error from infallible builder methods (e.g. json/form
    /// serialization failure). Surfaced at `send()` time so that the
    /// builder chain is never broken by `Result`.
    pub(crate) deferred_error: Option<Error>,
    /// When true, collect per-request diagnostics and attach them to the
    /// `Response`. Opt-in: off by default so the request hot path is unaffected.
    pub(crate) collect_diagnostics: bool,
}

/// Immutable request fields shared across retries via `Arc`.
///
/// When a retry policy is configured, this avoids deep-cloning `HeaderMap`,
/// `String`, and `Vec` fields on every retry attempt.  Only the `Arc`
/// reference count is incremented (O(1)).
pub(crate) struct SharedRequestContext {
    attempt_limits: AttemptLimits,
    pub(crate) execution: RequestExecution,
    pub(crate) method: http::Method,
    pub(crate) url: String,
    pub(crate) headers: HeaderMap,
    pub(crate) query_params: Vec<(String, String)>,
    pub(crate) extra_cookies: Vec<(String, String)>,
    pub(crate) cookie_overrides: Vec<String>,
    pub(crate) timeout: Option<Duration>,
    pub(crate) request_timeout: crate::timeout::RequestTimeout,
    pub(crate) proxy_override: Option<ProxyConfig>,
    pub(crate) version_override: Option<PreferredHttpVersion>,
    pub(crate) protocol_policy_override: Option<ProtocolPolicy>,
    pub(crate) no_decompress: bool,
    pub(crate) header_order: Option<Vec<http::header::HeaderName>>,
    pub(crate) h3_header_order: Option<Vec<http::header::HeaderName>>,
    pub(crate) cookie_order: Option<Vec<Box<str>>>,
    pub(crate) header_insertion_order: Vec<http::header::HeaderName>,
    pub(crate) priority: Option<lkh2::RequestPriority>,
    pub(crate) h2_priority_weight: Option<u8>,
    pub(crate) idempotency: Idempotency,
}

impl RequestBuilder {
    fn begin_execution(&mut self) -> (ExecutionGuard, Result<RecoveryOwner>) {
        self.request_timeout = crate::timeout::RequestTimeout::new(self.effective_total_timeout());
        let limits = self.effective_attempt_limits();
        let (execution, guard) =
            RequestExecution::with_limits(self.request_timeout, limits.as_ref().ok().copied());
        if let Some(observation) = self.observation.take() {
            observation.bind(&execution);
        }
        let admission = limits
            .and_then(|_| execution.start_http())
            .map(|(attempt, owner)| {
                self.execution = Some(execution);
                self.attempt = Some(attempt);
                owner
            });
        (guard, admission)
    }

    /// Set optional aggregate caps for this request. Unset fields inherit the
    /// session cap; a finite parent can be tightened but cannot be relaxed.
    pub fn attempt_limits(mut self, limits: AttemptLimits) -> Self {
        self.attempt_limits = limits;
        self
    }

    /// Return the request-level configuration before inheritance.
    pub fn configured_attempt_limits(&self) -> AttemptLimits {
        self.attempt_limits
    }

    /// Resolve the final request configuration without starting any I/O.
    pub fn effective_attempt_limits(&self) -> Result<EffectiveAttemptLimits> {
        self.attempt_limits.resolve(
            Some(&self.session.effective_attempt_limits()?),
            AttemptLimitScope::Request,
        )
    }

    /// Attach read-only observation before sending or spawning this request.
    /// Repeated calls return observers of the same operation.
    pub fn observe_attempts(mut self) -> (Self, AttemptObserver) {
        let observer = self
            .observation
            .get_or_insert_with(ObservationBinding::new)
            .observer();
        (self, observer)
    }

    /// Send and return an independent summary for either success or failure.
    pub async fn send_with_attempt_summary(self) -> (Result<Response>, AttemptSummary) {
        let (request, observer) = self.observe_attempts();
        let result = request.send().await;
        (result, observer.snapshot())
    }

    /// Send a streaming request and snapshot HTTP execution at publication.
    /// Subsequent response-body reads do not create HTTP submission attempts.
    pub async fn send_streaming_with_attempt_summary(
        self,
    ) -> (Result<StreamingResponse>, AttemptSummary) {
        let (request, observer) = self.observe_attempts();
        let result = request.send_streaming().await;
        (result, observer.snapshot())
    }

    pub(crate) fn new(session: Session, method: http::Method, url: &str) -> Self {
        Self {
            attempt_limits: AttemptLimits::default(),
            observation: None,
            session,
            method,
            url: url.to_string(),
            headers: HeaderMap::new(),
            redirect_defaults: None,
            body: None,
            query_params: Vec::new(),
            extra_cookies: Vec::new(),
            cookie_overrides: Vec::new(),
            timeout: None,
            request_timeout: crate::timeout::RequestTimeout::default(),
            execution: None,
            attempt: None,
            proxy_override: None,
            version_override: None,
            protocol_policy_override: None,
            accept_encoding: None,
            no_decompress: false,
            header_order: None,
            h3_header_order: None,
            cookie_order: None,
            header_insertion_order: Vec::new(),
            priority: None,
            h2_priority_weight: None,
            idempotency: Idempotency::default(),
            deferred_error: None,
            collect_diagnostics: false,
        }
    }

    /// Create a RequestBuilder from a shared context (used by retry loop).
    /// Only `session` (Arc) and `body` (Bytes, O(1) clone) are per-attempt.
    pub(crate) fn from_shared_context(
        session: Session,
        ctx: Arc<SharedRequestContext>,
        body: Option<RequestBody>,
        attempt: HttpAttempt,
    ) -> Self {
        Self {
            attempt_limits: ctx.attempt_limits,
            observation: None,
            session,
            method: ctx.method.clone(),
            url: ctx.url.clone(),
            headers: ctx.headers.clone(),
            redirect_defaults: None,
            body,
            query_params: ctx.query_params.clone(),
            extra_cookies: ctx.extra_cookies.clone(),
            cookie_overrides: ctx.cookie_overrides.clone(),
            timeout: ctx.timeout,
            request_timeout: ctx.request_timeout,
            execution: Some(ctx.execution.clone()),
            attempt: Some(attempt),
            proxy_override: ctx.proxy_override.clone(),
            version_override: ctx.version_override,
            protocol_policy_override: ctx.protocol_policy_override.clone(),
            accept_encoding: None,
            no_decompress: ctx.no_decompress,
            header_order: ctx.header_order.clone(),
            h3_header_order: ctx.h3_header_order.clone(),
            cookie_order: ctx.cookie_order.clone(),
            header_insertion_order: ctx.header_insertion_order.clone(),
            priority: ctx.priority,
            h2_priority_weight: ctx.h2_priority_weight,
            idempotency: ctx.idempotency,
            deferred_error: None,
            collect_diagnostics: false,
        }
    }

    pub(crate) fn execution(&self) -> Result<&RequestExecution> {
        self.execution
            .as_ref()
            .ok_or_else(|| Error::Http("missing request execution context".into()))
    }

    pub(crate) fn attempt(&self) -> Result<&HttpAttempt> {
        self.attempt
            .as_ref()
            .ok_or_else(|| Error::Http("missing HTTP attempt authority".into()))
    }

    /// Add a cookie to this request only (does not modify the session jar).
    ///
    /// When the outgoing `Cookie` header is built, pairs appear in this order:
    /// explicit `Cookie` header pairs (from [`header`](Self::header) /
    /// [`headers`](Self::headers)), then jar matches for names not overridden
    /// by those pairs, then request-level cookies from this method. If the jar
    /// already contains a cookie with the same name, **both** can be sent
    /// (the request-level one is appended after jar-derived pairs). This
    /// matches real browser behavior where the same cookie name can exist at
    /// different paths.
    ///
    /// Use [`cookie_override`](Self::cookie_override) to replace all
    /// same-name jar cookies instead.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://example.com")
    ///     .cookie("extra_token", "xyz")
    ///     .cookie("extra_token", "abc")  // both are sent
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn cookie(mut self, name: &str, value: &str) -> Self {
        self.extra_cookies
            .push((name.to_string(), value.to_string()));
        self
    }

    /// Add a cookie that **overrides** all same-name cookies from the jar.
    ///
    /// Unlike [`cookie`](Self::cookie), this removes all jar cookies with
    /// the same name and replaces them with the given value.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// // If jar has "token=old_val" at "/" and "token=api_val" at "/api",
    /// // this replaces both with a single "token=override".
    /// let resp = session.get("https://example.com/api")
    ///     .cookie_override("token", "override")
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn cookie_override(mut self, name: &str, value: &str) -> Self {
        self.extra_cookies
            .push((name.to_string(), value.to_string()));
        // Mark this name for full replacement (prefix with \0 as sentinel)
        self.cookie_overrides.push(name.to_string());
        self
    }

    /// Add a header to this request.
    ///
    /// For the `Cookie` header, values are merged with the session jar and
    /// [`cookie`](Self::cookie) entries at send time: your pairs are sent first
    /// and override the jar for the same cookie names.
    ///
    /// If `name` or `value` fails HTTP parsing, this call is a no-op (the header
    /// is skipped). Use [`header_typed`](Self::header_typed) with pre-validated
    /// values when you need explicit control.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        if let (Ok(n), Ok(v)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            http::header::HeaderValue::from_str(value),
        ) {
            if !self.header_insertion_order.contains(&n) {
                self.header_insertion_order.push(n.clone());
            }
            self.headers.insert(n, v);
        }
        self
    }

    /// Add a header using pre-parsed `HeaderName` and `HeaderValue`.
    ///
    /// Avoids the parsing overhead of [`header()`](Self::header) when
    /// the caller already has typed header values.
    pub fn header_typed(
        mut self,
        name: http::header::HeaderName,
        value: http::header::HeaderValue,
    ) -> Self {
        if !self.header_insertion_order.contains(&name) {
            self.header_insertion_order.push(name.clone());
        }
        self.headers.insert(name, value);
        self
    }

    /// Add a set of headers to this request.
    ///
    /// Headers are merged into any already set on this request, with new
    /// values overriding existing ones for the same header name. All values
    /// supplied for a name are preserved in their original order.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// use http::HeaderMap;
    ///
    /// let mut headers = HeaderMap::new();
    /// headers.insert("X-Custom", "value".parse().unwrap());
    /// headers.insert("Accept", "application/json".parse().unwrap());
    ///
    /// let resp = session.get("https://example.com")
    ///     .headers(headers)
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// `HeaderMap` does not guarantee a stable ordering when iterating. If you
    /// need a specific wire order when no client/session [`header_order`](Self::header_order)
    /// is set, use [`headers_with_order`](Self::headers_with_order) or
    /// [`headers_ordered`](Self::headers_ordered).
    pub fn headers(self, map: HeaderMap) -> Self {
        self.merge_header_map(map, None)
    }

    /// Merge a [`HeaderMap`] like [`headers`](Self::headers), but set **insertion
    /// order** for keys coming from `map` using `order` (field names as strings).
    ///
    /// Names listed in `order` are placed first (in that order); any other keys
    /// from `map` follow in their original map iteration order. Headers added
    /// earlier in the builder chain keep their relative positions **before** the
    /// keys merged from `map`.
    ///
    /// Invalid or unknown header names in `order` are skipped. This only affects
    /// insertion order when merging the map; it does **not** replace
    /// [`header_order`](Self::header_order) (fingerprint-style wire order).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # use http::HeaderMap;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let mut h = HeaderMap::new();
    /// h.insert("accept", "application/json".parse().unwrap());
    /// h.insert("cookie", "a=b".parse().unwrap());
    /// let _ = session
    ///     .get("https://example.com")
    ///     .headers_with_order(h, &["cookie", "accept"]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn headers_with_order(self, map: HeaderMap, order: &[&str]) -> Self {
        self.merge_header_map(map, Some(order))
    }

    /// Add many headers from an iterator of `(name, value)` pairs.
    ///
    /// Order on the wire (when no fingerprint `header_order` applies) matches
    /// iterator order; duplicate names only add to insertion order once (same
    /// rules as repeated [`header`](Self::header) calls).
    ///
    /// Pairs with invalid header names or values are skipped, matching
    /// [`header`](Self::header).
    pub fn headers_ordered<N, V>(mut self, pairs: impl IntoIterator<Item = (N, V)>) -> Self
    where
        N: AsRef<str>,
        V: AsRef<str>,
    {
        for (name, value) in pairs {
            if let (Ok(n), Ok(v)) = (
                http::header::HeaderName::from_bytes(name.as_ref().as_bytes()),
                http::header::HeaderValue::from_str(value.as_ref()),
            ) {
                if !self.header_insertion_order.contains(&n) {
                    self.header_insertion_order.push(n.clone());
                }
                self.headers.insert(n, v);
            }
        }
        self
    }

    fn merge_header_map(mut self, map: HeaderMap, order: Option<&[&str]>) -> Self {
        use std::collections::HashSet;

        let names: Vec<_> = map.keys().cloned().collect();
        for name in &names {
            let mut values = map.get_all(name).iter();
            if let Some(first) = values.next() {
                self.headers.insert(name.clone(), first.clone());
            }
            for value in values {
                self.headers.append(name.clone(), value.clone());
            }
        }

        if let Some(order_sl) = order {
            self.header_insertion_order.retain(|n| !map.contains_key(n));
            let mut tail = Vec::new();
            let mut seen_in_tail = HashSet::new();
            for s in order_sl {
                if let Ok(n) = http::header::HeaderName::from_bytes(s.as_bytes()) {
                    if map.contains_key(&n)
                        && self.headers.contains_key(&n)
                        && seen_in_tail.insert(n.clone())
                    {
                        tail.push(n);
                    }
                }
            }
            for n in &names {
                if !seen_in_tail.contains(n) {
                    tail.push(n.clone());
                    seen_in_tail.insert(n.clone());
                }
            }
            self.header_insertion_order.extend(tail);
        } else {
            for name in names {
                if !self.header_insertion_order.contains(&name) {
                    self.header_insertion_order.push(name);
                }
            }
        }

        self
    }

    /// Set the header **sending** order for this request only (fingerprint-style
    /// name order on the wire), not to be confused with merging a [`HeaderMap`]
    /// via [`headers`](Self::headers) / [`headers_with_order`](Self::headers_with_order).
    ///
    /// Overrides session-level and client-level `header_order`.
    pub fn header_order(mut self, order: Vec<&str>) -> Self {
        let names: Vec<http::header::HeaderName> = order
            .into_iter()
            .filter_map(|s| http::header::HeaderName::from_bytes(s.as_bytes()).ok())
            .collect();
        if !names.is_empty() {
            self.header_order = Some(names);
        }
        self
    }

    /// Set the HTTP/3-specific header sending order for this request only.
    ///
    /// Overrides request/session/client generic `header_order` for H3 requests.
    pub fn h3_header_order(mut self, order: Vec<&str>) -> Self {
        let names: Vec<http::header::HeaderName> = order
            .into_iter()
            .filter_map(|s| http::header::HeaderName::from_bytes(s.as_bytes()).ok())
            .collect();
        if !names.is_empty() {
            self.h3_header_order = Some(names);
        }
        self
    }

    /// Set the cookie sending order for this request only.
    pub fn cookie_order(mut self, order: Vec<&str>) -> Self {
        let names: Vec<Box<str>> = order.into_iter().map(|s| s.into()).collect();
        if !names.is_empty() {
            self.cookie_order = Some(names);
        }
        self
    }

    /// Enable HTTP basic authentication.
    ///
    /// Encodes `username:password` in Base64 and sets the `Authorization`
    /// header to `Basic <encoded>`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://api.example.com")
    ///     .basic_auth("admin", Some("secret"))
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn basic_auth(mut self, username: &str, password: Option<&str>) -> Self {
        use base64::Engine;
        let credentials = match password {
            Some(pw) => format!("{username}:{pw}"),
            None => format!("{username}:"),
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
        let value = format!("Basic {encoded}");
        if let Ok(v) = http::header::HeaderValue::from_str(&value) {
            self.headers.insert(http::header::AUTHORIZATION, v);
        }
        self
    }

    /// Enable HTTP bearer token authentication.
    ///
    /// Sets the `Authorization` header to `Bearer <token>`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://api.example.com")
    ///     .bearer_auth("eyJhbGciOiJIUzI1NiIs...")
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn bearer_auth(mut self, token: &str) -> Self {
        let value = format!("Bearer {token}");
        if let Ok(v) = http::header::HeaderValue::from_str(&value) {
            self.headers.insert(http::header::AUTHORIZATION, v);
        }
        self
    }

    /// Set the RFC 9218 request priority (urgency + incremental).
    ///
    /// Sets HTTP priority and the profile's optional H2 urgency-to-weight
    /// mapping (e.g. Chrome u=1 uses wire weight 219). Browsers such as Firefox
    /// use independent legacy weights; use [`Self::h2_priority_weight`] for
    /// that separate dimension.
    /// With per-request H3 priority updates enabled (Chrome 155), the resolved
    /// value also controls the update for the actual allocated request stream.
    /// Disabling automatic HTTP priority headers does not suppress that update.
    ///
    /// If not called, the profile's default priority is used
    /// (Chrome defaults to `u=1, i` for fetch/XHR).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().build();
    /// # let session = client.session().build();
    /// use lkh2::RequestPriority;
    ///
    /// let resp = session.get("https://example.com/image.png")
    ///     .priority(RequestPriority::image())
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn priority(mut self, priority: lkh2::RequestPriority) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Override the wire-level legacy H2 HEADERS weight (0 through 255).
    /// This is independent of the HTTP `priority` header, stream dependency,
    /// and exclusive flag. Profiles without legacy HEADERS priority remain
    /// unchanged. Has no effect on H1/H3.
    ///
    /// For the captured Firefox 156 favicon context, pair
    /// `.priority(RequestPriority::custom(6, false))` with
    /// `.h2_priority_weight(21)`. This describes that resource role, not every image.
    pub fn h2_priority_weight(mut self, weight: u8) -> Self {
        self.h2_priority_weight = Some(weight);
        self
    }

    /// Set a per-request end-to-end deadline.
    ///
    /// Bounds connection setup, upload, redirects, explicitly configured retries
    /// and backoff, and response body reads, including streaming reads after
    /// headers are returned. Overrides the client total while keeping phase
    /// limits active. The deadline never resets on retry.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set a per-request proxy.
    ///
    /// Overrides the session-level proxy for this request only. Useful when
    /// you want to route specific requests through different proxies while
    /// sharing the same session (cookie jar, connection pool).
    /// Invalid configuration is returned by `send` or `send_streaming` before
    /// DNS or connection establishment; it never falls back to another route.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://example.com")
    ///     .proxy("socks5://special-proxy:1080")
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn proxy(mut self, proxy_url: &str) -> Self {
        match ProxyConfig::parse(proxy_url) {
            Ok(config) => self.proxy_override = Some(config),
            Err(error) => {
                self.deferred_error.get_or_insert(error);
            }
        }
        self
    }

    /// Prefer a specific HTTP version behavior for this request.
    ///
    /// Overrides the session-level HTTP version preference without changing
    /// the rest of the protocol policy.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// use lkrequest::PreferredHttpVersion;
    ///
    /// let resp = session.get("https://example.com")
    ///     .preferred_http_version(PreferredHttpVersion::Http2Only)
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn preferred_http_version(mut self, version: PreferredHttpVersion) -> Self {
        self.version_override = Some(version);
        self
    }

    /// Force a specific HTTP version for this request.
    ///
    /// Legacy request-side setter. New code should call
    /// [`RequestBuilder::preferred_http_version`].
    ///
    /// [`HttpVersion::Unknown`] is treated as
    /// “no override” (ALPN / session preference decides).
    #[deprecated(
        since = "0.3.0",
        note = "use `preferred_http_version(PreferredHttpVersion)`"
    )]
    pub fn version(self, version: HttpVersion) -> Self {
        self.preferred_http_version(version.into())
    }

    /// Override the runtime protocol behavior for this request only.
    pub fn protocol_policy(mut self, policy: ProtocolPolicy) -> Self {
        self.protocol_policy_override = Some(policy);
        self
    }

    /// Override only this request's high-level H2/H3 intent.
    pub fn http_intent(mut self, intent: HttpIntent) -> Self {
        let policy = self
            .protocol_policy_override
            .take()
            .unwrap_or_else(|| self.session.protocol_policy().clone())
            .with_intent(intent);
        self.protocol_policy_override = Some(policy);
        self
    }

    /// Declare whether this request is safe to send in QUIC 0-RTT / TLS
    /// early data.
    ///
    /// See [`Idempotency`] for the exact semantics. The default is
    /// [`Idempotency::Default`], which lets lkrequest decide based on the
    /// HTTP method (RFC 9110 §9.2.1 safe methods → yes; everything else →
    /// no). Override to [`Idempotency::Idempotent`] if the request carries
    /// an application-level replay guard (e.g. an `Idempotency-Key` header)
    /// and you want non-safe methods to benefit from 0-RTT; override to
    /// [`Idempotency::NotIdempotent`] to force a full 1-RTT handshake even
    /// for GET/HEAD.
    ///
    /// This API matches Chromium's `HttpRequestInfo::idempotency` tri-state.
    pub fn idempotency(mut self, kind: Idempotency) -> Self {
        self.idempotency = kind;
        self
    }

    /// Set the `Accept-Encoding` for this request.
    ///
    /// Controls which compression algorithms are advertised to the server,
    /// and which decompression to apply on the response body. Overrides
    /// the session-level `default_accept_encoding`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// use lkrequest::AcceptEncoding;
    ///
    /// // First request: only gzip
    /// let resp1 = session.get("https://example.com/page1")
    ///     .accept_encoding(AcceptEncoding::GZIP)
    ///     .send().await?;
    ///
    /// // Second request: only brotli
    /// let resp2 = session.get("https://example.com/page2")
    ///     .accept_encoding(AcceptEncoding::BR)
    ///     .send().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn accept_encoding(mut self, encoding: AcceptEncoding) -> Self {
        self.accept_encoding = Some(encoding);
        self
    }

    /// Disable automatic response body decompression for this request.
    ///
    /// The raw response body is returned as-is, regardless of the
    /// `content-encoding` header. Useful when you need the raw compressed
    /// bytes or want to handle decompression yourself.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://example.com")
    ///     .no_auto_decompress()
    ///     .send()
    ///     .await?;
    /// // resp.bytes() returns the raw (possibly compressed) bytes
    /// # Ok(())
    /// # }
    /// ```
    pub fn no_auto_decompress(mut self) -> Self {
        self.no_decompress = true;
        self
    }

    /// Collect per-request diagnostics (phase timings, protocol, remote address)
    /// and attach them to the [`Response`](crate::response::Response), readable
    /// via [`Response::diagnostics`](crate::response::Response::diagnostics).
    ///
    /// Opt-in and off by default: when not enabled the request carries no
    /// diagnostics-collection overhead at all.
    pub fn collect_diagnostics(mut self, enabled: bool) -> Self {
        self.collect_diagnostics = enabled;
        self
    }

    /// Set the request body as raw bytes.
    ///
    /// Accepts any type that implements `Into<Bytes>`, including `Vec<u8>`,
    /// `&'static [u8]`, `String`, `Bytes`, etc.
    pub fn body(mut self, body: impl Into<bytes::Bytes>) -> Self {
        self.body = Some(RequestBody::from(body.into()));
        self
    }

    /// Upload from an asynchronous reader without buffering the complete body.
    ///
    /// `length` is the exact byte count, or `None` for an unknown-length body.
    /// Unknown-length HTTP/1.1 uploads use chunked framing. The source is
    /// single-use: once claimed by a transport, it cannot be retried or replayed
    /// for a body-preserving redirect. Works with both `send` and `send_streaming`.
    ///
    /// Pass an owned source; `Unpin` is not required. This setter performs no I/O
    /// and replaces any previous body. The source must reach EOF even when its
    /// exact length is supplied, so close a pipe's writer after its final bytes.
    /// Short/oversized bodies and conflicting framing headers fail during send.
    /// Request middleware sees `None` instead of buffering this source.
    ///
    /// For `std::io::Read`, use the identically named method on
    /// [`crate::blocking::RequestBuilder::body_reader`].
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # async fn upload(session: &lkrequest::Session) -> Result<(), Box<dyn std::error::Error>> {
    /// let file = tokio::fs::File::open("archive.zip").await?;
    /// let length = file.metadata().await?.len();
    /// let response = session.post("https://example.com/upload")
    ///     .body_reader(file, Some(length))
    ///     .send().await?;
    /// assert!(response.status().is_success());
    /// # Ok(())
    /// # }
    /// ```
    pub fn body_reader(
        mut self,
        reader: impl tokio::io::AsyncRead + Send + 'static,
        length: Option<u64>,
    ) -> Self {
        self.body = Some(RequestBody::reader(reader, length));
        self
    }

    /// Upload a single-use stream of byte chunks, with optional exact length.
    ///
    /// Empty chunks are skipped. Source errors abort the upload. Chunks are
    /// requested as the transport makes progress, without collecting the stream.
    ///
    /// The stream need not implement `Unpin`. Length validation, middleware and
    /// replay restrictions match [`body_reader`](Self::body_reader). Source errors
    /// do not undo bytes already sent. Keep producer queues bounded and terminate
    /// the stream after the last chunk, including when `length` is known.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use bytes::Bytes;
    /// use std::{io, pin::Pin, task::{Context, Poll}};
    /// struct Chunks(std::vec::IntoIter<io::Result<Bytes>>);
    /// impl futures_core::Stream for Chunks {
    ///     type Item = io::Result<Bytes>;
    ///     fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    ///         Poll::Ready(self.0.next())
    ///     }
    /// }
    /// # async fn upload(session: &lkrequest::Session) -> Result<(), lkrequest::error::Error> {
    /// let chunks = Chunks(vec![Ok(Bytes::from_static(b"hello"))].into_iter());
    /// let response = session.post("https://example.com/upload")
    ///     .body_stream(chunks, None)
    ///     .send().await?;
    /// assert!(response.status().is_success());
    /// # Ok(())
    /// # }
    /// ```
    pub fn body_stream<S>(mut self, stream: S, length: Option<u64>) -> Self
    where
        S: futures_core::Stream<Item = std::io::Result<bytes::Bytes>> + Send + 'static,
    {
        self.body = Some(RequestBody::stream(Box::pin(stream), length));
        self
    }

    /// Set the request body as a UTF-8 string.
    pub fn text_body(mut self, text: &str) -> Self {
        self.body = Some(bytes::Bytes::copy_from_slice(text.as_bytes()).into());
        self
    }

    /// Set the request body as JSON, serializing the given value.
    ///
    /// If serialization fails, the error is deferred until
    /// [`send()`](Self::send) / [`send_streaming()`](Self::send_streaming)
    /// so the builder chain is never broken.
    pub fn json<T: serde::Serialize>(mut self, value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(body) => {
                self.body = Some(bytes::Bytes::from(body).into());
                self.headers.insert(
                    http::header::CONTENT_TYPE,
                    http::header::HeaderValue::from_static("application/json"),
                );
            }
            Err(e) => {
                self.deferred_error =
                    Some(Error::Http(format!("failed to serialize JSON body: {e}")));
            }
        }
        self
    }

    /// Set the request body as `application/x-www-form-urlencoded`.
    ///
    /// Serializes the given value using `serde_urlencoded` and automatically
    /// sets the `Content-Type` header.
    ///
    /// If serialization fails, the error is deferred until
    /// [`send()`](Self::send) / [`send_streaming()`](Self::send_streaming)
    /// so the builder chain is never broken.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.post("https://example.com/login")
    ///     .form(&[("username", "alice"), ("password", "secret")])
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn form<T: serde::Serialize>(mut self, value: &T) -> Self {
        match serde_urlencoded::to_string(value) {
            Ok(body) => {
                self.body = Some(bytes::Bytes::from(body).into());
                self.headers.insert(
                    http::header::CONTENT_TYPE,
                    http::header::HeaderValue::from_static("application/x-www-form-urlencoded"),
                );
            }
            Err(e) => {
                self.deferred_error =
                    Some(Error::Http(format!("failed to serialize form body: {e}")));
            }
        }
        self
    }

    /// Set the request body as multipart/form-data.
    ///
    /// Encodes the multipart form and automatically sets the `Content-Type`
    /// header with the correct boundary.
    ///
    /// If a part's field name, filename or content type contains a CR or an
    /// LF — which would let it inject extra part headers or forge the
    /// boundary — the form is rejected and the error surfaces from
    /// [`Self::send`], the same way a bad `json()` or `form()` body does.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// # let photo_bytes = vec![0u8];
    /// use lkrequest::multipart::Multipart;
    ///
    /// let form = Multipart::new()
    ///     .text("field", "value")
    ///     .file("upload", "photo.jpg", "image/jpeg", photo_bytes);
    ///
    /// let resp = session.post("https://example.com/upload")
    ///     .multipart(form)
    ///     .send()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn multipart(mut self, form: crate::multipart::Multipart) -> Self {
        let content_type = form.content_type_header();
        match form.encode() {
            Ok(body) => {
                self.body = Some(bytes::Bytes::from(body).into());
                if let Ok(v) = http::header::HeaderValue::from_str(&content_type) {
                    self.headers.insert(http::header::CONTENT_TYPE, v);
                }
            }
            Err(e) => {
                self.deferred_error = Some(e);
            }
        }
        self
    }

    /// Append URL query parameters to this request.
    ///
    /// Multiple calls accumulate parameters.  Existing query parameters in
    /// the URL are preserved; the new ones are appended.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// let resp = session.get("https://api.example.com/search")
    ///     .query(&[("q", "rust"), ("page", "1")])
    ///     .send()
    ///     .await?;
    /// // Requests: GET https://api.example.com/search?q=rust&page=1
    /// # Ok(())
    /// # }
    /// ```
    pub fn query(mut self, params: &[(&str, &str)]) -> Self {
        for &(key, value) in params {
            self.query_params.push((key.to_string(), value.to_string()));
        }
        self
    }

    /// Send the request and return the response.
    ///
    /// For a **streaming** body, no automatic redirect following, or no session
    /// retries, use [`send_streaming`](Self::send_streaming) instead—it behaves
    /// differently; read its documentation before choosing.
    ///
    /// Follows redirects according to the session's [`RedirectPolicy`](super::RedirectPolicy):
    /// - `RedirectPolicy::Follow(n)` — automatically follow
    ///   up to `n` redirects (301, 302, 307, 308).
    /// - [`RedirectPolicy::None`](super::RedirectPolicy::None) — return the 3xx response as-is.
    ///
    /// Redirect behavior:
    /// - 301/302: Changes method to GET, drops body.
    /// - 307/308: Preserves original method and body.
    /// - Cross-origin redirects strip sensitive headers (Authorization, Cookie).
    ///
    /// If a retry policy is configured on the session, retryable failures will
    /// be automatically retried according to the policy.
    #[allow(clippy::let_and_return)] // `result` is consumed by the telemetry cfg arm
    pub async fn send(mut self) -> Result<Response> {
        let (mut guard, admission) = self.begin_execution();
        let result = match admission {
            Err(error) => Err(error),
            Ok(owner) => {
                if self.collect_diagnostics {
                    // Opt-in capture attaches phase diagnostics to the response.
                    let (result, diagnostics) = crate::diagnostics::capture_request_diagnostics(
                        guard.run(self.send_impl(owner)),
                    )
                    .await;
                    result.map(|mut response| {
                        response.set_diagnostics(diagnostics);
                        response
                    })
                } else {
                    guard.run(self.send_impl(owner)).await
                }
            }
        };
        let result = result.and_then(|response| {
            guard.publish()?;
            Ok(response)
        });
        if let Err(error) = &result {
            guard.finish_error(error);
        }
        #[cfg(feature = "telemetry")]
        crate::telemetry::counters().record_request(result.is_err());
        result.map_err(Error::into_public_connect_error)
    }

    #[cfg(feature = "bench-internals")]
    #[doc(hidden)]
    pub async fn send_transport_only_for_benchmark(mut self) -> Result<Response> {
        let (mut guard, admission) = self.begin_execution();
        let result = match admission
            .and_then(|_| self.session.validate_proxy_config())
            .and_then(|_| self.deferred_error.take().map_or(Ok(()), Err))
        {
            Err(error) => Err(error),
            Ok(()) => {
                guard
                    .run(self.send_single_request(
                        &self.url,
                        &self.method,
                        &self.headers,
                        self.body.clone(),
                    ))
                    .await
            }
        }
        .and_then(|response| {
            guard.publish()?;
            Ok(response)
        });
        if let Err(error) = &result {
            guard.finish_error(error);
        }
        result.map_err(Error::into_public_connect_error)
    }

    async fn send_impl(self, owner: RecoveryOwner) -> Result<Response> {
        let execution = self
            .execution
            .ok_or_else(|| Error::Http("missing request execution context".into()))?;
        execution.ensure_active()?;
        let mut attempt = self
            .attempt
            .ok_or_else(|| Error::Http("missing HTTP attempt authority".into()))?;
        self.session.validate_proxy_config()?;
        if let Some(err) = self.deferred_error {
            return Err(err);
        }

        let req_id = next_request_id();
        let span = tracing::info_span!(
            "http.request",
            req_id = req_id,
            method = %self.method,
            url = %self.url,
            // Result fields recorded after completion so a `tracing` subscriber
            // (e.g. tracing-opentelemetry) picks them up as span attributes.
            status = tracing::field::Empty,
            error = tracing::field::Empty,
        );

        let retry_policy = self.session.inner.retry_policy.clone();

        // --- Inject Accept-Encoding header if configured ---
        let mut headers = self.headers;
        if !headers.contains_key(http::header::ACCEPT_ENCODING) {
            let encoding = self
                .accept_encoding
                .or(self.session.inner.default_accept_encoding);
            if let Some(enc) = encoding {
                if let Ok(v) = http::header::HeaderValue::from_str(&enc.to_header_value()) {
                    headers.insert(http::header::ACCEPT_ENCODING, v);
                }
            }
        }

        let mut streaming_body = self
            .body
            .as_ref()
            .filter(|body| body.is_streaming())
            .cloned();

        // --- Middleware: on_request phase ---
        let mw_req = crate::middleware::MiddlewareRequest {
            method: self.method,
            url: self.url,
            headers,
            body: self.body.as_ref().and_then(|body| body.buffered()).cloned(),
        };

        let client_mws = self.session.inner.client.middlewares();
        let session_mws = &self.session.inner.middlewares;

        let mw_req =
            crate::middleware::apply_upload_middlewares(client_mws, mw_req, &mut streaming_body)?;
        let mw_req =
            crate::middleware::apply_upload_middlewares(session_mws, mw_req, &mut streaming_body)?;

        // Destructure middleware-processed request for retries.
        // Immutable fields are wrapped in Arc to avoid deep cloning on retries.
        let session = self.session;
        let body = mw_req.body.map(RequestBody::from).or(streaming_body);
        let ctx = Arc::new(SharedRequestContext {
            attempt_limits: self.attempt_limits,
            execution,
            method: mw_req.method,
            url: mw_req.url,
            headers: mw_req.headers,
            query_params: self.query_params,
            extra_cookies: self.extra_cookies,
            cookie_overrides: self.cookie_overrides,
            timeout: self.timeout,
            request_timeout: self.request_timeout,
            proxy_override: self.proxy_override,
            version_override: self.version_override,
            protocol_policy_override: self.protocol_policy_override,
            no_decompress: self.no_decompress,
            header_order: self.header_order,
            h3_header_order: self.h3_header_order,
            cookie_order: self.cookie_order,
            header_insertion_order: self.header_insertion_order,
            priority: self.priority,
            h2_priority_weight: self.h2_priority_weight,
            idempotency: self.idempotency,
        });

        let result = async move {
            let mut recovery = super::recovery::ApplicationRecovery::new(owner);
            // --- Core send logic (retry + redirect) ---
            let raw_response = if let Some(policy) = retry_policy {
                let retain_prior = ctx.execution.has_connect_limit();
                let mut prior: Option<Box<Result<Response>>> = None;
                loop {
                    let rb = RequestBuilder::from_shared_context(
                        session.clone(),
                        ctx.clone(),
                        body.clone(),
                        attempt,
                    );
                    recovery.start_attempt();
                    let submissions_before = retain_prior.then(|| ctx.execution.submissions());
                    let result = rb.send_with_redirects(&mut recovery).await;
                    if let Err(error) = &result {
                        if error.is_connect_attempt_denied()
                            && submissions_before == Some(ctx.execution.submissions())
                        {
                            if let Some(prior) = prior.take() {
                                ctx.execution.record_connect_denial(error);
                                break match *prior {
                                    Ok(response) => Ok(response),
                                    Err(prior) => {
                                        Err(result.err().unwrap().with_connect_prior(prior))
                                    }
                                };
                            }
                        }
                    }
                    prior = None;
                    let facts = super::recovery::ReplayFacts::new(
                        &ctx.method,
                        ctx.idempotency,
                        body.as_ref(),
                    );

                    match result {
                        Ok(resp) => {
                            let status = resp.status();
                            if let Some(approved) =
                                recovery.retry_status(policy.as_ref(), facts, status)
                            {
                                attempt = approved.attempt;
                                if retain_prior {
                                    prior = Some(Box::new(Ok(resp)));
                                }
                                tokio::time::sleep(approved.delay).await;
                                continue;
                            }
                            break Ok(resp);
                        }
                        Err(e) => {
                            if let Some(approved) = recovery.retry_error(policy.as_ref(), facts, &e)
                            {
                                attempt = approved.attempt;
                                if retain_prior {
                                    prior = Some(Box::new(Err(e)));
                                }
                                tokio::time::sleep(approved.delay).await;
                                continue;
                            }
                            break Err(e);
                        }
                    }
                }
            } else {
                let rb = RequestBuilder::from_shared_context(session.clone(), ctx, body, attempt);
                rb.send_with_redirects(&mut recovery).await
            };

            // --- Middleware: on_response phase ---
            match raw_response {
                Ok(mut resp) => {
                    let resp_url = resp.url().to_string();
                    let resp_version = resp.version();
                    let redirect_history = resp.take_redirect_history();

                    let mw_resp = crate::middleware::MiddlewareResponse {
                        status: resp.status(),
                        headers: resp.headers().clone(),
                        body: resp.into_bytes(),
                    };

                    let session_mws = &session.inner.middlewares;
                    let client_mws = session.inner.client.middlewares();

                    let mw_resp =
                        crate::middleware::apply_response_middlewares(session_mws, mw_resp)?;
                    let mw_resp =
                        crate::middleware::apply_response_middlewares(client_mws, mw_resp)?;

                    let mut final_resp =
                        Response::from_parts(mw_resp.status, mw_resp.headers, mw_resp.body);
                    final_resp.set_url(resp_url);
                    final_resp.set_http_version(resp_version);
                    final_resp.set_redirect_history(redirect_history);
                    Ok(final_resp)
                }
                Err(e) => Err(e),
            }
        }
        .instrument(span.clone())
        .await;

        // Record result fields on the request span (zero cost without a subscriber).
        match &result {
            Ok(resp) => {
                span.record("status", resp.status().as_u16());
            }
            Err(err) => {
                span.record("error", tracing::field::display(err));
            }
        }
        result
    }

    /// Send the request and return a streaming response.
    ///
    /// **Important:** This is **not** a streaming variant of [`send`](Self::send)
    /// with the same semantics. Compared to [`send`](Self::send), streaming mode
    /// does **not** follow redirects, does **not** apply the session retry
    /// policy, and returns the first response as-is. Inspect `status()`, read
    /// `Location`, and retry or follow manually if you need redirect behavior.
    ///
    /// Client and session request middleware run in the same order as [`send`](Self::send),
    /// followed by the session's HSTS URL upgrade. Response headers update HSTS,
    /// cookies, and Alt-Svc state; full-body response middleware does not run.
    ///
    /// Unlike [`send`](Self::send), the response body is **not** fully
    /// buffered. Instead, the body is read on demand via
    /// [`StreamingResponse::chunk()`].
    ///
    /// The total deadline continues after this method returns. For long-lived
    /// streams, disable `TimeoutConfig::total_timeout` and optionally configure
    /// `read_idle_timeout` to limit each pending body read.
    ///
    /// This is suitable for:
    /// - Large file downloads (avoids OOM)
    /// - Server-Sent Events (SSE)
    /// - Chunked transfer responses
    /// - Long-polling connections
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use lkrequest::Client;
    /// # use lktls::profile::presets;
    /// # async fn example() -> Result<(), lkrequest::error::Error> {
    /// # let client = Client::builder().fingerprint(presets::chrome_131()).build();
    /// # let session = client.session().build();
    /// # fn process(_: bytes::Bytes) {}
    /// let mut resp = session.get("https://example.com/stream")
    ///     .send_streaming()
    ///     .await?;
    ///
    /// while let Some(chunk) = resp.chunk().await? {
    ///     process(chunk);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_streaming(mut self) -> Result<StreamingResponse> {
        let (mut guard, admission) = self.begin_execution();
        let timeout = self.request_timeout;
        let read_idle_timeout = self.session.inner.client.timeouts().read_idle_timeout;
        let result = match admission {
            Err(error) => Err(error),
            Ok(owner) => guard.run(self.send_streaming_impl(owner)).await,
        }
        .and_then(|response| {
            guard.publish()?;
            Ok(response.with_timeouts(timeout, read_idle_timeout))
        });
        if let Err(error) = &result {
            guard.finish_error(error);
        }
        #[cfg(feature = "telemetry")]
        crate::telemetry::counters().record_request(result.is_err());
        result.map_err(Error::into_public_connect_error)
    }

    async fn send_streaming_impl(self, owner: RecoveryOwner) -> Result<StreamingResponse> {
        let execution = self
            .execution
            .ok_or_else(|| Error::Http("missing request execution context".into()))?;
        execution.ensure_active()?;
        let attempt = self
            .attempt
            .ok_or_else(|| Error::Http("missing HTTP attempt authority".into()))?;
        self.session.validate_proxy_config()?;
        if let Some(err) = self.deferred_error {
            return Err(err);
        }

        let req_id = next_request_id();
        let span = tracing::info_span!(
            "http.stream_request",
            req_id = req_id,
            method = %self.method,
            url = %self.url,
            status = tracing::field::Empty,
            error = tracing::field::Empty,
        );

        let mut headers = self.headers;
        if !headers.contains_key(http::header::ACCEPT_ENCODING) {
            let encoding = self
                .accept_encoding
                .or(self.session.inner.default_accept_encoding);
            if let Some(enc) = encoding {
                if let Ok(v) = http::header::HeaderValue::from_str(&enc.to_header_value()) {
                    headers.insert(http::header::ACCEPT_ENCODING, v);
                }
            }
        }

        let mut streaming_body = self
            .body
            .as_ref()
            .filter(|body| body.is_streaming())
            .cloned();
        let mw_req = crate::middleware::MiddlewareRequest {
            method: self.method,
            url: self.url,
            headers,
            body: self.body.as_ref().and_then(|body| body.buffered()).cloned(),
        };
        let mw_req = crate::middleware::apply_upload_middlewares(
            self.session.inner.client.middlewares(),
            mw_req,
            &mut streaming_body,
        )?;
        let mw_req = crate::middleware::apply_upload_middlewares(
            &self.session.inner.middlewares,
            mw_req,
            &mut streaming_body,
        )?;

        // Apply query parameters after middleware, matching the buffered path.
        let url = if self.query_params.is_empty() {
            mw_req.url
        } else {
            let mut parsed = Url::parse(&mw_req.url)
                .map_err(|e| Error::UrlParse(format!("{}: {e}", mw_req.url)))?;
            {
                let mut pairs = parsed.query_pairs_mut();
                for (key, value) in &self.query_params {
                    pairs.append_pair(key, value);
                }
            }
            parsed.to_string()
        };
        let hsts_policy = Arc::clone(&self.session.inner.hsts_policy);
        let url = super::transport::hsts_upgrade(&url, &*hsts_policy).unwrap_or(url);
        let hsts_host = super::transport::hsts_host_to_record(&url);

        let rb = StreamRequestBuilder {
            execution,
            attempt,
            session: self.session,
            method: mw_req.method,
            url,
            headers: mw_req.headers,
            body: mw_req.body.map(RequestBody::from).or(streaming_body),
            extra_cookies: self.extra_cookies,
            cookie_overrides: self.cookie_overrides,
            proxy_override: self.proxy_override,
            version_override: self.version_override,
            protocol_policy_override: self.protocol_policy_override,
            no_decompress: self.no_decompress,
            header_order: self.header_order,
            h3_header_order: self.h3_header_order,
            cookie_order: self.cookie_order,
            header_insertion_order: self.header_insertion_order,
            priority: self.priority,
            h2_priority_weight: self.h2_priority_weight,
            idempotency: self.idempotency,
            #[cfg(feature = "quic-h3")]
            race_send_gates: Vec::new(),
        };

        let result = rb
            .send_streaming_inner(owner)
            .instrument(span.clone())
            .await;

        match &result {
            Ok(resp) => {
                if let Some(sts) = resp
                    .headers()
                    .get(http::header::STRICT_TRANSPORT_SECURITY)
                    .and_then(|value| value.to_str().ok())
                {
                    if let Some(host) = hsts_host {
                        hsts_policy.record_sts(&host, sts);
                    }
                }
                span.record("status", resp.status().as_u16());
            }
            Err(err) => {
                span.record("error", tracing::field::display(err));
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;

    fn test_session() -> Session {
        Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .build()
            .session()
            .build()
    }

    #[cfg(feature = "bench-internals")]
    #[tokio::test]
    async fn benchmark_request_has_independent_recovery_accounting() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(stream.read_u8().await.unwrap());
                assert!(head.len() < 16 * 1024);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        let (outer_execution, _guard) =
            RequestExecution::new(crate::timeout::RequestTimeout::default());
        let run = async {
            let (attempt, _owner) = outer_execution.start_http().unwrap();
            attempt
                .take()
                .unwrap()
                .commit("outer_request")
                .unwrap()
                .submit(|| ());
            let response = Client::builder()
                .build()
                .session()
                .build()
                .get(&url)
                .send_transport_only_for_benchmark()
                .await
                .unwrap();
            assert_eq!(response.status(), http::StatusCode::OK);
            assert_eq!(
                outer_execution.snapshot(),
                (1, 0),
                "a benchmark request must not charge its caller's execution"
            );
        };
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn execution_counts_wire_attempts_across_redirect_and_application_retry() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/initial", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let responses = [
                "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ];
            let mut paths = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(stream.read_u8().await.unwrap());
                    assert!(head.len() < 16 * 1024);
                }
                paths.push(
                    String::from_utf8(head)
                        .unwrap()
                        .lines()
                        .next()
                        .unwrap()
                        .to_owned(),
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
            paths
        });
        let session = Client::builder()
            .build()
            .session()
            .retry_policy(crate::retry::FixedInterval::new(1, Duration::ZERO))
            .build();
        let (execution, _guard) = RequestExecution::new(crate::timeout::RequestTimeout::default());
        let run = async {
            let (attempt, owner) = execution.start_http().unwrap();
            let mut request = session.get(&url);
            request.execution = Some(execution.clone());
            request.attempt = Some(attempt);
            let response = request.send_impl(owner).await.unwrap();
            assert_eq!(response.status(), http::StatusCode::OK);
            assert_eq!(execution.snapshot(), (3, 1));
        };
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .unwrap();
        let paths = server.await.unwrap();
        assert_eq!(
            paths,
            [
                "GET /initial HTTP/1.1",
                "GET /next HTTP/1.1",
                "GET /initial HTTP/1.1"
            ]
        );
    }

    #[tokio::test]
    async fn missing_execution_rejects_both_entries_before_side_effects() {
        use crate::middleware::{Middleware, MiddlewareRequest};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::task::Poll;

        struct CountMiddleware(Arc<AtomicUsize>);

        impl Middleware for CountMiddleware {
            fn on_request(&self, request: MiddlewareRequest) -> Result<MiddlewareRequest> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(request)
            }
        }

        for (streaming, missing_context) in
            [(false, true), (true, true), (false, false), (true, false)]
        {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = format!("http://{}/upload", listener.local_addr().unwrap());
            let middleware_calls = Arc::new(AtomicUsize::new(0));
            let body_polls = Arc::new(AtomicUsize::new(0));
            let session = Client::builder()
                .middleware(CountMiddleware(middleware_calls.clone()))
                .build()
                .session()
                .http1_only()
                .build();
            let polls = body_polls.clone();
            let mut request = session.post(&url).body_stream(
                futures_util::stream::poll_fn(move |_| {
                    polls.fetch_add(1, Ordering::SeqCst);
                    Poll::<Option<std::io::Result<bytes::Bytes>>>::Ready(None)
                }),
                None,
            );
            let body = request.body.clone().unwrap();
            let (execution, _guard) =
                RequestExecution::new(crate::timeout::RequestTimeout::default());
            let (_attempt, owner) = execution.start_http().unwrap();
            if !missing_context {
                request.execution = Some(execution);
            }
            let expected = if missing_context {
                "missing request execution context"
            } else {
                "missing HTTP attempt authority"
            };
            let result = tokio::time::timeout(Duration::from_secs(1), async {
                if streaming {
                    request.send_streaming_impl(owner).await.map(|_| ())
                } else {
                    request.send_impl(owner).await.map(|_| ())
                }
            })
            .await
            .expect("missing execution must fail before I/O");
            assert!(matches!(
                result,
                Err(Error::Http(message)) if message == expected
            ));
            assert_eq!(middleware_calls.load(Ordering::SeqCst), 0);
            assert_eq!(body_polls.load(Ordering::SeqCst), 0);
            assert!(
                body.can_replay(),
                "missing execution must not claim the upload"
            );
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "missing execution must not open a connection"
            );
        }
    }

    // ====================================================================
    // json() / form() — deferred error mechanism
    // ====================================================================

    #[test]
    fn json_sets_body_and_content_type() {
        let session = test_session();
        let rb = session
            .post("https://example.com")
            .json(&serde_json::json!({"a": 1}));
        assert!(rb.deferred_error.is_none());
        assert!(rb.body.is_some());
        assert_eq!(
            rb.headers.get(http::header::CONTENT_TYPE).unwrap(),
            "application/json",
        );
    }

    #[test]
    fn json_with_valid_data_no_deferred_error() {
        let session = test_session();
        let rb = session.post("https://example.com").json(&vec![1, 2, 3]);
        assert!(rb.deferred_error.is_none());
    }

    /// A type whose `Serialize` impl always fails.
    struct FailSerialize;
    impl serde::Serialize for FailSerialize {
        fn serialize<S: serde::Serializer>(&self, _s: S) -> std::result::Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("intentional failure"))
        }
    }

    #[test]
    fn json_serialization_failure_defers_error() {
        let session = test_session();
        let rb = session.post("https://example.com").json(&FailSerialize);
        assert!(rb.deferred_error.is_some());
        let err_msg = format!("{}", rb.deferred_error.unwrap());
        assert!(err_msg.contains("serialize"), "err={err_msg}");
    }

    #[test]
    fn json_deferred_error_surfaces_at_send() {
        let session = test_session();
        let rb = session.post("https://example.com").json(&FailSerialize);

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(rb.send());
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("serialize"),
            "should surface json error: {err_msg}"
        );
    }

    #[test]
    fn form_serialization_failure_defers_error() {
        let session = test_session();
        let rb = session.post("https://example.com").form(&FailSerialize);
        assert!(rb.deferred_error.is_some());
        let err_msg = format!("{}", rb.deferred_error.unwrap());
        assert!(err_msg.contains("serialize"), "err={err_msg}");
    }

    #[test]
    fn form_sets_body_and_content_type() {
        let session = test_session();
        let rb = session
            .post("https://example.com")
            .form(&[("user", "alice"), ("pass", "secret")]);
        assert!(rb.deferred_error.is_none());
        assert!(rb.body.is_some());
        assert_eq!(
            rb.headers.get(http::header::CONTENT_TYPE).unwrap(),
            "application/x-www-form-urlencoded",
        );
        let body_str = std::str::from_utf8(rb.body.as_ref().unwrap().buffered().unwrap()).unwrap();
        assert!(body_str.contains("user=alice"));
        assert!(body_str.contains("pass=secret"));
    }

    #[test]
    fn json_chains_with_other_builders() {
        let session = test_session();
        let rb = session
            .post("https://example.com")
            .header("X-Custom", "value")
            .json(&serde_json::json!({"key": "val"}))
            .timeout(std::time::Duration::from_secs(5));
        assert!(rb.deferred_error.is_none());
        assert!(rb.headers.contains_key("x-custom"));
        assert_eq!(rb.timeout, Some(std::time::Duration::from_secs(5)));
    }

    #[test]
    fn form_chains_with_other_builders() {
        let session = test_session();
        let rb = session
            .post("https://example.com")
            .header("X-Custom", "value")
            .form(&[("k", "v")])
            .timeout(std::time::Duration::from_secs(5));
        assert!(rb.deferred_error.is_none());
        assert!(rb.headers.contains_key("x-custom"));
        assert_eq!(rb.timeout, Some(std::time::Duration::from_secs(5)));
    }

    // ====================================================================
    // preferred_http_version() / legacy version()
    // ====================================================================

    #[test]
    fn preferred_http_version_setter_records_preference() {
        let session = test_session();
        let rb = session
            .get("https://example.com")
            .preferred_http_version(PreferredHttpVersion::Http2Only);
        assert_eq!(rb.version_override, Some(PreferredHttpVersion::Http2Only));
    }

    #[test]
    #[allow(deprecated)]
    fn version_http10_maps_to_http1only() {
        let session = test_session();
        let rb = session
            .get("https://example.com")
            .version(HttpVersion::Http10);
        assert_eq!(rb.version_override, Some(PreferredHttpVersion::Http1Only));
    }

    #[test]
    #[allow(deprecated)]
    fn version_h2_maps_to_http2only() {
        let session = test_session();
        let rb = session.get("https://example.com").version(HttpVersion::H2);
        assert_eq!(rb.version_override, Some(PreferredHttpVersion::Http2Only));
    }

    #[test]
    #[allow(deprecated)]
    fn version_unknown_maps_to_auto() {
        let session = test_session();
        let rb = session
            .get("https://example.com")
            .version(HttpVersion::Unknown);
        assert_eq!(rb.version_override, Some(PreferredHttpVersion::Auto));
    }

    #[test]
    fn request_http_intent_override_updates_effective_policy() {
        let client = Client::builder()
            .protocol_policy(crate::protocol::ProtocolPolicy::crawler_throughput())
            .build();
        let session = client
            .session()
            .protocol_policy(crate::protocol::ProtocolPolicy::chrome_conservative())
            .build();
        let rb = session
            .get("https://example.com")
            .http_intent(crate::protocol::HttpIntent::H3Only);

        assert_eq!(
            rb.protocol_policy_override
                .as_ref()
                .expect("request policy override")
                .intent,
            crate::protocol::HttpIntent::H3Only
        );
        assert_eq!(
            rb.protocol_policy_override
                .as_ref()
                .expect("request policy override")
                .fallback,
            crate::protocol::FallbackPolicy::NoFallback
        );
    }

    // ====================================================================
    // headers / headers_with_order / headers_ordered
    // ====================================================================

    #[test]
    fn headers_with_order_places_template_before_rest() {
        let session = test_session();
        let mut map = http::HeaderMap::new();
        map.insert("accept", "application/json".parse().unwrap());
        map.insert("user-agent", "t".parse().unwrap());
        map.insert("cookie", "a=1".parse().unwrap());
        let rb = session
            .get("https://example.com")
            .headers_with_order(map, &["cookie", "accept", "user-agent"]);

        let names: Vec<&str> = rb
            .header_insertion_order
            .iter()
            .map(|n| n.as_str())
            .collect();
        assert_eq!(names, vec!["cookie", "accept", "user-agent"]);
    }

    #[test]
    fn headers_with_order_after_header_keeps_prefix() {
        let session = test_session();
        let mut map = http::HeaderMap::new();
        map.insert("accept", "application/json".parse().unwrap());
        map.insert("cookie", "a=1".parse().unwrap());
        let rb = session
            .get("https://example.com")
            .header("x-first", "1")
            .headers_with_order(map, &["cookie", "accept"]);

        let names: Vec<&str> = rb
            .header_insertion_order
            .iter()
            .map(|n| n.as_str())
            .collect();
        assert_eq!(names, vec!["x-first", "cookie", "accept"]);
    }

    #[test]
    fn headers_ordered_matches_pair_order() {
        let session = test_session();
        let rb = session.get("https://example.com").headers_ordered(vec![
            ("accept", "text/html"),
            ("user-agent", "u"),
            ("accept", "application/json"),
        ]);

        let names: Vec<&str> = rb
            .header_insertion_order
            .iter()
            .map(|n| n.as_str())
            .collect();
        assert_eq!(names, vec!["accept", "user-agent"]);
        assert_eq!(
            rb.headers.get("accept").unwrap().to_str().unwrap(),
            "application/json"
        );
    }
}
