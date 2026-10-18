use std::time::Duration;

use crate::body::WireBody;
use http::HeaderMap;
use tracing::Instrument;
use url::Url;

use crate::client::Client;
use crate::connection_pool::{AcquiredConnection, ConnectionKey, ConnectionPermit, Scheme};
use crate::error::{ConnectionPhase, Error, Result};
use crate::proxy::ProxyConfig;
use crate::response::{HttpVersion, RedirectRecord, Response};

use super::pipeline;
use super::request::RequestBuilder;
use super::PreferredHttpVersion;

#[derive(Clone)]
struct RequestRecovery {
    retry_pooled: bool,
    #[cfg(feature = "quic-h3")]
    race_send_gates: Vec<pipeline::RaceSendGate>,
}

impl RequestRecovery {
    fn next_attempt(&self) -> Self {
        let mut next = self.clone();
        next.retry_pooled = false;
        next
    }
}

#[cfg(feature = "quic-h3")]
struct QuicHandshakeGuard<'a> {
    session: &'a super::Session,
    key: &'a ConnectionKey,
    _completion: tokio::sync::watch::Sender<()>,
}

#[cfg(feature = "quic-h3")]
impl<'a> QuicHandshakeGuard<'a> {
    fn try_acquire(
        session: &'a super::Session,
        key: &'a ConnectionKey,
    ) -> std::result::Result<Self, tokio::sync::watch::Receiver<()>> {
        let mut in_flight = session.inner.quic_in_flight.lock();
        if let Some(existing) = in_flight.get(key) {
            return Err(existing.clone());
        }
        let (completion, receiver) = tokio::sync::watch::channel(());
        in_flight.insert(key.clone(), receiver);
        Ok(Self {
            session,
            key,
            _completion: completion,
        })
    }
}

#[cfg(feature = "quic-h3")]
impl Drop for QuicHandshakeGuard<'_> {
    fn drop(&mut self) {
        // Only the elected leader owns a guard. Remove its entry before the
        // sender is dropped, so awakened waiters can elect a replacement.
        self.session.inner.quic_in_flight.lock().remove(self.key);
    }
}

/// Shared context for a single HTTP request, passed through connection
/// establishment and protocol-specific send paths.
#[derive(Clone)]
pub(crate) struct RequestContext<'a> {
    pub method: &'a http::Method,
    pub host: &'a str,
    pub port: u16,
    pub scheme: Scheme,
    pub path: &'a str,
    pub conn_key: &'a ConnectionKey,
    pub extra_headers: &'a HeaderMap,
    pub parsed_url: &'a Url,
    /// Per-request replay and QUIC 0-RTT authorization. See
    /// [`super::Idempotency`] and [`super::can_send_early_data`].
    pub idempotency: super::Idempotency,
    /// Every enclosing race must select this job before it sends a request.
    #[cfg(feature = "quic-h3")]
    pub race_send_gates: Vec<pipeline::RaceSendGate>,
    /// Shares the transparent recovery budget with failed pooled requests.
    #[cfg(feature = "quic-h3")]
    pub retry_early_data: bool,
}

#[cfg(feature = "quic-h3")]
impl RequestContext<'_> {
    async fn acquire_send_gates(&self) {
        for gate in &self.race_send_gates {
            gate.acquired().await;
        }
    }

    fn recovery(&self, retry_pooled: bool) -> RequestRecovery {
        RequestRecovery {
            retry_pooled,
            race_send_gates: self.race_send_gates.clone(),
        }
    }
}

impl RequestBuilder {
    /// Inner send logic that handles redirect following.
    ///
    /// Heap-allocated future to avoid stack overflow (see `establish_and_send`).
    pub(crate) fn send_with_redirects<'a>(
        mut self,
        replay_safe: &'a mut bool,
        #[cfg_attr(not(feature = "quic-h3"), allow(unused_variables))]
        allow_policy_retry: &'a mut bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response>> + Send + 'a>> {
        Box::pin(async move {
            let max_redirects = self
                .session
                .inner
                .redirect_policy
                .max_redirects()
                .unwrap_or(0);
            let follow_redirects = !matches!(
                self.session.inner.redirect_policy,
                super::RedirectPolicy::None
            );

            // One absolute deadline for the *entire* request, shared across
            // every redirect hop (connect + all hops + body read). This gives a
            // true total timeout instead of resetting it per hop, which would
            // make the real worst case (N+1)x the configured value.
            let deadline = tokio::time::Instant::now() + self.effective_total_timeout();

            // Apply query parameters to the URL
            let mut current_url = if self.query_params.is_empty() {
                self.url.clone()
            } else {
                let mut parsed = Url::parse(&self.url)
                    .map_err(|e| Error::UrlParse(format!("{}: {e}", self.url)))?;
                {
                    let mut pairs = parsed.query_pairs_mut();
                    for (key, value) in &self.query_params {
                        pairs.append_pair(key, value);
                    }
                }
                parsed.to_string()
            };

            let mut current_method = self.method.clone();
            let mut current_headers = self.headers.clone();
            let mut current_body = self.body.clone();
            let mut redirects_remaining = max_redirects;
            let mut redirect_history: Vec<RedirectRecord> = Vec::new();

            loop {
                // HSTS pre-upgrade (RFC 6797 §8.3): rewrite http->https before
                // connecting, for any host the policy treats as HTTPS-only.
                // Applies uniformly to the initial URL and every redirect target.
                if let Some(upgraded) = hsts_upgrade(&current_url, &*self.session.inner.hsts_policy)
                {
                    current_url = upgraded;
                }

                // Opt-in https_only: refuse a non-HTTPS request once HSTS has
                // had its chance to upgrade. Default off keeps behavior
                // Chrome-faithful (downgrades are followed).
                if self.session.inner.https_only {
                    if let Ok(parsed) = Url::parse(&current_url) {
                        if parsed.scheme() != "https" {
                            return Err(Error::Http(format!(
                                "https_only: refusing non-HTTPS request to {current_url}"
                            )));
                        }
                    }
                }

                #[cfg(feature = "quic-h3")]
                let saved_policy = self.protocol_policy_override.clone();
                #[cfg(feature = "quic-h3")]
                let saved_version = self.version_override;
                #[cfg(feature = "quic-h3")]
                let mut h3_retries = 0;
                #[cfg(feature = "quic-h3")]
                let result = loop {
                    let result = self
                        .send_single_request(
                            &current_url,
                            &current_method,
                            &current_headers,
                            current_body.clone(),
                            deadline,
                        )
                        .await;
                    #[cfg(feature = "quic-h3")]
                    if let Err(ref error) = result {
                        if crate::retry::chrome_h3_owns_error(self.session.h3_retry_mode(), error) {
                            *allow_policy_retry = false;
                            let policy = self.effective_protocol_policy();
                            let route = pipeline::chrome_h3_retry_route(
                                &policy,
                                self.effective_http_version(&policy),
                                self.effective_proxy(),
                            );
                            if crate::retry::chrome_h3_can_retry(
                                error,
                                self.idempotency,
                                current_body.as_ref(),
                                h3_retries,
                            ) {
                                if let Some(route) = route {
                                    h3_retries += 1;
                                    if route == pipeline::ProtocolDecision::Tcp {
                                        self.protocol_policy_override =
                                            Some(pipeline::chrome_h3_retry_tcp_policy());
                                        self.version_override = Some(PreferredHttpVersion::Auto);
                                    }
                                    tracing::debug!(
                                        retry = h3_retries,
                                        protocol = route.as_str(),
                                        "h3.chrome_protocol_error_retry",
                                    );
                                    continue;
                                }
                            }
                        }
                    }
                    break result;
                };
                #[cfg(not(feature = "quic-h3"))]
                let result = self
                    .send_single_request(
                        &current_url,
                        &current_method,
                        &current_headers,
                        current_body.clone(),
                        deadline,
                    )
                    .await;
                #[cfg(feature = "quic-h3")]
                {
                    self.protocol_policy_override = saved_policy;
                    self.version_override = saved_version;
                }
                let resp = result?;

                // Later-hop failures cannot prove this completed request was unprocessed.
                *replay_safe &= super::can_send_early_data(&current_method, self.idempotency);

                // Learn dynamic HSTS from a Strict-Transport-Security response,
                // if the policy is stateful (no-op for NoHsts/StaticHsts).
                // `hsts_host_to_record` applies the RFC 6797 §8.1 gates.
                if let Some(sts) = resp
                    .headers()
                    .get(http::header::STRICT_TRANSPORT_SECURITY)
                    .and_then(|v| v.to_str().ok())
                {
                    if let Some(host) = hsts_host_to_record(&current_url) {
                        self.session.inner.hsts_policy.record_sts(&host, sts);
                    }
                }

                // Check for redirect status codes. Only the *followable* 3xx
                // codes count: 300/304/305/306 carry no `Location` and are
                // returned to the caller as-is (RFC 9110 §15.4) — see
                // `pipeline::is_followable_redirect`.
                let status = resp.status();
                let is_redirect = pipeline::is_followable_redirect(status);

                if !is_redirect || !follow_redirects || redirects_remaining == 0 {
                    if is_redirect && follow_redirects && redirects_remaining == 0 {
                        tracing::warn!(
                            status = status.as_u16(),
                            limit = max_redirects,
                            "http.too_many_redirects",
                        );
                        return Err(Error::TooManyRedirects(max_redirects));
                    }
                    tracing::info!(
                        status = status.as_u16(),
                        body_bytes = resp.bytes().len(),
                        "http.response",
                    );
                    let mut resp = resp;
                    resp.set_url(current_url);
                    resp.set_redirect_history(redirect_history);
                    return Ok(resp);
                }

                // Extract the Location header
                let location = resp.headers().get(http::header::LOCATION).ok_or_else(|| {
                    Error::Http("redirect response missing Location header".into())
                })?;
                let location = std::str::from_utf8(location.as_bytes()).map_err(|e| {
                    Error::UrlParse(format!("redirect Location is not valid UTF-8: {e}"))
                })?;

                // Resolve relative URLs against the current URL
                let base_url = Url::parse(&current_url)
                    .map_err(|e| Error::UrlParse(format!("{}: {e}", current_url)))?;
                let redirect_url = base_url.join(location).map_err(|e| {
                    Error::UrlParse(format!("invalid redirect URL '{location}': {e}"))
                })?;

                // Origin = scheme + host + port (Fetch "same origin"). Note the
                // redirect target's https_only / HSTS handling happens at the
                // top of the next loop iteration, after it becomes current_url.
                let is_cross_origin = redirect_is_cross_origin(&base_url, &redirect_url);

                tracing::debug!(
                    status = status.as_u16(),
                    from = %current_url,
                    to = %redirect_url,
                    remaining = redirects_remaining,
                    cross_origin = is_cross_origin,
                    "http.redirect",
                );

                let redirect_to_str = redirect_url.to_string();

                // Record this hop in the redirect history
                redirect_history.push(RedirectRecord::new(
                    current_url.clone(),
                    status,
                    resp.headers().clone(),
                    redirect_to_str.clone(),
                ));

                // Update method and body based on status code.
                let redirect_defaults = self
                    .redirect_defaults
                    .get_or_insert_with(|| self.session.inner.client.default_headers().clone());
                match status.as_u16() {
                    301..=303 => {
                        // Only *some* method/status combinations are rewritten
                        // to GET — see `redirect_rewrites_method_to_get`. When
                        // the method is preserved, so are the body and the
                        // request-body headers that describe it.
                        if redirect_rewrites_method_to_get(status.as_u16(), &current_method) {
                            current_method = http::Method::GET;
                            current_body = None;
                            // Fetch "request-body-header name" set.
                            current_headers.remove(http::header::CONTENT_ENCODING);
                            current_headers.remove(http::header::CONTENT_LANGUAGE);
                            current_headers.remove(http::header::CONTENT_LOCATION);
                            current_headers.remove(http::header::CONTENT_TYPE);
                            // Not in Fetch's set (browsers compute it), but a
                            // caller-supplied Content-Length would now describe
                            // a body that no longer exists.
                            current_headers.remove(http::header::CONTENT_LENGTH);
                            for name in [
                                http::header::CONTENT_ENCODING,
                                http::header::CONTENT_LANGUAGE,
                                http::header::CONTENT_LOCATION,
                                http::header::CONTENT_TYPE,
                                http::header::CONTENT_LENGTH,
                            ] {
                                redirect_defaults.remove(name);
                            }
                        }
                    }
                    307 | 308 => {
                        // 307/308: Preserve method and body
                    }
                    _ => {
                        // Defensive: `is_followable_redirect` already routed
                        // every non-followable 3xx (300/304/305/306) to the
                        // early return above, before `Location` was required.
                        let mut resp = resp;
                        resp.set_redirect_history(redirect_history);
                        return Ok(resp);
                    }
                }

                if current_body.as_ref().is_some_and(|body| !body.can_replay()) {
                    return Err(Error::Http(
                        "cannot replay consumed streaming body on redirect".into(),
                    ));
                }

                // Strip sensitive headers on cross-origin redirect.
                //
                // Per browser behavior (Fetch spec):
                // - Authorization: never forwarded cross-origin
                // - Cookie: handled below — always removed so merge_headers_common
                //   rebuilds from the latest jar (supports cookie_order + H2 multi-cookie)
                // - Host: rebuilt by merge_headers_common for the new target
                if is_cross_origin {
                    current_headers.remove(http::header::AUTHORIZATION);
                    current_headers.remove(http::header::HOST);
                    redirect_defaults.remove(http::header::AUTHORIZATION);
                    redirect_defaults.remove(http::header::HOST);
                    redirect_defaults.remove(http::header::COOKIE);
                    // Prevent request-level cookies from leaking to third-party domains
                    self.extra_cookies.clear();
                    self.cookie_overrides.clear();
                }

                // Chrome (and reqwest) drop the Referer when downgrading the
                // scheme from https to http, so the secure URL isn't leaked over
                // cleartext. Independent of cross-origin (same-host downgrade
                // still strips it).
                if base_url.scheme() == "https" && redirect_url.scheme() == "http" {
                    current_headers.remove(http::header::REFERER);
                    redirect_defaults.remove(http::header::REFERER);
                }

                // Always remove Cookie so merge_headers_common can rebuild from
                // the latest jar, explicit request pairs, and `.cookie()` data.
                // This ensures Set-Cookie responses from intermediate hops are
                // reflected, cookie_order is applied, and the correct H1/H2
                // format is used.
                current_headers.remove(http::header::COOKIE);

                current_url = redirect_to_str;
                redirects_remaining -= 1;
            }
        })
    }

    /// Send a single HTTP request without redirect following, bounded by an
    /// absolute `deadline`.
    ///
    /// The deadline is computed once and shared across the whole redirect chain
    /// by [`Self::send_with_redirects`], so the total timeout covers connect +
    /// every hop + body read — not each hop independently. This matches the
    /// "total timeout" semantics of reqwest, Go's `http.Client.Timeout`, and
    /// curl's `--max-time`.
    pub(crate) async fn send_single_request(
        &self,
        url: &str,
        method: &http::Method,
        extra_headers: &HeaderMap,
        body: Option<crate::body::RequestBody>,
        deadline: tokio::time::Instant,
    ) -> Result<Response> {
        tokio::time::timeout_at(
            deadline,
            self.send_single_request_inner(url, method, extra_headers, body),
        )
        .await
        .map_err(|_| {
            let total_timeout = self.effective_total_timeout();
            Error::timeout(
                format!("request timed out (total deadline of {total_timeout:?} exceeded)"),
                None,
                Some(total_timeout),
            )
        })?
    }

    /// Inner implementation of a single request (no timeout wrapper).
    ///
    /// 1. Parse URL
    /// 2. Build connection key
    /// 3. Try to acquire a pooled connection (H2 or H1.1)
    /// 4. If no pooled connection, establish TLS and select protocol via ALPN
    /// 5. Send request via the appropriate protocol
    /// 6. Handle cookies
    /// 7. Read response body
    ///
    /// Heap-allocated future to avoid stack overflow (see `establish_and_send`).
    pub(crate) fn send_single_request_inner<'a>(
        &'a self,
        url: &'a str,
        method: &'a http::Method,
        extra_headers: &'a HeaderMap,
        body: Option<crate::body::RequestBody>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response>> + Send + 'a>> {
        self.send_single_request_with_recovery(
            url,
            method,
            extra_headers,
            body,
            RequestRecovery {
                retry_pooled: true,
                #[cfg(feature = "quic-h3")]
                race_send_gates: Vec::new(),
            },
        )
    }

    fn send_single_request_with_recovery<'a>(
        &'a self,
        url: &'a str,
        method: &'a http::Method,
        extra_headers: &'a HeaderMap,
        body: Option<crate::body::RequestBody>,
        recovery: RequestRecovery,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response>> + Send + 'a>> {
        Box::pin(async move {
            let retry_pooled = recovery.retry_pooled;
            let effective_proxy = self.effective_proxy();
            let effective_policy = self.effective_protocol_policy();
            effective_policy.validate()?;
            let http_version_pref = self.effective_http_version(&effective_policy);
            let target = pipeline::parse_request_target(url, effective_proxy)?;

            let (pooled, discovery) = pipeline::acquire_pooled(
                &self.session,
                &target.conn_key,
                http_version_pref,
                &effective_policy,
                effective_proxy,
            )
            .await;

            let ctx = RequestContext {
                method,
                host: &target.host,
                port: target.port,
                scheme: target.scheme,
                path: &target.path,
                conn_key: &target.conn_key,
                extra_headers,
                parsed_url: &target.parsed_url,
                idempotency: self.idempotency,
                #[cfg(feature = "quic-h3")]
                race_send_gates: recovery.race_send_gates.clone(),
                #[cfg(feature = "quic-h3")]
                retry_early_data: retry_pooled,
            };

            match pooled {
                #[cfg(feature = "quic-h3")]
                Some(AcquiredConnection::H3 {
                    sender: mut cached_sender,
                    token,
                    cleanup,
                }) => {
                    tracing::debug!(host = %target.host, port = target.port, protocol = "h3", pooled = true, "connection.acquired");
                    let result = self
                        .send_h3_request(&mut cached_sender, &ctx, body.clone())
                        .await;

                    if let Err(ref error) = result {
                        pipeline::finish_closed_h3_attempt(
                            &self.session,
                            &target.conn_key,
                            &token,
                            &cleanup,
                            error,
                        )
                        .await;
                    }

                    match result {
                        Err(ref e)
                            if retry_pooled
                                && !crate::retry::chrome_h3_owns_error(
                                    self.session.h3_retry_mode(),
                                    e,
                                )
                                && e.is_connection_closed()
                                && crate::retry::retry_is_replay_safe(
                                    method,
                                    self.idempotency,
                                    e,
                                )
                                && self
                                    .session
                                    .inner
                                    .client
                                    .fallback()
                                    .retry_on_connection_close
                                && body
                                    .as_ref()
                                    .is_none_or(crate::body::RequestBody::can_replay) =>
                        {
                            tracing::debug!(
                                host = %target.host,
                                error = %e,
                                "connection.pooled_h3_closed_retrying",
                            );
                            {
                                let mut pool = self.session.inner.pool.lock();
                                pool.remove_acquired(&target.conn_key, &token);
                            }
                            self.send_single_request_with_recovery(
                                url,
                                method,
                                extra_headers,
                                body,
                                recovery.next_attempt(),
                            )
                            .await
                        }
                        other => other,
                    }
                }
                Some(AcquiredConnection::H2 {
                    sender: cached_sender,
                    token,
                }) => match cached_sender.ready().await {
                    Ok(sender) => {
                        tracing::debug!(host = %target.host, port = target.port, protocol = "h2", pooled = true, "connection.acquired");
                        let result = self.send_h2_request(sender, &ctx, body.clone()).await;

                        match result {
                            Err(ref e)
                                if retry_pooled
                                    && e.is_connection_closed()
                                    && crate::retry::retry_is_replay_safe(
                                        method,
                                        self.idempotency,
                                        e,
                                    )
                                    && self
                                        .session
                                        .inner
                                        .client
                                        .fallback()
                                        .retry_on_connection_close
                                    && body
                                        .as_ref()
                                        .is_none_or(crate::body::RequestBody::can_replay) =>
                            {
                                tracing::debug!(
                                    host = %target.host,
                                    error = %e,
                                    "connection.pooled_h2_closed_retrying",
                                );
                                {
                                    let mut pool = self.session.inner.pool.lock();
                                    pool.remove_acquired(&target.conn_key, &token);
                                }
                                self.send_single_request_with_recovery(
                                    url,
                                    method,
                                    extra_headers,
                                    body,
                                    recovery.next_attempt(),
                                )
                                .await
                            }
                            other => other,
                        }
                    }
                    Err(e) => {
                        tracing::debug!(host = %target.host, error = %e, "connection.stale_evicted");
                        {
                            let mut pool = self.session.inner.pool.lock();
                            pool.remove_acquired(&target.conn_key, &token);
                        }
                        if retry_pooled {
                            self.send_single_request_with_recovery(
                                url,
                                method,
                                extra_headers,
                                body,
                                recovery.next_attempt(),
                            )
                            .await
                        } else {
                            self.establish_and_send(&ctx, body, None).await
                        }
                    }
                },
                Some(AcquiredConnection::H1 {
                    mut sender,
                    conn_task,
                    permit,
                }) => match sender.ready().await {
                    Ok(()) => {
                        tracing::debug!(host = %target.host, port = target.port, protocol = "h1.1", pooled = true, "connection.acquired");
                        let result = self
                            .send_h1_request(sender, conn_task, permit, &ctx, body.clone())
                            .await;

                        match result {
                            Err(ref e)
                                if retry_pooled
                                    && e.is_connection_closed()
                                    && crate::retry::retry_is_replay_safe(
                                        method,
                                        self.idempotency,
                                        e,
                                    )
                                    && self
                                        .session
                                        .inner
                                        .client
                                        .fallback()
                                        .retry_on_connection_close
                                    && body
                                        .as_ref()
                                        .is_none_or(crate::body::RequestBody::can_replay) =>
                            {
                                tracing::debug!(
                                    host = %target.host,
                                    error = %e,
                                    "connection.pooled_h1_closed_retrying",
                                );
                                self.send_single_request_with_recovery(
                                    url,
                                    method,
                                    extra_headers,
                                    body,
                                    recovery.next_attempt(),
                                )
                                .await
                            }
                            other => other,
                        }
                    }
                    Err(e) => {
                        tracing::debug!(host = %target.host, error = %e, "connection.h1_stale_evicted");
                        conn_task.abort();
                        drop(permit);
                        if retry_pooled {
                            self.send_single_request_with_recovery(
                                url,
                                method,
                                extra_headers,
                                body,
                                recovery.next_attempt(),
                            )
                            .await
                        } else {
                            self.establish_and_send(&ctx, body, None).await
                        }
                    }
                },
                None => {
                    tracing::debug!(host = %target.host, port = target.port, pooled = false, "connection.new");
                    self.establish_and_send(&ctx, body, discovery).await
                }
            }
        })
    }

    // -----------------------------------------------------------------------
    // Connection establishment
    // -----------------------------------------------------------------------

    /// Establish a new connection, detect ALPN, and send the request.
    ///
    /// This is the fallback path when no pooled connection is available.
    ///
    /// Returns a `Pin<Box<..>>` future so that the (very large) async state
    /// machine lives on the heap instead of being inlined into the caller's
    /// future.  This prevents stack overflow in debug builds on platforms
    /// with small default stacks (e.g. Windows 1 MB main thread).
    pub(crate) fn establish_and_send<'a>(
        &'a self,
        ctx: &'a RequestContext<'a>,
        body: Option<crate::body::RequestBody>,
        discovery: Option<pipeline::QuicDiscovery>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response>> + Send + 'a>> {
        let host = ctx.host;
        let port = ctx.port;
        let scheme = ctx.scheme;

        let effective_proxy = self.effective_proxy().cloned();
        let via_proxy = effective_proxy.is_some();
        let span = tracing::debug_span!(
            "http.connect",
            host = %host,
            port = port,
            via_proxy = via_proxy,
            phase = tracing::field::Empty,
            duration_ms = tracing::field::Empty,
        );

        Box::pin(
            async move {
                if body.as_ref().is_some_and(|body| !body.can_replay()) {
                    return Err(Error::Http(
                        "cannot replay consumed streaming request body".into(),
                    ));
                }
                let connect_start = std::time::Instant::now();

                let effective_policy = self.effective_protocol_policy();
                effective_policy.validate()?;
                let http_version_pref = self.effective_http_version(&effective_policy);
                if http_version_pref == PreferredHttpVersion::Http3Only
                    && self.session.inner.client.quic_profile().is_none()
                {
                    return Err(Error::InvalidConfig(
                        "HTTP/3 requested but client has no QUIC/H3 profile".into(),
                    ));
                }
                pipeline::log_protocol_policy(
                    &ctx.conn_key.route,
                    host,
                    port,
                    &effective_policy,
                    http_version_pref,
                );
                let quic_discovery = match discovery {
                    Some(discovery) => discovery,
                    None => {
                        pipeline::discover_quic_support(
                            &self.session,
                            scheme,
                            host,
                            port,
                            effective_proxy.as_ref(),
                            &effective_policy,
                            http_version_pref,
                        )
                        .await
                    }
                };
                pipeline::log_quic_discovery(&quic_discovery);
                let decision = pipeline::decide_protocol(
                    http_version_pref,
                    &effective_policy,
                    &quic_discovery,
                );
                pipeline::log_protocol_decision(&quic_discovery, &effective_policy, decision);
                match decision {
                    pipeline::ProtocolDecision::Tcp => {
                        let result = self
                            .establish_and_send_tcp(
                                ctx,
                                body,
                                effective_proxy.clone(),
                                &effective_policy,
                                http_version_pref,
                                connect_start,
                            )
                            .await;
                        let schedule_probe = result.is_ok()
                            && pipeline::should_background_probe(
                                &effective_policy,
                                &quic_discovery,
                            );
                        pipeline::log_background_probe_decision(
                            &ctx.conn_key.route,
                            ctx.host,
                            ctx.port,
                            &effective_policy,
                            &quic_discovery,
                            schedule_probe,
                        );
                        if schedule_probe {
                            self.session.spawn_background_quic_probe(
                                ctx.host.to_string(),
                                ctx.port,
                                ctx.conn_key.clone(),
                                quic_discovery.clone(),
                                effective_proxy.clone(),
                            );
                        }
                        result
                    }
                    #[cfg(feature = "quic-h3")]
                    pipeline::ProtocolDecision::Race => {
                        self.establish_and_send_race(
                            ctx,
                            body,
                            &quic_discovery,
                            effective_proxy.as_ref(),
                            effective_proxy.clone(),
                            &effective_policy,
                            http_version_pref,
                            connect_start,
                        )
                        .await
                    }
                    #[cfg(not(feature = "quic-h3"))]
                    pipeline::ProtocolDecision::Race => {
                        self.establish_and_send_tcp(
                            ctx,
                            body,
                            effective_proxy,
                            &effective_policy,
                            http_version_pref,
                            connect_start,
                        )
                        .await
                    }
                    #[cfg(feature = "quic-h3")]
                    pipeline::ProtocolDecision::Quic => {
                        self.establish_and_send_quic(
                            ctx,
                            body,
                            &quic_discovery,
                            effective_proxy.as_ref(),
                            effective_proxy.clone(),
                            &effective_policy,
                            http_version_pref,
                            connect_start,
                        )
                        .await
                    }
                    #[cfg(not(feature = "quic-h3"))]
                    pipeline::ProtocolDecision::Quic => Err(Error::InvalidConfig(
                        "QUIC/H3 support is not compiled in; enable the `quic-h3` feature".into(),
                    )),
                }
            }
            .instrument(span),
        )
    }

    #[cfg(feature = "quic-h3")]
    #[allow(clippy::too_many_arguments)]
    fn establish_and_send_race<'a>(
        &'a self,
        ctx: &'a RequestContext<'a>,
        body: Option<crate::body::RequestBody>,
        discovery: &'a pipeline::QuicDiscovery,
        proxy: Option<&'a ProxyConfig>,
        effective_proxy_owned: Option<ProxyConfig>,
        protocol_policy: &'a crate::protocol::ProtocolPolicy,
        http_version_pref: PreferredHttpVersion,
        connect_start: std::time::Instant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response>> + Send + 'a>> {
        Box::pin(async move {
            if body.as_ref().is_some_and(|body| !body.can_replay()) {
                return Err(Error::Http(
                    "cannot replay consumed streaming request body".into(),
                ));
            }
            let config = pipeline::protocol_policy_chrome_like_config(
                protocol_policy,
                self.session.chrome_like_protocol_config(),
            );
            let (quic_gate, tcp_gate, selected) = pipeline::RaceSendGate::pair();
            let mut quic_ctx = ctx.clone();
            quic_ctx.race_send_gates.push(quic_gate);
            let mut tcp_ctx = ctx.clone();
            tcp_ctx.race_send_gates.push(tcp_gate);
            let quic_future = self.establish_and_send_quic(
                &quic_ctx,
                body.clone(),
                discovery,
                proxy,
                effective_proxy_owned.clone(),
                protocol_policy,
                http_version_pref,
                connect_start,
            );
            pipeline::run_protocol_race(
                config,
                selected,
                quic_future,
                || self.establish_and_send_tcp(
                    &tcp_ctx,
                    body.clone(),
                    effective_proxy_owned.clone(),
                    protocol_policy,
                    http_version_pref,
                    connect_start,
                ),
                |event| match event {
                    pipeline::RaceEvent::Won(pipeline::ProtocolDecision::Quic)
                        if config.keep_tcp_probe_after_quic_win =>
                    {
                        self.session.spawn_background_tcp_probe(
                            ctx.host.to_string(), ctx.port, ctx.scheme, ctx.conn_key.clone(),
                            effective_proxy_owned.clone(), http_version_pref,
                        );
                    }
                    pipeline::RaceEvent::Won(pipeline::ProtocolDecision::Tcp)
                        if config.keep_quic_probe_after_tcp_win =>
                    {
                        self.session.spawn_background_quic_probe(
                            ctx.host.to_string(), ctx.port, ctx.conn_key.clone(),
                            discovery.clone(), effective_proxy_owned.clone(),
                        );
                    }
                    pipeline::RaceEvent::Failed { protocol, stage, error } => match (protocol, stage) {
                        (pipeline::ProtocolDecision::Quic, pipeline::RaceFailureStage::BeforeTcpRelease) => {
                            tracing::warn!(host = %ctx.host, error = %error, fallback = "quic_to_tcp",
                                "http.protocol_race_quic_failed_before_tcp_release");
                        }
                        (pipeline::ProtocolDecision::Quic, pipeline::RaceFailureStage::WaitingForPeer) => {
                            tracing::warn!(host = %ctx.host, error = %error, fallback = "quic_to_tcp",
                                "http.protocol_race_quic_failed_waiting_for_tcp");
                        }
                        (pipeline::ProtocolDecision::Tcp, pipeline::RaceFailureStage::WaitingForPeer) => {
                            tracing::warn!(host = %ctx.host, error = %error, fallback = "tcp_to_quic",
                                "http.protocol_race_tcp_failed_waiting_for_quic");
                        }
                        _ => {}
                    },
                    _ => {}
                },
            ).await
        })
    }

    #[cfg(feature = "quic-h3")]
    #[allow(clippy::too_many_arguments)]
    fn establish_and_send_quic<'a>(
        &'a self,
        ctx: &'a RequestContext<'a>,
        body: Option<crate::body::RequestBody>,
        discovery: &'a pipeline::QuicDiscovery,
        proxy: Option<&'a ProxyConfig>,
        effective_proxy_owned: Option<ProxyConfig>,
        protocol_policy: &'a crate::protocol::ProtocolPolicy,
        http_version_pref: PreferredHttpVersion,
        connect_start: std::time::Instant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response>> + Send + 'a>> {
        Box::pin(async move {
            if body.as_ref().is_some_and(|body| !body.can_replay()) {
                return Err(Error::Http(
                    "cannot replay consumed streaming request body".into(),
                ));
            }

            let in_flight_guard = loop {
                match QuicHandshakeGuard::try_acquire(&self.session, ctx.conn_key) {
                    Ok(guard) => {
                        // The previous leader may have pooled a connection
                        // since our initial lookup, including before election.
                        let pooled = self
                            .session
                            .inner
                            .pool
                            .lock()
                            .try_acquire_h3_pooled_internal(ctx.conn_key);
                        if let Some(AcquiredConnection::H3 {
                            mut sender,
                            token,
                            cleanup,
                        }) = pooled
                        {
                            drop(guard);
                            let result = self.send_h3_request(&mut sender, ctx, body).await;
                            if let Err(ref error) = result {
                                pipeline::finish_closed_h3_attempt(
                                    &self.session,
                                    ctx.conn_key,
                                    &token,
                                    &cleanup,
                                    error,
                                )
                                .await;
                            }
                            return result;
                        }
                        break guard;
                    }
                    Err(mut wait) => {
                        tracing::debug!(
                            host = %ctx.host,
                            port = ctx.port,
                            "quic.handshake_coalesce_wait",
                        );
                        // Channel closure is persistent, unlike notify_waiters.
                        // Failure/cancellation requires another election, too.
                        let _ = wait.changed().await;
                        let tracker = self.session.broken_quic_tracker();
                        let skip = if tracker.is_route_broken(&discovery.route) {
                            Some(pipeline::QuicSkipReason::ProxyUdpUnavailable)
                        } else if tracker.is_broken_for_route(&discovery.route, &discovery.origin) {
                            Some(pipeline::QuicSkipReason::BrokenOrigin)
                        } else {
                            None
                        };
                        if let Some(skip) = skip {
                            let mut updated = discovery.clone();
                            updated.skip_reason = Some(skip);
                            if pipeline::decide_protocol(
                                http_version_pref,
                                protocol_policy,
                                &updated,
                            ) == pipeline::ProtocolDecision::Tcp
                            {
                                // Another request may have established a TCP
                                // fallback while we waited. Apply normal pool
                                // policy instead of insisting on another H3 dial.
                                return self
                                    .send_single_request_with_recovery(
                                        ctx.parsed_url.as_str(),
                                        ctx.method,
                                        ctx.extra_headers,
                                        body,
                                        ctx.recovery(ctx.retry_early_data),
                                    )
                                    .await;
                            }
                        }
                    }
                }
            };
            let permit = self.session.reserve_connection()?;

            let early_data_allowed = super::can_send_early_data(ctx.method, ctx.idempotency)
                && !body
                    .as_ref()
                    .is_some_and(crate::body::RequestBody::is_streaming);
            tracing::trace!(
                method = %ctx.method,
                idempotency = ?ctx.idempotency,
                early_data_allowed,
                proxy = proxy.is_some(),
                "h3.early_data_gate",
            );

            // Keep unconfirmed failures under the same fallback/permit owner.
            let connected = 'handshake: {
                match self
                    .session
                    .establish_h3_connection_with_0rtt(
                        ctx.host,
                        ctx.port,
                        discovery.advertised_host.as_deref(),
                        discovery.advertised_port,
                        proxy,
                        early_data_allowed,
                    )
                    .await
                {
                    Ok(super::H3ConnectOutcome::Handshake(h3_conn)) => {
                        Ok((h3_conn, permit, in_flight_guard))
                    }
                    Ok(super::H3ConnectOutcome::ZeroRtt {
                        connection: zero_rtt,
                        handshake_started,
                        handshake_timeout,
                    }) => {
                        let mut reservation = Some((permit, in_flight_guard));
                        let mut published = None;
                        let zero_rtt_result = self
                            .send_h3_0rtt_request(
                                zero_rtt,
                                ctx,
                                body.clone(),
                                handshake_started,
                                handshake_timeout,
                                |h3_conn| {
                                    let (permit, guard) = reservation.take().unwrap();
                                    let quic = h3_conn.quic_connection().clone();
                                    let (_, driver) =
                                        self.pool_h3_connection(ctx, discovery, h3_conn, permit);
                                    published = Some((quic, driver));
                                    drop(guard);
                                    tracing::debug!(
                                        route = %ctx.conn_key.route,
                                        path = "new_h3_0rtt",
                                        protocol = "h3",
                                        duration_ms = connect_start.elapsed().as_millis() as u64,
                                        "connection.established",
                                    );
                                },
                            )
                            .await;
                        match zero_rtt_result {
                            Ok(Some(response)) => return Ok(response),
                            Ok(None) => {}
                            Err(error) => {
                                if error.is_quic_handshake_failure() && reservation.is_some() {
                                    let (permit, guard) = reservation.take().unwrap();
                                    break 'handshake Err((error, permit, guard));
                                }
                                if crate::retry::chrome_h3_owns_error(
                                    self.session.h3_retry_mode(),
                                    &error,
                                ) {
                                    if let Some((_, driver)) = &published {
                                        pipeline::finish_closed_h3_attempt(
                                            &self.session,
                                            ctx.conn_key,
                                            &crate::connection_pool::PoolToken::H3Tracked(
                                                std::sync::Arc::downgrade(driver),
                                            ),
                                            driver,
                                            &error,
                                        )
                                        .await;
                                    }
                                    return Err(error);
                                }
                                let can_retry = ctx.retry_early_data
                                    && error.is_connection_closed()
                                    && crate::retry::retry_is_replay_safe(
                                        ctx.method,
                                        ctx.idempotency,
                                        &error,
                                    )
                                    && body
                                        .as_ref()
                                        .is_none_or(crate::body::RequestBody::can_replay)
                                    && self
                                        .session
                                        .inner
                                        .client
                                        .fallback()
                                        .retry_on_connection_close;
                                if !can_retry {
                                    return Err(error);
                                }
                                tracing::debug!(error = %error, "h3.early_data_failed_retrying");
                                if reservation.is_none() {
                                    let (quic, driver) = published.as_ref().unwrap();
                                    if quic.close_reason().is_some() {
                                        // A response may observe QUIC closure before
                                        // the tracked H3 driver releases its permit.
                                        while !driver.is_finished() {
                                            tokio::time::sleep(Duration::from_millis(1)).await;
                                        }
                                        self.session.inner.pool.lock().remove_acquired(
                                            ctx.conn_key,
                                            &crate::connection_pool::PoolToken::H3Tracked(
                                                std::sync::Arc::downgrade(driver),
                                            ),
                                        );
                                    }
                                    // Published connections can already carry other
                                    // requests. Recover through normal acquisition,
                                    // retaining the per-request replay bound.
                                    return self
                                        .send_single_request_with_recovery(
                                            ctx.parsed_url.as_str(),
                                            ctx.method,
                                            ctx.extra_headers,
                                            body,
                                            ctx.recovery(false),
                                        )
                                        .await;
                                }
                            }
                        }
                        let (permit, guard) = reservation.unwrap();
                        let replay_h3_conn = self
                            .session
                            .establish_h3_connection(
                                ctx.host,
                                ctx.port,
                                discovery.advertised_host.as_deref(),
                                discovery.advertised_port,
                                proxy,
                            )
                            .await;
                        match replay_h3_conn {
                            Ok(connection) => {
                                tracing::debug!(
                                    route = %ctx.conn_key.route,
                                    protocol = "h3",
                                    "h3.early_data_replay_connection_ready",
                                );
                                Ok((connection, permit, guard))
                            }
                            Err(error) => Err((error, permit, guard)),
                        }
                    }
                    Err(error) => Err((error, permit, in_flight_guard)),
                }
            };
            let (h3_conn, permit, in_flight_guard) = match connected {
                Ok(connection) => connection,
                Err((error, permit, in_flight_guard)) => {
                    // Direct and resumed attempts share handshake failure policy.
                    // H3 negotiation timeouts retain their post-handshake phase.
                    let is_handshake_class = error.is_quic_handshake_failure();
                    if is_handshake_class {
                        self.session
                            .broken_quic_tracker()
                            .mark_broken_for_route(&discovery.route, &discovery.origin);
                        self.session
                            .alt_svc_cache()
                            .clear_h3_validation_for_route(&discovery.route, &discovery.origin);
                    } else {
                        tracing::debug!(
                            host = %ctx.host,
                            error = %error,
                            "quic.non_handshake_error_no_broken_mark",
                        );
                    }

                    // A MASQUE proxy relays UDP only, so falling back to TCP
                    // cannot succeed — it just replaces the real handshake
                    // error with `masque_cannot_carry_tcp`'s "this proxy only
                    // relays UDP", pointing the caller at their proxy
                    // configuration when the actual failure was the inner
                    // connection's. Safety never depended on this branch
                    // (`connect_tcp` refuses the route as well); readability
                    // does.
                    let proxy_forbids_tcp_fallback = effective_proxy_owned
                        .as_ref()
                        .is_some_and(|proxy| proxy.forbids_direct_fallback());
                    let fallback_allowed = is_handshake_class
                        && http_version_pref != PreferredHttpVersion::Http3Only
                        && protocol_policy.intent != crate::protocol::HttpIntent::H3Only
                        && !proxy_forbids_tcp_fallback
                        && pipeline::fallback_permitted(protocol_policy, &error);
                    drop(permit);
                    if fallback_allowed {
                        tracing::warn!(
                            route = %discovery.route,
                            host = %ctx.host,
                            port = ctx.port,
                            fallback_policy = ?protocol_policy.fallback,
                            error = %error,
                            "quic.handshake_failed_fallback_tcp",
                        );
                        return self
                            .establish_and_send_tcp_with_ready(
                                ctx,
                                body,
                                effective_proxy_owned,
                                http_version_pref,
                                connect_start,
                                move || drop(in_flight_guard),
                            )
                            .await;
                    }
                    if is_handshake_class {
                        tracing::warn!(
                            route = %discovery.route,
                            host = %ctx.host,
                            port = ctx.port,
                            fallback_policy = ?protocol_policy.fallback,
                            error = %error,
                            "quic.handshake_failed_no_fallback",
                        );
                    }
                    return Err(error);
                }
            };

            let (mut send_sender, cleanup) =
                self.pool_h3_connection(ctx, discovery, h3_conn, permit);
            drop(in_flight_guard);

            tracing::debug!(
                route = %ctx.conn_key.route,
                path = "new_h3",
                protocol = "h3",
                duration_ms = connect_start.elapsed().as_millis() as u64,
                "connection.established",
            );

            let result = self.send_h3_request(&mut send_sender, ctx, body).await;
            if let Err(ref error) = result {
                pipeline::finish_closed_h3_attempt(
                    &self.session,
                    ctx.conn_key,
                    &crate::connection_pool::PoolToken::H3Tracked(std::sync::Arc::downgrade(
                        &cleanup,
                    )),
                    &cleanup,
                    error,
                )
                .await;
            }
            result
        })
    }

    #[cfg(feature = "quic-h3")]
    fn pool_h3_connection(
        &self,
        ctx: &RequestContext<'_>,
        discovery: &pipeline::QuicDiscovery,
        h3_conn: lkh3::H3Connection,
        permit: ConnectionPermit,
    ) -> (lkh3::H3Sender, std::sync::Arc<tokio::task::JoinHandle<()>>) {
        self.session
            .broken_quic_tracker()
            .mark_working_for_route(&discovery.route, &discovery.origin);
        self.session
            .broken_quic_tracker()
            .mark_route_working(&discovery.route);
        self.session
            .alt_svc_cache()
            .mark_h3_validated_for_route(&discovery.route, &discovery.origin);
        let (sender, driver) = h3_conn.into_parts();
        let send_sender = sender.clone();
        let driver = self.session.inner.pool.lock().insert_h3_reserved(
            ctx.conn_key.clone(),
            sender,
            driver,
            permit,
        );
        (send_sender, driver)
    }

    fn establish_and_send_tcp<'a>(
        &'a self,
        ctx: &'a RequestContext<'a>,
        body: Option<crate::body::RequestBody>,
        effective_proxy: Option<ProxyConfig>,
        _protocol_policy: &'a crate::protocol::ProtocolPolicy,
        http_version_pref: PreferredHttpVersion,
        connect_start: std::time::Instant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response>> + Send + 'a>> {
        self.establish_and_send_tcp_with_ready(
            ctx,
            body,
            effective_proxy,
            http_version_pref,
            connect_start,
            || {},
        )
    }

    fn establish_and_send_tcp_with_ready<'a>(
        &'a self,
        ctx: &'a RequestContext<'a>,
        body: Option<crate::body::RequestBody>,
        effective_proxy: Option<ProxyConfig>,
        http_version_pref: PreferredHttpVersion,
        connect_start: std::time::Instant,
        on_ready: impl FnOnce() + Send + 'a,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response>> + Send + 'a>> {
        let host = ctx.host;
        let port = ctx.port;
        let scheme = ctx.scheme;
        let conn_key = ctx.conn_key;

        Box::pin(async move {
            let mut on_ready = Some(on_ready);
            if body.as_ref().is_some_and(|body| !body.can_replay()) {
                return Err(Error::Http(
                    "cannot replay consumed streaming request body".into(),
                ));
            }

            let permit = self.session.reserve_connection()?;
            let client = &self.session.inner.client;
            let mut connect_config =
                pipeline::build_connect_config(client, http_version_pref, scheme);
            // `proxy_fallback_direct` does not apply to routes that forbid it
            // (MASQUE): falling back would leak the source address the tunnel
            // exists to hide. Gate it here as well as in `connect::connect_tcp`
            // so such a route does not even get the halved proxy timeout that
            // only makes sense when a direct attempt follows.
            if client.fallback().proxy_to_direct
                && effective_proxy
                    .as_ref()
                    .is_some_and(|proxy| !proxy.forbids_direct_fallback())
            {
                connect_config = connect_config
                    .with_proxy_fallback(connect_start, self.effective_total_timeout());
            }

            let conn = self
                .session
                .establish_connection(host, port, effective_proxy.as_ref(), &connect_config)
                .await?;

            #[cfg(feature = "quic-h3")]
            ctx.acquire_send_gates().await;

            if scheme == Scheme::Http {
                let tcp = conn
                    .into_tcp_stream()?
                    .into_plain_tcp()
                    .ok_or_else(|| Error::Http("expected plain TCP for HTTP scheme".into()))?;
                return self
                    .send_cleartext(tcp, permit, ctx, body, connect_start)
                    .await;
            }

            let negotiated_alpn = conn.negotiated_alpn();
            tracing::debug!(alpn = ?negotiated_alpn, "tls.alpn_negotiated");

            let use_h2 = pipeline::should_use_h2(negotiated_alpn, http_version_pref)?;

            if use_h2 {
                let h2_result: Result<Response> = async {
                    if body
                        .as_ref()
                        .is_some_and(crate::body::RequestBody::is_streaming)
                    {
                        let sender = pipeline::establish_h2_and_pool(
                            conn.into_tcp_stream()?,
                            client,
                            &self.session,
                            conn_key,
                            permit,
                        )
                        .await?;
                        on_ready.take().unwrap()();
                        return self.send_h2_request(sender, ctx, body.clone()).await;
                    }
                    let first_req = self.build_h2_request_for_preface(
                        ctx,
                        body.as_ref().and_then(crate::body::RequestBody::buffered),
                    )?;
                    let (first_resp, _pool_sender) = pipeline::establish_h2_with_first_request(
                        conn.into_tcp_stream()?,
                        client,
                        &self.session,
                        conn_key,
                        first_req,
                        permit,
                    )
                    .await?;
                    on_ready.take().unwrap()();

                    tracing::debug!(
                        protocol = "h2",
                        duration_ms = connect_start.elapsed().as_millis() as u64,
                        first_request_piggybacked = true,
                        "connection.established",
                    );

                    self.receive_h2_first_response(first_resp, ctx, body.clone())
                        .await
                }
                .await;

                match h2_result {
                    Ok(resp) => Ok(resp),
                    Err(e)
                        if http_version_pref != PreferredHttpVersion::Http2Only
                            && client.fallback().h2_to_h1
                            && body
                                .as_ref()
                                .is_none_or(crate::body::RequestBody::can_replay)
                            && (matches!(e, Error::H2(_)) || e.is_connection_closed())
                            && crate::retry::retry_is_replay_safe(
                                ctx.method,
                                ctx.idempotency,
                                &e,
                            ) =>
                    {
                        tracing::warn!(
                            error = %e,
                            fallback = "h2_to_h1",
                            "http.h2_failed_falling_back_to_h1",
                        );

                        let fallback_permit = self.session.reserve_connection()?;
                        let h1_config = pipeline::build_h1_only_connect_config(client, scheme);
                        let conn2 = self
                            .session
                            .establish_connection(host, port, effective_proxy.as_ref(), &h1_config)
                            .await?;

                        let (sender, conn_task) =
                            pipeline::handshake_h1(conn2.into_tcp_stream()?).await?;

                        tracing::debug!(
                            route = %ctx.conn_key.route,
                            path = "fallback_h1",
                            protocol = "h1.1",
                            fallback = true,
                            "connection.established_via_fallback",
                        );

                        self.send_h1_request(sender, conn_task, fallback_permit, ctx, body)
                            .await
                    }
                    Err(e) => Err(e),
                }
            } else {
                if negotiated_alpn != Some("http/1.1")
                    && negotiated_alpn.is_some()
                    && http_version_pref != PreferredHttpVersion::Http1Only
                {
                    tracing::warn!(
                        alpn = ?negotiated_alpn,
                        "tls.unexpected_alpn_falling_back_to_h1",
                    );
                }

                let (sender, conn_task) = pipeline::handshake_h1(conn.into_tcp_stream()?).await?;

                tracing::debug!(
                    route = %ctx.conn_key.route,
                    path = "new_h1",
                    protocol = "h1.1",
                    duration_ms = connect_start.elapsed().as_millis() as u64,
                    "connection.established",
                );

                self.send_h1_request(sender, conn_task, permit, ctx, body)
                    .await
            }
        })
    }

    // -----------------------------------------------------------------------
    // HTTP/2 request sending
    // -----------------------------------------------------------------------

    fn request_head_input<'a>(
        &'a self,
        ctx: &'a RequestContext<'_>,
    ) -> pipeline::RequestHeadInput<'a> {
        pipeline::RequestHeadInput {
            session: &self.session,
            method: ctx.method,
            scheme: ctx.scheme,
            host: ctx.host,
            port: ctx.port,
            path: ctx.path,
            parsed_url: ctx.parsed_url,
            headers: ctx.extra_headers,
            default_headers: self.effective_default_headers(),
            extra_cookies: &self.extra_cookies,
            cookie_overrides: &self.cookie_overrides,
            priority: self.priority,
            h2_priority_weight: self.h2_priority_weight,
            header_order: self.header_order.as_deref(),
            h3_header_order: self.h3_header_order.as_deref(),
            cookie_order: self.cookie_order.as_deref(),
            header_insertion_order: &self.header_insertion_order,
        }
    }

    /// Send a request via HTTP/2.
    pub(crate) async fn send_h2_request(
        &self,
        sender: lkh2::H2ReadySender,
        ctx: &RequestContext<'_>,
        body: Option<crate::body::RequestBody>,
    ) -> Result<Response> {
        #[cfg(feature = "quic-h3")]
        ctx.acquire_send_gates().await;
        let method = ctx.method;
        let host = ctx.host;
        let port = ctx.port;
        let parsed_url = ctx.parsed_url;
        let client = &self.session.inner.client;
        let mut prepared = pipeline::prepare_h2_request(
            &self.request_head_input(ctx),
            body.as_ref().and_then(crate::body::RequestBody::buffered),
            pipeline::H2RequestKind::Buffered,
        )?;
        tracing::debug!(
            method = %method, uri = %prepared.uri, protocol = "h2",
            has_body = body.is_some(), "http.request_sent",
        );
        let ttfb_started = std::time::Instant::now();
        let resp_future = if let Some(upload) = body.as_ref().filter(|body| body.is_streaming()) {
            upload.prepare_headers(&mut prepared.headers)?;
            sender.send_streaming_request(
                prepared.into_request(method),
                upload.clone().into_upload()?,
            )
        } else {
            let body = body
                .as_ref()
                .and_then(crate::body::RequestBody::buffered)
                .cloned();
            let pipeline::PreparedH2Request {
                uri,
                headers,
                priority,
                h2_priority_weight,
            } = prepared;
            let mut request =
                lkh2::NativeH2Request::new(method.clone(), uri, headers, body, Some(priority));
            if let Some(weight) = h2_priority_weight {
                request = request.with_h2_priority_weight(weight);
            }
            sender.send_native_request(request)
        };

        let resp = pipeline::await_response_headers(client, resp_future.await_response())
            .await?
            .map_err(|e| {
                Error::h2_or_connection_closed(
                    ConnectionPhase::HttpRequest,
                    format!("failed to receive H2 response: {e}"),
                )
            })?;
        crate::diagnostics::record_ttfb_ms(ttfb_started.elapsed().as_millis() as u64);
        crate::diagnostics::record_protocol("h2");

        let (parts, mut body_recv) = resp.into_parts();
        let status = parts.status;
        let resp_headers = parts.headers;
        let limits = self.session.inner.client.resource_limits();

        tracing::debug!(
            status = status.as_u16(),
            protocol = "h2",
            "http.response_headers"
        );

        limits.check_response_headers(&resp_headers)?;

        pipeline::store_cookies(&self.session, &resp_headers, parsed_url);
        pipeline::store_alt_svc(
            &self.session,
            &resp_headers,
            self.effective_proxy(),
            ctx.scheme,
            host,
            port,
        );

        let capacity_hint = resp_headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            .map(|cl| cl.min(limits.max_response_body_size))
            .unwrap_or(0);
        let mut body_data = bytes::BytesMut::with_capacity(capacity_hint);
        let body_start = std::time::Instant::now();
        while let Some(chunk) = body_recv.data().await {
            let chunk = chunk.map_err(|e| {
                Error::h2_or_connection_closed(
                    ConnectionPhase::HttpRequest,
                    format!("error reading response body: {e}"),
                )
            })?;
            let len = chunk.len();
            body_data.extend_from_slice(&chunk);

            limits.check_body_size(body_data.len())?;

            if let Some(min_rate) = limits.min_transfer_rate {
                let elapsed = body_start.elapsed();
                if elapsed > limits.transfer_rate_window {
                    let rate = body_data.len() as f64 / elapsed.as_secs_f64();
                    if rate < min_rate as f64 {
                        return Err(Error::timeout(
                            format!(
                                "transfer rate too slow: {:.0} bytes/s < {} bytes/s",
                                rate, min_rate
                            ),
                            None,
                            None,
                        ));
                    }
                }
            }

            let _ = body_recv.flow_control().release_capacity(len);
        }

        self.make_response(status, resp_headers, body_data.freeze(), HttpVersion::H2)
    }

    /// Send a request via HTTP/3.
    #[cfg(feature = "quic-h3")]
    fn build_h3_request(
        &self,
        ctx: &RequestContext<'_>,
        body: Option<crate::body::RequestBody>,
    ) -> Result<http::Request<Option<crate::body::RequestBody>>> {
        let mut request =
            pipeline::prepare_h3_request(&self.request_head_input(ctx), body.clone())?;
        if let Some(body) = body.as_ref().filter(|body| body.is_streaming()) {
            body.prepare_headers(request.headers_mut())?;
        }
        Ok(request)
    }

    #[cfg(feature = "quic-h3")]
    pub(crate) async fn send_h3_request(
        &self,
        sender: &mut lkh3::H3Sender,
        ctx: &RequestContext<'_>,
        body: Option<crate::body::RequestBody>,
    ) -> Result<Response> {
        ctx.acquire_send_gates().await;
        let method = ctx.method;

        let request = self.build_h3_request(ctx, body.clone())?;
        let upload = body
            .as_ref()
            .filter(|body| body.is_streaming())
            .map(|body| body.clone().into_upload())
            .transpose()?;
        let buffered = body
            .as_ref()
            .and_then(crate::body::RequestBody::buffered)
            .cloned();
        let request = request.map(|_| ());

        let early_data_allowed = super::can_send_early_data(method, ctx.idempotency)
            && !body
                .as_ref()
                .is_some_and(crate::body::RequestBody::is_streaming);
        tracing::trace!(
            method = %method,
            idempotency = ?ctx.idempotency,
            early_data_allowed,
            "h3.early_data_gate",
        );

        let ttfb_started = std::time::Instant::now();
        let response = pipeline::await_response_headers(&self.session.inner.client, async {
            match upload {
                Some(upload) => sender.send_streaming_request(request, upload).await,
                None => sender.send_request(request.map(|_| buffered)).await,
            }
        })
        .await?
        .map_err(|e| pipeline::h3_request_error(&self.session, e, false))?;
        crate::diagnostics::record_ttfb_ms(ttfb_started.elapsed().as_millis() as u64);
        crate::diagnostics::record_protocol("h3");

        self.receive_h3_response(response, ctx).await
    }

    #[cfg(feature = "quic-h3")]
    async fn receive_h3_response(
        &self,
        response: http::Response<lkh3::H3RecvStream>,
        ctx: &RequestContext<'_>,
    ) -> Result<Response> {
        let host = ctx.host;
        let port = ctx.port;
        let parsed_url = ctx.parsed_url;
        let client = &self.session.inner.client;

        let (parts, mut body_recv) = response.into_parts();
        let status = parts.status;
        let resp_headers = parts.headers;
        let limits = client.resource_limits();

        limits.check_response_headers(&resp_headers)?;
        pipeline::store_cookies(&self.session, &resp_headers, parsed_url);
        pipeline::store_alt_svc(
            &self.session,
            &resp_headers,
            self.effective_proxy(),
            ctx.scheme,
            host,
            port,
        );

        let mut body_data = bytes::BytesMut::new();
        while let Some(chunk) = body_recv.data().await {
            let chunk = chunk.map_err(|e| pipeline::h3_request_error(&self.session, e, true))?;
            body_data.extend_from_slice(&chunk);
            limits.check_body_size(body_data.len())?;
        }
        body_recv
            .trailers()
            .await
            .map_err(|e| pipeline::h3_request_error(&self.session, e, true))?;

        self.make_response(status, resp_headers, body_data.freeze(), HttpVersion::H3)
    }

    #[cfg(feature = "quic-h3")]
    async fn send_h3_0rtt_request(
        &self,
        zero_rtt: lkh3::H3ZeroRttConnection,
        ctx: &RequestContext<'_>,
        body: Option<crate::body::RequestBody>,
        handshake_started: tokio::time::Instant,
        handshake_timeout: Duration,
        on_ready: impl FnOnce(lkh3::H3Connection) + Send,
    ) -> Result<Option<Response>> {
        let mut early_sender = zero_rtt.sender();
        let accepted_fut = tokio::time::timeout(
            handshake_timeout.saturating_sub(handshake_started.elapsed()),
            zero_rtt.accepted(),
        );
        let send_fut = async {
            ctx.acquire_send_gates().await;
            let early_request = self.build_h3_request(ctx, body.clone())?.map(|body| {
                body.as_ref()
                    .and_then(crate::body::RequestBody::buffered)
                    .cloned()
            });
            pipeline::await_response_headers(
                &self.session.inner.client,
                early_sender.send_request(early_request),
            )
            .await
        };
        tokio::pin!(accepted_fut);
        tokio::pin!(send_fut);

        let mut send_result: Option<
            std::result::Result<http::Response<lkh3::H3RecvStream>, lkh3::H3Error>,
        > = None;
        let (h3_conn, accepted) = loop {
            tokio::select! {
                accepted = &mut accepted_fut => break accepted.map_err(|_| {
                    Error::timeout(
                        format!("QUIC handshake to {}:{} timed out after {handshake_timeout:?}", ctx.host, ctx.port),
                        Some(ConnectionPhase::QuicHandshake),
                        Some(handshake_timeout),
                    )
                })?,
                result = &mut send_fut, if send_result.is_none() => {
                    send_result = Some(result?);
                }
            }
        };

        let reused = h3_conn.quic_connection().rejected_0rtt_streams_reused();
        tracing::debug!(
            method = %ctx.method,
            idempotency = ?ctx.idempotency,
            accepted,
            reused,
            send_error = ?send_result
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(ToString::to_string),
            "h3.early_data_result"
        );

        if accepted || reused {
            on_ready(h3_conn);
            let response = match send_result {
                Some(result) => result,
                None => (&mut send_fut).await?,
            }
            .map_err(|e| pipeline::h3_request_error(&self.session, e, false))?;
            crate::diagnostics::record_protocol("h3");
            let response = self.receive_h3_response(response, ctx).await?;
            Ok(Some(response))
        } else {
            // Quinn also resolves this gate to false when the handshake fails.
            // Only a live connection represents a normal early-data rejection.
            if let Some(error) = h3_conn.quic_connection().close_reason() {
                return Err(Error::quic(
                    crate::error::QuicPhase::Handshake,
                    error.to_string(),
                ));
            }
            tracing::debug!(
                method = %ctx.method,
                "h3.early_data_rejected_replay_required"
            );
            drop(h3_conn);
            Ok(None)
        }
    }

    // -----------------------------------------------------------------------
    // HTTP/2 first-request (back-to-back with preface)
    // -----------------------------------------------------------------------

    /// Build an `http::Request<Option<Bytes>>` suitable for piggybacking on the
    /// H2 connection preface as a `FirstRequest`.
    ///
    /// This constructs the same request that `send_h2_request` would, but
    /// returns it as a value instead of sending it through a sender.
    fn build_h2_request_for_preface(
        &self,
        ctx: &RequestContext<'_>,
        body: Option<&bytes::Bytes>,
    ) -> Result<http::Request<Option<bytes::Bytes>>> {
        let prepared = pipeline::prepare_h2_request(
            &self.request_head_input(ctx),
            body,
            pipeline::H2RequestKind::Preface,
        )?;
        Ok(prepared.into_request(ctx.method).map(|()| body.cloned()))
    }

    /// Receive the response for a first request that was piggybacked on the
    /// H2 connection preface via `establish_h2_with_first_request`.
    async fn receive_h2_first_response(
        &self,
        first_resp: lkh2::driver::FirstRequestResponse,
        ctx: &RequestContext<'_>,
        body: Option<crate::body::RequestBody>,
    ) -> Result<Response> {
        let parsed_url = ctx.parsed_url;
        let client = &self.session.inner.client;

        // If there was a body, it was already included in the first request.
        // For requests with bodies, the body was sent inline as part of the
        // HEADERS+DATA frames in the first request.
        // (The lkh2 driver handles DATA frame emission for first requests
        // that have a body.)
        let _ = body;

        let ttfb_started = std::time::Instant::now();

        let resp =
            pipeline::await_response_headers(client, crate::h2::await_first_response(first_resp))
                .await?
                .map_err(|e| Error::H2(format!("first request response failed: {e}")))?;

        crate::diagnostics::record_ttfb_ms(ttfb_started.elapsed().as_millis() as u64);
        crate::diagnostics::record_protocol("h2");

        let (parts, mut body_recv) = resp.into_parts();
        let status = parts.status;
        let resp_headers = parts.headers;
        let limits = client.resource_limits();

        tracing::debug!(
            status = status.as_u16(),
            protocol = "h2",
            first_request = true,
            "http.response_headers"
        );

        limits.check_response_headers(&resp_headers)?;

        pipeline::store_cookies(&self.session, &resp_headers, parsed_url);
        pipeline::store_alt_svc(
            &self.session,
            &resp_headers,
            self.effective_proxy(),
            ctx.scheme,
            ctx.host,
            ctx.port,
        );

        let capacity_hint = resp_headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            .map(|cl| cl.min(limits.max_response_body_size))
            .unwrap_or(0);
        let mut body_data = bytes::BytesMut::with_capacity(capacity_hint);
        let body_start = std::time::Instant::now();
        while let Some(chunk) = body_recv.data().await {
            let chunk =
                chunk.map_err(|e| Error::H2(format!("error reading response body: {e}")))?;
            let len = chunk.len();
            body_data.extend_from_slice(&chunk);

            limits.check_body_size(body_data.len())?;

            if let Some(min_rate) = limits.min_transfer_rate {
                let elapsed = body_start.elapsed();
                if elapsed > limits.transfer_rate_window {
                    let rate = body_data.len() as f64 / elapsed.as_secs_f64();
                    if rate < min_rate as f64 {
                        return Err(Error::timeout(
                            format!(
                                "transfer rate too slow: {:.0} bytes/s < {} bytes/s",
                                rate, min_rate
                            ),
                            None,
                            None,
                        ));
                    }
                }
            }

            let _ = body_recv.flow_control().release_capacity(len);
        }

        self.make_response(status, resp_headers, body_data.freeze(), HttpVersion::H2)
    }

    // -----------------------------------------------------------------------
    // HTTP/1.1 request sending
    // -----------------------------------------------------------------------

    /// Send a request via HTTP/1.1.
    ///
    /// After a successful request, the sender is returned to the connection pool
    /// for keep-alive reuse.
    pub(crate) async fn send_h1_request(
        &self,
        mut sender: hyper::client::conn::http1::SendRequest<WireBody>,
        conn_task: std::sync::Arc<tokio::task::JoinHandle<()>>,
        permit: ConnectionPermit,
        ctx: &RequestContext<'_>,
        body: Option<crate::body::RequestBody>,
    ) -> Result<Response> {
        #[cfg(feature = "quic-h3")]
        ctx.acquire_send_gates().await;
        let method = ctx.method;
        let host = ctx.host;
        let path = ctx.path;
        let conn_key = ctx.conn_key;
        let extra_headers = ctx.extra_headers;
        let parsed_url = ctx.parsed_url;
        use http_body_util::BodyExt;

        let client = &self.session.inner.client;

        // Build URI — just the path for HTTP/1.1 (Host header carries the authority)
        let uri: http::Uri = path
            .parse()
            .map_err(|e| Error::Http(format!("invalid request path '{}': {e}", path)))?;

        // Build the per-hop request before claiming its upload source.
        //
        // `body` is *this hop's* body, which is not always `self.body`: a
        // redirect that rewrites the method to GET drops it. Content-Length
        // must be derived from this one — see the `auto_insert_content_length`
        // call below.
        let hop_body = body;
        let has_body = hop_body.as_ref().is_some_and(|body| body.len() != Some(0));

        let mut request = http::Request::builder()
            .method(method.clone())
            .uri(uri)
            .body(())
            .map_err(|e| Error::Http(format!("failed to build HTTP/1.1 request: {e}")))?;

        let header_order = pipeline::effective_header_order(
            self.header_order.as_deref(),
            self.session.inner.header_order.as_deref(),
            client.header_order(),
            &self.header_insertion_order,
        );
        let cookie_order = pipeline::effective_cookie_order(
            self.cookie_order.as_deref(),
            self.session.inner.cookie_order.as_deref(),
            client.cookie_order(),
        );

        // Every other send path passes the per-hop body here; this one used to
        // pass `self.body`. On a redirect that rewrote the method to GET that
        // re-inserted the *original* body's Content-Length onto a bodyless
        // request, and the server then blocked waiting for a body that never
        // came — on a pooled H1 connection, until the total timeout fired.
        pipeline::auto_insert_content_length(
            request.headers_mut(),
            hop_body
                .as_ref()
                .and_then(crate::body::RequestBody::buffered),
        );

        self.merge_headers(
            request.headers_mut(),
            client,
            extra_headers,
            parsed_url,
            true,
            HeaderMergeOrdering {
                header_order,
                cookie_order,
            },
        );

        tracing::debug!(
            method = %method,
            host = %host,
            path = %path,
            protocol = "h1.1",
            has_body = has_body,
            "http.request_sent",
        );

        // Send the request via H1.1
        let ttfb_started = std::time::Instant::now();
        let mut request = pipeline::into_wire_request(request, hop_body)?;
        let upload_guard = pipeline::H1UploadGuard::new(conn_task.clone(), request.body());
        request.body_mut().validate_empty().await?;
        let resp = pipeline::await_response_headers(client, sender.send_request(request))
            .await?
            .map_err(|e| Error::from_h1_error(e, "HTTP/1.1 request failed"))?;
        crate::diagnostics::record_ttfb_ms(ttfb_started.elapsed().as_millis() as u64);
        crate::diagnostics::record_protocol("http/1.1");

        // Decompose response to avoid cloning headers
        let (parts, mut body) = resp.into_parts();
        let status = parts.status;
        let resp_headers = parts.headers;
        let limits = self.session.inner.client.resource_limits();

        tracing::debug!(
            status = status.as_u16(),
            protocol = "h1.1",
            "http.response_headers"
        );

        limits.check_response_headers(&resp_headers)?;

        pipeline::store_cookies(&self.session, &resp_headers, parsed_url);
        pipeline::store_alt_svc(
            &self.session,
            &resp_headers,
            self.effective_proxy(),
            ctx.scheme,
            host,
            ctx.port,
        );

        // Read response body incrementally (matching H2 path behavior)
        let capacity_hint = resp_headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            .map(|cl| cl.min(limits.max_response_body_size))
            .unwrap_or(0);
        let mut body_data = bytes::BytesMut::with_capacity(capacity_hint);
        let body_start = std::time::Instant::now();

        while let Some(frame_result) = body.frame().await {
            let frame = frame_result
                .map_err(|e| Error::from_h1_error(e, "error reading HTTP/1.1 response body"))?;
            if let Some(chunk) = frame.data_ref() {
                body_data.extend_from_slice(chunk);

                limits.check_body_size(body_data.len())?;

                if let Some(min_rate) = limits.min_transfer_rate {
                    let elapsed = body_start.elapsed();
                    if elapsed > limits.transfer_rate_window {
                        let rate = body_data.len() as f64 / elapsed.as_secs_f64();
                        if rate < min_rate as f64 {
                            return Err(Error::timeout(
                                format!(
                                    "transfer rate too slow: {:.0} bytes/s < {} bytes/s",
                                    rate, min_rate
                                ),
                                None,
                                None,
                            ));
                        }
                    }
                }
            }
        }
        let body_data = body_data.freeze();

        // Return the sender to the pool for keep-alive reuse.
        // Check if the connection is still usable (not Connection: close).
        let connection_close = resp_headers
            .get(http::header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("close"))
            .unwrap_or(false);

        if !connection_close && upload_guard.is_complete() {
            let mut pool = self.session.inner.pool.lock();
            pool.return_h1_reserved(conn_key.clone(), sender, conn_task, permit);
            tracing::trace!(host = %host, "h1.connection_returned_to_pool");
        } else {
            tracing::trace!(host = %host, "h1.connection_close_not_pooled");
        }

        self.make_response(status, resp_headers, body_data, HttpVersion::Http11)
    }

    // -----------------------------------------------------------------------
    // Cleartext HTTP (h2c upgrade / prior knowledge / plain H1.1)
    // -----------------------------------------------------------------------

    /// Send a request over a cleartext (non-TLS) TCP connection.
    ///
    /// Protocol selection depends on [`PreferredHttpVersion`]:
    /// - `Http1Only`           → plain HTTP/1.1
    /// - `Http2Only`           → h2c with prior knowledge (RFC 7540 §3.4)
    /// - `Auto`                → plain HTTP/1.1
    /// - `Http3WithFallback`   → plain HTTP/1.1 (H3 fundamentally needs
    ///   QUIC + TLS, so cleartext HTTP **is** the fallback the user explicitly
    ///   asked for)
    /// - `Http3Only`           → hard error (user demanded H3 but supplied
    ///   an `http://` URL — config conflict)
    ///
    /// Note: real Chrome / Firefox / Safari never send `Upgrade: h2c` over
    /// `http://` — h2c upgrade was deprecated by all major browsers years
    /// before HTTP/2 became dominant, and HTTP/2 in practice is gated on
    /// TLS + ALPN. To keep the wire format byte-identical to the target
    /// browser (the project's core invariant), the `Auto` and
    /// `Http3WithFallback` policies on cleartext stay on plain HTTP/1.1.
    /// Callers that genuinely need h2c can opt in via `Http2Only` for
    /// prior-knowledge h2c, or by invoking `Self::send_h2c_upgrade`
    /// explicitly.
    async fn send_cleartext(
        &self,
        tcp: tokio::net::TcpStream,
        permit: ConnectionPermit,
        ctx: &RequestContext<'_>,
        body: Option<crate::body::RequestBody>,
        connect_start: std::time::Instant,
    ) -> Result<Response> {
        let policy = self.effective_protocol_policy();
        policy.validate()?;
        let http_version_pref = self.effective_http_version(&policy);

        match http_version_pref {
            PreferredHttpVersion::Http1Only
            | PreferredHttpVersion::Auto
            | PreferredHttpVersion::Http3WithFallback => {
                tracing::debug!(
                    protocol = "h1.1",
                    cleartext = true,
                    requested = ?http_version_pref,
                    "connection.h1_cleartext"
                );
                self.send_h1_cleartext(tcp, permit, ctx, body, connect_start)
                    .await
            }
            PreferredHttpVersion::Http2Only => {
                tracing::debug!(
                    protocol = "h2c",
                    mode = "prior_knowledge",
                    "connection.h2c_prior_knowledge",
                );
                self.send_h2c_prior_knowledge(tcp, permit, ctx, body, connect_start)
                    .await
            }
            PreferredHttpVersion::Http3Only => Err(Error::InvalidConfig(
                "HTTP/3 requires HTTPS and QUIC, but the request URL is cleartext `http://`".into(),
            )),
        }
    }

    /// Send a plain HTTP/1.1 request over a cleartext TCP connection.
    async fn send_h1_cleartext(
        &self,
        tcp: tokio::net::TcpStream,
        permit: ConnectionPermit,
        ctx: &RequestContext<'_>,
        body: Option<crate::body::RequestBody>,
        connect_start: std::time::Instant,
    ) -> Result<Response> {
        let stream = crate::connect::TransportStream::plain(tcp);
        let (sender, conn_task) = pipeline::handshake_h1(stream).await?;

        tracing::debug!(
            protocol = "h1.1",
            cleartext = true,
            duration_ms = connect_start.elapsed().as_millis() as u64,
            "connection.established",
        );

        self.send_h1_request(sender, conn_task, permit, ctx, body)
            .await
    }

    /// h2c with prior knowledge (RFC 7540 §3.4): send the HTTP/2 connection
    /// preface directly over TCP, then send the request as HTTP/2.
    async fn send_h2c_prior_knowledge(
        &self,
        tcp: tokio::net::TcpStream,
        permit: ConnectionPermit,
        ctx: &RequestContext<'_>,
        body: Option<crate::body::RequestBody>,
        connect_start: std::time::Instant,
    ) -> Result<Response> {
        let client = &self.session.inner.client;

        let stream = crate::connect::TransportStream::plain(tcp);
        let sender =
            pipeline::establish_h2_and_pool(stream, client, &self.session, ctx.conn_key, permit)
                .await
                .map_err(|e| {
                    Error::connection(
                        crate::error::ConnectionPhase::H2Negotiation,
                        format!("h2c prior knowledge handshake failed: {e}"),
                        None,
                    )
                })?;

        tracing::debug!(
            protocol = "h2c",
            mode = "prior_knowledge",
            duration_ms = connect_start.elapsed().as_millis() as u64,
            "connection.established",
        );

        self.send_h2_request(sender, ctx, body).await
    }

    /// h2c upgrade (RFC 7540 §3.2): send an HTTP/1.1 request with `Upgrade: h2c`
    /// and `HTTP2-Settings` headers. If the server accepts (101), switch to HTTP/2
    /// and resend the request; otherwise return the HTTP/1.1 response.
    ///
    /// Currently unused — the default `Auto` cleartext path stays on plain
    /// H1.1 to match real browser wire format (no major browser sends
    /// `Upgrade: h2c` over `http://`). Retained for a future explicit
    /// opt-in API (e.g. `HttpIntent::CleartextH2cUpgrade`) and as a
    /// reference implementation; removing it now would lose the carefully
    /// audited header-injection / pool-insertion logic.
    #[allow(dead_code)]
    async fn send_h2c_upgrade(
        &self,
        tcp: tokio::net::TcpStream,
        ctx: &RequestContext<'_>,
        body: Option<crate::body::RequestBody>,
        connect_start: std::time::Instant,
    ) -> Result<Response> {
        use http::header::{CONNECTION, UPGRADE};
        use http_body_util::BodyExt;
        use hyper_util::rt::TokioIo;

        let permit = self.session.reserve_connection()?;
        let method = ctx.method;
        let host = ctx.host;
        let path = ctx.path;
        let conn_key = ctx.conn_key;
        let extra_headers = ctx.extra_headers;
        let parsed_url = ctx.parsed_url;
        let client = &self.session.inner.client;

        let h2_settings_payload =
            crate::h2::profile::encode_h2_settings_base64url(client.h2_profile());

        let uri: http::Uri = path
            .parse()
            .map_err(|e| Error::Http(format!("invalid request path '{}': {e}", path)))?;

        let mut request = http::Request::builder()
            .method(method.clone())
            .uri(uri)
            .body(())
            .map_err(|e| Error::Http(format!("failed to build h2c upgrade request: {e}")))?;

        let header_order = pipeline::effective_header_order(
            self.header_order.as_deref(),
            self.session.inner.header_order.as_deref(),
            client.header_order(),
            &self.header_insertion_order,
        );
        let cookie_order = pipeline::effective_cookie_order(
            self.cookie_order.as_deref(),
            self.session.inner.cookie_order.as_deref(),
            client.cookie_order(),
        );

        pipeline::auto_insert_content_length(
            request.headers_mut(),
            body.as_ref().and_then(crate::body::RequestBody::buffered),
        );

        self.merge_headers(
            request.headers_mut(),
            client,
            extra_headers,
            parsed_url,
            true,
            HeaderMergeOrdering {
                header_order,
                cookie_order,
            },
        );

        request
            .headers_mut()
            .insert(UPGRADE, "h2c".parse().unwrap());
        request
            .headers_mut()
            .insert(CONNECTION, "Upgrade, HTTP2-Settings".parse().unwrap());
        request.headers_mut().insert(
            http::header::HeaderName::from_static("http2-settings"),
            http::header::HeaderValue::from_str(&h2_settings_payload)
                .map_err(|e| Error::Http(format!("invalid HTTP2-Settings value: {e}")))?,
        );

        tracing::debug!(
            method = %method,
            host = %host,
            path = %path,
            protocol = "h1.1",
            h2c_upgrade = true,
            "http.h2c_upgrade_request_sent",
        );

        let io = TokioIo::new(tcp);
        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .title_case_headers(true)
            .preserve_header_case(true)
            .handshake(io)
            .await
            .map_err(|e| Error::Http(format!("H1 handshake for h2c upgrade failed: {e}")))?;

        let conn_task = tokio::spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                tracing::debug!(error = %e, "h2c.upgrade_connection_closed");
            }
        });
        let conn_task = std::sync::Arc::new(conn_task);

        let mut request = pipeline::into_wire_request(request, body.clone())?;
        let _upload_guard = pipeline::H1UploadGuard::new(conn_task.clone(), request.body());
        request.body_mut().validate_empty().await?;
        let resp = pipeline::await_response_headers(client, sender.send_request(request))
            .await?
            .map_err(|e| Error::Http(format!("h2c upgrade request failed: {e}")))?;

        if resp.status() == http::StatusCode::SWITCHING_PROTOCOLS {
            tracing::debug!("h2c.upgrade_accepted");

            let upgraded = hyper::upgrade::on(resp).await.map_err(|e| {
                Error::connection(
                    crate::error::ConnectionPhase::H2cUpgrade,
                    format!("h2c upgrade extraction failed: {e}"),
                    None,
                )
            })?;

            let upgraded_io = TokioIo::new(upgraded);

            let h2_conn = crate::h2::connect_h2_with_config(
                upgraded_io,
                client.h2_profile(),
                None,
                client.max_pending_h2_requests(),
                client.h2_dispatch_batch_size(),
            )
            .await
            .map_err(|e| {
                Error::connection(
                    crate::error::ConnectionPhase::H2cUpgrade,
                    format!("h2c post-upgrade H2 handshake failed: {e}"),
                    None,
                )
            })?;
            let h2_sender = h2_conn.clone_sender();

            {
                let mut pool = self.session.inner.pool.lock();
                pool.insert_h2_reserved(
                    conn_key.clone(),
                    h2_conn.clone_sender(),
                    h2_conn.into_task(),
                    permit,
                );
            }

            tracing::debug!(
                protocol = "h2c",
                mode = "upgrade",
                duration_ms = connect_start.elapsed().as_millis() as u64,
                "connection.established",
            );

            let h2_sender = h2_sender
                .ready()
                .await
                .map_err(|e| Error::H2(format!("h2c connection not ready: {e}")))?;

            self.send_h2_request(h2_sender, ctx, body).await
        } else {
            // Server did not accept the upgrade — return the HTTP/1.1 response
            tracing::debug!(
                status = resp.status().as_u16(),
                "h2c.upgrade_rejected_using_h1",
            );

            let (parts, resp_body) = resp.into_parts();
            let status = parts.status;
            let resp_headers = parts.headers;
            let limits = self.session.inner.client.resource_limits();

            limits.check_response_headers(&resp_headers)?;
            pipeline::store_cookies(&self.session, &resp_headers, parsed_url);
            pipeline::store_alt_svc(
                &self.session,
                &resp_headers,
                self.effective_proxy(),
                ctx.scheme,
                host,
                ctx.port,
            );

            let body_collected = resp_body
                .collect()
                .await
                .map_err(|e| Error::Http(format!("error reading h2c fallback response: {e}")))?;
            let body_data = body_collected.to_bytes();
            limits.check_body_size(body_data.len())?;

            // Return the H1.1 sender to the pool for keep-alive reuse,
            // unless the server indicated Connection: close.
            let connection_close = resp_headers
                .get(http::header::CONNECTION)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.eq_ignore_ascii_case("close"))
                .unwrap_or(false);

            if !connection_close {
                let mut pool = self.session.inner.pool.lock();
                pool.return_h1_reserved(conn_key.clone(), sender, conn_task, permit);
                tracing::trace!(host = %host, "h2c.rejected_h1_returned_to_pool");
            }

            self.make_response(status, resp_headers, body_data, HttpVersion::Http11)
        }
    }

    // -----------------------------------------------------------------------
    // Shared helpers
    // -----------------------------------------------------------------------

    fn effective_default_headers(&self) -> &HeaderMap {
        self.redirect_defaults
            .as_ref()
            .unwrap_or_else(|| self.session.inner.client.default_headers())
    }

    /// Merge default headers + request headers + cookies into the request headers.
    pub(crate) fn merge_headers(
        &self,
        headers: &mut HeaderMap,
        client: &Client,
        extra_headers: &HeaderMap,
        parsed_url: &Url,
        is_h1: bool,
        ordering: HeaderMergeOrdering<'_>,
    ) {
        merge_headers_with_defaults(
            headers,
            self.redirect_defaults
                .as_ref()
                .unwrap_or_else(|| client.default_headers()),
            extra_headers,
            parsed_url,
            is_h1,
            &self.session.inner.cookie_jar,
            &self.extra_cookies,
            &self.cookie_overrides,
            ordering.header_order,
            ordering.cookie_order,
        );
    }

    /// Build a Response, applying decompression unless `no_decompress` is set.
    pub(crate) fn make_response(
        &self,
        status: http::StatusCode,
        headers: HeaderMap,
        body: bytes::Bytes,
        http_version: HttpVersion,
    ) -> Result<Response> {
        let mut resp = if self.no_decompress {
            Response::from_parts(status, headers, body)
        } else {
            Response::new(status, headers, body)?
        };
        resp.set_http_version(http_version);
        Ok(resp)
    }

    pub(crate) fn effective_proxy(&self) -> Option<&ProxyConfig> {
        pipeline::effective_proxy(self.proxy_override.as_ref(), &self.session)
    }

    pub(crate) fn effective_protocol_policy(&self) -> crate::protocol::ProtocolPolicy {
        pipeline::effective_protocol_policy(self.protocol_policy_override.as_ref(), &self.session)
    }

    pub(crate) fn effective_http_version(
        &self,
        protocol_policy: &crate::protocol::ProtocolPolicy,
    ) -> PreferredHttpVersion {
        pipeline::effective_http_version(self.version_override, protocol_policy, &self.session)
    }

    /// Resolve the effective total timeout for this request.
    pub(crate) fn effective_total_timeout(&self) -> Duration {
        self.timeout.unwrap_or_else(|| {
            self.session
                .inner
                .client
                .timeouts()
                .total_timeout_or(Duration::from_secs(60))
        })
    }
}

// ---------------------------------------------------------------------------
// Shared header merge logic
// ---------------------------------------------------------------------------

/// Parse `name=value` pairs from one `Cookie` header value (`;`-separated, RFC 6265-style).
fn parse_cookie_header_value(raw: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for part in raw.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((n, v)) = part.split_once('=') {
            out.push((n.trim().to_string(), v.trim().to_string()));
        } else {
            out.push((part.to_string(), String::new()));
        }
    }
    out
}

/// Remove all `Cookie` headers and return the parsed pairs in field order.
fn drain_cookie_pairs_from_headers(headers: &mut HeaderMap) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for val in headers.get_all(http::header::COOKIE) {
        if let Ok(s) = val.to_str() {
            pairs.extend(parse_cookie_header_value(s));
        }
    }
    headers.remove(http::header::COOKIE);
    pairs
}

/// Header name order and optional cookie name order for [`RequestBuilder::merge_headers`].
pub(crate) struct HeaderMergeOrdering<'a> {
    pub header_order: &'a [http::header::HeaderName],
    pub cookie_order: Option<&'a [Box<str>]>,
}

/// Merge default headers, request headers, and cookies into the target
/// `HeaderMap`.
///
/// This is the single implementation shared by `RequestBuilder::merge_headers`
/// and `merge_headers_for_streaming`.
///
/// `is_h1` controls whether the Host header is preserved (H1.1 needs it,
/// H2 uses `:authority` instead).
///
/// # Cookie merging
///
/// Whether two URLs differ in **origin** (scheme, host, or port).
///
/// This is the Fetch "same origin" comparison and is the trigger for stripping
/// the `Authorization` header on a cross-origin redirect (Fetch §4.4 / Chrome
/// M112+). Note that a scheme-only change (e.g. an `https`→`http` downgrade on
/// the same host) counts as cross-origin, because the default port differs and,
/// explicitly here, the scheme differs.
pub(crate) fn redirect_is_cross_origin(from: &Url, to: &Url) -> bool {
    from.scheme() != to.scheme()
        || from.host_str() != to.host_str()
        || from.port_or_known_default() != to.port_or_known_default()
}

/// Whether following a `status` redirect rewrites `method` to `GET` (and
/// therefore drops the request body).
///
/// This is the Fetch Standard's "HTTP-redirect fetch" step, which is what
/// browsers actually implement:
///
/// > If one of the following is true
/// >
/// > - internalResponse's status is 301 or 302 and request's method is `POST`
/// > - internalResponse's status is 303 and request's method is not `GET` or
/// >   `HEAD`
/// >
/// > then:
/// >
/// > 1. Set request's method to `GET` and request's body to null.
/// > 2. For each headerName of request-body-header name, delete headerName
/// >    from request's header list.
///
/// It agrees with RFC 9110: §15.4.2 (301) and §15.4.3 (302) permit the rewrite
/// only "from POST to GET"; §15.4.4 (303) directs the user agent to perform "a
/// GET or HEAD request", and calls out HEAD separately ("Except for responses
/// to a HEAD request, ..."), so a HEAD stays a HEAD.
///
/// 307/308 never rewrite, and the non-followable 3xx codes never reach here.
pub(crate) fn redirect_rewrites_method_to_get(status: u16, method: &http::Method) -> bool {
    match status {
        301 | 302 => *method == http::Method::POST,
        303 => *method != http::Method::GET && *method != http::Method::HEAD,
        _ => false,
    }
}

/// Apply an HSTS scheme upgrade to `url` if `policy` marks its host HTTPS-only.
///
/// Returns the rewritten `https://` URL (with an explicit `:80` bumped to
/// `:443`, per RFC 6797 §8.3), or `None` if no upgrade applies. Called before
/// connecting, for both the initial URL and every redirect target.
pub(super) fn hsts_upgrade(url: &str, policy: &dyn crate::hsts::HstsPolicy) -> Option<String> {
    let mut parsed = Url::parse(url).ok()?;
    if parsed.scheme() != "http" {
        return None;
    }
    let host = parsed.host_str()?.to_string();
    if !policy.should_upgrade(&host) {
        return None;
    }
    parsed.set_scheme("https").ok()?;
    if parsed.port() == Some(80) {
        parsed.set_port(Some(443)).ok()?;
    }
    Some(parsed.to_string())
}

/// The host to note as a Known HSTS Host from a `Strict-Transport-Security`
/// response header, or `None` when RFC 6797 §8.1 forbids noting this response.
///
/// Two gates, both mandatory:
///
/// * **Secure transport only.** "If an HTTP response is received over insecure
///   transport, the UA MUST ignore any present STS header field(s)." Without
///   this, anyone able to answer (or tamper with) a cleartext `http://`
///   response can pin — or, with `max-age=0`, un-pin — a host for the rest of
///   the session.
/// * **No IP-literal hosts.** "If the substring matching the host production
///   … is an IP address, the UA MUST NOT note this host as a Known HSTS Host."
///   `Url::host_str` yields IPv6 in bracketed form (`[::1]`), so this uses
///   [`lktls::handshake::hostname_is_ip_literal`], which accepts both forms,
///   rather than a bare `IpAddr` parse.
pub(super) fn hsts_host_to_record(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    // Secure transport: the only scheme this client sends requests over that
    // is TLS-protected. (`wss://` never reaches here — see `crate::ws`.)
    if parsed.scheme() != "https" {
        return None;
    }
    let host = parsed.host_str()?;
    if lktls::handshake::hostname_is_ip_literal(host) {
        return None;
    }
    Some(host.to_string())
}

/// Any `Cookie` set on the request (defaults or per-request headers) is taken
/// as **explicit** pairs. They are sent **first**, and override the session
/// jar for matching cookie names. Pairs from [`RequestBuilder::cookie`](crate::session::RequestBuilder::cookie)
/// are appended after jar-derived pairs (duplicates allowed, matching that API).
///
/// Fully synchronous — cookie reads use lock-free `ArcSwap::load()`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn merge_headers_common(
    headers: &mut HeaderMap,
    client: &Client,
    extra_headers: &HeaderMap,
    parsed_url: &Url,
    is_h1: bool,
    cookie_jar: &arc_swap::ArcSwap<crate::session::CookieJar>,
    extra_cookies: &[(String, String)],
    cookie_overrides: &[String],
    header_order: &[http::header::HeaderName],
    cookie_order: Option<&[Box<str>]>,
) {
    merge_headers_with_defaults(
        headers,
        client.default_headers(),
        extra_headers,
        parsed_url,
        is_h1,
        cookie_jar,
        extra_cookies,
        cookie_overrides,
        header_order,
        cookie_order,
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn merge_headers_with_defaults(
    headers: &mut HeaderMap,
    default_headers: &HeaderMap,
    extra_headers: &HeaderMap,
    parsed_url: &Url,
    is_h1: bool,
    cookie_jar: &arc_swap::ArcSwap<crate::session::CookieJar>,
    extra_cookies: &[(String, String)],
    cookie_overrides: &[String],
    header_order: &[http::header::HeaderName],
    cookie_order: Option<&[Box<str>]>,
) {
    use std::collections::HashSet;

    for name in default_headers.keys() {
        if !extra_headers.contains_key(name) {
            let mut values = default_headers.get_all(name).iter();
            if let Some(first) = values.next() {
                headers.insert(name.clone(), first.clone());
            }
            for value in values {
                headers.append(name.clone(), value.clone());
            }
        }
    }

    for name in extra_headers.keys() {
        let mut values = extra_headers.get_all(name).iter();
        if let Some(first) = values.next() {
            headers.insert(name.clone(), first.clone());
        }
        for value in values {
            headers.append(name.clone(), value.clone());
        }
    }

    if !is_h1 {
        headers.remove(http::header::HOST);
    }

    let manual_pairs = drain_cookie_pairs_from_headers(headers);

    let jar = cookie_jar.load();
    let matches = jar.matches(parsed_url);
    let mut cookie_list: Vec<(String, String)> = matches
        .iter()
        .map(|c| (c.name().to_string(), c.value().to_string()))
        .collect();

    if !cookie_overrides.is_empty() {
        cookie_list.retain(|(n, _)| !cookie_overrides.iter().any(|o| o == n));
    }

    let manual_names: HashSet<&str> = manual_pairs.iter().map(|(n, _)| n.as_str()).collect();
    cookie_list.retain(|(n, _)| !manual_names.contains(n.as_str()));

    for (name, value) in extra_cookies {
        cookie_list.push((name.clone(), value.clone()));
    }

    let mut merged: Vec<(String, String)> =
        Vec::with_capacity(manual_pairs.len() + cookie_list.len());
    merged.extend(manual_pairs);
    merged.extend(cookie_list);

    if let Some(order) = cookie_order {
        reorder_cookies(&mut merged, order);
    }

    if !merged.is_empty() {
        tracing::trace!(url = %parsed_url, "http.cookies_sent");

        // Split cookies into separate headers only when:
        // 1. The request is HTTP/2, AND
        // 2. The user has explicitly configured header ordering
        //    (via fingerprint preset or manual header_order)
        //
        // Without explicit ordering, use a single combined Cookie
        // header for maximum server compatibility.
        let split_h2_cookies = !is_h1 && !header_order.is_empty();

        if split_h2_cookies {
            for (n, v) in &merged {
                let pair = format!("{n}={v}");
                if let Ok(hv) = http::header::HeaderValue::from_str(&pair) {
                    headers.append(http::header::COOKIE, hv);
                }
            }
        } else {
            let val: String =
                merged
                    .iter()
                    .enumerate()
                    .fold(String::new(), |mut acc, (i, (n, v))| {
                        if i > 0 {
                            acc.push_str("; ");
                        }
                        acc.push_str(n);
                        acc.push('=');
                        acc.push_str(v);
                        acc
                    });
            if let Ok(hv) = http::header::HeaderValue::from_str(&val) {
                headers.insert(http::header::COOKIE, hv);
            }
        }
    }

    // Auto-insert Host for HTTP/1.1 if not already present.
    // Must happen before reorder_headers so that header_order can control Host position.
    if is_h1 && !headers.contains_key(http::header::HOST) {
        if let Some(host_value) = super::pipeline::build_host_value_from_url(parsed_url) {
            if let Ok(hv) = http::header::HeaderValue::from_str(&host_value) {
                headers.insert(http::header::HOST, hv);
            }
        }
    }

    if !header_order.is_empty() {
        reorder_headers(headers, header_order);
    }
}

// ---------------------------------------------------------------------------
// Header ordering
// ---------------------------------------------------------------------------

/// Reorder headers according to a template.
///
/// Headers matching entries in `order` are placed first, in the template's
/// order.  Remaining headers that are not in the template are appended
/// after the ordered ones, preserving their relative order from the
/// original `HeaderMap`.
///
/// Reorder a list of `(name, value)` cookie pairs according to a template.
///
/// Reorder a list of cookie pairs in-place according to a template.
///
/// Cookies whose names appear in `order` are placed first (in the template's
/// order). Remaining cookies are appended in their original order.
///
/// Generic over the string type (`String`, `Cow<str>`, etc.) to support
/// both owned and borrowed cookie data without extra allocations.
pub(crate) fn reorder_cookies<S: AsRef<str>, O: AsRef<str>>(
    cookies: &mut Vec<(S, S)>,
    order: &[O],
) {
    let mut result = Vec::with_capacity(cookies.len());

    for name in order {
        if let Some(pos) = cookies
            .iter()
            .position(|(n, _)| n.as_ref() == name.as_ref())
        {
            result.push(cookies.remove(pos));
        }
    }

    result.append(cookies);
    *cookies = result;
}

/// Reorder headers in-place according to a template.
///
/// Headers matching entries in `order` are placed first, in the template's
/// order. Remaining headers are appended after, preserving their relative
/// order. Multi-value headers (e.g. multiple `Cookie` entries in HTTP/2)
/// are fully preserved — all values for a given name are moved together.
pub(crate) fn reorder_headers(headers: &mut HeaderMap, order: &[http::header::HeaderName]) {
    // Snapshot all entries in their current iteration order BEFORE any
    // mutation.  `HeaderMap::remove()` uses backward-shift deletion which
    // can scramble the relative positions of remaining entries, so we must
    // drain first to capture the true insertion order.
    let mut all: Vec<(http::header::HeaderName, http::header::HeaderValue)> =
        Vec::with_capacity(headers.len());
    let mut last_name: Option<http::header::HeaderName> = None;
    for (opt_name, value) in headers.drain() {
        let name = match opt_name {
            Some(n) => {
                last_name = Some(n.clone());
                n
            }
            None => match &last_name {
                Some(n) => n.clone(),
                None => {
                    tracing::warn!("reorder_headers: skipping orphan header value (no field name)");
                    continue;
                }
            },
        };
        all.push((name, value));
    }

    let mut result = HeaderMap::with_capacity(all.len());

    // Phase 1: pull headers matching the template, in template order.
    for template_name in order {
        let mut i = 0;
        while i < all.len() {
            if all[i].0 == *template_name {
                let (name, value) = all.remove(i);
                result.append(name, value);
            } else {
                i += 1;
            }
        }
    }

    // Phase 2: append remaining headers in their original relative order.
    for (name, value) in all {
        result.append(name, value);
    }

    *headers = result;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "quic-h3")]
    #[tokio::test]
    async fn recovered_request_preserves_enclosing_race_send_gates() {
        let (outer_quic, outer_tcp, _) = pipeline::RaceSendGate::pair();
        let (inner_quic, _, inner_selected) = pipeline::RaceSendGate::pair();
        outer_tcp.acquired().await;
        let target = pipeline::parse_request_target("https://localhost/", None).unwrap();
        let headers = HeaderMap::new();
        let method = http::Method::POST;
        let mut ctx = RequestContext {
            method: &method,
            host: &target.host,
            port: target.port,
            scheme: target.scheme,
            path: &target.path,
            conn_key: &target.conn_key,
            extra_headers: &headers,
            parsed_url: &target.parsed_url,
            idempotency: super::super::Idempotency::NotIdempotent,
            race_send_gates: vec![outer_quic, inner_quic],
            retry_early_data: true,
        };
        let recovered = ctx.recovery(true).next_attempt();
        ctx.race_send_gates = recovered.race_send_gates;
        let gated = ctx.acquire_send_gates();
        tokio::pin!(gated);
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(gated.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        assert!(
            inner_selected.borrow().is_none(),
            "an outer losing job cannot enter a nested race"
        );
    }

    #[cfg(feature = "quic-h3")]
    #[tokio::test]
    async fn quic_handshake_completion_survives_late_waiters_and_new_generation() {
        let session = Client::builder()
            .preset(crate::preset::chrome_155())
            .build()
            .session()
            .build();
        let key = pipeline::parse_request_target("https://localhost/", None)
            .unwrap()
            .conn_key;
        let other_key = pipeline::parse_request_target("https://localhost:8443/", None)
            .unwrap()
            .conn_key;
        let guard = QuicHandshakeGuard::try_acquire(&session, &key)
            .ok()
            .unwrap();
        let other = QuicHandshakeGuard::try_acquire(&session, &other_key)
            .ok()
            .unwrap();
        let mut waiters = Vec::new();
        for _ in 0..4 {
            match QuicHandshakeGuard::try_acquire(&session, &key) {
                Ok(_) => panic!("another leader already owns this origin"),
                Err(waiter) => waiters.push(waiter),
            }
        }
        waiters.pop();
        assert_eq!(session.inner.quic_in_flight.lock().len(), 2);
        drop(guard);
        let next = QuicHandshakeGuard::try_acquire(&session, &key)
            .ok()
            .unwrap();
        for mut waiter in waiters {
            // Completion happened before this receiver's first poll, and a
            // replacement already owns the same key. Neither may be missed.
            assert!(
                tokio::time::timeout(Duration::from_secs(1), waiter.changed())
                    .await
                    .unwrap()
                    .is_err()
            );
            assert!(QuicHandshakeGuard::try_acquire(&session, &key).is_err());
        }
        drop(next);
        assert_eq!(session.inner.quic_in_flight.lock().len(), 1);
        drop(other);
        assert!(session.inner.quic_in_flight.lock().is_empty());
    }

    #[test]
    fn first_h2_request_resolves_destination_and_client_priority_defaults() {
        use lkh2::RequestPriority;
        for (request_header, default_header, expected) in [
            (
                Some(("sec-fetch-dest", "document")),
                None,
                RequestPriority::navigation(),
            ),
            (
                None,
                Some(("sec-fetch-dest", "document")),
                RequestPriority::navigation(),
            ),
            (
                None,
                Some(("priority", "u=4, i")),
                RequestPriority::custom(4, true),
            ),
        ] {
            let mut builder = Client::builder().preset(crate::preset::chrome_155());
            if let Some((name, value)) = default_header {
                builder = builder.default_header(name, value);
            }
            let client = builder.build();
            let session = client.session().build();
            let request = session.get("https://example.com/");
            let mut headers = HeaderMap::new();
            if let Some((name, value)) = request_header {
                headers.insert(
                    http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    value.parse().unwrap(),
                );
            }
            let target = pipeline::parse_request_target("https://example.com/", None).unwrap();
            let method = http::Method::GET;
            let ctx = RequestContext {
                method: &method,
                host: &target.host,
                port: target.port,
                scheme: target.scheme,
                path: &target.path,
                conn_key: &target.conn_key,
                extra_headers: &headers,
                parsed_url: &target.parsed_url,
                idempotency: super::super::Idempotency::Default,
                #[cfg(feature = "quic-h3")]
                race_send_gates: Vec::new(),
                #[cfg(feature = "quic-h3")]
                retry_early_data: true,
            };
            let prepared = request.build_h2_request_for_preface(&ctx, None).unwrap();
            assert_eq!(
                prepared.extensions().get::<RequestPriority>().copied(),
                Some(expected)
            );
            assert_eq!(
                prepared.headers().get("priority").unwrap(),
                expected.to_header_value().as_str()
            );
        }
    }

    #[test]
    fn redirect_cross_origin_trigger_includes_scheme() {
        let u = |s: &str| Url::parse(s).unwrap();

        // Same origin → not cross-origin.
        assert!(!redirect_is_cross_origin(
            &u("https://a.com/x"),
            &u("https://a.com/y")
        ));
        // Different host → cross-origin.
        assert!(redirect_is_cross_origin(
            &u("https://a.com/x"),
            &u("https://b.com/y")
        ));
        // Different (default) port via scheme downgrade → cross-origin.
        assert!(redirect_is_cross_origin(
            &u("https://a.com/x"),
            &u("http://a.com/y")
        ));
        // Same host+port but scheme differs (explicit equal ports) → still
        // cross-origin, because the scheme is part of the origin. This is the
        // case the old host+port-only predicate missed.
        assert!(redirect_is_cross_origin(
            &u("https://a.com:8443/x"),
            &u("http://a.com:8443/y")
        ));
        // Different explicit port → cross-origin.
        assert!(redirect_is_cross_origin(
            &u("https://a.com/x"),
            &u("https://a.com:8443/y")
        ));
    }

    /// Fetch "HTTP-redirect fetch": 301/302 rewrite **POST only**; every other
    /// method survives the hop unchanged. RFC 9110 §15.4.2/§15.4.3 say the same
    /// ("change the request method from POST to GET").
    #[test]
    fn redirect_301_302_rewrite_post_only() {
        for status in [301u16, 302] {
            assert!(
                redirect_rewrites_method_to_get(status, &http::Method::POST),
                "{status} must rewrite POST to GET"
            );
            for method in [
                http::Method::GET,
                http::Method::HEAD,
                http::Method::PUT,
                http::Method::DELETE,
                http::Method::PATCH,
                http::Method::OPTIONS,
            ] {
                assert!(
                    !redirect_rewrites_method_to_get(status, &method),
                    "{status} must preserve {method}, not rewrite it to GET"
                );
            }
        }
    }

    /// Fetch: 303 rewrites every method **except GET and HEAD**. RFC 9110
    /// §15.4.4 says the follow-up is "a GET or HEAD request", and treats HEAD
    /// separately, so a HEAD must not gain a body it never asked for.
    #[test]
    fn redirect_303_rewrites_everything_but_get_and_head() {
        for method in [
            http::Method::POST,
            http::Method::PUT,
            http::Method::DELETE,
            http::Method::PATCH,
            http::Method::OPTIONS,
        ] {
            assert!(
                redirect_rewrites_method_to_get(303, &method),
                "303 must rewrite {method} to GET"
            );
        }
        assert!(
            !redirect_rewrites_method_to_get(303, &http::Method::GET),
            "303 must leave GET alone"
        );
        assert!(
            !redirect_rewrites_method_to_get(303, &http::Method::HEAD),
            "303 must leave HEAD as HEAD"
        );
    }

    /// 307/308 preserve method and body for every method, and the
    /// non-followable 3xx codes never rewrite either.
    #[test]
    fn redirect_307_308_never_rewrite() {
        for status in [300u16, 304, 305, 306, 307, 308] {
            for method in [
                http::Method::GET,
                http::Method::HEAD,
                http::Method::POST,
                http::Method::PUT,
                http::Method::DELETE,
                http::Method::PATCH,
            ] {
                assert!(
                    !redirect_rewrites_method_to_get(status, &method),
                    "{status} must never rewrite {method}"
                );
            }
        }
    }

    /// RFC 6797 §8.1: an STS header is only noted when the response came over
    /// a secure transport, and never for an IP-address host.
    #[test]
    fn hsts_record_gate_requires_https_and_dns_host() {
        // Secure transport + DNS host → note it.
        assert_eq!(
            hsts_host_to_record("https://example.com/a"),
            Some("example.com".to_string())
        );
        assert_eq!(
            hsts_host_to_record("https://sub.example.com:8443/a?b=c"),
            Some("sub.example.com".to_string())
        );

        // Insecure transport → MUST ignore the header. A cleartext response
        // must not be able to pin (or, with max-age=0, un-pin) a host.
        assert_eq!(hsts_host_to_record("http://example.com/a"), None);
        assert_eq!(hsts_host_to_record("http://example.com:8080/a"), None);

        // IP-address host → MUST NOT be noted, in either literal form.
        assert_eq!(hsts_host_to_record("https://127.0.0.1:8443/a"), None);
        assert_eq!(hsts_host_to_record("https://192.0.2.10/a"), None);
        assert_eq!(hsts_host_to_record("https://[::1]:8443/a"), None);
        assert_eq!(hsts_host_to_record("https://[2001:db8::1]/a"), None);

        // Unparseable / host-less URLs are simply ignored.
        assert_eq!(hsts_host_to_record("not a url"), None);
    }

    #[test]
    fn test_reorder_headers_basic() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", "text/html".parse().unwrap());
        headers.insert("user-agent", "test/1.0".parse().unwrap());
        headers.insert("cookie", "a=b".parse().unwrap());

        let order = vec![
            http::header::HeaderName::from_static("user-agent"),
            http::header::HeaderName::from_static("accept"),
            http::header::HeaderName::from_static("cookie"),
        ];

        reorder_headers(&mut headers, &order);

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].as_str(), "user-agent");
        assert_eq!(keys[1].as_str(), "accept");
        assert_eq!(keys[2].as_str(), "cookie");
    }

    #[test]
    fn test_reorder_headers_extra_headers_appended() {
        let mut headers = HeaderMap::new();
        headers.insert("x-custom", "value".parse().unwrap());
        headers.insert("accept", "text/html".parse().unwrap());
        headers.insert("user-agent", "test/1.0".parse().unwrap());

        let order = vec![
            http::header::HeaderName::from_static("user-agent"),
            http::header::HeaderName::from_static("accept"),
        ];

        reorder_headers(&mut headers, &order);

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].as_str(), "user-agent");
        assert_eq!(keys[1].as_str(), "accept");
        assert_eq!(keys[2].as_str(), "x-custom");
    }

    #[test]
    fn test_reorder_headers_missing_template_entries() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", "text/html".parse().unwrap());

        let order = vec![
            http::header::HeaderName::from_static("user-agent"),
            http::header::HeaderName::from_static("accept"),
            http::header::HeaderName::from_static("cookie"),
        ];

        reorder_headers(&mut headers, &order);

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].as_str(), "accept");
    }

    #[test]
    fn test_reorder_headers_empty_template() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", "text/html".parse().unwrap());
        headers.insert("user-agent", "test/1.0".parse().unwrap());

        let order: Vec<http::header::HeaderName> = vec![];

        reorder_headers(&mut headers, &order);

        assert_eq!(headers.len(), 2);
        assert!(headers.contains_key("accept"));
        assert!(headers.contains_key("user-agent"));
    }

    #[test]
    fn test_reorder_headers_preserves_values() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", "application/json".parse().unwrap());
        headers.insert("user-agent", "Mozilla/5.0".parse().unwrap());

        let order = vec![
            http::header::HeaderName::from_static("user-agent"),
            http::header::HeaderName::from_static("accept"),
        ];

        reorder_headers(&mut headers, &order);

        assert_eq!(headers.get("user-agent").unwrap(), "Mozilla/5.0");
        assert_eq!(headers.get("accept").unwrap(), "application/json");
    }

    // -------------------------------------------------------------------
    // Cookie order tests
    // -------------------------------------------------------------------

    #[test]
    fn test_reorder_cookies_basic() {
        let mut cookies: Vec<(String, String)> = vec![
            ("c".into(), "3".into()),
            ("a".into(), "1".into()),
            ("b".into(), "2".into()),
        ];
        let order: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
        reorder_cookies(&mut cookies, &order);
        assert_eq!(cookies[0].0, "a");
        assert_eq!(cookies[1].0, "b");
        assert_eq!(cookies[2].0, "c");
    }

    #[test]
    fn test_reorder_cookies_extra_appended() {
        let mut cookies: Vec<(String, String)> = vec![
            ("z".into(), "9".into()),
            ("a".into(), "1".into()),
            ("x".into(), "8".into()),
        ];
        let order: Vec<String> = vec!["a".into()];
        reorder_cookies(&mut cookies, &order);
        assert_eq!(cookies[0].0, "a");
        assert_eq!(cookies[1].0, "z");
        assert_eq!(cookies[2].0, "x");
    }

    #[test]
    fn test_reorder_cookies_empty_template() {
        let mut cookies: Vec<(String, String)> =
            vec![("b".into(), "2".into()), ("a".into(), "1".into())];
        let order: Vec<&str> = vec![];
        reorder_cookies(&mut cookies, &order);
        assert_eq!(cookies[0].0, "b");
        assert_eq!(cookies[1].0, "a");
    }

    #[test]
    fn test_reorder_cookies_preserves_values() {
        let mut cookies: Vec<(String, String)> = vec![
            ("session".into(), "abc123".into()),
            ("csrf".into(), "token456".into()),
        ];
        let order: Vec<String> = vec!["csrf".into(), "session".into()];
        reorder_cookies(&mut cookies, &order);
        assert_eq!(cookies[0], ("csrf".into(), "token456".into()));
        assert_eq!(cookies[1], ("session".into(), "abc123".into()));
    }

    #[test]
    fn test_reorder_cookies_missing_template_entries_skipped() {
        let mut cookies: Vec<(String, String)> = vec![("a".into(), "1".into())];
        let order: Vec<String> = vec!["x".into(), "a".into(), "y".into()];
        reorder_cookies(&mut cookies, &order);
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].0, "a");
    }

    // -------------------------------------------------------------------
    // Multi-value header reorder tests
    // -------------------------------------------------------------------

    #[test]
    fn test_reorder_preserves_multi_value_header() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", "text/html".parse().unwrap());
        headers.append("cookie", "a=1".parse().unwrap());
        headers.append("cookie", "b=2".parse().unwrap());
        headers.append("cookie", "c=3".parse().unwrap());

        let order = vec![
            http::header::HeaderName::from_static("accept"),
            http::header::HeaderName::from_static("cookie"),
        ];

        reorder_headers(&mut headers, &order);

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].as_str(), "accept");
        assert_eq!(keys[1].as_str(), "cookie");

        let cookie_values: Vec<&str> = headers
            .get_all("cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(cookie_values, vec!["a=1", "b=2", "c=3"]);
    }

    #[test]
    fn test_reorder_multi_value_in_template() {
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "test/1.0".parse().unwrap());
        headers.append("cookie", "x=1".parse().unwrap());
        headers.append("cookie", "y=2".parse().unwrap());
        headers.insert("accept", "text/html".parse().unwrap());

        let order = vec![
            http::header::HeaderName::from_static("cookie"),
            http::header::HeaderName::from_static("user-agent"),
            http::header::HeaderName::from_static("accept"),
        ];

        reorder_headers(&mut headers, &order);

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys[0].as_str(), "cookie");
        assert_eq!(keys[1].as_str(), "user-agent");
        assert_eq!(keys[2].as_str(), "accept");

        let cookie_values: Vec<&str> = headers
            .get_all("cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(cookie_values, vec!["x=1", "y=2"]);
    }

    #[test]
    fn test_reorder_mixed_single_and_multi_value() {
        let mut headers = HeaderMap::new();
        headers.insert("x-custom", "val".parse().unwrap());
        headers.append("cookie", "a=1".parse().unwrap());
        headers.append("cookie", "b=2".parse().unwrap());
        headers.insert("accept", "text/html".parse().unwrap());
        headers.append("x-multi", "v1".parse().unwrap());
        headers.append("x-multi", "v2".parse().unwrap());

        let order = vec![
            http::header::HeaderName::from_static("accept"),
            http::header::HeaderName::from_static("cookie"),
        ];

        reorder_headers(&mut headers, &order);

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys[0].as_str(), "accept");
        assert_eq!(keys[1].as_str(), "cookie");

        let cookie_values: Vec<&str> = headers
            .get_all("cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(cookie_values, vec!["a=1", "b=2"]);

        let multi_values: Vec<&str> = headers
            .get_all("x-multi")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(multi_values, vec!["v1", "v2"]);

        assert_eq!(headers.get("x-custom").unwrap(), "val");
    }

    // -------------------------------------------------------------------
    // Host auto-insert in merge_headers_common tests
    // -------------------------------------------------------------------

    fn make_test_client_with_order(order: Vec<&str>) -> Client {
        Client::builder().header_order(order).build()
    }

    #[test]
    fn test_host_auto_insert_respects_header_order() {
        let client = make_test_client_with_order(vec!["host", "accept", "user-agent"]);
        let mut headers = HeaderMap::new();
        let extra = HeaderMap::new();
        let url = url::Url::parse("https://example.com/path").unwrap();
        let jar = arc_swap::ArcSwap::from_pointee(crate::session::CookieJar::default());

        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            true,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys[0].as_str(), "host");
        assert_eq!(headers.get("host").unwrap(), "example.com");
    }

    #[test]
    fn test_host_auto_insert_not_in_template() {
        let client = make_test_client_with_order(vec!["accept", "user-agent"]);
        let mut headers = HeaderMap::new();
        let mut extra = HeaderMap::new();
        extra.insert("accept", "text/html".parse().unwrap());
        let url = url::Url::parse("https://example.com/path").unwrap();
        let jar = arc_swap::ArcSwap::from_pointee(crate::session::CookieJar::default());

        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            true,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys[0].as_str(), "accept");
        let host_pos = keys.iter().position(|k| k.as_str() == "host").unwrap();
        assert!(host_pos > 0, "Host should be after template items");
    }

    #[test]
    fn test_host_not_overwritten_if_user_set() {
        let client = make_test_client_with_order(vec!["host", "accept"]);
        let mut headers = HeaderMap::new();
        let mut extra = HeaderMap::new();
        extra.insert("host", "custom-host.example.com".parse().unwrap());
        let url = url::Url::parse("https://example.com/path").unwrap();
        let jar = arc_swap::ArcSwap::from_pointee(crate::session::CookieJar::default());

        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            true,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        assert_eq!(headers.get("host").unwrap(), "custom-host.example.com");
    }

    #[test]
    fn test_host_value_format() {
        let client = make_test_client_with_order(vec!["host"]);
        let jar = arc_swap::ArcSwap::from_pointee(crate::session::CookieJar::default());
        let ho = client.header_order().unwrap_or(&[]);
        let co = client.cookie_order();

        // HTTPS port 443: omit port
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/").unwrap();
        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            true,
            &jar,
            &[],
            &[],
            ho,
            co,
        );
        assert_eq!(headers.get("host").unwrap(), "example.com");

        // HTTPS non-standard port: include port
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com:8443/").unwrap();
        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            true,
            &jar,
            &[],
            &[],
            ho,
            co,
        );
        assert_eq!(headers.get("host").unwrap(), "example.com:8443");

        // HTTP port 80: omit port
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("http://example.com/").unwrap();
        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            true,
            &jar,
            &[],
            &[],
            ho,
            co,
        );
        assert_eq!(headers.get("host").unwrap(), "example.com");

        // HTTP non-standard port: include port
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("http://example.com:8080/").unwrap();
        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            true,
            &jar,
            &[],
            &[],
            ho,
            co,
        );
        assert_eq!(headers.get("host").unwrap(), "example.com:8080");
    }

    #[test]
    fn test_host_not_inserted_for_h2() {
        let client = make_test_client_with_order(vec!["host", "accept"]);
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = arc_swap::ArcSwap::from_pointee(crate::session::CookieJar::default());

        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            false,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        assert!(
            !headers.contains_key("host"),
            "Host should not be present for H2"
        );
    }

    // -------------------------------------------------------------------
    // Cookie path tests (unified path + H1/H2 branching)
    // -------------------------------------------------------------------

    fn make_jar_with_cookies(
        url_str: &str,
        cookies: &[(&str, &str)],
    ) -> arc_swap::ArcSwap<crate::session::CookieJar> {
        let url = url::Url::parse(url_str).unwrap();
        let mut jar = crate::session::CookieJar::default();
        for (name, value) in cookies {
            let raw = cookie_store::RawCookie::build((*name, *value))
                .domain(url.host_str().unwrap())
                .path("/")
                .build();
            let _ = jar.insert_raw(&raw, &url);
        }
        arc_swap::ArcSwap::from_pointee(jar)
    }

    #[test]
    fn test_merge_explicit_cookie_with_jar_and_extra() {
        let client = make_test_client_with_order(vec![]);
        let mut headers = HeaderMap::new();
        let mut extra = HeaderMap::new();
        extra.insert("cookie", "sid=manual".parse().unwrap());
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies("https://example.com/", &[("from_jar", "yes")]);

        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            true,
            &jar,
            &[("from_extra".to_string(), "1".to_string())],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let cookie_val = headers.get("cookie").unwrap().to_str().unwrap();
        assert!(cookie_val.contains("sid=manual"), "explicit: {cookie_val}");
        assert!(cookie_val.contains("from_jar=yes"), "jar: {cookie_val}");
        assert!(cookie_val.contains("from_extra=1"), "extra: {cookie_val}");
        let sid = cookie_val.find("sid=manual").unwrap();
        let j = cookie_val.find("from_jar=yes").unwrap();
        let e = cookie_val.find("from_extra=1").unwrap();
        assert!(
            sid < j && j < e,
            "expected explicit → jar → .cookie order: {cookie_val}"
        );
    }

    #[test]
    fn jar_cookies_outside_cookie_order_keep_chrome_order() {
        let client = make_test_client_with_order(vec![]);
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/api/x").unwrap();
        let mut jar = crate::session::CookieJar::default();
        for set_cookie in [
            "a=1; Path=/",
            "b=2; Path=/",
            "deep=3; Path=/api",
            "c=4; Path=/",
            "d=5; Path=/",
        ] {
            let raw = cookie_store::RawCookie::parse(set_cookie).unwrap();
            jar.insert_raw(&raw, &url).unwrap();
        }
        let jar = arc_swap::ArcSwap::from_pointee(jar);
        let order: Vec<Box<str>> = vec!["c".into()];

        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            true,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            Some(&order),
        );

        // `cookie_order` places `c`; the rest follow Chrome: longer path
        // first, then creation order.
        assert_eq!(headers.get("cookie").unwrap(), "c=4; deep=3; a=1; b=2; d=5");
    }

    #[test]
    fn test_explicit_cookie_overrides_same_name_in_jar() {
        let client = make_test_client_with_order(vec![]);
        let mut headers = HeaderMap::new();
        let mut extra = HeaderMap::new();
        extra.insert("cookie", "dup=from_header".parse().unwrap());
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies("https://example.com/", &[("dup", "from_jar")]);

        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            true,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let cookie_val = headers.get("cookie").unwrap().to_str().unwrap();
        assert!(
            cookie_val.contains("dup=from_header"),
            "header should win: {cookie_val}"
        );
        assert!(
            !cookie_val.contains("from_jar"),
            "jar value should be overridden: {cookie_val}"
        );
    }

    #[test]
    fn test_parse_cookie_header_value_splits_pairs() {
        let p = parse_cookie_header_value("a=1; b=two; c=");
        assert_eq!(
            p,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "two".to_string()),
                ("c".to_string(), "".to_string()),
            ]
        );
    }

    #[test]
    fn test_cookie_no_order_no_extra_unchanged() {
        let client = make_test_client_with_order(vec![]);
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies("https://example.com/", &[("a", "1"), ("b", "2")]);

        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            true,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let cookie_val = headers.get("cookie").unwrap().to_str().unwrap();
        assert!(cookie_val.contains("a=1"));
        assert!(cookie_val.contains("b=2"));
    }

    #[test]
    fn test_cookie_with_order_applied() {
        let client = Client::builder().cookie_order(vec!["b", "a"]).build();
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies("https://example.com/", &[("a", "1"), ("b", "2")]);

        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            true,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let cookie_val = headers.get("cookie").unwrap().to_str().unwrap();
        let b_pos = cookie_val.find("b=2").unwrap();
        let a_pos = cookie_val.find("a=1").unwrap();
        assert!(b_pos < a_pos, "b should come before a, got: {cookie_val}");
    }

    #[test]
    fn test_h2_multiple_cookie_headers() {
        let client = make_test_client_with_order(vec!["cookie"]);
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies(
            "https://example.com/",
            &[("a", "1"), ("b", "2"), ("c", "3")],
        );

        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            false,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let cookie_values: Vec<&str> = headers
            .get_all("cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            cookie_values.len(),
            3,
            "H2 should have 3 separate Cookie headers"
        );
        for val in &cookie_values {
            assert!(
                !val.contains("; "),
                "Each H2 Cookie header should be a single pair: {val}"
            );
        }
    }

    #[test]
    fn test_h1_single_cookie_header() {
        let client = make_test_client_with_order(vec![]);
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies(
            "https://example.com/",
            &[("a", "1"), ("b", "2"), ("c", "3")],
        );

        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            true,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let cookie_values: Vec<&str> = headers
            .get_all("cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            cookie_values.len(),
            1,
            "H1 should have 1 combined Cookie header"
        );
        assert!(
            cookie_values[0].contains("; "),
            "H1 Cookie should have semicolon separators"
        );
    }

    #[test]
    fn test_h2_cookie_order_before_split() {
        let client = Client::builder()
            .header_order(vec!["cookie"])
            .cookie_order(vec!["c", "a", "b"])
            .build();
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies(
            "https://example.com/",
            &[("a", "1"), ("b", "2"), ("c", "3")],
        );

        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            false,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let cookie_values: Vec<&str> = headers
            .get_all("cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(cookie_values.len(), 3);
        assert_eq!(cookie_values[0], "c=3");
        assert_eq!(cookie_values[1], "a=1");
        assert_eq!(cookie_values[2], "b=2");
    }

    #[test]
    fn test_h2_cookie_survives_reorder_headers() {
        let client = Client::builder()
            .header_order(vec!["accept", "cookie", "user-agent"])
            .build();
        let mut headers = HeaderMap::new();
        let mut extra = HeaderMap::new();
        extra.insert("accept", "text/html".parse().unwrap());
        extra.insert("user-agent", "test/1.0".parse().unwrap());
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies("https://example.com/", &[("x", "1"), ("y", "2")]);

        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            false,
            &jar,
            &[],
            &[],
            client.header_order().unwrap_or(&[]),
            client.cookie_order(),
        );

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys[0].as_str(), "accept");
        assert_eq!(keys[1].as_str(), "cookie");
        assert_eq!(keys[2].as_str(), "user-agent");

        let cookie_values: Vec<&str> = headers
            .get_all("cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            cookie_values.len(),
            2,
            "Both H2 Cookie values should survive reorder"
        );
    }

    #[test]
    fn test_h2_no_header_order_uses_single_cookie() {
        let client = Client::builder().build();
        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies("https://example.com/", &[("a", "1"), ("b", "2")]);

        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            false,
            &jar,
            &[],
            &[],
            &[],
            None,
        );

        let cookie_values: Vec<&str> = headers
            .get_all("cookie")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            cookie_values.len(),
            1,
            "H2 without header_order should use single Cookie header for compatibility"
        );
        assert!(
            cookie_values[0].contains("; "),
            "Single Cookie header should use semicolons"
        );
    }

    // -------------------------------------------------------------------
    // Header/cookie ordering override hierarchy tests
    // -------------------------------------------------------------------

    #[test]
    fn test_session_header_order_overrides_client() {
        let client = Client::builder()
            .header_order(vec!["user-agent", "accept"])
            .build();
        let session = client
            .session()
            .header_order(vec!["accept", "user-agent"])
            .build();

        let mut headers = HeaderMap::new();
        let mut extra = HeaderMap::new();
        extra.insert("accept", "text/html".parse().unwrap());
        extra.insert("user-agent", "test/1.0".parse().unwrap());
        let url = url::Url::parse("https://example.com/").unwrap();

        let header_order = super::super::pipeline::effective_header_order(
            None,
            session.header_order(),
            client.header_order(),
            &[],
        );
        let cookie_order = super::super::pipeline::effective_cookie_order(
            None,
            session.cookie_order(),
            client.cookie_order(),
        );

        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            true,
            &session.inner.cookie_jar,
            &[],
            &[],
            header_order,
            cookie_order,
        );

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys[0].as_str(), "accept");
        assert_eq!(keys[1].as_str(), "user-agent");
    }

    #[test]
    fn test_request_header_order_overrides_session_and_client() {
        let client = Client::builder()
            .header_order(vec!["user-agent", "accept"])
            .build();
        let session = client
            .session()
            .header_order(vec!["accept", "user-agent"])
            .build();

        let request_order = vec![
            http::header::HeaderName::from_static("cookie"),
            http::header::HeaderName::from_static("accept"),
            http::header::HeaderName::from_static("user-agent"),
        ];

        let mut headers = HeaderMap::new();
        let mut extra = HeaderMap::new();
        extra.insert("accept", "text/html".parse().unwrap());
        extra.insert("user-agent", "test/1.0".parse().unwrap());
        let url = url::Url::parse("https://example.com/").unwrap();

        let header_order = super::super::pipeline::effective_header_order(
            Some(&request_order),
            session.header_order(),
            client.header_order(),
            &[],
        );
        let cookie_order = super::super::pipeline::effective_cookie_order(
            None,
            session.cookie_order(),
            client.cookie_order(),
        );

        let jar = make_jar_with_cookies("https://example.com/", &[("sid", "abc")]);
        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            true,
            &jar,
            &[],
            &[],
            header_order,
            cookie_order,
        );

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(
            keys[0].as_str(),
            "cookie",
            "cookie should be first per request order"
        );
        assert_eq!(keys[1].as_str(), "accept");
        assert_eq!(keys[2].as_str(), "user-agent");
    }

    #[test]
    fn test_no_explicit_order_uses_insertion_order() {
        let client = Client::builder().build();
        let session = client.session().build();

        let insertion_order = vec![
            http::header::HeaderName::from_static("x-custom"),
            http::header::HeaderName::from_static("accept"),
            http::header::HeaderName::from_static("user-agent"),
        ];

        let mut headers = HeaderMap::new();
        let mut extra = HeaderMap::new();
        extra.insert("accept", "text/html".parse().unwrap());
        extra.insert("user-agent", "test/1.0".parse().unwrap());
        extra.insert("x-custom", "value".parse().unwrap());
        let url = url::Url::parse("https://example.com/").unwrap();

        let header_order = super::super::pipeline::effective_header_order(
            None,
            session.header_order(),
            client.header_order(),
            &insertion_order,
        );
        let cookie_order = super::super::pipeline::effective_cookie_order(
            None,
            session.cookie_order(),
            client.cookie_order(),
        );

        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            true,
            &session.inner.cookie_jar,
            &[],
            &[],
            header_order,
            cookie_order,
        );

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(
            keys[0].as_str(),
            "x-custom",
            "insertion order should be respected"
        );
        assert_eq!(keys[1].as_str(), "accept");
        assert_eq!(keys[2].as_str(), "user-agent");
    }

    #[test]
    fn test_no_fingerprint_no_implicit_header_order() {
        let client = Client::builder().build();
        assert!(
            client.header_order().is_none(),
            "No implicit header_order without fingerprint"
        );
    }

    #[test]
    fn test_header_insertion_order_dedup() {
        let client = Client::builder().build();
        let session = client.session().build();

        let rb = session
            .get("https://example.com")
            .header("accept", "text/html")
            .header("user-agent", "test/1.0")
            .header("accept", "application/json");

        assert_eq!(rb.header_insertion_order.len(), 2);
        assert_eq!(rb.header_insertion_order[0].as_str(), "accept");
        assert_eq!(rb.header_insertion_order[1].as_str(), "user-agent");
    }

    #[test]
    fn test_session_cookie_order_overrides_client() {
        let client = Client::builder().cookie_order(vec!["a", "b", "c"]).build();
        let session = client.session().cookie_order(vec!["c", "b", "a"]).build();

        let mut headers = HeaderMap::new();
        let url = url::Url::parse("https://example.com/").unwrap();
        let jar = make_jar_with_cookies(
            "https://example.com/",
            &[("a", "1"), ("b", "2"), ("c", "3")],
        );

        let header_order = super::super::pipeline::effective_header_order(
            None,
            session.header_order(),
            client.header_order(),
            &[],
        );
        let cookie_order = super::super::pipeline::effective_cookie_order(
            None,
            session.cookie_order(),
            client.cookie_order(),
        );

        merge_headers_common(
            &mut headers,
            &client,
            &HeaderMap::new(),
            &url,
            true,
            &jar,
            &[],
            &[],
            header_order,
            cookie_order,
        );

        let cookie_val = headers.get("cookie").unwrap().to_str().unwrap();
        let c_pos = cookie_val.find("c=3").unwrap();
        let b_pos = cookie_val.find("b=2").unwrap();
        let a_pos = cookie_val.find("a=1").unwrap();
        assert!(
            c_pos < b_pos,
            "c should come before b per session cookie_order"
        );
        assert!(
            b_pos < a_pos,
            "b should come before a per session cookie_order"
        );
    }

    #[test]
    fn test_user_sets_headers_no_config_order_preserved() {
        let client = Client::builder().build();
        let session = client.session().build();

        let insertion_order = vec![
            http::header::HeaderName::from_static("x-first"),
            http::header::HeaderName::from_static("x-second"),
            http::header::HeaderName::from_static("x-third"),
        ];

        let mut headers = HeaderMap::new();
        let mut extra = HeaderMap::new();
        extra.insert("x-first", "1".parse().unwrap());
        extra.insert("x-second", "2".parse().unwrap());
        extra.insert("x-third", "3".parse().unwrap());
        let url = url::Url::parse("https://example.com/").unwrap();

        let header_order = super::super::pipeline::effective_header_order(
            None,
            session.header_order(),
            client.header_order(),
            &insertion_order,
        );

        merge_headers_common(
            &mut headers,
            &client,
            &extra,
            &url,
            true,
            &session.inner.cookie_jar,
            &[],
            &[],
            header_order,
            None,
        );

        let keys: Vec<&http::header::HeaderName> = headers.keys().collect();
        assert_eq!(keys[0].as_str(), "x-first");
        assert_eq!(keys[1].as_str(), "x-second");
        assert_eq!(keys[2].as_str(), "x-third");
    }

    #[test]
    fn test_request_protocol_policy_override_wins_over_session_policy() {
        let client = Client::builder()
            .protocol_policy(crate::protocol::ProtocolPolicy::crawler_throughput())
            .build();
        let session = client
            .session()
            .protocol_policy(crate::protocol::ProtocolPolicy::chrome_conservative())
            .build();
        let rb = session
            .get("https://example.com")
            .protocol_policy(crate::protocol::ProtocolPolicy::h3_strict());

        assert_eq!(
            rb.effective_protocol_policy(),
            crate::protocol::ProtocolPolicy::h3_strict()
        );
    }
}
