use std::sync::Arc;

use crate::body::WireBody;
use http::HeaderMap;

use crate::connection_pool::{AcquiredConnection, ConnectionPermit};
use crate::error::{ConnectionPhase, Error, Result};
use crate::protocol::ProtocolPolicy;
use crate::proxy::ProxyConfig;
use crate::response::{BodyStream, StreamingResponse};

use super::pipeline;
use super::{PreferredHttpVersion, Session};

/// Internal builder used by [`super::RequestBuilder::send_streaming`].
///
/// Mirrors the relevant fields of `RequestBuilder` but produces a
/// [`StreamingResponse`] instead of a buffered [`crate::response::Response`].
#[derive(Clone)]
pub(crate) struct StreamRequestBuilder {
    pub(crate) session: Session,
    pub(crate) method: http::Method,
    pub(crate) url: String,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Option<crate::body::RequestBody>,
    pub(crate) extra_cookies: Vec<(String, String)>,
    pub(crate) cookie_overrides: Vec<String>,
    pub(crate) proxy_override: Option<ProxyConfig>,
    pub(crate) version_override: Option<PreferredHttpVersion>,
    pub(crate) protocol_policy_override: Option<ProtocolPolicy>,
    pub(crate) no_decompress: bool,
    pub(crate) header_order: Option<Vec<http::header::HeaderName>>,
    #[cfg_attr(not(feature = "quic-h3"), allow(dead_code))]
    pub(crate) h3_header_order: Option<Vec<http::header::HeaderName>>,
    pub(crate) cookie_order: Option<Vec<Box<str>>>,
    pub(crate) header_insertion_order: Vec<http::header::HeaderName>,
    /// Explicit RFC 9218 priority from the originating RequestBuilder.
    pub(crate) priority: Option<lkh2::RequestPriority>,
    pub(crate) h2_priority_weight: Option<u8>,
    pub(crate) idempotency: super::Idempotency,
    #[cfg(feature = "quic-h3")]
    pub(crate) race_send_gate: Option<pipeline::RaceSendGate>,
}

impl StreamRequestBuilder {
    /// Core streaming request implementation (no redirect following).
    ///
    /// Heap-allocated future to avoid stack overflow (see `establish_and_send`).
    pub(crate) fn send_streaming_inner(
        self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<StreamingResponse>> + Send>>
    {
        #[cfg(feature = "quic-h3")]
        if self.session.h3_retry_mode() == crate::retry::H3RetryMode::Chrome155ProtocolErrors {
            return Box::pin(async move {
                let mut request = self;
                let mut retries = 0;
                loop {
                    let result = request.clone().send_streaming_with_pool_retry(true).await;
                    if let Err(ref error) = result {
                        if crate::retry::chrome_h3_owns_error(
                            request.session.h3_retry_mode(),
                            error,
                        ) && crate::retry::chrome_h3_can_retry(
                            error,
                            request.idempotency,
                            request.body.as_ref(),
                            retries,
                        ) {
                            let policy = request.effective_protocol_policy();
                            if let Some(route) = pipeline::chrome_h3_retry_route(
                                &policy,
                                request.effective_http_version(&policy),
                                request.effective_proxy(),
                            ) {
                                retries += 1;
                                if route == pipeline::ProtocolDecision::Tcp {
                                    request.protocol_policy_override =
                                        Some(pipeline::chrome_h3_retry_tcp_policy());
                                    request.version_override = Some(PreferredHttpVersion::Auto);
                                }
                                tracing::debug!(
                                    retry = retries,
                                    protocol = route.as_str(),
                                    "h3.chrome_protocol_error_retry",
                                );
                                continue;
                            }
                        }
                    }
                    return result;
                }
            });
        }
        self.send_streaming_with_pool_retry(true)
    }

    fn send_streaming_with_pool_retry(
        self,
        retry_pooled: bool,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<StreamingResponse>> + Send>>
    {
        Box::pin(async move {
            let effective_proxy = self.effective_proxy();
            let protocol_policy = self.effective_protocol_policy();
            protocol_policy.validate()?;
            let http_version_pref = self.effective_http_version(&protocol_policy);
            let target = pipeline::parse_request_target(&self.url, effective_proxy)?;

            let (pooled, discovery) = pipeline::acquire_pooled(
                &self.session,
                &target.conn_key,
                http_version_pref,
                &protocol_policy,
                effective_proxy,
            )
            .await;

            match pooled {
                #[cfg(feature = "quic-h3")]
                Some(AcquiredConnection::H3 {
                    sender: mut cached_sender,
                    token,
                    cleanup,
                }) => {
                    let result = self.send_h3_streaming(&mut cached_sender, &target).await;

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
                                    &self.method,
                                    self.idempotency,
                                    e,
                                )
                                && self
                                    .session
                                    .inner
                                    .client
                                    .fallback()
                                    .retry_on_connection_close
                                && self
                                    .body
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
                            self.send_streaming_with_pool_retry(false).await
                        }
                        other => other,
                    }
                }
                Some(AcquiredConnection::H2 {
                    sender: cached_sender,
                    token,
                }) => match cached_sender.ready().await {
                    Ok(sender) => {
                        let result = self.send_h2_streaming(sender, &target).await;

                        match result {
                            Err(ref e)
                                if retry_pooled
                                    && e.is_connection_closed()
                                    && crate::retry::retry_is_replay_safe(
                                        &self.method,
                                        self.idempotency,
                                        e,
                                    )
                                    && self
                                        .session
                                        .inner
                                        .client
                                        .fallback()
                                        .retry_on_connection_close
                                    && self
                                        .body
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
                                self.send_streaming_with_pool_retry(false).await
                            }
                            other => other,
                        }
                    }
                    Err(_) => {
                        {
                            let mut pool = self.session.inner.pool.lock();
                            pool.remove_acquired(&target.conn_key, &token);
                        }
                        if retry_pooled {
                            self.send_streaming_with_pool_retry(false).await
                        } else {
                            self.establish_and_send_streaming(&target, None).await
                        }
                    }
                },
                Some(AcquiredConnection::H1 {
                    mut sender,
                    conn_task,
                    permit,
                }) => {
                    if sender.ready().await.is_err() {
                        conn_task.abort();
                        drop(permit);
                        return if retry_pooled {
                            self.send_streaming_with_pool_retry(false).await
                        } else {
                            self.establish_and_send_streaming(&target, None).await
                        };
                    }
                    let result = self
                        .send_h1_streaming(sender, conn_task, permit, &target)
                        .await;
                    match result {
                        Err(ref error)
                            if retry_pooled
                                && error.is_connection_closed()
                                && crate::retry::retry_is_replay_safe(
                                    &self.method,
                                    self.idempotency,
                                    error,
                                )
                                && self
                                    .session
                                    .inner
                                    .client
                                    .fallback()
                                    .retry_on_connection_close
                                && self
                                    .body
                                    .as_ref()
                                    .is_none_or(crate::body::RequestBody::can_replay) =>
                        {
                            self.send_streaming_with_pool_retry(false).await
                        }
                        other => other,
                    }
                }
                None => self.establish_and_send_streaming(&target, discovery).await,
            }
        })
    }

    fn request_head_input<'a>(
        &'a self,
        target: &'a pipeline::ParsedTarget,
    ) -> pipeline::RequestHeadInput<'a> {
        pipeline::RequestHeadInput {
            session: &self.session,
            method: &self.method,
            scheme: target.scheme,
            host: &target.host,
            port: target.port,
            path: &target.path,
            parsed_url: &target.parsed_url,
            headers: &self.headers,
            default_headers: self.session.inner.client.default_headers(),
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

    /// Send a streaming request via HTTP/2 using an existing sender.
    async fn send_h2_streaming(
        &self,
        sender: lkh2::H2ReadySender,
        target: &pipeline::ParsedTarget,
    ) -> Result<StreamingResponse> {
        let client = &self.session.inner.client;
        let end_stream = self.body.is_none();
        let mut request = pipeline::prepare_h2_request(
            &self.request_head_input(target),
            self.body
                .as_ref()
                .and_then(crate::body::RequestBody::buffered),
            pipeline::H2RequestKind::Streaming,
        )?
        .into_request(&self.method);

        let resp_future = if let Some(body) = self.body.as_ref().filter(|body| body.is_streaming())
        {
            body.prepare_headers(request.headers_mut())?;
            sender.send_streaming_request(request, body.clone().into_upload()?)
        } else {
            let (resp_future, mut send_stream) =
                sender.send_request(request, end_stream).map_err(|e| {
                    Error::h2_or_connection_closed(
                        ConnectionPhase::HttpRequest,
                        format!("failed to send H2 request: {e}"),
                    )
                })?;

            if let Some(body_data) = self
                .body
                .as_ref()
                .and_then(crate::body::RequestBody::buffered)
            {
                send_stream
                    .send_data(body_data.clone(), true)
                    .map_err(|e| {
                        Error::h2_or_connection_closed(
                            ConnectionPhase::HttpRequest,
                            format!("failed to send request body: {e}"),
                        )
                    })?;
            }

            resp_future
        };
        let ttfb_started = std::time::Instant::now();
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

        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let limits = client.resource_limits();
        limits.check_response_headers(&resp_headers)?;
        let body_stream = BodyStream::H2(resp.into_body());

        pipeline::store_cookies(&self.session, &resp_headers, &target.parsed_url);
        pipeline::store_alt_svc(
            &self.session,
            &resp_headers,
            self.effective_proxy(),
            target.scheme,
            &target.host,
            target.port,
        );

        Ok(StreamingResponse::new(status, resp_headers, body_stream)
            .with_max_body_size(limits.max_response_body_size)
            .with_no_decompress(self.no_decompress))
    }

    #[cfg(feature = "quic-h3")]
    async fn send_h3_streaming(
        &self,
        sender: &mut lkh3::H3Sender,
        target: &pipeline::ParsedTarget,
    ) -> Result<StreamingResponse> {
        if let Some(gate) = &self.race_send_gate {
            gate.acquired().await;
        }
        let client = &self.session.inner.client;
        let mut request =
            pipeline::prepare_h3_request(&self.request_head_input(target), self.body.clone())?;

        let ttfb_started = std::time::Instant::now();
        let upload = if let Some(body) = self.body.as_ref().filter(|body| body.is_streaming()) {
            body.prepare_headers(request.headers_mut())?;
            Some(body.clone().into_upload()?)
        } else {
            None
        };
        let buffered = self
            .body
            .as_ref()
            .and_then(crate::body::RequestBody::buffered)
            .cloned();
        let request = request.map(|_| ());
        let response = pipeline::await_response_headers(client, async {
            match upload {
                Some(upload) => sender.send_streaming_request(request, upload).await,
                None => sender.send_request(request.map(|_| buffered)).await,
            }
        })
        .await?
        .map_err(|e| pipeline::h3_request_error(&self.session, e, false))?;
        crate::diagnostics::record_ttfb_ms(ttfb_started.elapsed().as_millis() as u64);
        crate::diagnostics::record_protocol("h3");

        let (parts, body) = response.into_parts();
        let status = parts.status;
        let resp_headers = parts.headers;
        let limits = client.resource_limits();
        limits.check_response_headers(&resp_headers)?;

        pipeline::store_cookies(&self.session, &resp_headers, &target.parsed_url);
        pipeline::store_alt_svc(
            &self.session,
            &resp_headers,
            self.effective_proxy(),
            target.scheme,
            &target.host,
            target.port,
        );

        Ok(StreamingResponse::new(
            status,
            resp_headers,
            BodyStream::H3(Box::new(crate::response::H3BodyStream {
                stream: body,
                data_eof: false,
                sender: Some(sender.clone()),
            })),
        )
        .with_max_body_size(limits.max_response_body_size)
        .with_no_decompress(self.no_decompress))
    }

    /// Establish a new connection and send a streaming request.
    ///
    /// Heap-allocated future to avoid stack overflow.
    fn establish_and_send_streaming<'a>(
        &'a self,
        target: &'a pipeline::ParsedTarget,
        discovery: Option<pipeline::QuicDiscovery>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<StreamingResponse>> + Send + 'a>>
    {
        Box::pin(async move {
            if self.body.as_ref().is_some_and(|body| !body.can_replay()) {
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
            let effective_proxy = self.effective_proxy().cloned();
            pipeline::log_protocol_policy(
                &target.conn_key.route,
                &target.host,
                target.port,
                &effective_policy,
                http_version_pref,
            );
            let quic_discovery = match discovery {
                Some(discovery) => discovery,
                None => {
                    pipeline::discover_quic_support(
                        &self.session,
                        target.scheme,
                        &target.host,
                        target.port,
                        effective_proxy.as_ref(),
                        &effective_policy,
                        http_version_pref,
                    )
                    .await
                }
            };
            pipeline::log_quic_discovery(&quic_discovery);
            let decision =
                pipeline::decide_protocol(http_version_pref, &effective_policy, &quic_discovery);
            pipeline::log_protocol_decision(&quic_discovery, &effective_policy, decision);
            match decision {
                pipeline::ProtocolDecision::Tcp => {
                    let result = self
                        .establish_and_send_streaming_tcp(
                            target,
                            effective_proxy.clone(),
                            &effective_policy,
                            http_version_pref,
                            connect_start,
                        )
                        .await;
                    let schedule_probe = result.is_ok()
                        && pipeline::should_background_probe(&effective_policy, &quic_discovery);
                    pipeline::log_background_probe_decision(
                        &target.conn_key.route,
                        &target.host,
                        target.port,
                        &effective_policy,
                        &quic_discovery,
                        schedule_probe,
                    );
                    if schedule_probe {
                        self.session.spawn_background_quic_probe(
                            target.host.clone(),
                            target.port,
                            target.conn_key.clone(),
                            quic_discovery.clone(),
                            effective_proxy.clone(),
                        );
                    }
                    result
                }
                #[cfg(feature = "quic-h3")]
                pipeline::ProtocolDecision::Race => {
                    self.establish_and_send_streaming_race(
                        target,
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
                    self.establish_and_send_streaming_tcp(
                        target,
                        effective_proxy,
                        &effective_policy,
                        http_version_pref,
                        connect_start,
                    )
                    .await
                }
                #[cfg(feature = "quic-h3")]
                pipeline::ProtocolDecision::Quic => {
                    self.establish_and_send_streaming_quic(
                        target,
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
        })
    }

    fn effective_proxy(&self) -> Option<&ProxyConfig> {
        pipeline::effective_proxy(self.proxy_override.as_ref(), &self.session)
    }

    fn effective_protocol_policy(&self) -> ProtocolPolicy {
        pipeline::effective_protocol_policy(self.protocol_policy_override.as_ref(), &self.session)
    }

    fn effective_http_version(&self, protocol_policy: &ProtocolPolicy) -> PreferredHttpVersion {
        pipeline::effective_http_version(self.version_override, protocol_policy, &self.session)
    }

    #[cfg(feature = "quic-h3")]
    #[allow(clippy::too_many_arguments)]
    fn establish_and_send_streaming_race<'a>(
        &'a self,
        target: &'a pipeline::ParsedTarget,
        discovery: &'a pipeline::QuicDiscovery,
        proxy: Option<&'a ProxyConfig>,
        effective_proxy_owned: Option<ProxyConfig>,
        protocol_policy: &'a ProtocolPolicy,
        http_version_pref: PreferredHttpVersion,
        connect_start: std::time::Instant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<StreamingResponse>> + Send + 'a>>
    {
        Box::pin(async move {
            let config = pipeline::protocol_policy_chrome_like_config(
                protocol_policy,
                self.session.chrome_like_protocol_config(),
            );
            let (quic_gate, tcp_gate, selected) = pipeline::RaceSendGate::pair();
            let mut quic_request = self.clone();
            quic_request.race_send_gate = Some(quic_gate);
            let mut tcp_request = self.clone();
            tcp_request.race_send_gate = Some(tcp_gate);
            let quic_future = quic_request.establish_and_send_streaming_quic(
                target,
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
                || tcp_request.establish_and_send_streaming_tcp(
                    target,
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
                            target.host.clone(), target.port, target.scheme, target.conn_key.clone(),
                            effective_proxy_owned.clone(), http_version_pref,
                        );
                    }
                    pipeline::RaceEvent::Won(pipeline::ProtocolDecision::Tcp)
                        if config.keep_quic_probe_after_tcp_win =>
                    {
                        self.session.spawn_background_quic_probe(
                            target.host.clone(), target.port, target.conn_key.clone(),
                            discovery.clone(), effective_proxy_owned.clone(),
                        );
                    }
                    pipeline::RaceEvent::Failed { protocol, stage, error } => match (protocol, stage) {
                        (pipeline::ProtocolDecision::Quic, pipeline::RaceFailureStage::BeforeTcpRelease) => {
                            tracing::warn!(host = %target.host, error = %error, fallback = "quic_to_tcp",
                                "streaming.protocol_race_quic_failed_before_tcp_release");
                        }
                        (pipeline::ProtocolDecision::Quic, pipeline::RaceFailureStage::WaitingForPeer) => {
                            tracing::warn!(host = %target.host, error = %error, fallback = "quic_to_tcp",
                                "streaming.protocol_race_quic_failed_waiting_for_tcp");
                        }
                        (pipeline::ProtocolDecision::Tcp, pipeline::RaceFailureStage::WaitingForPeer) => {
                            tracing::warn!(host = %target.host, error = %error, fallback = "tcp_to_quic",
                                "streaming.protocol_race_tcp_failed_waiting_for_quic");
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
    fn establish_and_send_streaming_quic<'a>(
        &'a self,
        target: &'a pipeline::ParsedTarget,
        discovery: &'a pipeline::QuicDiscovery,
        proxy: Option<&'a ProxyConfig>,
        effective_proxy_owned: Option<ProxyConfig>,
        protocol_policy: &'a ProtocolPolicy,
        http_version_pref: PreferredHttpVersion,
        connect_start: std::time::Instant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<StreamingResponse>> + Send + 'a>>
    {
        Box::pin(async move {
            if self.body.as_ref().is_some_and(|body| !body.can_replay()) {
                return Err(Error::Http(
                    "cannot replay consumed streaming request body".into(),
                ));
            }

            let permit = self.session.reserve_connection()?;
            let h3_conn = match self
                .session
                .establish_h3_connection(
                    &target.host,
                    target.port,
                    discovery.advertised_host.as_deref(),
                    discovery.advertised_port,
                    proxy,
                )
                .await
            {
                Ok(h3_conn) => h3_conn,
                Err(error) => {
                    let is_handshake_class = error.is_quic_handshake_failure();
                    if is_handshake_class {
                        self.session
                            .broken_quic_tracker()
                            .mark_broken_for_route(&discovery.route, &discovery.origin);
                        self.session
                            .alt_svc_cache()
                            .clear_h3_validation_for_route(&discovery.route, &discovery.origin);
                    }

                    let proxy_forbids_tcp_fallback = effective_proxy_owned
                        .as_ref()
                        .is_some_and(|proxy| proxy.forbids_direct_fallback());
                    let fallback_allowed = is_handshake_class
                        && http_version_pref != PreferredHttpVersion::Http3Only
                        && protocol_policy.intent != crate::protocol::HttpIntent::H3Only
                        && !proxy_forbids_tcp_fallback
                        && pipeline::fallback_permitted(protocol_policy, &error);
                    if fallback_allowed {
                        tracing::warn!(
                            route = %discovery.route,
                            host = %target.host,
                            port = target.port,
                            fallback_policy = ?protocol_policy.fallback,
                            error = %error,
                            "quic.handshake_failed_fallback_tcp",
                        );
                        drop(permit);
                        return self
                            .establish_and_send_streaming_tcp(
                                target,
                                effective_proxy_owned,
                                protocol_policy,
                                http_version_pref,
                                connect_start,
                            )
                            .await;
                    }
                    tracing::warn!(
                        route = %discovery.route,
                        host = %target.host,
                        port = target.port,
                        fallback_policy = ?protocol_policy.fallback,
                        error = %error,
                        "quic.handshake_failed_no_fallback",
                    );
                    return Err(error);
                }
            };

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
            let mut send_sender = sender.clone();
            let cleanup = {
                let mut pool = self.session.inner.pool.lock();
                pool.insert_h3_reserved(target.conn_key.clone(), sender, driver, permit)
            };

            tracing::debug!(
                route = %target.conn_key.route,
                path = "new_h3",
                protocol = "h3",
                duration_ms = connect_start.elapsed().as_millis() as u64,
                "connection.established",
            );

            let result = self.send_h3_streaming(&mut send_sender, target).await;
            if let Err(ref error) = result {
                pipeline::finish_closed_h3_attempt(
                    &self.session,
                    &target.conn_key,
                    &crate::connection_pool::PoolToken::H3Tracked(Arc::downgrade(&cleanup)),
                    &cleanup,
                    error,
                )
                .await;
            }
            result
        })
    }

    fn establish_and_send_streaming_tcp<'a>(
        &'a self,
        target: &'a pipeline::ParsedTarget,
        effective_proxy: Option<ProxyConfig>,
        _protocol_policy: &'a ProtocolPolicy,
        http_version_pref: PreferredHttpVersion,
        connect_start: std::time::Instant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<StreamingResponse>> + Send + 'a>>
    {
        Box::pin(async move {
            if self.body.as_ref().is_some_and(|body| !body.can_replay()) {
                return Err(Error::Http(
                    "cannot replay consumed streaming request body".into(),
                ));
            }

            let permit = self.session.reserve_connection()?;
            let client = &self.session.inner.client;
            let connect_config =
                pipeline::build_connect_config(client, http_version_pref, target.scheme);
            let conn = self
                .session
                .establish_connection(
                    &target.host,
                    target.port,
                    effective_proxy.as_ref(),
                    &connect_config,
                )
                .await?;

            #[cfg(feature = "quic-h3")]
            if let Some(gate) = &self.race_send_gate {
                gate.acquired().await;
            }

            let use_h2 = if target.scheme == crate::connection_pool::Scheme::Http {
                match http_version_pref {
                    PreferredHttpVersion::Http2Only => true,
                    PreferredHttpVersion::Http3Only => {
                        return Err(Error::Http("HTTP/3 requires HTTPS".into()));
                    }
                    _ => false,
                }
            } else {
                pipeline::should_use_h2(conn.negotiated_alpn(), http_version_pref)?
            };

            if use_h2 {
                let h2_result: Result<StreamingResponse> = async {
                    let sender = pipeline::establish_h2_and_pool(
                        conn.into_tcp_stream()?,
                        client,
                        &self.session,
                        &target.conn_key,
                        permit,
                    )
                    .await?;

                    tracing::debug!(
                        route = %target.conn_key.route,
                        path = "new_h2",
                        protocol = "h2",
                        duration_ms = connect_start.elapsed().as_millis() as u64,
                        "connection.established",
                    );

                    self.send_h2_streaming(sender, target).await
                }
                .await;

                match h2_result {
                    Ok(resp) => Ok(resp),
                    Err(e)
                        if http_version_pref != PreferredHttpVersion::Http2Only
                            && client.fallback().h2_to_h1
                            && self
                                .body
                                .as_ref()
                                .is_none_or(crate::body::RequestBody::can_replay)
                            && (matches!(e, Error::H2(_)) || e.is_connection_closed())
                            && crate::retry::retry_is_replay_safe(
                                &self.method,
                                self.idempotency,
                                &e,
                            ) =>
                    {
                        tracing::warn!(
                            error = %e,
                            fallback = "h2_to_h1",
                            "streaming.h2_failed_falling_back_to_h1",
                        );

                        let fallback_permit = self.session.reserve_connection()?;
                        let h1_config =
                            pipeline::build_h1_only_connect_config(client, target.scheme);
                        let conn2 = self
                            .session
                            .establish_connection(
                                &target.host,
                                target.port,
                                effective_proxy.as_ref(),
                                &h1_config,
                            )
                            .await?;

                        let (sender, conn_task) =
                            pipeline::handshake_h1(conn2.into_tcp_stream()?).await?;

                        tracing::debug!(
                            route = %target.conn_key.route,
                            path = "fallback_h1",
                            protocol = "h1.1",
                            fallback = true,
                            "connection.established_via_fallback",
                        );

                        self.send_h1_streaming(sender, conn_task, fallback_permit, target)
                            .await
                    }
                    Err(e) => Err(e),
                }
            } else {
                let negotiated_alpn = conn.negotiated_alpn();
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
                    route = %target.conn_key.route,
                    path = "new_h1",
                    protocol = "h1.1",
                    duration_ms = connect_start.elapsed().as_millis() as u64,
                    "connection.established",
                );

                self.send_h1_streaming(sender, conn_task, permit, target)
                    .await
            }
        })
    }

    async fn send_h1_streaming(
        &self,
        mut sender: hyper::client::conn::http1::SendRequest<WireBody>,
        conn_task: Arc<tokio::task::JoinHandle<()>>,
        permit: ConnectionPermit,
        target: &pipeline::ParsedTarget,
    ) -> Result<StreamingResponse> {
        let client = &self.session.inner.client;
        let mut request = self.build_h1_request_obj(target)?;
        let upload_guard = pipeline::H1UploadGuard::new(conn_task.clone(), request.body());
        request.body_mut().validate_empty().await?;
        let ttfb_started = std::time::Instant::now();
        let resp = pipeline::await_response_headers(client, sender.send_request(request))
            .await?
            .map_err(|e| Error::from_h1_error(e, "HTTP/1.1 request failed"))?;
        crate::diagnostics::record_ttfb_ms(ttfb_started.elapsed().as_millis() as u64);
        crate::diagnostics::record_protocol("http/1.1");

        let status = resp.status();
        let resp_headers = resp.headers().clone();
        let limits = client.resource_limits();
        limits.check_response_headers(&resp_headers)?;
        let mut incoming = resp.into_body();

        let (tx, rx) = tokio::sync::mpsc::channel(2);
        tokio::spawn(async move {
            use http_body_util::BodyExt;

            let _conn_task = conn_task;
            let _upload_guard = upload_guard;
            let _permit = permit;
            loop {
                let frame = tokio::select! {
                    _ = tx.closed() => break,
                    frame = incoming.frame() => match frame {
                        Some(frame) => frame,
                        None => break,
                    },
                };
                match frame {
                    Ok(f) => {
                        if let Some(data) = f.data_ref() {
                            if tx.send(Ok(data.clone())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx
                            .send(Err(format!("error reading H1 body stream: {e}")))
                            .await;
                        break;
                    }
                }
            }
        });

        let body_stream = BodyStream::H1(rx);
        pipeline::store_cookies(&self.session, &resp_headers, &target.parsed_url);
        pipeline::store_alt_svc(
            &self.session,
            &resp_headers,
            self.effective_proxy(),
            target.scheme,
            &target.host,
            target.port,
        );

        Ok(StreamingResponse::new(status, resp_headers, body_stream)
            .with_max_body_size(limits.max_response_body_size)
            .with_no_decompress(self.no_decompress))
    }

    fn build_h1_request_obj(
        &self,
        target: &pipeline::ParsedTarget,
    ) -> Result<http::Request<WireBody>> {
        let client = &self.session.inner.client;

        let uri: http::Uri = target
            .path
            .parse()
            .map_err(|e| Error::Http(format!("invalid request path '{}': {e}", target.path)))?;

        let mut request = http::Request::builder()
            .method(self.method.clone())
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

        pipeline::auto_insert_content_length(
            request.headers_mut(),
            self.body
                .as_ref()
                .and_then(crate::body::RequestBody::buffered),
        );

        pipeline::merge_headers(
            request.headers_mut(),
            client,
            &self.headers,
            &target.parsed_url,
            true,
            &self.session,
            &self.extra_cookies,
            &self.cookie_overrides,
            header_order,
            cookie_order,
        );

        pipeline::into_wire_request(request, self.body.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Client;
    use url::Url;

    fn test_session() -> Session {
        let client = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .default_header("user-agent", "TestBot/1.0")
            .build();
        client.session().build()
    }

    // ====================================================================
    // store_cookies (pipeline) — server Set-Cookie handling
    // ====================================================================

    #[test]
    fn stores_single_set_cookie_header() {
        let session = test_session();
        let url = Url::parse("https://shop.example.com/cart").unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::SET_COOKIE,
            "cart_id=abc123; Path=/".parse().unwrap(),
        );

        pipeline::store_cookies(&session, &headers, &url);

        assert_eq!(
            session.get_cookie("https://shop.example.com/cart", "cart_id"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn stores_multiple_set_cookie_headers() {
        let session = test_session();
        let url = Url::parse("https://example.com/login").unwrap();

        let mut headers = HeaderMap::new();
        headers.append(
            http::header::SET_COOKIE,
            "session=xyz; Path=/; HttpOnly".parse().unwrap(),
        );
        headers.append(
            http::header::SET_COOKIE,
            "theme=dark; Path=/".parse().unwrap(),
        );

        pipeline::store_cookies(&session, &headers, &url);

        assert_eq!(
            session.get_cookie("https://example.com/", "session"),
            Some("xyz".to_string())
        );
        assert_eq!(
            session.get_cookie("https://example.com/", "theme"),
            Some("dark".to_string())
        );
    }

    #[test]
    fn no_set_cookie_headers_is_noop() {
        let session = test_session();
        let url = Url::parse("https://example.com").unwrap();
        let headers = HeaderMap::new();

        pipeline::store_cookies(&session, &headers, &url);
        assert!(session.get_cookies("https://example.com").is_empty());
    }

    // ====================================================================
    // merge_headers (pipeline) — header assembly for requests
    // ====================================================================

    #[test]
    fn default_headers_applied() {
        let session = test_session();
        let url = Url::parse("https://example.com/api").unwrap();
        let client = session.client();

        let mut target = HeaderMap::new();
        pipeline::merge_headers(
            &mut target,
            client,
            &HeaderMap::new(),
            &url,
            false,
            &session,
            &[],
            &[],
            &[],
            None,
        );

        assert!(target.contains_key("user-agent"));
    }

    #[test]
    fn request_headers_override_defaults() {
        let session = test_session();
        let url = Url::parse("https://example.com").unwrap();
        let client = session.client();

        let mut extra = HeaderMap::new();
        extra.insert("user-agent", "CustomBot/2.0".parse().unwrap());

        let mut target = HeaderMap::new();
        pipeline::merge_headers(
            &mut target,
            client,
            &extra,
            &url,
            false,
            &session,
            &[],
            &[],
            &[],
            None,
        );

        assert_eq!(target.get("user-agent").unwrap(), "CustomBot/2.0");
    }

    #[test]
    fn cookies_from_jar_merged_into_request() {
        let session = test_session();
        session.set_cookie("https://example.com", "sid", "abc");
        let url = Url::parse("https://example.com/page").unwrap();
        let client = session.client();

        let mut target = HeaderMap::new();
        pipeline::merge_headers(
            &mut target,
            client,
            &HeaderMap::new(),
            &url,
            true,
            &session,
            &[],
            &[],
            &[],
            None,
        );

        let cookie_hdr = target.get(http::header::COOKIE).unwrap().to_str().unwrap();
        assert!(cookie_hdr.contains("sid=abc"));
    }

    #[test]
    fn extra_cookies_appended() {
        let session = test_session();
        let url = Url::parse("https://example.com").unwrap();
        let client = session.client();

        let extra_cookies = vec![("tracking".to_string(), "xyz".to_string())];

        let mut target = HeaderMap::new();
        pipeline::merge_headers(
            &mut target,
            client,
            &HeaderMap::new(),
            &url,
            true,
            &session,
            &extra_cookies,
            &[],
            &[],
            None,
        );

        let cookie_hdr = target.get(http::header::COOKIE).unwrap().to_str().unwrap();
        assert!(cookie_hdr.contains("tracking=xyz"));
    }

    #[test]
    fn cookie_overrides_remove_jar_cookies() {
        let session = test_session();
        session.set_cookie("https://example.com", "token", "old_val");
        let url = Url::parse("https://example.com").unwrap();
        let client = session.client();

        let extra_cookies = vec![("token".to_string(), "new_val".to_string())];
        let overrides = vec!["token".to_string()];

        let mut target = HeaderMap::new();
        pipeline::merge_headers(
            &mut target,
            client,
            &HeaderMap::new(),
            &url,
            true,
            &session,
            &extra_cookies,
            &overrides,
            &[],
            None,
        );

        let cookie_hdr = target.get(http::header::COOKIE).unwrap().to_str().unwrap();
        assert!(cookie_hdr.contains("new_val"));
        assert!(!cookie_hdr.contains("old_val"));
    }

    #[test]
    fn h2_skips_host_header_from_defaults() {
        let client = Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .default_header("host", "should-be-skipped.com")
            .default_header("accept", "text/html")
            .build();
        let session = client.session().build();
        let url = Url::parse("https://example.com").unwrap();

        let mut target = HeaderMap::new();
        pipeline::merge_headers(
            &mut target,
            &client,
            &HeaderMap::new(),
            &url,
            false,
            &session,
            &[],
            &[],
            &[],
            None,
        );

        assert!(!target.contains_key("host"));
        assert!(target.contains_key("accept"));
    }
}
