//! Shared request-head preparation; upload claims and dispatch stay with callers.

use bytes::Bytes;
use http::{header::HeaderName, HeaderMap, Method, Request};
use url::Url;

use crate::connection_pool::Scheme;
use crate::error::{Error, Result};
use crate::session::{pipeline, Session};

pub(crate) struct RequestHeadInput<'a> {
    pub session: &'a Session,
    #[cfg_attr(not(feature = "quic-h3"), allow(dead_code))]
    pub method: &'a Method,
    pub scheme: Scheme,
    pub host: &'a str,
    pub port: u16,
    pub path: &'a str,
    pub parsed_url: &'a Url,
    pub headers: &'a HeaderMap,
    pub default_headers: &'a HeaderMap,
    pub extra_cookies: &'a [(String, String)],
    pub cookie_overrides: &'a [String],
    pub priority: Option<lkh2::RequestPriority>,
    pub h2_priority_weight: Option<u8>,
    pub header_order: Option<&'a [HeaderName]>,
    #[cfg_attr(not(feature = "quic-h3"), allow(dead_code))]
    pub h3_header_order: Option<&'a [HeaderName]>,
    pub cookie_order: Option<&'a [Box<str>]>,
    pub header_insertion_order: &'a [HeaderName],
}

#[derive(Clone, Copy)]
pub(crate) enum H2RequestKind {
    Buffered,
    Preface,
    Streaming,
}

#[derive(Debug)]
pub(crate) struct PreparedH2Request {
    pub uri: http::Uri,
    pub headers: HeaderMap,
    pub priority: lkh2::RequestPriority,
    pub h2_priority_weight: Option<u8>,
}

impl PreparedH2Request {
    /// Materialize the request at the caller's original dispatch phase.
    pub fn into_request(self, method: &Method) -> Request<()> {
        let mut request = Request::new(());
        *request.method_mut() = method.clone();
        *request.uri_mut() = self.uri;
        *request.headers_mut() = self.headers;
        request.extensions_mut().insert(self.priority);
        if let Some(weight) = self.h2_priority_weight {
            request
                .extensions_mut()
                .insert(lkh2::H2PriorityWeight(weight));
        }
        request
    }
}

pub(crate) fn prepare_h2_request(
    input: &RequestHeadInput<'_>,
    body: Option<&Bytes>,
    kind: H2RequestKind,
) -> Result<PreparedH2Request> {
    let client = &input.session.inner.client;
    let uri = pipeline::build_h2_uri(input.scheme, input.host, input.port, input.path);

    // Preserve the existing URI validation phase and error context of each path.
    let parsed_uri = match kind {
        H2RequestKind::Buffered => Some(
            uri.parse::<http::Uri>()
                .map_err(|e| Error::Http(format!("failed to build HTTP request URI: {e}")))?,
        ),
        H2RequestKind::Streaming => Some(
            uri.parse::<http::Uri>()
                .map_err(|e| Error::Http(format!("failed to build HTTP request: {e}")))?,
        ),
        H2RequestKind::Preface => None,
    };
    let mut headers = HeaderMap::new();
    if matches!(kind, H2RequestKind::Preface) {
        pipeline::auto_insert_content_length(&mut headers, body);
    }

    let config = &client.h2_profile().priority_config;
    let resolved =
        pipeline::resolve_request_priority(input.priority, input.headers, input.default_headers);
    let priority = config.effective_priority(resolved);
    if config.auto_priority_header && !input.headers.contains_key("priority") {
        if let Ok(value) = http::HeaderValue::from_str(&priority.to_header_value()) {
            headers.insert("priority", value);
        }
    }

    let header_order = pipeline::effective_header_order(
        input.header_order,
        input.session.inner.header_order.as_deref(),
        client.header_order(),
        input.header_insertion_order,
    );
    let cookie_order = pipeline::effective_cookie_order(
        input.cookie_order,
        input.session.inner.cookie_order.as_deref(),
        client.cookie_order(),
    );
    if !matches!(kind, H2RequestKind::Preface) {
        pipeline::auto_insert_content_length(&mut headers, body);
    }
    crate::session::transport::merge_headers_with_defaults(
        &mut headers,
        input.default_headers,
        input.headers,
        input.parsed_url,
        false,
        &input.session.inner.cookie_jar,
        input.extra_cookies,
        input.cookie_overrides,
        header_order,
        cookie_order,
    );

    let uri = match parsed_uri {
        Some(uri) => uri,
        None => uri
            .parse::<http::Uri>()
            .map_err(|e| Error::Http(format!("failed to build first H2 request: {e}")))?,
    };
    Ok(PreparedH2Request {
        uri,
        headers,
        priority,
        h2_priority_weight: input.h2_priority_weight,
    })
}

#[cfg(feature = "quic-h3")]
pub(crate) fn prepare_h3_request(
    input: &RequestHeadInput<'_>,
    body: Option<crate::body::RequestBody>,
) -> Result<Request<Option<crate::body::RequestBody>>> {
    let client = &input.session.inner.client;
    let uri = pipeline::build_h2_uri(input.scheme, input.host, input.port, input.path);
    let mut request = Request::builder()
        .method(input.method.clone())
        .uri(&uri)
        .body(body.clone())
        .map_err(|e| Error::Http3Request(format!("failed to build HTTP/3 request: {e}")))?;

    let resolved =
        pipeline::resolve_request_priority(input.priority, input.headers, input.default_headers);
    let priority = resolved.unwrap_or_else(lkh2::RequestPriority::fetch);
    request
        .extensions_mut()
        .insert(lkh3::RequestPriorityUpdate(priority.to_header_value()));
    if client.h2_profile().priority_config.auto_priority_header
        && !input.headers.contains_key("priority")
        && !input.default_headers.contains_key("priority")
    {
        if let Ok(value) = http::HeaderValue::from_str(&priority.to_header_value()) {
            request.headers_mut().insert("priority", value);
        }
    }

    let header_order = pipeline::effective_h3_header_order(
        input.h3_header_order,
        input.header_order,
        input.session.h3_header_order(),
        input.session.header_order(),
        client.h3_header_order(),
        client.header_order(),
        input.header_insertion_order,
    );
    let cookie_order = pipeline::effective_cookie_order(
        input.cookie_order,
        input.session.inner.cookie_order.as_deref(),
        client.cookie_order(),
    );
    pipeline::auto_insert_content_length(
        request.headers_mut(),
        body.as_ref().and_then(crate::body::RequestBody::buffered),
    );
    crate::session::transport::merge_headers_with_defaults(
        request.headers_mut(),
        input.default_headers,
        input.headers,
        input.parsed_url,
        false,
        &input.session.inner.cookie_jar,
        input.extra_cookies,
        input.cookie_overrides,
        header_order,
        cookie_order,
    );
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ClientBuilder;
    use crate::Client;

    fn client_builder(auto_priority: bool) -> ClientBuilder {
        let mut profile = lkh2::profile::chrome_144_h2();
        profile.priority_config.auto_priority_header = auto_priority;
        profile.priority_config.default_urgency = 5;
        profile.priority_config.default_incremental = false;
        Client::builder()
            .fingerprint(lktls::profile::presets::chrome_144())
            .h2_profile(profile)
    }

    fn input<'a>(
        session: &'a Session,
        url: &'a Url,
        headers: &'a HeaderMap,
    ) -> RequestHeadInput<'a> {
        static METHOD: Method = Method::POST;
        RequestHeadInput {
            session,
            method: &METHOD,
            scheme: Scheme::Https,
            host: "example.test",
            port: 8443,
            path: "/upload?x=1",
            parsed_url: url,
            headers,
            default_headers: session.inner.client.default_headers(),
            extra_cookies: &[],
            cookie_overrides: &[],
            priority: None,
            h2_priority_weight: None,
            header_order: None,
            h3_header_order: None,
            cookie_order: None,
            header_insertion_order: &[],
        }
    }

    fn header_pairs(headers: &HeaderMap) -> Vec<(&str, &str)> {
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.to_str().unwrap()))
            .collect()
    }

    #[test]
    fn h2_kinds_preserve_default_insertion_order_and_priority_extensions() {
        let session = client_builder(true).build().session().build();
        let url = Url::parse("https://example.test:8443/upload?x=1").unwrap();
        let headers = HeaderMap::new();
        let mut input = input(&session, &url, &headers);
        input.priority = Some(lkh2::RequestPriority::navigation());
        input.h2_priority_weight = Some(42);
        let body = Bytes::from_static(b"abc");

        for (kind, expected) in [
            (
                H2RequestKind::Buffered,
                vec![("priority", "u=0, i"), ("content-length", "3")],
            ),
            (
                H2RequestKind::Preface,
                vec![("content-length", "3"), ("priority", "u=0, i")],
            ),
            (
                H2RequestKind::Streaming,
                vec![("priority", "u=0, i"), ("content-length", "3")],
            ),
        ] {
            let prepared = prepare_h2_request(&input, Some(&body), kind).unwrap();
            assert_eq!(prepared.priority, lkh2::RequestPriority::navigation());
            assert_eq!(prepared.h2_priority_weight, Some(42));
            let request = prepared.into_request(input.method);
            assert_eq!(request.uri(), "https://example.test:8443/upload?x=1");
            assert_eq!(request.method(), Method::POST);
            assert_eq!(header_pairs(request.headers()), expected);
            assert_eq!(
                request.extensions().get::<lkh2::RequestPriority>(),
                Some(&lkh2::RequestPriority::navigation())
            );
            assert_eq!(
                request.extensions().get::<lkh2::H2PriorityWeight>(),
                Some(&lkh2::H2PriorityWeight(42))
            );
        }
    }

    #[test]
    fn h2_preserves_explicit_headers_cookie_overrides_and_repeated_cookies() {
        let session = client_builder(true)
            .default_header("x-default", "kept")
            .default_header("x-choice", "client")
            .default_header("priority", "u=6")
            .header_order(vec!["x-default", "priority"])
            .build()
            .session()
            .header_order(vec!["x-choice", "priority"])
            .build();
        let url = Url::parse("https://example.test:8443/upload?x=1").unwrap();
        session.set_cookie(url.as_str(), "sid", "jar");
        session.set_cookie(url.as_str(), "removed", "jar");
        let mut headers = HeaderMap::new();
        headers.insert("host", "ignored.example".parse().unwrap());
        headers.insert("x-choice", "request".parse().unwrap());
        headers.insert("priority", "u=4".parse().unwrap());
        headers.insert("content-length", "99".parse().unwrap());
        headers.insert("cookie", "sid=manual".parse().unwrap());
        let order = [
            "cookie",
            "x-choice",
            "content-length",
            "priority",
            "x-default",
        ]
        .map(HeaderName::from_static);
        let extra_cookies = [("sid".into(), "extra".into()), ("extra".into(), "2".into())];
        let overrides = ["removed".into()];
        let cookie_order = [Box::<str>::from("extra"), Box::<str>::from("sid")];
        let mut input = input(&session, &url, &headers);
        input.priority = Some(lkh2::RequestPriority::navigation());
        input.header_order = Some(&order);
        input.extra_cookies = &extra_cookies;
        input.cookie_overrides = &overrides;
        input.cookie_order = Some(&cookie_order);

        let prepared = prepare_h2_request(
            &input,
            Some(&Bytes::from_static(b"abc")),
            H2RequestKind::Buffered,
        )
        .unwrap();
        assert_eq!(prepared.priority, lkh2::RequestPriority::navigation());
        assert_eq!(prepared.h2_priority_weight, None);
        let request = prepared.into_request(input.method);
        assert_eq!(
            header_pairs(request.headers()),
            vec![
                ("cookie", "extra=2"),
                ("cookie", "sid=manual"),
                ("cookie", "sid=extra"),
                ("x-choice", "request"),
                ("content-length", "99"),
                ("priority", "u=4"),
                ("x-default", "kept"),
            ]
        );
        assert!(request
            .extensions()
            .get::<lkh2::H2PriorityWeight>()
            .is_none());
    }

    #[test]
    fn h2_default_overrides_preserve_automatic_header_positions() {
        let url = Url::parse("https://example.test/").unwrap();
        let headers = HeaderMap::new();
        let body = Bytes::from_static(b"abc");
        for (name, value) in [("priority", "u=6"), ("content-length", "9")] {
            let session = client_builder(true)
                .default_header(name, value)
                .build()
                .session()
                .build();
            let mut input = input(&session, &url, &headers);
            input.priority = Some(lkh2::RequestPriority::navigation());
            for kind in [
                H2RequestKind::Buffered,
                H2RequestKind::Preface,
                H2RequestKind::Streaming,
            ] {
                let prepared = prepare_h2_request(&input, Some(&body), kind).unwrap();
                let mut expected = vec![
                    (
                        "priority",
                        if name == "priority" { "u=6" } else { "u=0, i" },
                    ),
                    (
                        "content-length",
                        if name == "content-length" { "9" } else { "3" },
                    ),
                ];
                if matches!(kind, H2RequestKind::Preface) {
                    expected.reverse();
                }
                assert_eq!(header_pairs(&prepared.headers), expected);
            }
        }
    }

    #[test]
    fn h2_default_priority_header_survives_explicit_priority_with_auto_on_or_off() {
        let url = Url::parse("https://example.test/").unwrap();
        let headers = HeaderMap::new();
        for auto_priority in [true, false] {
            let session = client_builder(auto_priority)
                .default_header("priority", "u=6")
                .build()
                .session()
                .build();
            let mut input = input(&session, &url, &headers);
            input.priority = Some(lkh2::RequestPriority::navigation());
            let prepared = prepare_h2_request(&input, None, H2RequestKind::Buffered).unwrap();
            assert_eq!(prepared.priority, lkh2::RequestPriority::navigation());
            let request = prepared.into_request(input.method);
            assert_eq!(request.headers()["priority"], "u=6");
            assert!(!request.headers().contains_key("content-length"));
        }
    }

    #[test]
    fn h2_resolves_request_default_and_resource_priority_without_injecting_when_disabled() {
        let session = client_builder(false)
            .default_header("priority", "u=6")
            .build()
            .session()
            .build();
        let url = Url::parse("https://example.test/").unwrap();
        let headers = HeaderMap::new();
        let prepared = prepare_h2_request(
            &input(&session, &url, &headers),
            None,
            H2RequestKind::Streaming,
        )
        .unwrap();
        assert_eq!(prepared.priority, lkh2::RequestPriority::custom(6, false));

        let mut headers = HeaderMap::new();
        headers.insert("priority", "u=2, i".parse().unwrap());
        let prepared = prepare_h2_request(
            &input(&session, &url, &headers),
            None,
            H2RequestKind::Streaming,
        )
        .unwrap();
        assert_eq!(prepared.priority, lkh2::RequestPriority::image());

        let session = client_builder(false).build().session().build();
        let mut headers = HeaderMap::new();
        headers.insert("sec-fetch-dest", "style".parse().unwrap());
        let prepared = prepare_h2_request(
            &input(&session, &url, &headers),
            None,
            H2RequestKind::Streaming,
        )
        .unwrap();
        assert_eq!(prepared.priority, lkh2::RequestPriority::css());
        assert!(!prepared.headers.contains_key("priority"));

        headers.clear();
        let mut input = input(&session, &url, &headers);
        input.port = 443;
        let prepared =
            prepare_h2_request(&input, Some(&Bytes::new()), H2RequestKind::Preface).unwrap();
        assert_eq!(prepared.priority, lkh2::RequestPriority::custom(5, false));
        let request = prepared.into_request(input.method);
        assert_eq!(request.uri(), "https://example.test/upload?x=1");
        assert_eq!(
            header_pairs(request.headers()),
            vec![("content-length", "0")]
        );
    }

    #[test]
    fn h2_materializes_after_upload_headers_are_finalized_at_dispatch() {
        let session = client_builder(true).build().session().build();
        let url = Url::parse("https://example.test/").unwrap();
        let headers = HeaderMap::new();
        let input = input(&session, &url, &headers);
        let upload = crate::body::RequestBody::reader(tokio::io::empty(), Some(3));
        let mut prepared = prepare_h2_request(&input, None, H2RequestKind::Buffered).unwrap();
        assert!(!prepared.headers.contains_key("content-length"));

        upload.prepare_headers(&mut prepared.headers).unwrap();
        let request = prepared.into_request(&Method::PUT);
        assert_eq!(request.method(), Method::PUT);
        assert_eq!(request.headers()["content-length"], "3");
        assert_eq!(
            request.extensions().get::<lkh2::RequestPriority>(),
            Some(&lkh2::RequestPriority::custom(5, false))
        );
        assert!(upload.can_replay());
    }

    #[test]
    fn h2_invalid_uri_retains_each_call_sites_error_context() {
        let session = client_builder(false).build().session().build();
        let url = Url::parse("https://example.test/").unwrap();
        let headers = HeaderMap::new();
        let mut input = input(&session, &url, &headers);
        input.host = "bad host";
        for (kind, prefix) in [
            (H2RequestKind::Buffered, "failed to build HTTP request URI:"),
            (H2RequestKind::Preface, "failed to build first H2 request:"),
            (H2RequestKind::Streaming, "failed to build HTTP request:"),
        ] {
            let error = prepare_h2_request(&input, None, kind).unwrap_err();
            assert!(matches!(error, Error::Http(message) if message.starts_with(prefix)));
        }
    }

    #[cfg(feature = "quic-h3")]
    #[test]
    fn h3_request_specific_order_overrides_generic_and_session_orders() {
        let session = client_builder(true)
            .header_order(vec!["x-a", "x-b"])
            .h3_header_order(vec!["x-a", "priority"])
            .build()
            .session()
            .header_order(vec!["x-b", "x-a"])
            .h3_header_order(vec!["priority", "x-b"])
            .build();
        let url = Url::parse("https://example.test:8443/upload?x=1").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-a", "a".parse().unwrap());
        headers.insert("x-b", "b".parse().unwrap());
        headers.insert("host", "ignored.example".parse().unwrap());
        headers.insert("cookie", "a=1; b=2".parse().unwrap());
        let generic_order = ["x-a", "x-b"].map(HeaderName::from_static);
        let h3_order =
            ["cookie", "x-b", "x-a", "content-length", "priority"].map(HeaderName::from_static);
        let mut input = input(&session, &url, &headers);
        input.header_order = Some(&generic_order);
        input.h3_header_order = Some(&h3_order);
        let request = prepare_h3_request(&input, Some(Bytes::from_static(b"abc").into())).unwrap();
        assert_eq!(request.uri(), "https://example.test:8443/upload?x=1");
        assert_eq!(request.method(), Method::POST);
        assert_eq!(
            header_pairs(request.headers()),
            vec![
                ("cookie", "a=1"),
                ("cookie", "b=2"),
                ("x-b", "b"),
                ("x-a", "a"),
                ("content-length", "3"),
                ("priority", "u=1, i"),
            ]
        );
        assert_eq!(
            request
                .body()
                .as_ref()
                .unwrap()
                .buffered()
                .unwrap()
                .as_ref(),
            b"abc"
        );
        assert_eq!(
            request
                .extensions()
                .get::<lkh3::RequestPriorityUpdate>()
                .unwrap()
                .0,
            "u=1, i"
        );

        input.h3_header_order = None;
        let request = prepare_h3_request(&input, None).unwrap();
        assert_eq!(
            request
                .headers()
                .keys()
                .take(2)
                .map(HeaderName::as_str)
                .collect::<Vec<_>>(),
            vec!["x-a", "x-b"]
        );
        input.header_order = None;
        let request = prepare_h3_request(&input, None).unwrap();
        assert_eq!(
            request
                .headers()
                .keys()
                .take(2)
                .map(HeaderName::as_str)
                .collect::<Vec<_>>(),
            vec!["priority", "x-b"]
        );
    }

    #[cfg(feature = "quic-h3")]
    #[test]
    fn h3_auto_priority_switch_preserves_supplied_headers_and_update_extension() {
        let url = Url::parse("https://example.test/").unwrap();
        for auto_priority in [true, false] {
            let session = client_builder(auto_priority)
                .default_header("priority", "u=6")
                .default_header("content-length", "99")
                .build()
                .session()
                .build();
            let headers = HeaderMap::new();
            let mut input = input(&session, &url, &headers);
            input.priority = Some(lkh2::RequestPriority::navigation());
            let request =
                prepare_h3_request(&input, Some(Bytes::from_static(b"abc").into())).unwrap();
            assert_eq!(request.headers()["priority"], "u=6");
            assert_eq!(request.headers()["content-length"], "99");
            assert_eq!(
                request
                    .extensions()
                    .get::<lkh3::RequestPriorityUpdate>()
                    .unwrap()
                    .0,
                "u=0, i"
            );
        }

        let session = client_builder(false).build().session().build();
        let mut headers = HeaderMap::new();
        headers.insert("priority", "u=4".parse().unwrap());
        let request = prepare_h3_request(&input(&session, &url, &headers), None).unwrap();
        assert_eq!(request.headers()["priority"], "u=4");
        assert_eq!(
            request
                .extensions()
                .get::<lkh3::RequestPriorityUpdate>()
                .unwrap()
                .0,
            "u=4"
        );
        headers.clear();
        let request = prepare_h3_request(&input(&session, &url, &headers), None).unwrap();
        assert!(request.headers().is_empty());
        assert_eq!(
            request
                .extensions()
                .get::<lkh3::RequestPriorityUpdate>()
                .unwrap()
                .0,
            "u=1, i"
        );
    }

    #[cfg(feature = "quic-h3")]
    #[test]
    fn h3_preparation_does_not_validate_or_claim_streaming_upload() {
        let session = client_builder(false).build().session().build();
        let url = Url::parse("https://example.test/").unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("content-length", "wrong".parse().unwrap());
        let body = crate::body::RequestBody::reader(tokio::io::empty(), Some(3));
        let mut request =
            prepare_h3_request(&input(&session, &url, &headers), Some(body.clone())).unwrap();
        assert!(body.can_replay());
        assert!(request.body().as_ref().unwrap().is_streaming());
        assert_eq!(request.headers()["content-length"], "wrong");
        assert!(body.prepare_headers(request.headers_mut()).is_err());
        assert!(body.can_replay());
    }

    #[cfg(feature = "quic-h3")]
    #[test]
    fn h3_invalid_uri_retains_request_error_context() {
        let session = client_builder(false).build().session().build();
        let url = Url::parse("https://example.test/").unwrap();
        let headers = HeaderMap::new();
        let mut input = input(&session, &url, &headers);
        input.host = "bad host";
        let error = prepare_h3_request(&input, None).unwrap_err();
        assert!(
            matches!(error, Error::Http3Request(message) if message.starts_with("failed to build HTTP/3 request:"))
        );
    }
}
