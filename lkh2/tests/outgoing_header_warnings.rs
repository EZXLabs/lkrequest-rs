use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use bytes::BytesMut;
use lkh2::{engine::H2Engine, frame::H2Frame, hpack::HeaderDecoder, profile::chrome_144_h2};
use tracing::{
    field::{Field, Visit},
    Event, Subscriber,
};
use tracing_subscriber::{
    layer::{Context, Layer},
    prelude::*,
};

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

#[derive(Default)]
struct Fields(BTreeMap<String, String>);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

impl<S: Subscriber> Layer<S> for Events {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        if event.metadata().target() == "lkh2::request" {
            assert_eq!(*event.metadata().level(), tracing::Level::WARN);
            let mut fields = Fields::default();
            event.record(&mut fields);
            self.0.lock().unwrap().push(fields.0);
        }
    }
}

fn encode_twice(headers: &[(&str, &str)]) -> BytesMut {
    let (mut engine, _) = H2Engine::client(&chrome_144_h2());
    let mut decoder = HeaderDecoder::default();
    let mut wire = BytesMut::new();
    for _ in 0..2 {
        let stream_id = engine.open_stream();
        let frames = engine.build_headers(stream_id, headers, true, None);
        let block: Vec<_> = frames
            .iter()
            .flat_map(|frame| match frame {
                H2Frame::Headers(frame) => frame.header_block.iter().copied(),
                H2Frame::Continuation(frame) => frame.header_block.iter().copied(),
                _ => panic!("unexpected frame"),
            })
            .collect();
        let decoded = decoder.decode(&block).unwrap();
        let expected: Vec<_> = headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        assert_eq!(
            decoded, expected,
            "warning must not rewrite any header, value or order"
        );
        engine.encode_frames(&frames, &mut wire);
    }
    wire
}

#[test]
fn outgoing_h2_warns_without_rewriting_headers() {
    let long_value = "private-value-".repeat(4000);
    let headers = [
        (":method", "GET"),
        (":scheme", "https"),
        (":authority", "private-host.invalid"),
        (":path", "/private?token=private-query"),
        ("connection", "private-connection-value"),
        ("keep-alive", "private-keepalive-value"),
        ("connection", "second-private-value"),
        ("cookie", "private-cookie-value"),
        ("authorization", "private-authorization-value"),
        ("x-long", long_value.as_str()),
    ];
    let events = Events::default();
    let subscriber = tracing_subscriber::registry().with(events.clone());
    let with_warning = tracing::subscriber::with_default(subscriber, || encode_twice(&headers));
    let without_warning =
        tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
            encode_twice(&headers)
        });
    assert_eq!(
        with_warning, without_warning,
        "logging must not change frames or HPACK state"
    );
    let logs = events.0.lock().unwrap();
    assert_eq!(
        logs.len(),
        2,
        "one warning per HEADERS block, including reused connections"
    );
    for (index, fields) in logs.iter().enumerate() {
        assert_eq!(fields["diagnostic"], "h2.request_headers_noncompliant");
        assert_eq!(fields["stream_id"], (1 + index * 2).to_string());
        assert_eq!(fields["headers"], "[\"connection\", \"keep-alive\"]");
        assert!(fields["message"].contains("PROTOCOL_ERROR"));
        assert!(fields["message"].contains("sent unchanged"));
        assert!(
            !format!("{fields:?}").contains("private"),
            "do not log any target or field value"
        );
    }
}

#[test]
fn outgoing_h2_connection_fields_and_invalid_te_warn() {
    for (name, value, expected) in [
        ("Connection", "keep-alive", "connection"),
        ("Keep-Alive", "timeout=5", "keep-alive"),
        ("Proxy-Connection", "keep-alive", "proxy-connection"),
        ("Transfer-Encoding", "chunked", "transfer-encoding"),
        ("Upgrade", "h2c", "upgrade"),
        ("TE", "gzip", "te"),
        ("te", "trailers, gzip", "te"),
        ("te", "trailers;q=1", "te"),
        ("te", "", "te"),
    ] {
        let events = Events::default();
        let subscriber = tracing_subscriber::registry().with(events.clone());
        tracing::subscriber::with_default(subscriber, || {
            encode_twice(&[(name, value)]);
        });
        let logs = events.0.lock().unwrap();
        assert_eq!(logs.len(), 2, "field {name}");
        assert_eq!(logs[0]["headers"], format!("[\"{expected}\"]"));
    }
}

#[test]
fn outgoing_h2_valid_te_and_ordinary_headers_do_not_warn() {
    for value in ["trailers", "Trailers", " trailers\t", "trailers, trailers"] {
        let events = Events::default();
        let subscriber = tracing_subscriber::registry().with(events.clone());
        tracing::subscriber::with_default(subscriber, || {
            encode_twice(&[
                ("te", value),
                ("te", "trailers"),
                ("x-header", "connection"),
            ]);
        });
        assert!(events.0.lock().unwrap().is_empty());
    }
}

#[test]
fn outgoing_h2_http_request_path_warns() {
    let events = Events::default();
    let subscriber = tracing_subscriber::registry().with(events.clone());
    tracing::subscriber::with_default(subscriber, || {
        let (mut engine, _) = H2Engine::client(&chrome_144_h2());
        let request = http::Request::builder()
            .uri("https://example.test/")
            .header("connection", "keep-alive")
            .body(None)
            .unwrap();
        let stream_id = engine.open_stream();
        assert!(!engine.build_request(stream_id, request).is_empty());
    });
    let logs = events.0.lock().unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0]["headers"], "[\"connection\"]");
}
