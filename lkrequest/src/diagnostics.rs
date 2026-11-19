use std::cell::RefCell;
use std::future::Future;
use std::time::Instant;

/// Lightweight per-request diagnostics snapshot.
#[derive(Debug, Clone, Default)]
pub struct RequestDiagnostics {
    /// TAI negotiation for the connection established by this request, if any.
    pub trust_anchor: Option<Box<lktls::trust_anchor::TrustAnchorInfo>>,
    /// DNS resolution time in milliseconds, if measured.
    pub dns_ms: Option<u64>,
    /// TCP connect time in milliseconds, if measured.
    pub tcp_ms: Option<u64>,
    /// TLS-over-TCP handshake time in milliseconds, if measured.
    pub tls_ms: Option<u64>,
    /// QUIC handshake time including TLS, excluding DNS, proxy setup and H3 setup.
    /// Absent for reused connections or an uncompleted handshake.
    pub quic_ms: Option<u64>,
    /// Time-to-first-byte in milliseconds, if measured.
    pub ttfb_ms: Option<u64>,
    /// Total request wall-clock time in milliseconds.
    pub total_ms: Option<u64>,
    /// Remote peer socket address (`ip:port`) the request connected to.
    pub remote_addr: Option<String>,
    /// Negotiated application protocol (e.g. `"h2"`, `"http/1.1"`, `"h3"`).
    pub protocol: Option<String>,
    /// Negotiated TLS cipher suite name, if available.
    pub cipher_suite: Option<String>,
}

#[derive(Default)]
struct DiagnosticsState {
    request: RequestDiagnostics,
    #[cfg(feature = "quic-h3")]
    quic_connection: Option<usize>,
}

tokio::task_local! {
    static REQUEST_DIAGNOSTICS: RefCell<DiagnosticsState>;
}

fn with_diagnostics_mut(f: impl FnOnce(&mut RequestDiagnostics)) {
    let _ = REQUEST_DIAGNOSTICS.try_with(|cell| f(&mut cell.borrow_mut().request));
}

#[cfg(feature = "quic-h3")]
pub(crate) fn record_quic_handshake(connection: &quinn::Connection, started: tokio::time::Instant) {
    let _ = REQUEST_DIAGNOSTICS.try_with(|cell| {
        let mut state = cell.borrow_mut();
        state.request.quic_ms = Some(started.elapsed().as_millis() as u64);
        state.quic_connection = Some(connection.stable_id());
    });
}

#[cfg(feature = "quic-h3")]
pub(crate) fn record_h3_connection(connection: &quinn::Connection, remote_dns: bool) {
    let _ = REQUEST_DIAGNOSTICS.try_with(|cell| {
        let mut state = cell.borrow_mut();
        let fresh = state.quic_connection == Some(connection.stable_id());
        let diag = &mut state.request;
        if !fresh {
            diag.dns_ms = None;
            diag.quic_ms = None;
        }
        if remote_dns {
            diag.dns_ms = None;
        }
        diag.tcp_ms = None;
        diag.tls_ms = None;
        // Proxy-resolved endpoints can use a synthetic Quinn address.
        diag.remote_addr = (!remote_dns).then(|| connection.remote_address().to_string());
        diag.cipher_suite = connection
            .handshake_data()
            .and_then(|data| data.downcast::<lktls_quic::HandshakeData>().ok())
            .and_then(|data| data.cipher_suite)
            .map(|suite| format!("0x{suite:04x}"));
    });
}

/// Race branches must not write into each other's diagnostics while polling.
#[cfg(feature = "quic-h3")]
pub(crate) fn isolate<'a, T: Send + 'a>(
    future: std::pin::Pin<Box<dyn Future<Output = crate::error::Result<T>> + Send + 'a>>,
) -> std::pin::Pin<Box<dyn Future<Output = crate::error::Result<T>> + Send + 'a>> {
    let Ok(first_ttfb) = REQUEST_DIAGNOSTICS.try_with(|cell| cell.borrow().request.ttfb_ms) else {
        return future;
    };
    Box::pin(async move {
        let (result, state) = REQUEST_DIAGNOSTICS
            .scope(RefCell::default(), async {
                let result = future.await;
                let state =
                    REQUEST_DIAGNOSTICS.with(|cell| std::mem::take(&mut *cell.borrow_mut()));
                (result, state)
            })
            .await;
        let _ = REQUEST_DIAGNOSTICS.try_with(|cell| {
            let mut parent = cell.borrow_mut();
            *parent = state;
            parent.request.ttfb_ms = first_ttfb.or(parent.request.ttfb_ms);
        });
        result
    })
}

pub fn record_trust_anchor(info: lktls::trust_anchor::TrustAnchorInfo) {
    with_diagnostics_mut(|diag| diag.trust_anchor = Some(Box::new(info)));
}

/// Record DNS resolution time (ms) into the active diagnostics scope (no-op outside one).
pub fn record_dns_ms(ms: u64) {
    with_diagnostics_mut(|diag| diag.dns_ms = Some(ms));
}

/// Record TCP connect time (ms) into the active diagnostics scope (no-op outside one).
pub fn record_tcp_ms(ms: u64) {
    with_diagnostics_mut(|diag| diag.tcp_ms = Some(ms));
}

/// Record TLS handshake time (ms) into the active diagnostics scope (no-op outside one).
pub fn record_tls_ms(ms: u64) {
    with_diagnostics_mut(|diag| diag.tls_ms = Some(ms));
}

/// Record time-to-first-byte (ms); only the first value recorded in a scope is kept.
pub fn record_ttfb_ms(ms: u64) {
    with_diagnostics_mut(|diag| {
        if diag.ttfb_ms.is_none() {
            diag.ttfb_ms = Some(ms);
        }
    });
}

/// Record the remote peer address into the active diagnostics scope (no-op outside one).
pub fn record_remote_addr(addr: impl Into<String>) {
    with_diagnostics_mut(|diag| diag.remote_addr = Some(addr.into()));
}

/// Record the negotiated protocol into the active diagnostics scope (no-op outside one).
pub fn record_protocol(protocol: impl Into<String>) {
    with_diagnostics_mut(|diag| {
        let protocol = protocol.into();
        if protocol != "h3" {
            diag.quic_ms = None;
        }
        diag.protocol = Some(protocol);
    });
}

/// Record the negotiated cipher suite into the active diagnostics scope (no-op outside one).
pub fn record_cipher_suite(cipher_suite: impl Into<String>) {
    with_diagnostics_mut(|diag| diag.cipher_suite = Some(cipher_suite.into()));
}

/// Run a future with request diagnostics collection enabled.
pub async fn capture_request_diagnostics<Fut, T>(future: Fut) -> (T, RequestDiagnostics)
where
    Fut: Future<Output = T>,
{
    REQUEST_DIAGNOSTICS
        .scope(RefCell::default(), async move {
            let started_at = Instant::now();
            let output = future.await;
            let mut diagnostics = REQUEST_DIAGNOSTICS.with(|cell| cell.borrow().request.clone());
            diagnostics.total_ms = Some(started_at.elapsed().as_millis() as u64);
            (output, diagnostics)
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_diagnostics_is_all_none() {
        let d = RequestDiagnostics::default();
        assert!(d.dns_ms.is_none());
        assert!(d.tcp_ms.is_none());
        assert!(d.tls_ms.is_none());
        assert!(d.quic_ms.is_none());
        assert!(d.ttfb_ms.is_none());
        assert!(d.total_ms.is_none());
        assert!(d.remote_addr.is_none());
        assert!(d.protocol.is_none());
        assert!(d.cipher_suite.is_none());
    }

    #[tokio::test]
    async fn record_outside_scope_is_a_noop_and_does_not_leak() {
        // Outside `capture_request_diagnostics` the task-local is absent, so every
        // recorder must be a silent no-op (exercises the `try_with` Err arm) and
        // must not leak into a later capture scope.
        record_dns_ms(1);
        record_tcp_ms(2);
        record_remote_addr("203.0.113.1:443");
        record_protocol("h2");
        record_cipher_suite("TLS_AES_128_GCM_SHA256");

        let (_, diag) = capture_request_diagnostics(async {
            record_tcp_ms(20); // only this in-scope record should be visible
        })
        .await;

        assert_eq!(diag.dns_ms, None, "out-of-scope dns record must not leak");
        assert_eq!(diag.remote_addr, None);
        assert_eq!(diag.protocol, None);
        assert_eq!(diag.cipher_suite, None);
        assert_eq!(diag.tcp_ms, Some(20));
    }

    #[tokio::test]
    async fn capture_collects_every_recorded_field() {
        let (output, diag) = capture_request_diagnostics(async {
            record_dns_ms(10);
            record_tcp_ms(20);
            record_tls_ms(30);
            record_ttfb_ms(40);
            record_remote_addr("198.51.100.7:443");
            record_protocol("h2");
            record_cipher_suite("TLS_AES_256_GCM_SHA384");
            "done"
        })
        .await;

        assert_eq!(output, "done");
        assert_eq!(diag.dns_ms, Some(10));
        assert_eq!(diag.tcp_ms, Some(20));
        assert_eq!(diag.tls_ms, Some(30));
        assert_eq!(diag.ttfb_ms, Some(40));
        assert_eq!(diag.remote_addr.as_deref(), Some("198.51.100.7:443"));
        assert_eq!(diag.protocol.as_deref(), Some("h2"));
        assert_eq!(diag.cipher_suite.as_deref(), Some("TLS_AES_256_GCM_SHA384"));
        // total_ms is always stamped by the harness, independent of recorders.
        assert!(diag.total_ms.is_some());
    }

    #[tokio::test]
    async fn ttfb_records_only_the_first_value() {
        let (_, diag) = capture_request_diagnostics(async {
            record_ttfb_ms(7);
            record_ttfb_ms(99); // must be ignored: TTFB is set once, on first byte
        })
        .await;
        assert_eq!(diag.ttfb_ms, Some(7));
    }
}
